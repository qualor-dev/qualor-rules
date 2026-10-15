using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// How a member is used at an operation (review note M1 of Task 5: SymbolMatch matches a property symbol against both
/// get and set patterns, so the engine picks the patterns by the access): a call (methods and constructors), a property
/// read or a property write. A compound assignment (`x.P += v`) is both a read and a write.
internal enum Access { Call, Get, Set }

/// The model entries (of type T) whose member patterns match a symbol, for one access; cached by the symbol's
/// definition (a reduced extension method by its static form), so SymbolMatch runs once per member and access.
internal sealed class MemberTable<T>
{
    private readonly List<(MemberPattern Pattern, T Item)> _entries = new();
    private readonly Dictionary<(ISymbol, Access), T[]> _cache = new(new KeyComparer());

    public void Add(MemberPattern pattern, T item) => _entries.Add((pattern, item));

    public bool IsEmpty => _entries.Count == 0;

    public T[] Match(ISymbol symbol, Access access)
    {
        if (_entries.Count == 0) return Array.Empty<T>();
        var key = Definition(symbol);
        if (_cache.TryGetValue((key, access), out var hit)) return hit;
        var result = _entries.Where(e => KindFits(e.Pattern.Kind, access) && SymbolMatch.Matches(e.Pattern, key)).Select(e => e.Item).ToArray();
        _cache[(key, access)] = result;
        return result;
    }

    public static ISymbol Definition(ISymbol symbol) => symbol is IMethodSymbol m ? (m.ReducedFrom ?? m).OriginalDefinition : symbol.OriginalDefinition;

    private static bool KindFits(MemberKind kind, Access access) => access switch
    {
        Access.Call => kind is MemberKind.Method or MemberKind.Constructor,
        Access.Get => kind == MemberKind.PropertyGet,
        Access.Set => kind == MemberKind.PropertySet,
        _ => false,
    };

    private sealed class KeyComparer : IEqualityComparer<(ISymbol Symbol, Access Access)>
    {
        public bool Equals((ISymbol Symbol, Access Access) x, (ISymbol Symbol, Access Access) y) =>
            x.Access == y.Access && SymbolEqualityComparer.Default.Equals(x.Symbol, y.Symbol);

        public int GetHashCode((ISymbol Symbol, Access Access) obj) =>
            HashCode.Combine(SymbolEqualityComparer.Default.GetHashCode(obj.Symbol), obj.Access);
    }
}

/// A sink of one rule a member is.
internal sealed record SinkHit(string RuleId, SinkModel Sink);

/// The rules' sinks and sanitizers (models/csharp/<name>.yml of every taint rule), by member.
internal sealed class SinkFinder
{
    private readonly MemberTable<SinkHit> _sinks = new();
    private readonly MemberTable<string> _sanitizers = new();
    private readonly List<(string Rule, StringSanitizer Sanitizer)> _stringSanitizers = new();
    private readonly List<(string Rule, System.Text.RegularExpressions.Regex Name)> _lookups = new();
    private readonly Dictionary<string, string[]> _lookupCache = new(StringComparer.Ordinal);
    private readonly List<(string Rule, System.Text.RegularExpressions.Regex Name)> _awaitedLookups = new();
    private readonly Dictionary<string, string[]> _awaitedLookupCache = new(StringComparer.Ordinal);
    private readonly MemberTable<(string Rule, string ReceiverType)> _receiverSanitizers = new();
    private readonly MemberTable<IReadOnlyList<string>> _keepingSanitizers = new();
    private readonly List<(string Rule, string Type, string Method)> _named = new();
    private readonly Dictionary<ISymbol, string[]> _namedCache = new(SymbolEqualityComparer.Default);
    private readonly MemberTable<(string Rule, KeySanitizer Sanitizer)> _keySanitizers = new();

    public SinkFinder(IEnumerable<RuleModel> rules)
    {
        var allowLists = new List<string>();
        // Taint rules, and the taint form of a misuse rule (its `sinks:`, Task 29).
        foreach (var rule in rules.Where(r => r.Kind == RuleKind.Taint || r.Sinks.Count > 0))
        {
            foreach (var k in rule.KeySanitizers)
            {
                _keySanitizers.Add(k.Member, (rule.RuleId, k));
                HasKeyCalls |= k.Member.Kind == MemberKind.Method;
            }
            foreach (var sink in rule.Sinks) _sinks.Add(sink.Member, new SinkHit(rule.RuleId, sink));
            foreach (var sanitizer in rule.Sanitizers) _sanitizers.Add(sanitizer, rule.RuleId);
            foreach (var s in rule.StringSanitizers) _stringSanitizers.Add((rule.RuleId, s));
            foreach (var l in rule.LookupSanitizers) _lookups.Add((rule.RuleId, l));
            foreach (var l in rule.AwaitedLookupSanitizers) _awaitedLookups.Add((rule.RuleId, l));
            foreach (var (member, receiverType) in rule.ReceiverSanitizers) _receiverSanitizers.Add(member, (rule.RuleId, receiverType));
            foreach (var (member, kept) in rule.KeepingSanitizers) _keepingSanitizers.Add(member, kept);
            foreach (var (type, method) in rule.NamedSanitizers) _named.Add((rule.RuleId, type, method));
            foreach (var g in rule.Guards) Guards.Add(g.Member, (rule.RuleId, g));
            if (rule.AllowLists) allowLists.Add(rule.RuleId);
        }
        AllowListRules = allowLists.ToArray();
    }

    /// The guards of every rule (models/README.md, `guards:`), by the member that checks.
    public MemberTable<(string Rule, GuardModel Guard)> Guards { get; } = new();

    /// The rules the shared allow-lists apply to (`allow-list: literal-tables`).
    public string[] AllowListRules { get; }

    /// Whether any rule has an awaited `lookup:` sanitizer.
    public bool HasAwaitedLookups => _awaitedLookups.Count > 0;

    /// The rules whose awaited `lookup:` sanitizers name a method of this name.
    public string[] AwaitedLookups(string methodName)
    {
        if (_awaitedLookups.Count == 0) return Array.Empty<string>();
        if (_awaitedLookupCache.TryGetValue(methodName, out var hit)) return hit;
        hit = _awaitedLookups.Where(l => l.Name.IsMatch(methodName)).Select(l => l.Rule).Distinct().ToArray();
        _awaitedLookupCache[methodName] = hit;
        return hit;
    }

    /// The rules whose `by-name:` sanitizers name this method (by its simple name and its type's simple name).
    public string[] SanitizesByName(IMethodSymbol method)
    {
        if (_named.Count == 0) return Array.Empty<string>();
        if (_namedCache.TryGetValue(method.OriginalDefinition, out var hit)) return hit;
        hit = _named.Where(n => n.Method == method.Name && n.Type == method.ContainingType?.Name).Select(n => n.Rule).Distinct().ToArray();
        _namedCache[method.OriginalDefinition] = hit;
        return hit;
    }

    /// The properties of the call's result that keep what the call was given (`keep-members:`, R-E37 refined).
    public IReadOnlyCollection<string> KeptMembers(IMethodSymbol method)
    {
        if (_keepingSanitizers.IsEmpty) return Array.Empty<string>();
        var hits = _keepingSanitizers.Match(method, Access.Call);
        return hits.Length == 0 ? Array.Empty<string>() : hits.SelectMany(k => k).Distinct(StringComparer.Ordinal).ToList();
    }

    /// The rules whose `receiver-type:` sanitizers this call is: the member matches and the receiver's static type is
    /// the sanitizer's type or derives from it.
    public IReadOnlyCollection<string> SanitizesOnReceiver(IMethodSymbol method, ITypeSymbol? receiverType)
    {
        if (_receiverSanitizers.IsEmpty || receiverType == null) return Array.Empty<string>();
        List<string>? rules = null;
        foreach (var (rule, type) in _receiverSanitizers.Match(method, Access.Call))
        {
            for (var t = receiverType; t != null; t = t.BaseType)
            {
                if (SymbolMatch.MetadataName(t) != type) continue;
                (rules ??= new List<string>()).Add(rule);
                break;
            }
        }
        return (IReadOnlyCollection<string>?)rules ?? Array.Empty<string>();
    }

    /// Whether any rule has a `string-prefix:` sanitizer (the analysis then tracks the text before each value it
    /// builds into a string).
    public bool HasStringSanitizers => _stringSanitizers.Count > 0;

    /// The rules for which a value of type `type` placed into a string after the text `prefix` is clean.
    public IReadOnlyCollection<string> CleanInString(string prefix, ITypeSymbol? type)
    {
        List<string>? rules = null;
        string? typeName = null;
        foreach (var (rule, s) in _stringSanitizers)
        {
            if (s.Type != null && (type == null || s.Type != (typeName ??= SymbolMatch.MetadataName(type)))) continue;
            if (s.Prefix.IsMatch(prefix)) (rules ??= new List<string>()).Add(rule);
        }
        return (IReadOnlyCollection<string>?)rules ?? Array.Empty<string>();
    }

    /// The rules whose `lookup:` sanitizers name a method of this name.
    public string[] Lookups(string methodName)
    {
        if (_lookups.Count == 0) return Array.Empty<string>();
        if (_lookupCache.TryGetValue(methodName, out var hit)) return hit;
        hit = _lookups.Where(l => l.Name.IsMatch(methodName)).Select(l => l.Rule).Distinct().ToArray();
        _lookupCache[methodName] = hit;
        return hit;
    }

    /// The sinks a method or constructor is (its arguments at the sinks' ordinals) or a property write is (the
    /// assigned value).
    public SinkHit[] Sinks(ISymbol member, Access access) => _sinks.Match(member, access);

    /// The rules whose sanitizers this call or property read is (its result is clean for them).
    public string[] Sanitizes(ISymbol member, Access access) => _sanitizers.Match(member, access);

    /// The rules whose keyed sanitizers (`key:`, `key-is:`) this indexer read is: its key is a constant matching the
    /// expression, or a read of the named field or property.
    public IReadOnlyCollection<string> SanitizesKey(IPropertySymbol indexer, IOperation key) =>
        _keySanitizers.IsEmpty ? Array.Empty<string>() : KeyRules(_keySanitizers.Match(indexer, Access.Get), key, null);

    /// Whether any rule has a keyed sanitizer on a method (`method: T.TryGetValue` with `key:`/`key-is:`).
    public bool HasKeyCalls { get; private set; }

    /// The rules whose keyed method sanitizers this call is (M1 of the Task 29 review: `Headers.TryGetValue("Host", out
    /// v)`): its key (argument 0) matches and its receiver's static type is the sanitizer's `receiver-type` (or derives
    /// from it or implements it); the call's `out` values are clean for them.
    public IReadOnlyCollection<string> SanitizesKeyCall(IMethodSymbol method, ITypeSymbol? receiverType, IOperation key) =>
        !HasKeyCalls ? Array.Empty<string>() : KeyRules(_keySanitizers.Match(method, Access.Call), key, receiverType);

    private static IReadOnlyCollection<string> KeyRules((string Rule, KeySanitizer Sanitizer)[] hits, IOperation key, ITypeSymbol? receiverType)
    {
        if (hits.Length == 0) return Array.Empty<string>();
        while (key is IConversionOperation c) key = c.Operand;
        List<string>? rules = null;
        foreach (var (rule, s) in hits)
        {
            if (s.ReceiverType != null && !IsOfType(receiverType, s.ReceiverType)) continue;
            var match = s.Matches != null
                ? key.ConstantValue is { HasValue: true, Value: string text } && s.Matches.IsMatch(text)
                : key switch
                {
                    IFieldReferenceOperation f => f.Field.Name == s.Is!.MemberName && SymbolMatch.MetadataName(f.Field.ContainingType) == s.Is.TypeName,
                    IPropertyReferenceOperation p => SymbolMatch.Matches(s.Is!, p.Property),
                    _ => false,
                };
            if (match) (rules ??= new List<string>()).Add(rule);
        }
        return (IReadOnlyCollection<string>?)rules ?? Array.Empty<string>();
    }

    /// A type that is `name`, derives from it or implements it.
    private static bool IsOfType(ITypeSymbol? type, string name)
    {
        if (type == null) return false;
        for (var t = type; t != null; t = t.BaseType)
            if (SymbolMatch.MetadataName(t) == name) return true;
        return type.AllInterfaces.Any(i => SymbolMatch.MetadataName(i) == name);
    }

    private readonly Dictionary<(string, ISymbol), string?> _messages = new();

    /// The message of the sink of `rule` this member is (`message:`, Task 29), or null.
    public string? MessageFor(string rule, ISymbol member)
    {
        var key = (rule, MemberTable<SinkHit>.Definition(member));
        if (_messages.TryGetValue(key, out var cached)) return cached;
        string? message = null;
        foreach (var access in new[] { Access.Call, Access.Set })
            foreach (var hit in _sinks.Match(member, access))
                if (hit.RuleId == rule && hit.Sink.Message != null) message ??= hit.Sink.Message;
        _messages[key] = message;
        return message;
    }

    /// Whether an argument is a sink's argument: the ordinal of its parameter in the member's definition (an extension
    /// method's `this` is 0) is one of the sink's, that parameter's type one of `param-types` and its name one of
    /// `param-names` when those are given.
    public static bool IsSinkArgument(SinkModel sink, IParameterSymbol definitionParameter) =>
        sink.Args.Contains(definitionParameter.Ordinal)
        && (sink.ParamTypes.Count == 0 || sink.ParamTypes.Contains(SymbolMatch.MetadataName(definitionParameter.Type)))
        && (sink.ParamNames.Count == 0 || sink.ParamNames.Contains(definitionParameter.Name));
}
