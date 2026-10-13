using Microsoft.CodeAnalysis;

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

    public SinkFinder(IEnumerable<RuleModel> rules)
    {
        foreach (var rule in rules.Where(r => r.Kind == RuleKind.Taint))
        {
            foreach (var sink in rule.Sinks) _sinks.Add(sink.Member, new SinkHit(rule.RuleId, sink));
            foreach (var sanitizer in rule.Sanitizers) _sanitizers.Add(sanitizer, rule.RuleId);
        }
    }

    /// The sinks a method or constructor is (its arguments at the sinks' ordinals) or a property write is (the
    /// assigned value).
    public SinkHit[] Sinks(ISymbol member, Access access) => _sinks.Match(member, access);

    /// The rules whose sanitizers this call or property read is (its result is clean for them).
    public string[] Sanitizes(ISymbol member, Access access) => _sanitizers.Match(member, access);

    /// Whether an argument is a sink's argument: the ordinal of its parameter in the member's definition (an extension
    /// method's `this` is 0) is one of the sink's, and that parameter's type one of `param-types` when those are given.
    public static bool IsSinkArgument(SinkModel sink, IParameterSymbol definitionParameter) =>
        sink.Args.Contains(definitionParameter.Ordinal)
        && (sink.ParamTypes.Count == 0 || sink.ParamTypes.Contains(SymbolMatch.MetadataName(definitionParameter.Type)));
}
