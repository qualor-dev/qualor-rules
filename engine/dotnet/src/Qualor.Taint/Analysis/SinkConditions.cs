using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// What a conditional sink's conditions say at one site: not a sink, the whole sink argument, or some of its elements
/// (operations of the original operation tree, which the analysis evaluates in its state).
internal readonly record struct SinkDecision(bool Holds, IReadOnlyList<IOperation>? Elements)
{
    public static readonly SinkDecision No = new(false, null);
    public static readonly SinkDecision Whole = new(true, null);
}

/// The conditions of conditional sinks (models/README.md, `when:`). They are read on the original operation tree of
/// the body that holds the site (the CFG rewrites initializers into flow captures), flow-insensitively: a property
/// set anywhere in the body, before or after the sink, counts, and a local's constant values are all the constants
/// assigned to it in the body. The facts of a body are computed once, when a tainted value first reaches one of its
/// conditional sinks.
internal sealed class SinkConditions
{
    private readonly Dictionary<SyntaxNode, BodyFacts> _facts = new();

    /// Checks `sink`'s conditions at `site` (a CFG invocation or object creation with the sink argument at
    /// `ordinal`, or a property assignment, ordinal −1).
    /// `model` is the semantic model of the body's original tree (the CFG's own operations carry none).
    public SinkDecision Check(SinkModel sink, IOperation site, int ordinal, SemanticModel? model)
    {
        model ??= site.SemanticModel;
        if (model == null) return SinkDecision.No;
        var original = sink.Member.Kind == MemberKind.PropertySet
            ? Original<IAssignmentOperation>(site, model)
            : (IOperation?)Original<IInvocationOperation>(site, model) ?? Original<IObjectCreationOperation>(site, model);
        if (original == null) return SinkDecision.No;
        var facts = Facts(original);

        IOperation? argument;
        string? self;
        IOperation? receiver = null;
        switch (original)
        {
            case IAssignmentOperation assignment:
                argument = assignment.Value;
                self = Unwrap(assignment.Target) is IPropertyReferenceOperation p ? facts.Key(p.Instance) : null;
                break;
            case IInvocationOperation invocation:
                argument = ArgumentValue(invocation, ordinal);
                receiver = invocation.Instance ?? (invocation.TargetMethod.IsExtensionMethod ? ArgumentValue(invocation, 0) : null);
                self = facts.Key(receiver);
                break;
            default:
                argument = ArgumentValue(original, ordinal);
                self = facts.Key(original);
                break;
        }
        if (argument == null) return SinkDecision.No;

        // A receiver condition first: it moves the object of the property conditions to the receiver's owner.
        foreach (var c in sink.When.Where(c => c.Kind == SinkConditionKind.Receiver))
        {
            if (BodyFacts.Initialized(Unwrap(receiver)) is not IPropertyReferenceOperation property || !SymbolMatch.Matches(c.Member!, property.Property))
                return SinkDecision.No;
            self = facts.Key(property.Instance);
        }

        IReadOnlyList<IOperation>? elements = null;
        foreach (var c in sink.When)
        {
            switch (c.Kind)
            {
                case SinkConditionKind.Argument:
                    if (ArgumentValue(original, c.Arg) is not { } other || !AnyMatch(c.Pattern!, facts.Constants(other))) return SinkDecision.No;
                    break;
                case SinkConditionKind.Property:
                {
                    var key = c.Arg >= 0 ? facts.Key(ArgumentValue(original, c.Arg)) : self;
                    if (key == null || !AnyMatch(c.Pattern!, facts.PropertyConstants(key, c.Property!))) return SinkDecision.No;
                    break;
                }
                case SinkConditionKind.LiteralText:
                {
                    if (InPlaceElements(argument) != null) return SinkDecision.No;
                    var fragments = new List<string>();
                    Fragments(argument, fragments, 0);
                    if (fragments.Count > 0 && !fragments.Any(c.Pattern!.IsMatch)) return SinkDecision.No;
                    break;
                }
                case SinkConditionKind.After:
                {
                    if (InPlaceElements(argument) is { } list)
                    {
                        var chosen = new List<IOperation>();
                        for (var k = 0; k < list.Count; k++)
                            if (Follows(c, facts, list, k)) chosen.Add(list[k]);
                        if (chosen.Count == 0) return SinkDecision.No;
                        elements = elements == null ? chosen : elements.Intersect(chosen).ToList();
                        if (elements.Count == 0) return SinkDecision.No;
                    }
                    else if (original is IInvocationOperation { Instance: { } collection } && facts.Key(collection) is { } key)
                    {
                        var added = facts.Adds(key);
                        var k = added.FindIndex(a => a.Syntax == argument.Syntax);
                        if (k < 0 || !Follows(c, facts, added, k)) return SinkDecision.No;
                    }
                    else
                    {
                        return SinkDecision.No;
                    }
                    break;
                }
            }
        }
        return elements != null ? new SinkDecision(true, elements) : SinkDecision.Whole;
    }

    private static bool Follows(SinkCondition c, BodyFacts facts, IReadOnlyList<IOperation> list, int k)
    {
        if (c.Next) return k > 0 && AnyMatch(c.Pattern!, facts.Constants(list[k - 1]));
        for (var j = 0; j < k; j++)
            if (AnyMatch(c.Pattern!, facts.Constants(list[j]))) return true;
        return false;
    }

    private static bool AnyMatch(System.Text.RegularExpressions.Regex pattern, IEnumerable<string> values) => values.Any(pattern.IsMatch);

    private BodyFacts Facts(IOperation original)
    {
        var root = original;
        while (root.Parent != null) root = root.Parent;
        if (!_facts.TryGetValue(root.Syntax, out var facts)) _facts[root.Syntax] = facts = new BodyFacts(root);
        return facts;
    }

    /// The operation of the original (not CFG-rewritten) tree of the same syntax and kind as `cfg`. An implicit
    /// operation (a collection initializer's Add) shares its syntax with the operations it holds.
    private static T? Original<T>(IOperation cfg, SemanticModel model) where T : class, IOperation
    {
        if (model.SyntaxTree != cfg.Syntax.SyntaxTree || model.GetOperation(cfg.Syntax) is not { } op) return null;
        for (var o = op; o != null && o.Syntax == cfg.Syntax; o = o.Parent)
            if (o is T t) return t;
        var stack = new Stack<IOperation>();
        stack.Push(op);
        while (stack.Count > 0)
        {
            var o = stack.Pop();
            if (o is T t) return t;
            foreach (var child in o.ChildOperations)
                if (child.Syntax == cfg.Syntax) stack.Push(child);
        }
        return null;
    }

    /// The value of the argument at parameter `ordinal` of the member's definition (an extension method's `this` is 0).
    internal static IOperation? ArgumentValue(IOperation call, int ordinal)
    {
        var (method, instance, arguments) = call switch
        {
            IInvocationOperation i => (i.TargetMethod, i.Instance, i.Arguments),
            IObjectCreationOperation c => (c.Constructor, null, c.Arguments),
            _ => (null, null, default),
        };
        if (method == null) return null;
        var reduced = method.ReducedFrom != null;
        if (reduced && ordinal == 0) return instance;
        foreach (var a in arguments)
            if (a.Parameter != null && a.Parameter.Ordinal + (reduced ? 1 : 0) == ordinal)
                return a.ArgumentKind == ArgumentKind.DefaultValue ? null : a.Value;
        return null;
    }

    internal static IOperation? Unwrap(IOperation? op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }

    /// The elements of a collection written in place: an array creation with an initializer, an object creation
    /// whose initializer is a collection initializer (its Adds' arguments), a collection expression without spreads.
    internal static IReadOnlyList<IOperation>? InPlaceElements(IOperation? op)
    {
        switch (Unwrap(op))
        {
            case IArrayCreationOperation { Initializer: { } init }:
                return init.ElementValues;
            case IObjectCreationOperation { Initializer: { Initializers.Length: > 0 } init }
                when init.Initializers.All(i => i is IInvocationOperation { Arguments.Length: 1 }):
                return init.Initializers.Select(i => ((IInvocationOperation)i).Arguments[0].Value).ToList();
            case ICollectionExpressionOperation collection when collection.Elements.All(e => e is not ISpreadOperation):
                return collection.Elements;
            default:
                return null;
        }
    }

    /// The literal text a string argument is built from in place: constants, the operands of a string `+`, the text
    /// and holes of an interpolated string, both branches of `?:` and `??`, and the arguments of string.Format, Concat
    /// and Join. A variable or another call adds nothing.
    internal static void Fragments(IOperation? op, List<string> into, int depth)
    {
        op = Unwrap(op);
        if (op == null || depth > 32) return;
        if (op.ConstantValue is { HasValue: true, Value: string s })
        {
            into.Add(s);
            return;
        }
        switch (op)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } b:
                Fragments(b.LeftOperand, into, depth + 1);
                Fragments(b.RightOperand, into, depth + 1);
                break;
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                {
                    if (part is IInterpolatedStringTextOperation text) Fragments(text.Text, into, depth + 1);
                    else if (part is IInterpolationOperation hole) Fragments(hole.Expression, into, depth + 1);
                }
                break;
            case IConditionalOperation conditional:
                Fragments(conditional.WhenTrue, into, depth + 1);
                Fragments(conditional.WhenFalse, into, depth + 1);
                break;
            case ICoalesceOperation coalesce:
                Fragments(coalesce.Value, into, depth + 1);
                Fragments(coalesce.WhenNull, into, depth + 1);
                break;
            case IInvocationOperation { TargetMethod: { ContainingType.SpecialType: SpecialType.System_String, Name: "Format" or "Concat" or "Join" } } call:
                foreach (var a in call.Arguments) Fragments(a.Value, into, depth + 1);
                break;
            case IArrayCreationOperation { Initializer: { } init } when depth > 0:
                foreach (var e in init.ElementValues) Fragments(e, into, depth + 1);
                break;
        }
    }
}

/// The flow-insensitive facts of one body (its original operation tree) the conditions read: which constants each
/// object's properties are set to, which constants each local is assigned, and the Adds to each collection in source
/// order. Objects are keyed by access path (a local, parameter, `this` or static type, then field and property names;
/// an object creation by its position); a variable assigned exactly one object creation is the same object as it.
internal sealed class BodyFacts
{
    private readonly Dictionary<ISymbol, int> _ids = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<string, string> _union = new(StringComparer.Ordinal);
    private readonly List<(string Key, string Property, IOperation Value)> _properties = new();
    private readonly List<(string Key, IOperation Value)> _adds = new();
    private readonly Dictionary<ILocalSymbol, List<IOperation>> _locals = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<string, List<string>> _aliases = new(StringComparer.Ordinal);

    public BodyFacts(IOperation root)
    {
        foreach (var op in root.DescendantsAndSelf())
        {
            switch (op)
            {
                case ISimpleAssignmentOperation assignment:
                {
                    var target = SinkConditions.Unwrap(assignment.Target);
                    if (target is IPropertyReferenceOperation { Arguments.Length: 0 } p && Key(p) is { } owner)
                        _properties.Add((owner[..owner.LastIndexOf('.')], p.Property.Name, assignment.Value));
                    if (target is ILocalReferenceOperation l) Local(l.Local, assignment.Value);
                    if (target != null) Alias(target, assignment.Value);
                    break;
                }
                case IVariableDeclaratorOperation { Initializer: { } init } declarator:
                    Local(declarator.Symbol, init.Value);
                    if (SinkConditions.Unwrap(init.Value) is IObjectCreationOperation created && Key(created) is { } c) AddAlias("L" + Id(declarator.Symbol), c);
                    break;
                case IObjectCreationOperation creation when Key(creation) is { } key:
                    foreach (var a in creation.Arguments)
                        if (a.Parameter != null && a.ArgumentKind != ArgumentKind.DefaultValue) _properties.Add((key, a.Parameter.Name, a.Value));
                    break;
                case IInvocationOperation { TargetMethod: { Name: "Add", IsStatic: false }, Instance: { } instance, Arguments.Length: 1 } add
                    when Key(instance) is { } collection:
                    _adds.Add((collection, add.Arguments[0].Value));
                    break;
            }
        }
        // A variable is the object it was created as only when it is assigned one object creation in the body (a
        // variable reused for a second object keeps the two apart: neither creation's properties are its).
        foreach (var (variable, creations) in _aliases)
            if (creations.Count == 1) Union(variable, creations[0]);
    }

    private void Local(ILocalSymbol local, IOperation value)
    {
        if (!_locals.TryGetValue(local, out var list)) _locals[local] = list = new List<IOperation>();
        list.Add(value);
    }

    private void Alias(IOperation target, IOperation value)
    {
        if (SinkConditions.Unwrap(value) is IObjectCreationOperation creation && Key(target) is { } t && Key(creation) is { } c) AddAlias(t, c);
    }

    private void AddAlias(string variable, string creation)
    {
        if (!_aliases.TryGetValue(variable, out var list)) _aliases[variable] = list = new List<string>();
        list.Add(creation);
    }

    /// The constants a value may be: a constant, both branches of `?:` and `??`, a local's assigned values (unknown
    /// values add nothing).
    public IEnumerable<string> Constants(IOperation? op) => Constants(op, 0).Distinct(StringComparer.Ordinal);

    private IEnumerable<string> Constants(IOperation? op, int depth)
    {
        op = SinkConditions.Unwrap(op);
        if (op == null || depth > 8) yield break;
        if (op.ConstantValue.HasValue)
        {
            if (op.ConstantValue.Value is string s) yield return s;
            yield break;
        }
        switch (op)
        {
            case IConditionalOperation c:
                foreach (var v in Constants(c.WhenTrue, depth + 1)) yield return v;
                foreach (var v in Constants(c.WhenFalse, depth + 1)) yield return v;
                break;
            case ICoalesceOperation c:
                foreach (var v in Constants(c.Value, depth + 1)) yield return v;
                foreach (var v in Constants(c.WhenNull, depth + 1)) yield return v;
                break;
            case ILocalReferenceOperation l when _locals.TryGetValue(l.Local, out var values):
                foreach (var value in values)
                    foreach (var v in Constants(value, depth + 1)) yield return v;
                break;
        }
    }

    /// The constants property `property` (or a constructor parameter of that name, ignoring case) of the object `key`
    /// is set to anywhere in the body.
    public IEnumerable<string> PropertyConstants(string key, string property)
    {
        var canonical = Canonical(key);
        return _properties.Where(p => string.Equals(p.Property, property, StringComparison.OrdinalIgnoreCase) && Canonical(p.Key) == canonical)
            .SelectMany(p => Constants(p.Value));
    }

    /// The arguments of the Adds to the collection `key`, in source order.
    public List<IOperation> Adds(string key)
    {
        var canonical = Canonical(key);
        return _adds.Where(a => Canonical(a.Key) == canonical).Select(a => a.Value).OrderBy(v => v.Syntax.SpanStart).ToList();
    }

    /// An object's access path, or null when it has none (a call's result, an element).
    public string? Key(IOperation? op)
    {
        switch (SinkConditions.Unwrap(op))
        {
            case ILocalReferenceOperation l:
                return "L" + Id(l.Local);
            case IParameterReferenceOperation p:
                return "P" + Id(p.Parameter);
            case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }:
                return "this";
            case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ImplicitReceiver } implicitReceiver:
                return Initialized(implicitReceiver) is { } initialized && initialized != implicitReceiver ? Key(initialized) : null;
            case IObjectCreationOperation creation:
                return "N" + creation.Syntax.SpanStart.ToString(System.Globalization.CultureInfo.InvariantCulture);
            case IFieldReferenceOperation f:
                return Member(f.Instance, f.Field);
            case IPropertyReferenceOperation { Arguments.Length: 0 } p:
                return Member(p.Instance, p.Property);
            default:
                return null;
        }
    }

    private string? Member(IOperation? instance, ISymbol member)
    {
        var owner = instance == null ? "S" + Id(member.ContainingType) : Key(instance);
        return owner == null ? null : owner + "." + member.Name;
    }

    /// What an implicit receiver stands for: the object an object or collection initializer initializes (the created
    /// object, or the member a nested initializer initializes). Any other operation is itself.
    public static IOperation? Initialized(IOperation? op)
    {
        if (op is not IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ImplicitReceiver }) return op;
        for (var o = op.Parent; o != null; o = o.Parent)
        {
            if (o is not IObjectOrCollectionInitializerOperation init) continue;
            return init.Parent switch
            {
                IObjectCreationOperation creation => creation,
                IMemberInitializerOperation member => member.InitializedMember,
                _ => null,
            };
        }
        return null;
    }

    private string Id(ISymbol symbol)
    {
        if (!_ids.TryGetValue(symbol, out var id)) _ids[symbol] = id = _ids.Count;
        return id.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private string Find(string key)
    {
        while (_union.TryGetValue(key, out var parent) && parent != key) key = parent;
        return key;
    }

    private void Union(string a, string b)
    {
        foreach (var k in new[] { a, b }) _union.TryAdd(k, k);
        var ra = Find(a);
        var rb = Find(b);
        if (ra != rb) _union[ra] = rb;
    }

    /// A key with its longest aliased prefix replaced by that alias's representative (`x.StartInfo` of a local x
    /// assigned `new Process()` is that creation's StartInfo).
    private string Canonical(string key)
    {
        for (var end = key.Length; end > 0; end = key.LastIndexOf('.', end - 1))
        {
            var prefix = key[..end];
            if (_union.ContainsKey(prefix)) return Find(prefix) + key[end..];
            if (end == 0) break;
        }
        return key;
    }
}
