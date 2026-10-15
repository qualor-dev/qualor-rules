using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// Guards as project code writes them (Task 33; models/README.md, "Guards in project code" and "Membership"):
///
/// - Equality with a value: where `x == y` holds, x's text is y's: x is clean for the rules y is clean for, and where y
///   carries no request data at all x is y (only its labels: what a caller gives). A sanitizer's result on x itself
///   (`x == Path.GetFileName(x)`, a fixed point) makes x as clean as that result.
/// - Conditions as written: `a || b` true and `a && b` false hold what both sides hold (the join of each side's state);
///   a condition held in a bool local assigned once (the check after it, every variable it cleans unchanged since) and a
///   condition the graph split into one capture (`return a && b;`) are read from the operation tree as written.
/// - Containment (the `assigned-from:` guard): a full path assigned in a conditional whose arms are GetFullPath calls,
///   constants or read-only fields that hold no request data; a GetFullPath call written in place; the path the
///   one-argument GetFullPath was given (a local or parameter unchanged since) is clean too. Its prefix's text follows locals and conditionals (GuardTexts).
/// - Membership: a collection the server built (AllowLists.IsServerCollection, IsBuiltHere) that holds no request data in
///   any request; a search whose predicate compares a value with an element (`First`, `Single`, `Last` returned; `Any`,
///   `Exists` true; `Find`, `FirstOrDefault` not null).
/// - Summaries: a project method returning bool records what each parameter holds where it returns true or false
///   (BodySummary.Guards), and every method what it holds at its normal exit (Exits; none for an iterator, an async
///   method's only where the call is awaited at once); a call site applies them on that branch or after the call when
///   every target of the call is such a body outside the caller's component.
/// - Stored data never vouches (ruling R-E41): equality and membership read nothing a request may have stored in any
///   request (StoredSomewhere: a field or auto-property some request wrote request data to, also through a local copy
///   or as the argument a guard summary compares with); data set at startup or from configuration still guards. A
///   containment check's root is no allow-list (R-E41 refined): its "is the root itself" arm keeps Task 11's rule.
internal sealed partial class MethodAnalyzer
{
    /// The values of the operands guards compare (both sides of `==`, the receiver and arguments of Equals, Contains,
    /// searches), by syntax: a condition read as written finds them there.
    private readonly Dictionary<SyntaxNode, TaintValue> _operands = new();

    private readonly Dictionary<SyntaxNode, TaintValue> _guardArgumentsBySyntax = new();

    /// The values flow captures captured (a conditional's arms), by the captured value's syntax.
    private readonly Dictionary<SyntaxNode, TaintValue> _captureValues = new();

    /// The receiver and inputs of the bool-returning calls of project methods evaluated here, by syntax (GuardSummary).
    private readonly Dictionary<SyntaxNode, (IMethodSymbol Method, TaintValue Receiver, Input[] Inputs)> _callInputs = new();

    private readonly Dictionary<SyntaxNode, IOperation?> _originals = new();

    private static readonly HashSet<string> ComparedNames = new(StringComparer.Ordinal)
    {
        "Equals", "SequenceEqual", "Contains", "ContainsKey", "TryGetValue", "First", "Single", "Last", "FirstOrDefault", "SingleOrDefault",
        "LastOrDefault", "Any", "Find", "Exists",
    };

    /// Records the value of an operand a guard may compare (Value calls it for every operation).
    private void RecordOperand(IOperation operation, TaintValue value)
    {
        switch (operation.Parent)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals }:
                _operands[operation.Syntax] = value;
                break;
            case IArgumentOperation { Parent: IInvocationOperation call } when ComparedNames.Contains(call.TargetMethod.Name):
                _operands[operation.Syntax] = value;
                break;
            case IInvocationOperation call when ReferenceEquals(call.Instance, operation) && ComparedNames.Contains(call.TargetMethod.Name):
                _operands[operation.Syntax] = value;
                break;
        }
    }

    /// A captured value of a flow capture (a conditional's arm).
    private void RecordCaptured(IOperation value, TaintValue taint) => _captureValues[value.Syntax] = taint;

    /// The operation tree of `op`'s syntax as written (the graph splits `a || b` and `c ? x : y` over blocks).
    private IOperation? Original(IOperation op)
    {
        if (_originals.TryGetValue(op.Syntax, out var known)) return known;
        IOperation? result = null;
        try
        {
            if (Model() is { } model && model.SyntaxTree == op.Syntax.SyntaxTree) result = model.GetOperation(op.Syntax);
        }
        catch (ArgumentException)
        {
            result = null;
        }
        _originals[op.Syntax] = result;
        return result;
    }

    /// The expression a value assigned to a local or returned is, as written: the right side of the declarator, the
    /// assignment, the `return` or the expression body that holds it. The graph splits `a && b`, `!(a && b)` or
    /// `c ? x : y` over blocks into one capture whose syntax may be a part of what it holds (the capture of `!(a && b)` has
    /// the syntax of `a && b`), so the capture's own syntax is not read; the whole right side is, when the capture's
    /// syntax is it (through parentheses and `!`).
    private IOperation? WrittenAs(IOperation value)
    {
        Microsoft.CodeAnalysis.CSharp.Syntax.ExpressionSyntax? whole = null;
        for (var n = value.Syntax; n != null && whole == null; n = n.Parent)
        {
            switch (n)
            {
                case Microsoft.CodeAnalysis.CSharp.Syntax.VariableDeclaratorSyntax d:
                    whole = d.Initializer?.Value;
                    break;
                case Microsoft.CodeAnalysis.CSharp.Syntax.AssignmentExpressionSyntax a when a.OperatorToken.ValueText == "=":
                    whole = a.Right;
                    break;
                case Microsoft.CodeAnalysis.CSharp.Syntax.ReturnStatementSyntax r:
                    whole = r.Expression;
                    break;
                case Microsoft.CodeAnalysis.CSharp.Syntax.ArrowExpressionClauseSyntax e:
                    whole = e.Expression;
                    break;
                case Microsoft.CodeAnalysis.CSharp.Syntax.StatementSyntax or Microsoft.CodeAnalysis.CSharp.Syntax.AnonymousFunctionExpressionSyntax:
                    return null;
            }
            if (n is Microsoft.CodeAnalysis.CSharp.Syntax.VariableDeclaratorSyntax or Microsoft.CodeAnalysis.CSharp.Syntax.AssignmentExpressionSyntax
                or Microsoft.CodeAnalysis.CSharp.Syntax.ReturnStatementSyntax or Microsoft.CodeAnalysis.CSharp.Syntax.ArrowExpressionClauseSyntax && whole == null) return null;
        }
        if (whole == null || Stripped(whole) != Stripped(value.Syntax) || Model() is not { } model || model.SyntaxTree != whole.SyntaxTree) return null;
        return model.GetOperation(whole);

        static SyntaxNode Stripped(SyntaxNode node)
        {
            while (true)
            {
                switch (node)
                {
                    case Microsoft.CodeAnalysis.CSharp.Syntax.ParenthesizedExpressionSyntax p:
                        node = p.Expression;
                        continue;
                    case Microsoft.CodeAnalysis.CSharp.Syntax.PrefixUnaryExpressionSyntax u when u.OperatorToken.ValueText == "!":
                        node = u.Operand;
                        continue;
                    default:
                        return node;
                }
            }
        }
    }

    /// A condition that writes nothing: no assignment, increment, declaration, `out` or `ref` argument, or await.
    private static bool IsPure(IOperation condition)
    {
        foreach (var o in condition.DescendantsAndSelf())
        {
            switch (o)
            {
                case IAssignmentOperation or IIncrementOrDecrementOperation or IDeclarationExpressionOperation or IAwaitOperation:
                case IArgumentOperation { Parameter.RefKind: RefKind.Ref or RefKind.Out }:
                    return false;
            }
        }
        return true;
    }

    /// `left || right` true (outcome true) or `left && right` false: what holds on both ways the outcome comes about,
    /// the left side alone and the right side after the left one had the other outcome.
    private void EitherSide(IOperation left, IOperation right, bool outcome, TaintState state, ref TaintState? refined, int depth)
    {
        var current = refined ?? state;
        TaintState? onLeft = null;
        Facts(left, outcome, current, ref onLeft, depth + 1);
        if (onLeft == null) return;
        TaintState? passed = null;
        Facts(left, !outcome, current, ref passed, depth + 1);
        TaintState? onRight = null;
        Facts(right, outcome, passed ?? current, ref onRight, depth + 1);
        if (onRight == null) return;
        var joined = onLeft.Clone();
        joined.JoinWith(onRight);
        refined = joined;
    }

    /// A bool local checked (`var ok = full.StartsWith(root); if (!ok) return;`): its one assignment's condition as
    /// written, read on this branch, cleans the locals and parameters that no code changes after the assignment.
    private void StoredCondition(ILocalSymbol flag, IOperation use, bool outcome, TaintState state, ref TaintState? refined, int depth)
    {
        if (Assignments(flag) is not [var assigned] || NestedWrites().Contains(flag)) return;
        if (use.Syntax.SpanStart <= assigned.Syntax.SpanStart) return;
        var condition = assigned is IFlowCaptureReferenceOperation ? WrittenAs(assigned) : Original(assigned);
        if (condition == null || condition is IFlowCaptureReferenceOperation || !IsPure(condition)) return;
        var current = refined ?? state;
        TaintState? held = null;
        Facts(condition, outcome, current, ref held, depth + 1);
        if (held == null) return;
        foreach (var (key, value) in held.Entries)
        {
            if (key is not (ILocalSymbol or IParameterSymbol)) continue;
            var symbol = (ISymbol)key;
            if (ReferenceEquals(value, current.Get(symbol)) || !StableAfter(symbol, assigned)) continue;
            refined ??= state.Clone();
            refined.Set(symbol, value);
        }
    }

    /// Whether no code writes a local or parameter after `point` (its assignments all before it, no other write, none in a
    /// lambda or local function).
    private bool StableAfter(ISymbol symbol, IOperation point)
    {
        if (NestedWrites().Contains(symbol)) return false;
        if (_assignments == null) Assignments(symbol);
        if (!_assignments!.TryGetValue(symbol, out var writes)) return true;
        return writes != null && writes.All(w => w.Syntax.SpanStart < point.Syntax.SpanStart);
    }

    private HashSet<ISymbol>? _nestedWrites;

    /// The locals and parameters a lambda or local function of the method assigns or writes by `ref`/`out`.
    private HashSet<ISymbol> NestedWrites()
    {
        if (_nestedWrites != null) return _nestedWrites;
        var set = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        foreach (var o in RootOriginal().Descendants())
        {
            if (o is not (IAnonymousFunctionOperation or ILocalFunctionOperation)) continue;
            foreach (var n in o.Descendants())
            {
                IOperation? target = n switch
                {
                    IAssignmentOperation a => a.Target,
                    IIncrementOrDecrementOperation i => i.Target,
                    IArgumentOperation { Parameter.RefKind: RefKind.Ref or RefKind.Out } r => r.Value,
                    _ => null,
                };
                if (target == null) continue;
                foreach (var t in target.DescendantsAndSelf())
                {
                    if (t is ILocalReferenceOperation l) set.Add(l.Local);
                    else if (t is IParameterReferenceOperation p) set.Add(p.Parameter);
                }
            }
        }
        return _nestedWrites = set;
    }

    private IOperation RootOriginal()
    {
        var g = _cfg;
        while (g.Parent != null) g = g.Parent;
        return g.OriginalOperation;
    }

    // ---- Equality ----

    /// `x == S(x)` with S a sanitizer of the models: x is S's result, clean for S's rules.
    private void FixedPoint(IOperation sanitized, IOperation other, TaintState state, ref TaintState? refined)
    {
        if (Unwrapped(sanitized) is not IInvocationOperation call) return;
        var rules = _ctx.Sinks.Sanitizes(call.TargetMethod, Access.Call);
        if (rules.Length == 0) return;
        var input = call.TargetMethod.IsStatic ? (call.Arguments.Length > 0 ? call.Arguments[0].Value : null) : call.Instance;
        if (input != null && SameVariable(input, other)) Clean(other, rules, state, ref refined);
    }

    /// Whether two operations read the same local, parameter or access path.
    private bool SameVariable(IOperation a, IOperation b)
    {
        a = Unwrapped(a);
        b = Unwrapped(b);
        return (a, b) switch
        {
            (ILocalReferenceOperation x, ILocalReferenceOperation y) => SymbolEqualityComparer.Default.Equals(x.Local, y.Local),
            (IParameterReferenceOperation x, IParameterReferenceOperation y) => SymbolEqualityComparer.Default.Equals(x.Parameter, y.Parameter),
            _ => PathOf(a) is { } p && PathOf(b) is { } q && p.Equals(q),
        };
    }

    /// `target`'s text equals that of `other`, a value of taint `equalTo`, on this branch. Nothing, when `other` reads data
    /// a request may have stored (ruling R-E41: stored data never vouches for fresh input; StoredSomewhere).
    private void Narrow(IOperation target, TaintValue equalTo, IOperation other, TaintState state, ref TaintState? refined)
    {
        // R-E41 refined: the "is the root itself" arm of a containment check keeps Task 11's rule for its root (a root the
        // current request chose holds request data here and cleans nothing; one stored earlier guards, as configuration).
        if (!IsRootArm(target, other) && StoredSomewhere(other)) return;
        if (!equalTo.Any)
        {
            CleanAll(target, state, ref refined);
            return;
        }
        var rules = CleanRules(equalTo);
        if (rules.Count > 0) Clean(target, rules, state, ref refined);
        if (equalTo.Request) return;
        // No request data, only what callers give: the target is that, when it holds request data itself, or when what it
        // is compared with is an element of a collection a caller gives (membership written as a loop).
        // Or when what it is compared with is the object's own state (`full.Equals(_root)` in a helper: `this` or a member
        // of it), which a value equal to it is.
        var membership = CollectionLabels(equalTo) || OwnState(equalTo);
        foreach (var key in Keys(target))
        {
            var current = (refined ?? state).Get(key);
            if (!current.Any || (!current.Request && !membership)) continue;
            TaintValue next;
            if (membership)
            {
                next = KeepIdentity(current, equalTo);
            }
            else
            {
                // For each rule, what the other holds where that is no more than what the target holds.
                var taken = _ctx.RuleIds.Where(r => NoMoreFor(equalTo, current, r)).ToList();
                if (taken.Count == 0) continue;
                next = taken.Count == _ctx.RuleIds.Length ? KeepIdentity(current, equalTo)
                    : current.CleanedFor(taken).WithTaintOf(equalTo.CleanedFor(_ctx.AllBut(taken)));
            }
            refined ??= state.Clone();
            refined.Set(key, next);
        }
    }

    /// Whether `x == root` is the "is the root itself" arm of a containment check (ruling R-E41 refined): joined by `||`
    /// (directly, or within one chain of `||`) with `x.StartsWith(prefix)` whose prefix is built from the same root (a
    /// field, local or parameter; through locals assigned from it).
    private bool IsRootArm(IOperation x, IOperation root)
    {
        if (VariableOf(root) is not { } symbol || Model() is not { } model) return false;
        var node = x.Syntax;
        while (node != null && !node.Span.Contains(root.Syntax.Span)) node = node.Parent;
        if (node == null) return false;
        while (node.Parent is Microsoft.CodeAnalysis.CSharp.Syntax.ParenthesizedExpressionSyntax) node = node.Parent;
        var top = node;
        while (top.Parent is Microsoft.CodeAnalysis.CSharp.Syntax.BinaryExpressionSyntax { RawKind: (int)Microsoft.CodeAnalysis.CSharp.SyntaxKind.LogicalOrExpression }
               or Microsoft.CodeAnalysis.CSharp.Syntax.ParenthesizedExpressionSyntax)
            top = top.Parent;
        if (ReferenceEquals(top, node) || model.SyntaxTree != top.SyntaxTree) return false;
        foreach (var side in OrSides(top))
        {
            if (ReferenceEquals(side, node) || side.Span.Contains(node.Span)) continue;
            if (model.GetOperation(side) is IInvocationOperation { TargetMethod: { Name: "StartsWith", ContainingType.SpecialType: SpecialType.System_String }, Instance: { } instance } check
                && check.Arguments.Length >= 1 && SameVariable(instance, x) && Mentions(check.Arguments[0].Value, symbol, 0))
                return true;
        }
        return false;

        static IEnumerable<SyntaxNode> OrSides(SyntaxNode n)
        {
            switch (n)
            {
                case Microsoft.CodeAnalysis.CSharp.Syntax.ParenthesizedExpressionSyntax p:
                    foreach (var x in OrSides(p.Expression)) yield return x;
                    break;
                case Microsoft.CodeAnalysis.CSharp.Syntax.BinaryExpressionSyntax { RawKind: (int)Microsoft.CodeAnalysis.CSharp.SyntaxKind.LogicalOrExpression } b:
                    foreach (var x in OrSides(b.Left)) yield return x;
                    foreach (var x in OrSides(b.Right)) yield return x;
                    break;
                default:
                    yield return n;
                    break;
            }
        }
    }

    /// The field, auto-property, local or parameter an operation reads, or null.
    private static ISymbol? VariableOf(IOperation op) => Unwrapped(op) switch
    {
        IFieldReferenceOperation f => f.Field.OriginalDefinition,
        IPropertyReferenceOperation { Arguments.Length: 0 } p => p.Property.OriginalDefinition,
        ILocalReferenceOperation l => l.Local,
        IParameterReferenceOperation p => p.Parameter,
        _ => null,
    };

    /// Whether an operation reads `symbol` (also through locals assigned from it, up to three steps).
    private bool Mentions(IOperation op, ISymbol symbol, int depth)
    {
        if (depth > 3) return false;
        foreach (var o in op.DescendantsAndSelf())
        {
            if (VariableOf(o) is { } read && SymbolEqualityComparer.Default.Equals(read, symbol)) return true;
            if (o is ILocalReferenceOperation { IsDeclaration: false } l && Assignments(l.Local) is { } writes)
                foreach (var w in writes)
                    if (Mentions(w is IFlowCaptureReferenceOperation ? WrittenAs(w) ?? w : w, symbol, depth + 1)) return true;
        }
        return false;
    }

    /// The rules a value carries nothing for: no request data for them and no label not cleaned for them.
    private IReadOnlyCollection<string> CleanRules(TaintValue value)
    {
        if (!value.Any) return _ctx.RuleIds;
        var rules = new List<string>();
        foreach (var r in _ctx.RuleIds)
            if ((!value.Request || value.CleanFor.Contains(r)) && value.Labels.All(l => l.CleanFor.Contains(r))) rules.Add(r);
        return rules;
    }

    /// Whether every label of a value is a parameter of the analysed method that holds a collection (no string).
    private bool CollectionLabels(TaintValue value)
    {
        if (value.Labels.Length == 0 || _body.Root.Symbol is not IMethodSymbol method) return false;
        foreach (var l in value.Labels)
        {
            if (l.Owner != _body.Root.Id || l.Slot < 0 || l.Slot >= method.Parameters.Length) return false;
            var type = method.Parameters[l.Slot].Type;
            if (type.SpecialType == SpecialType.System_String || !(type.SpecialType == SpecialType.System_Collections_IEnumerable
                || type.AllInterfaces.Any(i => i.SpecialType == SpecialType.System_Collections_IEnumerable) || type is IArrayTypeSymbol)) return false;
        }
        return true;
    }

    /// Whether every label of a value is the analysed method's `this` or a member read through it.
    private bool OwnState(TaintValue value) => value.Labels.Length > 0 && value.Labels.All(OwnStateLabel);

    /// The analysed method's `this` or a member read through it: the object's own state, which its callers fill (what a
    /// value equal to it holds is that; NoMoreFor counts it as nothing more).
    private bool OwnStateLabel(Label l) =>
        l.Owner == _body.Root.Id && (ObjectTable.IsMemberSlot(l.Slot) ? _ctx.Objects.OfMemberSlot(l.Slot).Slot : l.Slot) == -1;

    /// `taint` in place of `current`'s taint, keeping the objects and members `current` is known to be.
    private static TaintValue KeepIdentity(TaintValue current, TaintValue taint) =>
        current.HasIdentity ? (TaintValue.Clean with { Objects = current.Objects, Members = current.Members }).WithTaintOf(taint) : taint.WithoutIdentity();

    /// MemoryExtensions.Equals and SequenceEqual (spans of char compared).
    private static bool IsSpanEquals(IMethodSymbol method) =>
        method.Name is "Equals" or "SequenceEqual" && method.IsStatic && method.ContainingType is { } type && SymbolMatch.MetadataName(type) == "System.MemoryExtensions";

    /// ReadOnlySpan, Span, ReadOnlyMemory or Memory of char: text.
    private static bool IsCharSpan(ITypeSymbol type) =>
        type is INamedTypeSymbol { TypeArguments: [{ SpecialType: SpecialType.System_Char }] } named
        && SymbolMatch.MetadataName(named.OriginalDefinition) is "System.ReadOnlySpan`1" or "System.Span`1" or "System.ReadOnlyMemory`1" or "System.Memory`1";

    // ---- Containment ----

    /// An assignment of the checked local that makes it a full path: a call of the `assigned-from` member, or (Task 33) a
    /// conditional each arm of which is such a call, a constant, or a read-only field that holds no request data here
    /// (the labels it carries, its object's, join `extra`: Holds).
    private bool AssignedFrom(IOperation assigned, MemberPattern member, ref TaintValue extra)
    {
        if (Awaited(assigned) is { } from && SymbolMatch.Matches(member, from.TargetMethod)) return true;
        if (assigned is not IFlowCaptureReferenceOperation || WrittenAs(assigned) is not IConditionalOperation { WhenFalse: { } whenFalse } conditional) return false;
        var labels = TaintValue.Clean;
        if (!Arm(conditional.WhenTrue) || !Arm(whenFalse)) return false;
        extra = extra.Join(labels);
        return true;

        bool Arm(IOperation arm)
        {
            if (Awaited(arm) is { } call && SymbolMatch.Matches(member, call.TargetMethod)) return true;
            var value = Unwrapped(arm);
            if (value.ConstantValue is { HasValue: true, Value: string }) return true;
            if (value is not IFieldReferenceOperation { Field.IsReadOnly: true } || !_captureValues.TryGetValue(arm.Syntax, out var taint) || taint.Request) return false;
            labels = labels.Join(taint.LabelPart.WithoutIdentity());
            return true;
        }
    }

    /// The path a checked full path was made of: the argument of the `assigned-from` call written in place, or of every
    /// assignment of the checked local when they all take the same local or parameter, unchanged after each of them.
    private IEnumerable<IOperation> FullPathSources(IOperation checkedValue, GuardModel guard)
    {
        var condition = guard.When.FirstOrDefault(c => c.Kind == GuardConditionKind.AssignedFrom);
        if (condition == null) yield break;
        var value = Unwrapped(checkedValue);
        // Only GetFullPath(path): GetFullPath(path, basePath) resolves against another base than a sink given the path does
        // (review I2).
        if (value is IInvocationOperation inPlace && SymbolMatch.Matches(condition.Member!, inPlace.TargetMethod))
        {
            if (inPlace.Arguments.Length == 1) yield return inPlace.Arguments[0].Value;
            yield break;
        }
        if (value is not ILocalReferenceOperation local || Assignments(local.Local) is not { Count: > 0 } all) yield break;
        IOperation? source = null;
        foreach (var a in all)
        {
            if (Awaited(a) is not { Arguments.Length: 1 } call || !SymbolMatch.Matches(condition.Member!, call.TargetMethod)) yield break;
            var argument = call.Arguments[0].Value;
            var variable = Unwrapped(argument) switch
            {
                ILocalReferenceOperation l => (ISymbol)l.Local,
                IParameterReferenceOperation p => p.Parameter,
                _ => null,
            };
            if (variable == null || !StableAfter(variable, a) || (source != null && !SameVariable(source, argument))) yield break;
            source = argument;
        }
        if (source != null) yield return source;
    }

    // ---- Membership ----

    private Dictionary<ILocalSymbol, bool>? _builtHere;

    /// Whether `table` (or its Keys or Values) is a collection the server built that holds no request data: a field that
    /// AllowLists.IsServerCollection accepts whose location (and, searched by key, the dictionary's keys) no request
    /// wrote in any request, or a local built here (AllowLists.IsBuiltHere) from nothing a request wrote in any request
    /// (StoredSomewhere: `var copy = Seen.ToList()` with Seen written by another request is none; ruling R-E41); its value
    /// here carries nothing.
    private bool ServerCollection(IOperation? table, bool byKey)
    {
        if (table == null || !_operands.TryGetValue(table.Syntax, out var value) || value.Request) return false;
        var op = Unwrapped(table);
        if (op is IPropertyReferenceOperation { Property.Name: "Keys" or "Values", Arguments.Length: 0, Instance: { } owner } part)
        {
            byKey = part.Property.Name == "Keys";
            op = Unwrapped(owner);
        }
        switch (op)
        {
            case IFieldReferenceOperation f:
                if (!_body.IsHeapMember(f.Field) || !_ctx.AllowLists.IsServerCollection(f.Field, Model()?.Compilation)) return false;
                if (_body.RequestAnywhere(f.Field)) return false;
                return !(byKey && AllowLists.IsDictionary(f.Field.Type) && _body.RequestAnywhere(f.Field, keys: true));
            case ILocalReferenceOperation l:
                if (value.Any) return false;
                _builtHere ??= new Dictionary<ILocalSymbol, bool>(SymbolEqualityComparer.Default);
                if (!_builtHere.TryGetValue(l.Local, out var built)) _builtHere[l.Local] = built = AllowLists.IsBuiltHere(l.Local, RootOriginal());
                return built && !StoredSomewhere(table);
            default:
                return false;
        }
    }

    /// A key written into a dictionary held in a field: its request data is recorded as the dictionary's keys.
    private void RecordKeys(IOperation? receiver, TaintValue key)
    {
        if (!key.Request || receiver == null || Unwrapped(receiver) is not IFieldReferenceOperation f || !_body.IsHeapMember(f.Field)) return;
        if (AllowLists.IsDictionary(f.Field.Type)) _body.WriteKeys(f.Field, key);
    }

    private enum Search { None, Throws, NotNull, True }

    /// How a search of .NET's collections tells that its predicate matched an element: First, Single and Last return
    /// (they throw otherwise); FirstOrDefault, SingleOrDefault, LastOrDefault, Array.Find and List.Find give an element
    /// that is not null (of a reference type); Any, Array.Exists and List.Exists are true.
    private static Search SearchOf(IMethodSymbol method)
    {
        if (SymbolKeys.InSource(method) || method.ContainingType is not { } type) return Search.None;
        var definition = method.ReducedFrom ?? method;
        var parameters = definition.Parameters;
        if (parameters.Length == 0 || parameters[^1].Type.TypeKind != TypeKind.Delegate) return Search.None;
        // A result that is not null tells a match only for elements of a reference type (FirstOrDefault of an int gives 0).
        var notNull = method.ReturnType.IsReferenceType ? Search.NotNull : Search.None;
        switch (SymbolMatch.MetadataName(type.OriginalDefinition))
        {
            case "System.Linq.Enumerable" when parameters.Length == 2:
                return method.Name switch
                {
                    "First" or "Single" or "Last" => Search.Throws,
                    "FirstOrDefault" or "SingleOrDefault" or "LastOrDefault" => notNull,
                    "Any" => Search.True,
                    _ => Search.None,
                };
            case "System.Array" when parameters.Length == 2:
                return method.Name switch { "Find" => notNull, "Exists" => Search.True, _ => Search.None };
            case "System.Collections.Generic.List`1" when parameters.Length == 1:
                return method.Name switch { "Find" => notNull, "Exists" => Search.True, _ => Search.None };
            default:
                return Search.None;
        }
    }

    /// The call returned (Search.Throws): its predicate matched.
    private void SearchReturned(IOperation operation, TaintState state)
    {
        if (operation is not IInvocationOperation call || SearchOf(call.TargetMethod) != Search.Throws) return;
        TaintState? refined = state;
        SearchNarrow(call, null, state, ref refined);
    }

    /// A search's predicate matched an element: the values its predicate compares with an element (`e => e.Key == key`,
    /// `string.Equals(e, name, ...)`) are clean for the allow-list rules where the element side carries no request data:
    /// the element itself of a collection the server built (ServerCollection), or a path of members declared in source
    /// (fields, auto-properties) of it that no request wrote. With `after` (a result held in a local), the compared values
    /// must be unchanged since that call.
    private void SearchNarrow(IInvocationOperation call, IOperation? after, TaintState state, ref TaintState? refined)
    {
        if (_ctx.Sinks.AllowListRules.Length == 0) return;
        var method = call.TargetMethod;
        var list = SymbolMatch.MetadataName(method.ContainingType.OriginalDefinition) == "System.Collections.Generic.List`1";
        var source = list ? call.Instance : ThisOperation(call) ?? (call.Arguments.Length > 0 ? call.Arguments[0].Value : null);
        var predicate = call.Arguments.LastOrDefault()?.Value;
        if (source == null || predicate == null) return;
        var lambda = LambdaOf(predicate);
        if (lambda is not { Parameters.Length: 1 } || BodyOf(lambda) is not IBlockOperation { Operations: [IReturnOperation { ReturnedValue: { } returned }] }) return;
        if (!IsPure(returned)) return;
        // The collection searched carries nothing here (no request data, no value a caller gives; a field of the object's
        // own state counts only as that field), and no request wrote what it is read from in any request (review C1,
        // ruling R-E41): an element of a posted list equal to a posted value is no registered key.
        if (!_operands.TryGetValue(source.Syntax, out var held) || held.Request || StoredSomewhere(source)) return;
        if (held.Labels.Length > 0 && !(held.Labels.All(OwnStateLabel) && Unwrapped(source) is IFieldReferenceOperation)) return;
        var element = lambda.Parameters[0];
        foreach (var (compared, side) in Compared(returned, element))
        {
            if (!ElementClean(side, element, source)) continue;
            if (after != null)
            {
                var variable = Unwrapped(compared) switch
                {
                    ILocalReferenceOperation l => (ISymbol)l.Local,
                    IParameterReferenceOperation p => p.Parameter,
                    _ => null,
                };
                if (variable == null || !StableAfter(variable, after)) continue;
            }
            Clean(compared, _ctx.Sinks.AllowListRules, state, ref refined);
        }
    }

    /// The lambda a delegate argument is (the graph's or the operation tree's), or null.
    private IMethodSymbol? LambdaOf(IOperation op)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            switch (op)
            {
                case IConversionOperation c:
                    op = c.Operand;
                    continue;
                case IDelegateCreationOperation d:
                    op = d.Target;
                    continue;
                case IFlowCaptureReferenceOperation r when _captured.TryGetValue(r.Id, out var list) && list.Count == 1:
                    op = list[0];
                    continue;
                case IFlowAnonymousFunctionOperation f:
                    return f.Symbol;
                case IAnonymousFunctionOperation a:
                    return a.Symbol;
                default:
                    return null;
            }
        }
        return null;
    }

    /// The (compared value, element side) pairs a predicate's result being true proves equal: `==`, string's and the
    /// spans' Equals, either side of `&&`.
    private IEnumerable<(IOperation Compared, IOperation Side)> Compared(IOperation condition, IParameterSymbol element)
    {
        condition = Unwrapped(condition);
        switch (condition)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalAnd } both:
                foreach (var p in Compared(both.LeftOperand, element)) yield return p;
                foreach (var p in Compared(both.RightOperand, element)) yield return p;
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Equals } equal
                when equal.OperatorMethod == null || equal.OperatorMethod.ContainingType?.SpecialType == SpecialType.System_String:
                if (Pair(equal.LeftOperand, equal.RightOperand) is { } a) yield return a;
                break;
            case IInvocationOperation { TargetMethod: { Name: "Equals" } m } call when m.ContainingType?.SpecialType == SpecialType.System_String || IsSpanEquals(m):
                if (call.Instance != null && call.Arguments.Length >= 1 && Pair(call.Instance, call.Arguments[0].Value) is { } b) yield return b;
                else if (m.IsStatic && call.Arguments.Length >= 2 && Pair(call.Arguments[0].Value, call.Arguments[1].Value) is { } c) yield return c;
                break;
        }

        (IOperation, IOperation)? Pair(IOperation x, IOperation y) =>
            RootedAt(x, element) && Outside(y, element) ? (y, x) : RootedAt(y, element) && Outside(x, element) ? (x, y) : null;
    }

    /// The element itself, or a chain of field and property reads on it.
    private static bool RootedAt(IOperation op, IParameterSymbol element)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            op = Unwrapped(op);
            switch (op)
            {
                case IParameterReferenceOperation p:
                    return SymbolEqualityComparer.Default.Equals(p.Parameter, element);
                case IFieldReferenceOperation { Field.IsStatic: false, Instance: { } i }:
                    op = i;
                    continue;
                case IPropertyReferenceOperation { Property.IsStatic: false, Arguments.Length: 0, Instance: { } i }:
                    op = i;
                    continue;
                default:
                    return false;
            }
        }
        return false;
    }

    /// A local or parameter of the enclosing code (or a path on one) the predicate compares.
    private static bool Outside(IOperation op, IParameterSymbol element)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            op = Unwrapped(op);
            switch (op)
            {
                case ILocalReferenceOperation l:
                    return !SymbolEqualityComparer.Default.Equals(l.Local.ContainingSymbol, element.ContainingSymbol);
                case IParameterReferenceOperation p:
                    return !SymbolEqualityComparer.Default.Equals(p.Parameter.ContainingSymbol, element.ContainingSymbol);
                case IFieldReferenceOperation { Field.IsStatic: false, Instance: { } i }:
                    op = i;
                    continue;
                case IPropertyReferenceOperation { Property.IsStatic: false, Arguments.Length: 0, Instance: { } i }:
                    op = i;
                    continue;
                default:
                    return false;
            }
        }
        return false;
    }

    /// The element side of a comparison carries no request data: the element of a server-built collection, or members
    /// declared in source that hold data no request wrote (in any request).
    private bool ElementClean(IOperation side, IParameterSymbol element, IOperation source)
    {
        side = Unwrapped(side);
        if (side is IParameterReferenceOperation) return ServerCollection(source, false);
        for (var depth = 0; depth < 8; depth++)
        {
            side = Unwrapped(side);
            ISymbol member;
            IOperation? instance;
            switch (side)
            {
                case IParameterReferenceOperation p:
                    return SymbolEqualityComparer.Default.Equals(p.Parameter, element);
                case IFieldReferenceOperation f:
                    member = f.Field;
                    instance = f.Instance;
                    break;
                case IPropertyReferenceOperation p:
                    member = p.Property;
                    instance = p.Instance;
                    break;
                default:
                    return false;
            }
            if (!SymbolKeys.InSource(member) || !_body.IsHeapMember(member) || _body.RequestAnywhere(member)) return false;
            if (instance == null) return false;
            side = instance;
        }
        return false;
    }

    // ---- Summaries ----

    /// Records the receiver and inputs of a bool-returning call of project code (GuardSummary reads them on its branch).
    private void RecordCallInputs(IOperation operation, IMethodSymbol method, TaintValue receiver, Input[] inputs, IReadOnlyList<Target>? targets)
    {
        if (operation is IInvocationOperation && method.ReturnType.SpecialType == SpecialType.System_Boolean && targets is { Count: > 0 }
            && targets.Any(t => t.Kind == TargetKind.Body))
            _callInputs[operation.Syntax] = (method, receiver, inputs);
    }

    /// A call of project methods returning bool on its `outcome` branch: each argument holds what every target's guard
    /// summary says its parameter holds there.
    private void GuardSummary(IInvocationOperation call, bool outcome, TaintState state, ref TaintState? refined)
    {
        if (!_callInputs.TryGetValue(call.Syntax, out var recorded) || !SymbolEqualityComparer.Default.Equals(recorded.Method, call.TargetMethod)) return;
        var targets = _body.Targets(call.TargetMethod, call.IsVirtual, call.Instance?.Type);
        // Every target must be a summarised body (Summarised: no metadata or opaque implementation, none in this
        // component), and each must have an entry for the slot (below): a target's missing entry is the parameter as given.
        // The second check alone would still reject a lax implementation; the first also keeps `t.Body!` safe (review M4).
        if (!Summarised(targets, s => s.Guards != null)) return;
        var args = Arguments(recorded.Receiver, recorded.Inputs);
        IOperation? Op(int slot) => slot == -1 ? call.Instance : ArgumentOf(call, slot);
        foreach (var i in recorded.Inputs)
        {
            if (i.RefKind != RefKind.None || i.Ordinal < 0) continue;
            var entries = new List<(Body, TaintValue)>(targets.Count);
            foreach (var t in targets)
                if (t.Body!.Summary.Guards!.TryGetValue((outcome, i.Ordinal), out var v)) entries.Add((t.Body, v));
            if (entries.Count != targets.Count || ArgumentOf(call, i.Ordinal) is not { } target) continue;
            ApplyGuardValue(target, entries, i.Ordinal, args, Op, state, ref refined);
        }
    }

    /// After a call of project methods: each argument holds what every target's exit summary says its parameter holds at
    /// the exit (a method that throws unless its check holds). An async method's exit is where its task completes: only a
    /// call awaited right there (through ConfigureAwait) has run it (`_ = EnsureAsync(p);` or a task awaited later has not;
    /// review I1). Iterators record no exit (GuardSummaries).
    private void ApplyExits(IOperation operation, IReadOnlyList<Target>? targets, TaintValue receiver, IOperation? instance, Input[] inputs, TaintState state)
    {
        if (targets == null || !Summarised(targets, s => s.Exits is { Count: > 0 })) return;
        if (targets.Any(t => t.Method.IsAsync) && !AwaitedAtOnce(operation)) return;
        var args = Arguments(receiver, inputs);
        IOperation? Op(int slot)
        {
            if (slot == -1) return instance;
            foreach (var i in inputs) if (i.Ordinal == slot) return i.Operation;
            return null;
        }
        TaintState? refined = state;
        foreach (var i in inputs)
        {
            if (i.RefKind != RefKind.None || i.Ordinal < 0) continue;
            var entries = new List<(Body, TaintValue)>(targets.Count);
            foreach (var t in targets)
                if (t.Body!.Summary.Exits!.TryGetValue(i.Ordinal, out var v)) entries.Add((t.Body, v));
            if (entries.Count == targets.Count) ApplyGuardValue(i.Operation, entries, i.Ordinal, args, Op, state, ref refined);
        }
    }

    /// Whether a call is the operand of an `await` (directly or through ConfigureAwait).
    private static bool AwaitedAtOnce(IOperation call)
    {
        var parent = call.Parent;
        while (parent is IConversionOperation) parent = parent.Parent;
        if (parent is IInvocationOperation { TargetMethod.Name: "ConfigureAwait" } configure && ReferenceEquals(configure.Instance, call)) parent = configure.Parent;
        return parent is IAwaitOperation;
    }

    /// Every target of a call is a body outside this one's component (its summary final) for which `has` holds.
    private bool Summarised(IReadOnlyList<Target> targets, Func<BodySummary, bool> has) =>
        targets.Count > 0 && targets.All(t => t.Kind == TargetKind.Body && !_body.SameComponent(t.Body!) && has(t.Body!.Summary));

    /// The argument of a call for a definition parameter ordinal (an extension method's `this` is 0).
    private static IOperation? ArgumentOf(IInvocationOperation call, int ordinal)
    {
        var reduced = call.TargetMethod.ReducedFrom != null;
        if (reduced && call.Instance != null && ordinal == 0) return call.Instance;
        foreach (var a in call.Arguments)
            if ((a.Parameter?.Ordinal ?? -2) + (reduced ? 1 : 0) == ordinal) return a.ArgumentKind == ArgumentKind.Explicit ? a.Value : null;
        return null;
    }

    /// The argument `target` given to parameter `slot` holds what the callees' summaries say (one entry per target, each
    /// in its callee's labels; the join of what each gives).
    private void ApplyGuardValue(IOperation target, List<(Body Callee, TaintValue Value)> entries, int slot, Func<int, TaintValue> args, Func<int, IOperation?> ops,
        TaintState state, ref TaintState? refined)
    {
        foreach (var key in Keys(target))
        {
            var current = (refined ?? state).Get(key);
            TaintValue? joined = null;
            foreach (var (callee, v) in entries)
            {
                if (GuardValue(current, v, callee.Id, slot, args, ops) is not { } n)
                {
                    joined = null;
                    break;
                }
                joined = joined == null ? n : joined.Join(n);
            }
            if (joined == null || joined.SameTaint(current)) continue;
            refined ??= state.Clone();
            refined.Set(key, current.HasIdentity && !joined.HasIdentity ? KeepIdentity(current, joined) : joined);
        }
        if (PathOf(target) is not { } path || !CanHold(path) || entries.Any(e => MayWrite(e.Callee.Summary, path))) return;
        HashSet<string>? rules = null;
        foreach (var (callee, v) in entries)
        {
            var r = GuardRules(v, callee.Id, slot, args);
            if (r == null) return;
            if (rules == null) rules = new HashSet<string>(r);
            else rules.IntersectWith(r);
        }
        if (rules is not { Count: > 0 }) return;
        refined ??= state.Clone();
        refined.AddFact(new MemberFact(path, rules.Count == _ctx.RuleIds.Length && _ctx.RuleIds.All(rules.Contains), rules.ToImmutableHashSet(), ImmutableHashSet<IOperation>.Empty));
    }

    /// Whether a callee may write a member on a guarded path (its summary's writes through its parameters' objects or
    /// through unknown ones, its heap writes, or a parameter given on to code whose effects are unknown): the member then
    /// gets no fact from its summary.
    private static bool MayWrite(BodySummary s, AccessPath path)
    {
        if (!s.ObjWrites.IsEmpty || !s.Escapes.IsEmpty) return true;
        foreach (var m in path.Members)
        {
            var key = SymbolKeys.Of(m);
            if (s.TopWrites != null && s.TopWrites.Contains(key)) return true;
            foreach (var (location, _) in s.Heap.Values)
                if (location is ISymbol symbol && SymbolEqualityComparer.Default.Equals(symbol.OriginalDefinition, m)) return true;
        }
        return false;
    }

    /// What an argument holding `current` holds after a summary entry `v` of `owner`'s parameter `slot`: its own value
    /// cleaned as the callee's label of it is (when the entry has it), with what the other labels stand for at this call
    /// (the caller's arguments, cleaned as the labels are) and the request data the callee itself put there; null when the
    /// entry holds a member slot (a member of an argument, which this does not substitute). An entry that holds other
    /// values only (the argument equals one of them: membership written as a loop, equality) says nothing when an
    /// argument it reads from reads data a request may have stored (`Seen.Has(tag)` with Seen written by another request;
    /// ruling R-E41).
    private TaintValue? GuardValue(TaintValue current, TaintValue v, int owner, int slot, Func<int, TaintValue> args, Func<int, IOperation?> ops)
    {
        var others = v.Request ? v.RequestPart.WithoutIdentity().Within(_body.WriteReach) : TaintValue.Clean;
        ImmutableHashSet<string>? own = null;
        foreach (var l in v.Labels)
        {
            if (ObjectTable.IsMemberSlot(l.Slot)) return null;
            if (l.Owner == owner)
            {
                if (l.Slot == slot)
                {
                    own = l.CleanFor;
                    continue;
                }
                var a = args(l.Slot).WithoutIdentity();
                if (a.Any) others = others.Join(a.CleanedFor(l.CleanFor));
            }
            else if (_body.Keeps(l.Owner))
            {
                others = others.Join(TaintValue.Clean with { Labels = ImmutableArray.Create(l) });
            }
        }
        // The entry holds the argument's own value, cleaned for some rules: only those rules change, the other parts
        // standing in for it there (`IsInside(root, p)`: p is clean for path traversal as far as root is); for every other
        // rule the argument keeps what it holds (an exit joining a narrowed and a plain return adds nothing).
        if (own != null)
            return own.Count == 0 ? null : current.CleanedFor(own).WithTaintOf(others.Any ? others.CleanedFor(_ctx.AllBut(own)) : others);
        // The entry holds other values only (the argument equals one of them): for each rule the argument takes what
        // they hold where that is no more than what it holds itself (a server value compared with a collection the request
        // fills stays the server's).
        foreach (var l in v.Labels)
            if (l.Owner == owner && (ops(l.Slot) is not { } given || StoredSomewhere(given))) return null;
        var taken = _ctx.RuleIds.Where(r => NoMoreFor(others, current, r)).ToList();
        if (taken.Count == 0) return null;
        if (taken.Count == _ctx.RuleIds.Length)
        {
            var basis = current.HasIdentity ? TaintValue.Clean with { Objects = current.Objects, Members = current.Members } : TaintValue.Clean;
            return basis.WithTaintOf(others);
        }
        return current.CleanedFor(taken).WithTaintOf(others.Any ? others.CleanedFor(_ctx.AllBut(taken)) : others);
    }

    /// Whether `a` carries no more than `b` for a rule: request data for it only where b has some; where b has request
    /// data for it and a none, a is taken whatever labels it has (what callers give rather than what the request sent);
    /// else no label for it that b lacks, the object's own state aside (OwnStateLabel).
    private bool NoMoreFor(TaintValue a, TaintValue b, string rule)
    {
        if (a.TaintedFor(rule) && !b.TaintedFor(rule)) return false;
        if (b.TaintedFor(rule) && !a.TaintedFor(rule)) return true;
        foreach (var l in a.Labels)
            if (l.TaintedFor(rule) && !OwnStateLabel(l) && !b.Labels.Any(m => m.Owner == l.Owner && m.Slot == l.Slot && m.TaintedFor(rule))) return false;
        return true;
    }

    /// The rules a member path given to parameter `slot` is clean for after a summary entry `v` (GuardValue's view: the
    /// own label's cleanliness and the other parts' rules); null when nothing is known.
    private IReadOnlyCollection<string>? GuardRules(TaintValue v, int owner, int slot, Func<int, TaintValue> args)
    {
        var others = v.Request ? v.RequestPart.WithoutIdentity() : TaintValue.Clean;
        ImmutableHashSet<string>? own = null;
        foreach (var l in v.Labels)
        {
            if (ObjectTable.IsMemberSlot(l.Slot)) return null;
            if (l.Owner == owner && l.Slot == slot)
            {
                own = l.CleanFor;
                continue;
            }
            if (l.Owner == owner)
            {
                var a = args(l.Slot).WithoutIdentity();
                if (a.Any) others = others.Join(a.CleanedFor(l.CleanFor));
            }
            else
            {
                others = others.Join(TaintValue.Clean with { Labels = ImmutableArray.Create(l) });
            }
        }
        var clean = CleanRules(others);
        return own == null ? clean : clean.Where(own.Contains).ToList();
    }

    private bool _guardParamsDone;
    private List<IParameterSymbol>? _guardParams;
    private readonly Dictionary<(bool Outcome, int Slot), TaintValue> _guardReturns = new();

    /// The parameters guard and exit summaries track: passed by value, not of a scalar type, never assigned in the body
    /// (or written by its lambdas). Null when there are none or the body is a lambda or local function.
    private List<IParameterSymbol>? GuardParams()
    {
        if (_guardParamsDone) return _guardParams;
        _guardParamsDone = true;
        if (_body.Method is not { Parameters.Length: > 0 } method || _cfg.Parent != null) return null;
        var list = method.Parameters.Where(p => p.RefKind == RefKind.None && !_ctx.Sources.IsScalar(p.Type) && !IsReassigned(p) && !NestedWrites().Contains(p)).ToList();
        return _guardParams = list.Count > 0 ? list : null;
    }

    /// A return of a bool method: what each tracked parameter holds where the returned value is true, and where false.
    private void RecordGuardReturn(IOperation returned, TaintState state)
    {
        if (_body.Method?.ReturnType.SpecialType != SpecialType.System_Boolean || GuardParams() is not { } parameters) return;
        var constant = Unwrapped(returned).ConstantValue is { HasValue: true, Value: bool b } ? b : (bool?)null;
        foreach (var outcome in new[] { true, false })
        {
            if (constant is { } c && c != outcome) continue;
            // A returned condition the graph split into one capture (`return a && b;`) is read as written.
            var condition = returned is IFlowCaptureReferenceOperation && WrittenAs(returned) is { } written && IsPure(written) ? written : returned;
            var on = constant == null ? Refine(condition, outcome, state) : state;
            foreach (var p in parameters)
            {
                var v = _body.Local(p, on.Get(p)).WithoutIdentity();
                var key = (outcome, p.Ordinal);
                _guardReturns[key] = _guardReturns.TryGetValue(key, out var old) ? old.Join(v) : v;
            }
        }
    }

    /// The body's guard and exit summaries (BodySummary.Guards, Exits): the entries that differ from the parameter as
    /// given; null when it tracks no parameter.
    internal (ImmutableDictionary<(bool Outcome, int Slot), TaintValue> Returns, ImmutableDictionary<int, TaintValue> Exits)? GuardSummaries(int owner)
    {
        if (GuardParams() is not { } parameters) return null;
        var returns = ImmutableDictionary<(bool, int), TaintValue>.Empty;
        foreach (var (key, v) in _guardReturns)
            if (!Unchanged(v, owner, key.Slot)) returns = returns.Add(key, v);
        var exits = ImmutableDictionary<int, TaintValue>.Empty;
        // An iterator runs nothing when it is called (review I1): no exit.
        if (ExitState is { } exit && _body.Method is { IsIterator: false })
        {
            foreach (var p in parameters)
            {
                var v = _body.Local(p, exit.Get(p)).WithoutIdentity();
                if (!Unchanged(v, owner, p.Ordinal)) exits = exits.Add(p.Ordinal, v);
            }
        }
        return (returns, exits);
    }

    /// Whether a value is read from data a request may have stored in any request (ruling R-E41): a field or
    /// auto-property of the project's (read in it, also through a local assigned from it, up to three steps) to which some
    /// request wrote request data (Heap.RequestAnywhere: this unit is analysed again when that changes). A local written
    /// otherwise than by assignments (`ref`, `out`) counts as stored.
    private bool StoredSomewhere(IOperation? op, int depth = 0)
    {
        if (op == null || depth > 3) return false;
        foreach (var o in op.DescendantsAndSelf())
        {
            switch (o)
            {
                case IFieldReferenceOperation f when SymbolKeys.InSource(f.Field) && _body.IsHeapMember(f.Field):
                    if (_body.RequestAnywhere(f.Field)) return true;
                    break;
                case IPropertyReferenceOperation p when SymbolKeys.InSource(p.Property) && _body.IsHeapMember(p.Property):
                    if (_body.RequestAnywhere(p.Property)) return true;
                    break;
                case ILocalReferenceOperation { IsDeclaration: false } l:
                    if (_assignments == null) Assignments(l.Local);
                    if (!_assignments!.TryGetValue(l.Local, out var writes)) break;
                    if (writes == null) return true;
                    foreach (var w in writes)
                        if (StoredSomewhere(w is IFlowCaptureReferenceOperation ? WrittenAs(w) ?? w : w, depth + 1)) return true;
                    break;
                case IFlowCaptureReferenceOperation r when _captured.TryGetValue(r.Id, out var captured):
                    foreach (var c in captured)
                        if (StoredSomewhere(c, depth + 1)) return true;
                    break;
            }
        }
        return false;
    }

    /// A parameter's own label, not cleaned, and nothing else.
    private static bool Unchanged(TaintValue v, int owner, int slot) =>
        !v.Request && v.Labels.Length == 1 && v.Labels[0].Owner == owner && v.Labels[0].Slot == slot && v.Labels[0].CleanFor.Count == 0;
}
