using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// Guards on the control-flow graph (Task 11; models/README.md, "Guards" and "Allow-lists"): a block that ends in a
/// condition passes to each successor the state refined by what the condition says on that branch.
///
/// - Equality: where `x == c`, `x.Equals(c)`, `string.Equals(x, c)` or `x is c` (`c` a constant, `null` too; a pattern
///   of constants joined by `or`) holds, the local or parameter x is that constant: clean for every rule.
/// - Model guards (`guards:`): where a call of a guard's member returns its `clean-when`, the checked argument (or the
///   receiver) is clean for the guard's rule, if the guard's conditions hold. A `not-null` guard: where a local held the
///   (awaited) result of such a call and a null check says it is not null, the call's checked argument is clean.
/// - Allow-lists (`allow-list: literal-tables`): where `T.Contains(x)` or `T.ContainsKey(x)` (Enumerable.Contains too) on
///   an allow-list table T holds, x is clean for those rules.
/// - `!`, `&&` and `||` left in a condition are taken apart (the graph usually splits them into blocks itself); a
///   condition held in a flow capture is the captured condition.
///
/// A guard cleans a local or a parameter (and the flow capture that holds one): the value is clean on the branch where
/// the check succeeded only, so it is not clean inside the failing branch, and where that branch rejoins (it did not
/// leave the method) the join is the unchecked value again.
///
/// A guard on a member read on one (`x.M`, `x.M.N`, `this.M`; Task 21) records a must-hold fact for that access path in
/// the state (TaintState.Facts): a read of the path is clean while the fact holds. A join keeps a fact only where every
/// predecessor has it; an assignment of x, a write of a member on the path (on any object), a ref or out use, and a call
/// that may change an object along the path (ForgetForCall: by type) end it. The not-null guard's call records the path
/// as pending; its null check turns that into a fact if the record survived.
internal sealed partial class MethodAnalyzer
{
    private Dictionary<ISymbol, List<IOperation>?>? _assignments;

    /// The values the arguments of a call that has guards had when it was evaluated (a guard's `arg ... text` condition
    /// reads them instead of evaluating the argument again).
    private readonly Dictionary<IOperation, TaintValue> _guardArguments = new();

    /// The state on the successor of a block whose condition `condition` had this outcome.
    private TaintState Refine(IOperation condition, bool outcome, TaintState state)
    {
        TaintState? refined = null;
        Facts(condition, outcome, state, ref refined, 0);
        return refined ?? state;
    }

    private void Facts(IOperation op, bool outcome, TaintState state, ref TaintState? refined, int depth)
    {
        if (depth > 16) return;
        while (op is IConversionOperation conversion) op = conversion.Operand;
        switch (op)
        {
            case IUnaryOperation { OperatorKind: UnaryOperatorKind.Not } not:
                Facts(not.Operand, !outcome, state, ref refined, depth + 1);
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalAnd } both when outcome:
                Facts(both.LeftOperand, true, state, ref refined, depth + 1);
                Facts(both.RightOperand, true, state, ref refined, depth + 1);
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalOr } either when !outcome:
                Facts(either.LeftOperand, false, state, ref refined, depth + 1);
                Facts(either.RightOperand, false, state, ref refined, depth + 1);
                break;
            // Task 33: `a || b` true (and `a && b` false) holds what both sides hold.
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalOr } either:
                EitherSide(either.LeftOperand, either.RightOperand, true, state, ref refined, depth);
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalAnd } both:
                EitherSide(both.LeftOperand, both.RightOperand, false, state, ref refined, depth);
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals } equality:
            {
                // `ModelState.IsValid == false` (Task 31): the check's own outcome.
                if (ValidityOutcome(equality, outcome, out var check) is { } validity)
                {
                    Facts(check!, validity, state, ref refined, depth + 1);
                    break;
                }
                // Only the built-in equality (or string's operator): a user-defined `==` may compare anything (ruling R-E13).
                var builtIn = equality.OperatorMethod == null || equality.OperatorMethod.ContainingType?.SpecialType == SpecialType.System_String;
                Equality(equality.LeftOperand, equality.RightOperand, (equality.OperatorKind == BinaryOperatorKind.Equals) == outcome, builtIn, state, ref refined);
                // Task 35 (c): `x.IndexOfAny(separators) == -1`.
                if (equality.OperatorMethod == null) IndexComparison(equality, outcome, state, ref refined);
                break;
            }
            // Task 35 (c): `x.IndexOf(separator) < 0`, `>= 0` false.
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.LessThan or BinaryOperatorKind.LessThanOrEqual or BinaryOperatorKind.GreaterThan
                or BinaryOperatorKind.GreaterThanOrEqual, OperatorMethod: null } relation:
                IndexComparison(relation, outcome, state, ref refined);
                break;
            case IIsPatternOperation pattern:
                Pattern(pattern.Value, pattern.Pattern, outcome, state, ref refined);
                break;
            case IInvocationOperation call:
                Call(call, outcome, state, ref refined);
                break;
            case IPropertyReferenceOperation property when outcome && _ctx.Validation.IsValidity(property):
                Validated(state, ref refined);
                break;
            case IFlowCaptureReferenceOperation capture when _captured.TryGetValue(capture.Id, out var list) && list.Count == 1:
                Facts(list[0], outcome, state, ref refined, depth + 1);
                break;
            // Task 33: a condition held in a bool local.
            case ILocalReferenceOperation { Local: { Type.SpecialType: SpecialType.System_Boolean, RefKind: RefKind.None } flag } use:
                StoredCondition(flag, use, outcome, state, ref refined, depth);
                break;
        }
    }

    /// `left == right` holds (equal) or does not. With `cleans` (a built-in equality, string's), a string, char, number,
    /// boolean or enum equal to a constant is that constant.
    private void Equality(IOperation left, IOperation right, bool equal, bool cleans, TaintState state, ref TaintState? refined)
    {
        if (equal && cleans)
        {
            // Task 35 (a): a local computed from the value alone before the check is computed from that constant.
            if (IsConstant(right) && IsEqualityType(left))
            {
                CleanAll(left, state, ref refined);
                CleanDerived(left, null, left, state, ref refined);
            }
            if (IsConstant(left) && IsEqualityType(right))
            {
                CleanAll(right, state, ref refined);
                CleanDerived(right, null, right, state, ref refined);
            }
            // Task 33: a value equal to a sanitizer's result on it (`x == Path.GetFileName(x)`) is as clean as that result;
            // a value equal to another is as clean as that other.
            FixedPoint(left, right, state, ref refined);
            FixedPoint(right, left, state, ref refined);
            if (!IsConstant(right) && IsEqualityType(left) && _operands.TryGetValue(right.Syntax, out var r)) Narrow(left, r, right, state, ref refined);
            if (!IsConstant(left) && IsEqualityType(right) && _operands.TryGetValue(left.Syntax, out var l)) Narrow(right, l, left, state, ref refined);
            // Task 35 (b): a full path equal to a containment check's root is the root itself.
            RootItself(left, right, state, ref refined);
            RootItself(right, left, state, ref refined);
        }
        if (IsNull(right)) NullCheck(left, !equal, state, ref refined);
        else if (IsNull(left)) NullCheck(right, !equal, state, ref refined);
    }

    private void Pattern(IOperation value, IPatternOperation pattern, bool outcome, TaintState state, ref TaintState? refined)
    {
        switch (pattern)
        {
            case INegatedPatternOperation negated:
                Pattern(value, negated.Pattern, !outcome, state, ref refined);
                break;
            case IConstantPatternOperation constant:
                if (outcome)
                {
                    CleanAll(value, state, ref refined);
                    CleanDerived(value, null, value, state, ref refined);
                }
                if (IsNull(constant.Value)) NullCheck(value, !outcome, state, ref refined);
                break;
            case IBinaryPatternOperation { OperatorKind: BinaryOperatorKind.Or } alternatives when outcome && OnlyConstants(alternatives):
                CleanAll(value, state, ref refined);
                CleanDerived(value, null, value, state, ref refined);
                break;
        }

        static bool OnlyConstants(IPatternOperation p) => p switch
        {
            IConstantPatternOperation => true,
            IBinaryPatternOperation { OperatorKind: BinaryOperatorKind.Or } b => OnlyConstants(b.LeftPattern) && OnlyConstants(b.RightPattern),
            _ => false,
        };
    }

    /// A call in a condition: `x.Equals(c)` and `string.Equals(x, c)` (System.String's and the primitives' Equals only, not an
    /// override: ruling R-E13), the model's guards, the allow-lists' membership.
    private void Call(IInvocationOperation call, bool outcome, TaintState state, ref TaintState? refined)
    {
        var method = call.TargetMethod;
        if (outcome && _ctx.Validation.IsTryValidate(call)) TryValidated(call, state, ref refined);
        if (outcome && ((method.Name == "Equals" && method.ContainingType is { SpecialType: not (SpecialType.None or SpecialType.System_Object) }) || IsSpanEquals(method)))
        {
            if (call.Instance != null && call.Arguments.Length >= 1) Equality(call.Instance, call.Arguments[0].Value, true, true, state, ref refined);
            else if (method.IsStatic && call.Arguments.Length >= 2) Equality(call.Arguments[0].Value, call.Arguments[1].Value, true, true, state, ref refined);
        }

        foreach (var (rule, guard) in _ctx.Sinks.Guards.Match(method, Access.Call))
        {
            if (guard.Kind != GuardKind.Result || guard.CleanWhen != outcome) continue;
            var checkedValue = guard.Arg < 0 ? ThisOperation(call) : SinkConditions.ArgumentValue(call, guard.Arg);
            if (checkedValue == null || !Holds(guard, call, checkedValue, out var extra)) continue;
            var rules = new[] { rule };
            Clean(checkedValue, rules, state, ref refined, extra);
            // Task 33: the path a checked full path was made of (`GetFullPath(p)`) resolves to the same file.
            foreach (var source in FullPathSources(checkedValue, guard)) Clean(source, rules, state, ref refined, extra);
        }

        if (outcome && _ctx.Sinks.AllowListRules.Length > 0 && method.Name is "Contains" or "ContainsKey" or "TryGetValue" && !SymbolKeys.InSource(method))
        {
            var first = call.Instance != null ? 0 : 1;
            var table = call.Instance ?? (call.Arguments.Length > 1 ? call.Arguments[0].Value : null);
            var value = call.Arguments.Length > first ? call.Arguments[first].Value : null;
            // Any further argument (not an `out` value) is a comparer: only one of .NET's own (a project's comparer may say
            // anything is equal).
            var comparers = call.Arguments.Skip(first + 1).All(a => a.ArgumentKind == ArgumentKind.DefaultValue || a.Parameter?.RefKind == RefKind.Out
                || AllowLists.IsNetComparer(Unwrapped(a.Value)));
            // Task 33: a collection the server built and the request never wrote is an allow-list too (a dictionary's keys:
            // ContainsKey, TryGetValue, Keys).
            if (value != null && comparers && (_ctx.AllowLists.IsTable(table, Model()?.Compilation) || ServerCollection(table, method.Name != "Contains")))
            {
                Clean(value, _ctx.Sinks.AllowListRules, state, ref refined);
                CleanDerived(value, _ctx.Sinks.AllowListRules, call, state, ref refined);
            }
        }

        // Task 33: a project method returning bool whose summary says what its arguments hold on this outcome; a search
        // whose predicate matched (`Any`, `Exists`).
        if (method.ReturnType.SpecialType == SpecialType.System_Boolean) GuardSummary(call, outcome, state, ref refined);
        // Task 35 (c): `x.Contains(separator)` false.
        if (!outcome && method.Name is "Contains" or "ContainsAny") ContainsCheck(call, outcome, state, ref refined);
        if (outcome && SearchOf(method) == Search.True) SearchNarrow(call, null, state, ref refined);
    }

    /// A null check of `checkedLocal`: where it is not null, the `not-null` guards of the call it was assigned clean that
    /// call's checked argument.
    private void NullCheck(IOperation checkedLocal, bool notNull, TaintState state, ref TaintState? refined)
    {
        if (!notNull) return;
        while (checkedLocal is IConversionOperation c) checkedLocal = c.Operand;
        // Task 33: a search's result checked in place (`if (list.Find(...) is null) return;`).
        if (checkedLocal is IInvocationOperation searched && SearchOf(searched.TargetMethod) == Search.NotNull)
        {
            SearchNarrow(searched, null, state, ref refined);
            return;
        }
        if (checkedLocal is not ILocalReferenceOperation local || Assignments(local.Local) is not [var assigned]) return;
        if (Awaited(assigned) is not { } call) return;
        if (SearchOf(call.TargetMethod) == Search.NotNull) SearchNarrow(call, call, state, ref refined);
        foreach (var (rule, guard) in _ctx.Sinks.Guards.Match(call.TargetMethod, Access.Call))
        {
            if (guard.Kind != GuardKind.NotNull || SinkConditions.ArgumentValue(call, guard.Arg) is not { } checkedValue) continue;
            if (UnchangedAfter(checkedValue, call) && Holds(guard, call, checkedValue, out var extra))
            {
                Clean(checkedValue, new[] { rule }, state, ref refined, extra);
            }
            else if (PathOf(checkedValue) is { } path && (refined ?? state).Fact(path) is { } fact && fact.Pending.Contains(call) && Holds(guard, call, checkedValue, out var memberExtra)
                && !memberExtra.Any)
            {
                // A member given to the call and unchanged since (its pending fact survived every write and call).
                refined ??= state.Clone();
                refined.AddFact(new MemberFact(path, false, ImmutableHashSet.Create(rule), ImmutableHashSet<IOperation>.Empty));
            }
        }
    }

    /// Whether the variable a checked argument is (a local or a parameter) is assigned nowhere after the call in the body
    /// (written in no other way either), so the value the null check speaks of is still the one it holds.
    private bool UnchangedAfter(IOperation checkedValue, IOperation call)
    {
        var value = Unwrapped(checkedValue);
        ISymbol? symbol = value switch
        {
            ILocalReferenceOperation l => l.Local,
            IParameterReferenceOperation p => p.Parameter,
            _ => null,
        };
        if (symbol == null) return false;
        if (_assignments == null) Assignments(symbol);
        if (!_assignments!.TryGetValue(symbol, out var writes)) return true;
        return writes != null && writes.All(w => w.Syntax.SpanStart < call.Syntax.SpanStart);
    }

    private static IOperation Unwrapped(IOperation op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }

    /// A type whose equality to a constant makes a value that constant: string, char, a number, bool, an enum (or
    /// Nullable of one).
    private static bool IsEqualityType(IOperation value)
    {
        var type = Unwrapped(value).Type;
        if (type == null) return false;
        type = SourceFinder.UnwrapNullable(type);
        if (IsCharSpan(type)) return true;
        return type.TypeKind == TypeKind.Enum || type.SpecialType is SpecialType.System_String or SpecialType.System_Char or SpecialType.System_Boolean
            or SpecialType.System_SByte or SpecialType.System_Byte or SpecialType.System_Int16 or SpecialType.System_UInt16 or SpecialType.System_Int32
            or SpecialType.System_UInt32 or SpecialType.System_Int64 or SpecialType.System_UInt64 or SpecialType.System_Decimal or SpecialType.System_Single
            or SpecialType.System_Double;
    }

    /// Records the values of a call's arguments when the call is a guard's (for Holds); a `not-null` guard's checked
    /// argument that is a member (`x.M`) gets a pending fact, which its null check turns into a guard if no write or call
    /// has ended it by then.
    private void GuardArguments(IOperation operation, IMethodSymbol method, Input[] inputs, TaintState state)
    {
        if (_ctx.Sinks.Guards.IsEmpty) return;
        var guards = _ctx.Sinks.Guards.Match(method, Access.Call);
        if (guards.Length == 0) return;
        foreach (var i in inputs)
        {
            _guardArguments[i.Operation] = i.Value;
            _guardArgumentsBySyntax[i.Operation.Syntax] = i.Value;
        }
        if (operation is not IInvocationOperation call) return;
        foreach (var (_, guard) in guards)
        {
            if (guard.Kind == GuardKind.NotNull && SinkConditions.ArgumentValue(call, guard.Arg) is { } checkedValue && PathOf(checkedValue) is { } path && CanHold(path))
                state.AddFact(new MemberFact(path, false, ImmutableHashSet<string>.Empty, ImmutableHashSet.Create<IOperation>(call)));
        }
    }

    /// The call a value comes from: through conversions, an await and ConfigureAwait.
    private static IInvocationOperation? Awaited(IOperation value)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            switch (value)
            {
                case IConversionOperation c:
                    value = c.Operand;
                    continue;
                case IAwaitOperation a:
                    value = a.Operation;
                    continue;
                case IInvocationOperation { TargetMethod.Name: "ConfigureAwait", Instance: { } task }:
                    value = task;
                    continue;
                case IInvocationOperation call:
                    return call;
                default:
                    return null;
            }
        }
        return null;
    }

    /// A guard's conditions (`when:`) at a call. `extra`: the parameter labels an `arg ... text` argument carries (Task 33:
    /// in a helper given its root, the check holds as far as the caller's root is clean; Clean keeps them, for the
    /// guard's rules, in the checked value).
    private bool Holds(GuardModel guard, IInvocationOperation call, IOperation checkedValue, out TaintValue extra)
    {
        extra = TaintValue.Clean;
        foreach (var c in guard.When)
        {
            switch (c.Kind)
            {
                case GuardConditionKind.AssignedFrom:
                {
                    var value = checkedValue;
                    while (value is IConversionOperation conversion) value = conversion.Operand;
                    // Task 33: the call written in place (`Path.GetFullPath(p).StartsWith(...)`).
                    if (value is IInvocationOperation inPlace && SymbolMatch.Matches(c.Member!, inPlace.TargetMethod)) break;
                    if (value is not ILocalReferenceOperation local || Assignments(local.Local) is not { Count: > 0 } all) return false;
                    foreach (var a in all)
                        if (!AssignedFrom(a, c.Member!, ref extra)) return false;
                    break;
                }
                case GuardConditionKind.ArgumentText:
                {
                    if (SinkConditions.ArgumentValue(call, c.Arg) is not { } argument) return false;
                    if (!_guardArguments.TryGetValue(argument, out var argumentValue) && !_guardArgumentsBySyntax.TryGetValue(argument.Syntax, out argumentValue)) return false;
                    if (argumentValue.Request) return false;
                    // Every text the argument may have (Task 33: through locals and conditionals) must match.
                    if (!GuardTexts(argument, 0, null).All(t => c.Pattern!.IsMatch(t))) return false;
                    extra = extra.Join(argumentValue.LabelPart.WithoutIdentity());
                    break;
                }
            }
        }
        return true;
    }

    private const int MaxTexts = 8;

    /// The texts a guard's argument may have, built from: constants, both sides of a string `+`, the text and holes of an
    /// interpolated string, Path.DirectorySeparatorChar and AltDirectorySeparatorChar as '/'; and (Task 33) what a local is
    /// assigned (each assignment an alternative) and both arms of a conditional, where an arm that is a value `v` taken
    /// when `Path.EndsInDirectorySeparator(v)` (or `v.EndsWith('/')`, ...) holds is a folder and a separator. Any other
    /// value is a Hole. Beyond MaxTexts alternatives, a Hole alone (which no separator pattern matches).
    private List<string> GuardTexts(IOperation? op, int depth, HashSet<ISymbol>? seen)
    {
        while (op is IConversionOperation c) op = c.Operand;
        if (op == null || depth > 32) return new List<string> { "" };
        if (op.ConstantValue is { HasValue: true, Value: string or char })
            return new List<string> { Convert.ToString(op.ConstantValue.Value, System.Globalization.CultureInfo.InvariantCulture) ?? "" };
        switch (op)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } b:
                return Product(GuardTexts(b.LeftOperand, depth + 1, seen), GuardTexts(b.RightOperand, depth + 1, seen));
            case IInterpolatedStringOperation interpolated:
            {
                var texts = new List<string> { "" };
                foreach (var part in interpolated.Parts)
                {
                    if (part is IInterpolatedStringTextOperation t) texts = Product(texts, GuardTexts(t.Text, depth + 1, seen));
                    else if (part is IInterpolationOperation hole) texts = Product(texts, GuardTexts(hole.Expression, depth + 1, seen));
                }
                return texts;
            }
            case IFieldReferenceOperation { Field: { Name: "DirectorySeparatorChar" or "AltDirectorySeparatorChar", ContainingType: { } type } }
                when SymbolMatch.MetadataName(type) == "System.IO.Path":
                return new List<string> { "/" };
            case ILocalReferenceOperation l when Assignments(l.Local) is { Count: > 0 } all && (seen == null || !seen.Contains(l.Local)):
            {
                seen = seen == null ? new HashSet<ISymbol>(SymbolEqualityComparer.Default) : new HashSet<ISymbol>(seen, SymbolEqualityComparer.Default);
                seen.Add(l.Local);
                var texts = new List<string>();
                foreach (var a in all) texts.AddRange(GuardTexts(a is IFlowCaptureReferenceOperation ? WrittenAs(a) : a, depth + 1, seen));
                return Capped(texts);
            }
            case IConditionalOperation { WhenFalse: { } whenFalse } conditional:
            {
                var texts = ArmTexts(conditional, conditional.WhenTrue, true, depth, seen);
                texts.AddRange(ArmTexts(conditional, whenFalse, false, depth, seen));
                return Capped(texts);
            }
            default:
                return new List<string> { Hole.ToString() };
        }
    }

    private List<string> ArmTexts(IConditionalOperation conditional, IOperation arm, bool whenTrue, int depth, HashSet<ISymbol>? seen)
    {
        if (EndsInSeparator(conditional.Condition) is { } check && check.Holds == whenTrue && SameVariable(arm, check.Value))
            return new List<string> { Hole + "/" };
        return GuardTexts(arm, depth + 1, seen);
    }

    /// `Path.EndsInDirectorySeparator(v)`, `v.EndsWith(c)` with c a separator (a constant '/' or '\', "/" or "\",
    /// Path.DirectorySeparatorChar or AltDirectorySeparatorChar), or a negation of one: the value and whether the check
    /// holds when the condition is true.
    private static (IOperation Value, bool Holds)? EndsInSeparator(IOperation condition)
    {
        var holds = true;
        while (true)
        {
            while (condition is IConversionOperation c) condition = c.Operand;
            if (condition is IUnaryOperation { OperatorKind: UnaryOperatorKind.Not } not)
            {
                holds = !holds;
                condition = not.Operand;
                continue;
            }
            break;
        }
        if (condition is not IInvocationOperation call) return null;
        var method = call.TargetMethod;
        if (method.Name == "EndsInDirectorySeparator" && method.IsStatic && method.ContainingType is { } path && SymbolMatch.MetadataName(path) == "System.IO.Path"
            && call.Arguments.Length == 1 && Unwrapped(call.Arguments[0].Value).Type?.SpecialType == SpecialType.System_String)
            return (call.Arguments[0].Value, holds);
        if (method.Name == "EndsWith" && method.ContainingType?.SpecialType == SpecialType.System_String && call.Instance != null && call.Arguments.Length >= 1
            && IsSeparator(call.Arguments[0].Value))
            return (call.Instance, holds);
        return null;

        static bool IsSeparator(IOperation op)
        {
            op = Unwrapped(op);
            if (op.ConstantValue is { HasValue: true, Value: '/' or '\\' or "/" or "\\" }) return true;
            return op is IFieldReferenceOperation { Field: { Name: "DirectorySeparatorChar" or "AltDirectorySeparatorChar", ContainingType: { } t } }
                && SymbolMatch.MetadataName(t) == "System.IO.Path";
        }
    }

    private static List<string> Product(List<string> a, List<string> b)
    {
        var result = new List<string>(a.Count * b.Count);
        foreach (var x in a)
            foreach (var y in b)
                result.Add(x + y);
        return Capped(result);
    }

    private static List<string> Capped(List<string> texts) => texts.Count <= MaxTexts ? texts : new List<string> { Hole.ToString() };

    /// What a local is assigned in this body (its declaration's initializer too); null when it is also written otherwise
    /// (a `ref` or `out` argument, a compound assignment, a deconstruction, an increment).
    private List<IOperation>? Assignments(ISymbol local)
    {
        if (_assignments == null)
        {
            _assignments = new Dictionary<ISymbol, List<IOperation>?>(SymbolEqualityComparer.Default);
            foreach (var block in _cfg.Blocks)
            {
                foreach (var root in block.Operations.Append(block.BranchValue))
                {
                    if (root == null) continue;
                    foreach (var o in root.DescendantsAndSelf()) Collect(o);
                }
            }
        }
        return _assignments.TryGetValue(local, out var list) ? list : null;

        void Collect(IOperation o)
        {
            switch (o)
            {
                // Task 35 (review M1): a `ref` local made to refer to a variable writes it whenever it is written.
                case IVariableDeclaratorOperation { Symbol.RefKind: not RefKind.None, Initializer: { } byRef } r:
                    Spoil(r.Symbol);
                    SpoilReferenced(byRef.Value);
                    break;
                case ISimpleAssignmentOperation { IsRef: true } refAssignment:
                    SpoilReferenced(refAssignment.Target);
                    SpoilReferenced(refAssignment.Value);
                    break;
                case ISimpleAssignmentOperation { Target: ILocalReferenceOperation l } a:
                    Add(l.Local, a.Value);
                    break;
                case ISimpleAssignmentOperation { Target: IParameterReferenceOperation p } a:
                    Add(p.Parameter, a.Value);
                    break;
                case IAssignmentOperation { Target: IParameterReferenceOperation p }:
                    Spoil(p.Parameter);
                    break;
                case IIncrementOrDecrementOperation { Target: IParameterReferenceOperation p }:
                    Spoil(p.Parameter);
                    break;
                case IArgumentOperation { Value: IParameterReferenceOperation p, Parameter.RefKind: RefKind.Ref or RefKind.Out }:
                    Spoil(p.Parameter);
                    break;
                case IVariableDeclaratorOperation { Initializer: { } init } d:
                    Add(d.Symbol, init.Value);
                    break;
                case IAssignmentOperation { Target: ILocalReferenceOperation l }:
                    Spoil(l.Local);
                    break;
                case IIncrementOrDecrementOperation { Target: ILocalReferenceOperation l }:
                    Spoil(l.Local);
                    break;
                case IArgumentOperation { Value: ILocalReferenceOperation l, Parameter.RefKind: RefKind.Ref or RefKind.Out }:
                    Spoil(l.Local);
                    break;
                case IArgumentOperation { Value: IDeclarationExpressionOperation { Expression: ILocalReferenceOperation l } }:
                    Spoil(l.Local);
                    break;
                case IDeconstructionAssignmentOperation deconstruction:
                    foreach (var l in deconstruction.Target.DescendantsAndSelf().OfType<ILocalReferenceOperation>()) Spoil(l.Local);
                    foreach (var p in deconstruction.Target.DescendantsAndSelf().OfType<IParameterReferenceOperation>()) Spoil(p.Parameter);
                    break;
            }
        }

        void Add(ISymbol l, IOperation value)
        {
            if (!_assignments!.TryGetValue(l, out var list)) _assignments[l] = list = new List<IOperation>();
            list?.Add(value);
        }

        void Spoil(ISymbol l) => _assignments![l] = null;

        void SpoilReferenced(IOperation op)
        {
            while (op is IConversionOperation c) op = c.Operand;
            if (op is ILocalReferenceOperation l) Spoil(l.Local);
            else if (op is IParameterReferenceOperation p) Spoil(p.Parameter);
        }
    }

    private static bool IsConstant(IOperation op)
    {
        while (op is IConversionOperation c && !op.ConstantValue.HasValue) op = c.Operand;
        return op.ConstantValue.HasValue;
    }

    private static bool IsNull(IOperation op)
    {
        while (op is IConversionOperation c && !op.ConstantValue.HasValue) op = c.Operand;
        return op.ConstantValue is { HasValue: true, Value: null };
    }

    /// The value is a constant on this branch: clean for every rule (its labels too). A member's access path gets the
    /// fact.
    private void CleanAll(IOperation value, TaintState state, ref TaintState? refined)
    {
        foreach (var key in Keys(value))
        {
            refined ??= state.Clone();
            refined.Set(key, TaintValue.Clean);
        }
        if (PathOf(value) is { } path && CanHold(path))
        {
            refined ??= state.Clone();
            refined.AddFact(new MemberFact(path, true, ImmutableHashSet<string>.Empty, ImmutableHashSet<IOperation>.Empty));
        }
    }

    /// The value is clean for these rules on this branch. A member's access path gets the fact. With `extra` (Task 33:
    /// the labels a guard's condition read, Holds), the value stays request data for these rules as far as they are: a
    /// local or parameter keeps them for these rules only; a member gets no fact.
    private void Clean(IOperation value, IReadOnlyCollection<string> rules, TaintState state, ref TaintState? refined, TaintValue? extra = null)
    {
        var also = extra is { Any: true } ? extra.CleanedFor(_ctx.AllBut(rules)) : null;
        foreach (var key in Keys(value))
        {
            var current = (refined ?? state).Get(key);
            if (!current.Any) continue;
            refined ??= state.Clone();
            refined.Set(key, also == null ? current.CleanedFor(rules) : current.CleanedFor(rules).WithTaintOf(also));
        }
        if (also != null) return;
        if (rules.Count > 0 && PathOf(value) is { } path && CanHold(path))
        {
            refined ??= state.Clone();
            refined.AddFact(new MemberFact(path, false, rules.ToImmutableHashSet(), ImmutableHashSet<IOperation>.Empty));
        }
    }

    // ---- Guards on members (Task 21) ----

    /// What the nested bodies and method-group delegates of the analysed method may change (NestedEffects): a guard on
    /// a path that mentions one is not recorded, since the delegate may run at any call.
    private HashSet<object>? _nestedEffects;

    /// The access path an operation reads (`x.M`, `x.M.N`, `this.M`, `T.S.M`; through conversions and a flow capture of
    /// one value), or null: a plain local or parameter (guarded as before), an indexer, a call, a path longer than
    /// AccessPath.MaxMembers. With `captureRoot` (strong updates, Task 27) a flow capture of something that is no path (the
    /// object an initializer fills, a call's result) is a root of its own.
    private AccessPath? PathOf(IOperation operation, bool captureRoot = false)
    {
        while (operation is IConversionOperation conversion) operation = conversion.Operand;
        if (operation is IFlowCaptureReferenceOperation capture && _captured.TryGetValue(capture.Id, out var values) && values.Count > 1)
        {
            // `x?.M` held in one capture: the path on one branch, null on the other (where it reads nothing).
            AccessPath? common = null;
            foreach (var v in values)
            {
                if (IsNull(v)) continue;
                if (v is IFlowCaptureReferenceOperation || PathOf(v) is not { } p || (common != null && !common.Equals(p))) return null;
                common = p;
            }
            return common;
        }
        var members = new List<ISymbol>(2);
        var types = new List<ITypeSymbol>(3);
        IOperation? op = operation;
        object? root = null;
        for (var depth = 0; depth < 16 && root == null; depth++)
        {
            while (op is IConversionOperation c) op = c.Operand;
            switch (op)
            {
                case IFieldReferenceOperation f:
                    members.Add(f.Field.OriginalDefinition);
                    if (MemberFacts.IsChangeable(f.Field.Type)) types.Add(f.Field.Type);
                    if (f.Field.IsStatic) root = AccessPath.Static;
                    else op = f.Instance;
                    break;
                case IPropertyReferenceOperation { Arguments.Length: 0 } p:
                    members.Add(p.Property.OriginalDefinition);
                    if (MemberFacts.IsChangeable(p.Property.Type)) types.Add(p.Property.Type);
                    if (p.Property.IsStatic) root = AccessPath.Static;
                    else op = p.Instance;
                    break;
                case ILocalReferenceOperation l:
                    root = l.Local;
                    if (MemberFacts.IsChangeable(l.Local.Type)) types.Add(l.Local.Type);
                    break;
                case IParameterReferenceOperation p:
                    root = p.Parameter;
                    if (MemberFacts.IsChangeable(p.Parameter.Type)) types.Add(p.Parameter.Type);
                    break;
                case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance } i:
                    root = AccessPath.This;
                    if (i.Type != null) types.Add(i.Type);
                    break;
                case IFlowCaptureReferenceOperation r when _captured.TryGetValue(r.Id, out var list) && list.Count == 1 && (!captureRoot || IsPathPart(list[0])):
                    op = list[0];
                    break;
                case IFlowCaptureReferenceOperation r when captureRoot:
                    root = r.Id;
                    if (MemberFacts.IsChangeable(r.Type)) types.Add(r.Type!);
                    break;
                default:
                    return null;
            }
            if (op == null) return null;
        }
        if (root == null || members.Count == 0 || members.Count > AccessPath.MaxMembers) return null;
        members.Reverse();
        return new AccessPath(root, members.ToImmutableArray(), types.ToImmutableArray());
    }

    private static bool IsPathPart(IOperation operation)
    {
        while (operation is IConversionOperation c) operation = c.Operand;
        return operation is ILocalReferenceOperation or IParameterReferenceOperation or IInstanceReferenceOperation or IFieldReferenceOperation
            or IPropertyReferenceOperation { Arguments.Length: 0 } or IFlowCaptureReferenceOperation;
    }

    /// Whether the body assigns a parameter (or writes it by ref): its strong updates at the exit are not its caller's.
    internal bool IsReassigned(IParameterSymbol parameter)
    {
        Assignments(parameter);
        return _assignments!.ContainsKey(parameter);
    }

    /// A member read on a path a guard cleaned on this branch: clean (for every rule, or for the guard's rules).
    private TaintValue Guarded(IOperation member, TaintValue value, TaintState state)
    {
        if (!value.Any || !state.HasFacts || PathOf(member) is not { } path || state.Fact(path) is not { Cleans: true } fact) return value;
        if (fact.All) return TaintValue.Clean;
        var cleaned = value.CleanedFor(fact.Rules);
        // Model validation cleans the request data only, not what a caller passed (Task 31, review C1).
        return fact.Validated.Count > 0 ? cleaned.RequestCleanedFor(fact.Validated) : cleaned;
    }

    /// Whether a guard on this path may be recorded:
    /// - no lambda or local function of the method writes its root or one of its members, or gives its root (or an
    ///   object read from it) to a call, a constructor or as a receiver; and no method-group delegate of the method is
    ///   bound to an object read from its root (the delegate may run at any call; fix round 1, I1);
    /// - no member on it is a property declared in source that is not an auto-property: a computed or field-backed
    ///   getter reads state a write of another member changes (fix round 1, I2); nor a virtual, abstract or interface
    ///   property one of whose overrides or implementations has a getter body (fix round 2, RR2).
    private bool CanHold(AccessPath path)
    {
        foreach (var m in path.Members)
        {
            if (m is not IPropertySymbol property) continue;
            if (SymbolKeys.InSource(property) && !_body.IsHeapMember(property)) return false;
            // A virtual, abstract or interface property: every override or implementation (Dispatch) must be an
            // auto-property or external (fix round 2, RR2).
            if ((property.IsVirtual || property.IsAbstract || property.IsOverride || property.ContainingType?.TypeKind == TypeKind.Interface)
                && property.GetMethod is { } getter
                && _body.Targets(getter, true, property.ContainingType).Any(t => t.Kind is TargetKind.Body or TargetKind.Opaque))
                return false;
        }
        _nestedEffects ??= NestedEffects();
        if (_nestedEffects.Count == 0) return true;
        if (_nestedEffects.Contains(path.Root)) return false;
        foreach (var m in path.Members) if (_nestedEffects.Contains(m)) return false;
        return true;
    }

    /// The roots and members the nested bodies of the method may change (see CanHold): the locals, parameters, members
    /// and `this` (AccessPath.This) that a lambda or local function assigns or gives to a call, and the roots of the
    /// objects method-group delegates are bound to.
    private HashSet<object> NestedEffects()
    {
        var set = new HashSet<object>(SymbolOrCapture.Comparer);
        var g = _cfg;
        while (g.Parent != null) g = g.Parent;
        foreach (var o in g.OriginalOperation.Descendants())
        {
            if (o is IMethodReferenceOperation { Instance: { } bound }) AddRoot(bound);
            if (o is not (IAnonymousFunctionOperation or ILocalFunctionOperation)) continue;
            foreach (var n in o.Descendants())
            {
                switch (n)
                {
                    case IAssignmentOperation a:
                        AddTarget(a.Target);
                        break;
                    case IIncrementOrDecrementOperation i:
                        AddTarget(i.Target);
                        break;
                    case IArgumentOperation { Parameter.RefKind: RefKind.Ref or RefKind.Out } r:
                        AddTarget(r.Value);
                        break;
                    case IArgumentOperation a:
                        AddRoot(a.Value);
                        break;
                    case IInvocationOperation { Instance: { } receiver }:
                        AddRoot(receiver);
                        break;
                    case IDynamicInvocationOperation or IDynamicObjectCreationOperation or IDynamicIndexerAccessOperation:
                        foreach (var child in n.ChildOperations) AddRoot(child);
                        break;
                }
            }
        }
        return set;

        void AddTarget(IOperation target)
        {
            foreach (var t in target.DescendantsAndSelf())
            {
                switch (t)
                {
                    case ILocalReferenceOperation l:
                        set.Add(l.Local);
                        break;
                    case IParameterReferenceOperation p:
                        set.Add(p.Parameter);
                        break;
                    case IFieldReferenceOperation f:
                        set.Add(f.Field.OriginalDefinition);
                        break;
                    case IPropertyReferenceOperation p:
                        set.Add(p.Property.OriginalDefinition);
                        break;
                    case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }:
                        set.Add(AccessPath.This);
                        break;
                }
            }
        }

        // The root an object given to a call is read from (`f`, `f.Paging`, `this`), when it may lead to an object.
        void AddRoot(IOperation value)
        {
            var op = value;
            for (var depth = 0; depth < 16 && op != null; depth++)
            {
                while (op is IConversionOperation c) op = c.Operand;
                if (depth == 0 && !MemberFacts.MayHold(op?.Type)) return;
                switch (op)
                {
                    case IFieldReferenceOperation f when !f.Field.IsStatic:
                        op = f.Instance;
                        continue;
                    case IPropertyReferenceOperation p when !p.Property.IsStatic:
                        op = p.Instance;
                        continue;
                    case ILocalReferenceOperation l:
                        set.Add(l.Local);
                        return;
                    case IParameterReferenceOperation p:
                        set.Add(p.Parameter);
                        return;
                    case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }:
                        set.Add(AccessPath.This);
                        return;
                    default:
                        return;
                }
            }
        }
    }

    /// Whether an await waits for a call made right there (through conversions and ConfigureAwait) that is given no task:
    /// otherwise it may wait for work started earlier (fix round 1, M3).
    private static bool AwaitsFreshCall(IOperation awaited)
    {
        var op = awaited;
        for (var depth = 0; depth < 8; depth++)
        {
            while (op is IConversionOperation c) op = c.Operand;
            if (op is IInvocationOperation { TargetMethod.Name: "ConfigureAwait", Instance: { } task }) op = task;
            else break;
        }
        if (op is not IInvocationOperation call) return false;
        if (call.Instance != null && HoldsTask(call.Instance.Type)) return false;
        foreach (var a in call.Arguments)
            if (HoldsTask(Unwrapped(a.Value).Type)) return false;
        return true;

        // A task, or a type holding one in an element type, a type argument or a containing type's type argument
        // (`Dictionary<string, Task>.ValueCollection`; fix round 2, RR4).
        static bool HoldsTask(ITypeSymbol? type, int depth = 0)
        {
            if (type == null || depth > 6) return false;
            if (type is IArrayTypeSymbol array) return HoldsTask(array.ElementType, depth + 1);
            if (type is not INamedTypeSymbol named) return false;
            if (named.ContainingNamespace?.ToDisplayString() == "System.Threading.Tasks" && named.Name is "Task" or "ValueTask") return true;
            foreach (var a in named.TypeArguments)
                if (HoldsTask(a, depth + 1)) return true;
            return named.ContainingType != null && HoldsTask(named.ContainingType, depth + 1);
        }
    }

    /// A local or parameter assigned: its paths' facts end.
    /// A `ref` local or a `ref`/`out` parameter writes through to whatever it refers to (a root, a member): every fact
    /// ends (fix round 1, M1).
    private static void ForgetRoot(ISymbol symbol, TaintState state)
    {
        if (symbol is ILocalSymbol { RefKind: RefKind.Ref } or IParameterSymbol { RefKind: RefKind.Ref or RefKind.Out })
        {
            state.ForgetAll();
            state.ForgetPointsTo();
            return;
        }
        if (!state.HasFacts) return;
        state.Forget(p => SymbolOrCapture.Comparer.Equals(p.Root, symbol));
    }

    /// What a write of `target` (an assignment, an increment, a ref or out argument, a collection write into it) ends: the
    /// facts rooted at a local or parameter written, at `this` written into, and of every path that mentions a member
    /// written, on whatever object (an alias writes the same member).
    private void ForgetWritten(IOperation? target, TaintState state, int depth = 0)
    {
        if (!state.HasFacts || target == null || depth > 8) return;
        while (target is IConversionOperation c) target = c.Operand;
        switch (target)
        {
            case ILocalReferenceOperation l:
                ForgetRoot(l.Local, state);
                break;
            case IParameterReferenceOperation p:
                ForgetRoot(p.Parameter, state);
                break;
            case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }:
                state.Forget(p => ReferenceEquals(p.Root, AccessPath.This));
                break;
            case IFieldReferenceOperation f:
            {
                var member = f.Field.OriginalDefinition;
                state.Forget(p => p.Mentions(member));
                break;
            }
            case IPropertyReferenceOperation p:
            {
                var member = p.Property.OriginalDefinition;
                state.Forget(x => x.Mentions(member));
                break;
            }
            case IArrayElementReferenceOperation e:
                ForgetWritten(e.ArrayReference, state, depth + 1);
                break;
            case IDeclarationExpressionOperation d:
                ForgetWritten(d.Expression, state, depth + 1);
                break;
            case ITupleOperation t:
                foreach (var e in t.Elements) ForgetWritten(e, state, depth + 1);
                break;
            case IFlowCaptureReferenceOperation r when _captured.TryGetValue(r.Id, out var list):
                foreach (var captured in list) ForgetWritten(captured, state, depth + 1);
                break;
        }
    }

    /// What a call (or a setter or getter with a body) does to the facts and to the body's own summary (Task 27):
    /// - the facts it may end (ForgetForCall);
    /// - for a symbolic body's summary, what its callers need to end theirs: the members its callees write through
    ///   unknown objects, and its parameters whose objects (or what it read from them) reach calls whose effects are
    ///   unknown (an external method, a body that is not symbolic, a delegate), also through the parameters of a
    ///   symbolic callee that escape.
    /// `targets` are the call's targets (null: a delegate's invocation, or a call without a method); `receiver` the
    /// receiver's value. `guards`: the call ends guards' facts too (a getter does not, as before Task 27).
    private void CallEffects(IOperation? instance, TaintValue receiver, Input[] inputs, TaintState state, IReadOnlyList<Target>? targets, bool guards = true)
    {
        // A body of this body's own component has no final summary yet: its call is one whose effects are unknown.
        var summarised = targets is { Count: > 0 } && targets.All(t => t.Kind == TargetKind.Body && _body.IsSymbolic(t.Body!) && !_body.SameComponent(t.Body!));
        var keepsMembers = targets is { Count: > 0 } && targets.All(t => t.Kind == TargetKind.External && KeepsMembers(t.Method)) && !GivesDelegate(instance, inputs);
        if (_body.RootSymbolic && !keepsMembers)
        {
            if (summarised)
            {
                foreach (var t in targets!)
                {
                    var s = t.Body!.Summary;
                    if (s.TopWrites != null) _body.AbsorbTopWrites(s.TopWrites);
                    foreach (var slot in s.Escapes) EscapeArgument(slot, instance, receiver, inputs);
                }
            }
            else if (targets == null || !targets.All(t => t.Kind == TargetKind.Auto))
            {
                if (instance != null) Escape(instance, receiver);
                foreach (var i in inputs) if (i.RefKind != RefKind.Out) Escape(i.Operation, i.Value);
            }
        }
        if (state.HasFacts) ForgetForCall(instance, inputs, state, summarised ? targets : null, guards, keepsMembers);
    }

    private static readonly HashSet<string> MemberKeepingNamespaces = new(StringComparer.Ordinal)
    {
        "System", "System.Collections", "System.Collections.Generic", "System.Collections.Concurrent", "System.Collections.Immutable",
        "System.Collections.ObjectModel", "System.Linq", "System.Text", "System.Threading", "System.Threading.Tasks", "System.Globalization",
        "Microsoft.Extensions.Logging",
    };

    /// Whether an external method leaves the members of the project's objects it is given as they are (Task 27): one of
    /// .NET's core libraries (the System namespace itself, collections, LINQ, text, tasks, globalization) or logging, which
    /// set no member of an object of the project (unlike reflection, serializers, binders, mappers). A lambda it is given
    /// is analysed with the method that wrote it (a strong update its writes could end is not recorded there).
    private static bool KeepsMembers(IMethodSymbol method) =>
        !SymbolKeys.InSource(method) && method.ContainingNamespace?.ToDisplayString() is { } ns && MemberKeepingNamespaces.Contains(ns)
        // Reflection and delegates run what they are told (fix round 1, I3): Type.InvokeMember, Delegate.DynamicInvoke.
        && method.ContainingType is { } type && SymbolMatch.MetadataName(type.OriginalDefinition) is not ("System.Type" or "System.Delegate" or "System.MulticastDelegate");

    /// Whether a call is given a delegate that is no lambda or local function of this method (a method group, a
    /// delegate held in a variable or parameter): the core library runs it, and it may set any member (fix round 1, I3).
    private bool GivesDelegate(IOperation? instance, Input[] inputs)
    {
        if (Foreign(instance)) return true;
        foreach (var i in inputs) if (Foreign(i.Operation)) return true;
        return false;

        bool Foreign(IOperation? op)
        {
            if (op == null) return false;
            var unwrapped = op;
            while (unwrapped is IConversionOperation c) unwrapped = c.Operand;
            if (unwrapped.Type?.TypeKind != TypeKind.Delegate && op.Type?.TypeKind != TypeKind.Delegate) return false;
            return DelegateOf(op) switch
            {
                IFlowAnonymousFunctionOperation lambda => CallsUnknown(BodyOf(lambda.Symbol)),
                IMethodReferenceOperation { Method: { MethodKind: MethodKind.LocalFunction } local } => CallsUnknown(BodyOf(local)),
                _ => true,
            };
        }
    }

    private Dictionary<IOperation, bool>? _callsUnknown;

    /// Whether a lambda's or local function's body calls anything but external methods that keep members (fix round 2,
    /// R1-I1): a project method it calls may write a member of what the core library hands it (`ForEach(x =>
    /// Fill(x, q))`), so such a delegate is as foreign as a method group. Unknown when the body cannot be found.
    private bool CallsUnknown(IOperation? body)
    {
        if (body == null) return true;
        _callsUnknown ??= new Dictionary<IOperation, bool>();
        if (_callsUnknown.TryGetValue(body, out var known)) return known;
        var result = false;
        foreach (var o in body.DescendantsAndSelf())
        {
            switch (o)
            {
                case IInvocationOperation call:
                    if (call.TargetMethod.MethodKind == MethodKind.DelegateInvoke
                        || _body.Targets(call.TargetMethod, call.IsVirtual, call.Instance?.Type).Any(t => t.Kind != TargetKind.External || !KeepsMembers(t.Method))
                        || HandsForeignDelegate(call))
                        result = true;
                    break;
                case IObjectCreationOperation { Constructor: { } constructor } when SymbolKeys.InSource(constructor):
                    result = true;
                    break;
                case IPropertyReferenceOperation { Property: { } property, Parent: IAssignmentOperation assignment } p
                    when ReferenceEquals(assignment.Target, p) && SymbolKeys.InSource(property) && !_body.IsHeapMember(property):
                    result = true;
                    break;
                case IDynamicInvocationOperation or IDynamicObjectCreationOperation or IFunctionPointerInvocationOperation:
                    result = true;
                    break;
            }
            if (result) break;
        }
        _callsUnknown[body] = result;
        return result;
    }

    /// Whether a member-keeping call inside a lambda's body is given a delegate that is no lambda or local function written
    /// there (fix round 3, R2-I1: `b => b.Items.ForEach(Rename)` hands the core library a method group): a nested lambda
    /// is part of the body already scanned, a local function is scanned in turn.
    private bool HandsForeignDelegate(IInvocationOperation call)
    {
        foreach (var operand in call.Arguments.Select(a => a.Value).Prepend(call.Instance))
        {
            var op = operand;
            if (op == null || (op.Type?.TypeKind != TypeKind.Delegate && op is not (IDelegateCreationOperation or IConversionOperation))) continue;
            while (op is IConversionOperation or IDelegateCreationOperation)
                op = op is IConversionOperation c ? c.Operand : ((IDelegateCreationOperation)op).Target;
            switch (op)
            {
                case IAnonymousFunctionOperation:
                    continue;
                case IMethodReferenceOperation { Method: { MethodKind: MethodKind.LocalFunction } local }:
                    if (CallsUnknown(BodyOf(local))) return true;
                    continue;
                default:
                    if (op.Type?.TypeKind == TypeKind.Delegate || op is IMethodReferenceOperation) return true;
                    continue;
            }
        }
        return false;
    }

    /// The operation tree of a lambda's or local function's body, or null.
    private IOperation? BodyOf(IMethodSymbol function)
    {
        if (function.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not { } syntax || Model() is not { } model || model.SyntaxTree != syntax.SyntaxTree)
            return null;
        return model.GetOperation(syntax) switch
        {
            IAnonymousFunctionOperation lambda => lambda.Body,
            ILocalFunctionOperation local => local.Body,
            _ => null,
        };
    }

    /// A callee's parameter `slot` escapes: what the call gives it escapes from this body.
    private void EscapeArgument(int slot, IOperation? instance, TaintValue receiver, Input[] inputs)
    {
        if (slot == -1)
        {
            if (instance != null) Escape(instance, receiver);
            return;
        }
        foreach (var i in inputs) if (i.Ordinal == slot && i.RefKind != RefKind.Out) Escape(i.Operation, i.Value);
    }

    /// A value given to a call whose effects are unknown escapes when its type may lead to an object (not a string or a
    /// scalar, whose labels say only where its text came from).
    private void Escape(IOperation? operation, TaintValue value)
    {
        while (operation is IConversionOperation { IsImplicit: true } c) operation = c.Operand;
        if (MemberFacts.MayHold(operation?.Type)) _body.RecordEscape(value);
    }

    /// A call (or a setter that is not an auto-property's) may change what it is given. The choice (conservative, by
    /// type): every fact of a static path ends; a ref or out argument is a write; and a fact ends when an object along
    /// its path (the root's or a member's) could be reached from the receiver or an argument: a type the value's type
    /// reaches (itself, elements, type arguments, the fields of a project's type; TypeReach) is the same type, one
    /// derived from the other, an implemented interface, or object or a type parameter (MemberFacts.MayChange). A
    /// struct receiver declared in source is written in place. Not covered: an object the callee reaches through the
    /// heap (a static, or a field typed object) without being given it or an object that holds it.
    ///
    /// Task 27: a strong update ends, at a call whose every target is a symbolic body, when one of them (with its
    /// callees) writes a member on its path into a parameter's object or through unknown objects, or when an object
    /// along it could be reached (as above, by type) from an argument whose parameter escapes to a call whose effects are
    /// unknown; at a call of external methods that keep members (KeepsMembers) none ends; at any other call as a guard's
    /// fact does. A getter ends no guard's fact (`guards` false).
    private void ForgetForCall(IOperation? instance, Input[] inputs, TaintState state, IReadOnlyList<Target>? summarised = null, bool guards = true, bool keepsMembers = false)
    {
        state.ForgetParts(p => guards && ReferenceEquals(p.Root, AccessPath.Static), p => summarised == null && !keepsMembers && ReferenceEquals(p.Root, AccessPath.Static));
        if (!state.HasFacts) return;
        List<ITypeSymbol>? types = null;
        Given(instance, true);
        foreach (var i in inputs)
        {
            if (i.RefKind is RefKind.Ref or RefKind.Out) ForgetWritten(i.Operation, state);
            else if (!ReferenceEquals(i.Operation, instance)) Given(i.Operation, false);
        }
        if (!state.HasFacts) return;
        var reaches = types?.Select(t => _ctx.TypeReach.Of(t)).ToList();
        bool ByArguments(AccessPath p) => reaches != null && p.ObjectTypes.Any(held => reaches.Any(r => MemberFacts.MayChange(r, held)));
        var bySummary = summarised == null ? null : SummaryKill(summarised, instance, inputs);
        state.ForgetParts(p => guards && ByArguments(p), p => bySummary != null ? bySummary(p) : !keepsMembers && ByArguments(p));

        void Given(IOperation? op, bool receiver)
        {
            while (op is IConversionOperation c) op = c.Operand;
            if (op == null) return;
            if (op is IArrayCreationOperation { Initializer: { } initializer })
            {
                foreach (var e in initializer.ElementValues) Given(e, false);
                return;
            }
            if (!MemberFacts.MayHold(op.Type)) return;
            // A struct of the project called in place is written; any value given (a struct or tuple by value too) may
            // lead to the objects its type reaches (fix round 1, I3).
            if (receiver && op.Type!.IsValueType && MemberFacts.IsChangeable(op.Type)) ForgetWritten(op, state);
            (types ??= new List<ITypeSymbol>()).Add(op.Type!);
        }
    }

    /// Which strong updates a call of these symbolic bodies may end (see ForgetForCall).
    private Func<AccessPath, bool> SummaryKill(IReadOnlyList<Target> targets, IOperation? instance, Input[] inputs)
    {
        var members = new HashSet<object>();
        var tops = new List<HashSet<object>>(1);
        var escaped = new List<TypeReach.Result>();
        foreach (var t in targets)
        {
            var s = t.Body!.Summary;
            foreach (var (_, (symbol, _)) in s.ObjWrites) members.Add(SymbolKeys.Of(symbol));
            if (s.TopWrites != null && !tops.Contains(s.TopWrites)) tops.Add(s.TopWrites);
            foreach (var slot in s.Escapes)
            {
                if (slot == -1) Escaped(instance);
                else foreach (var i in inputs) if (i.Ordinal == slot && i.RefKind != RefKind.Out) Escaped(i.Operation);
            }
        }
        return p =>
        {
            foreach (var m in p.Members)
            {
                var key = SymbolKeys.Of(m);
                if (members.Contains(key)) return true;
                foreach (var top in tops) if (top.Contains(key)) return true;
            }
            return escaped.Count > 0 && p.ObjectTypes.Any(held => escaped.Any(r => MemberFacts.MayChange(r, held)));
        };

        void Escaped(IOperation? op)
        {
            while (op is IConversionOperation c) op = c.Operand;
            if (op?.Type is { } type && MemberFacts.MayHold(type)) escaped.Add(_ctx.TypeReach.Of(type));
        }
    }


    /// The state keys a checked value is held in: a local, a parameter, a flow capture (and the local or parameter it
    /// captured).
    private IEnumerable<object> Keys(IOperation value)
    {
        while (value is IConversionOperation c) value = c.Operand;
        switch (value)
        {
            case ILocalReferenceOperation l:
                yield return l.Local;
                break;
            case IParameterReferenceOperation p:
                yield return p.Parameter;
                break;
            case IFlowCaptureReferenceOperation r:
                yield return r.Id;
                if (_captured.TryGetValue(r.Id, out var list) && list.Count == 1 && list[0] is not IFlowCaptureReferenceOperation)
                    foreach (var k in Keys(list[0])) yield return k;
                break;
        }
    }
}
