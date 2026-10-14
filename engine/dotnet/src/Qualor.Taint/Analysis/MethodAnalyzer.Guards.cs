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
internal sealed partial class MethodAnalyzer
{
    private Dictionary<ILocalSymbol, List<IOperation>?>? _assignments;

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
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals } equality:
                Equality(equality.LeftOperand, equality.RightOperand, (equality.OperatorKind == BinaryOperatorKind.Equals) == outcome, state, ref refined);
                break;
            case IIsPatternOperation pattern:
                Pattern(pattern.Value, pattern.Pattern, outcome, state, ref refined);
                break;
            case IInvocationOperation call:
                Call(call, outcome, state, ref refined);
                break;
            case IFlowCaptureReferenceOperation capture when _captured.TryGetValue(capture.Id, out var list) && list.Count == 1:
                Facts(list[0], outcome, state, ref refined, depth + 1);
                break;
        }
    }

    /// `left == right` holds (equal) or does not.
    private void Equality(IOperation left, IOperation right, bool equal, TaintState state, ref TaintState? refined)
    {
        if (equal)
        {
            if (IsConstant(right)) CleanAll(left, state, ref refined);
            if (IsConstant(left)) CleanAll(right, state, ref refined);
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
                if (outcome) CleanAll(value, state, ref refined);
                if (IsNull(constant.Value)) NullCheck(value, !outcome, state, ref refined);
                break;
            case IBinaryPatternOperation { OperatorKind: BinaryOperatorKind.Or } alternatives when outcome && OnlyConstants(alternatives):
                CleanAll(value, state, ref refined);
                break;
        }

        static bool OnlyConstants(IPatternOperation p) => p switch
        {
            IConstantPatternOperation => true,
            IBinaryPatternOperation { OperatorKind: BinaryOperatorKind.Or } b => OnlyConstants(b.LeftPattern) && OnlyConstants(b.RightPattern),
            _ => false,
        };
    }

    /// A call in a condition: `x.Equals(c)` and `string.Equals(x, c)`, the model's guards, the allow-lists' membership.
    private void Call(IInvocationOperation call, bool outcome, TaintState state, ref TaintState? refined)
    {
        var method = call.TargetMethod;
        if (outcome && method.Name == "Equals")
        {
            if (call.Instance != null && call.Arguments.Length >= 1) Equality(call.Instance, call.Arguments[0].Value, true, state, ref refined);
            else if (method.IsStatic && call.Arguments.Length >= 2) Equality(call.Arguments[0].Value, call.Arguments[1].Value, true, state, ref refined);
        }

        foreach (var (rule, guard) in _ctx.Sinks.Guards.Match(method, Access.Call))
        {
            if (guard.Kind != GuardKind.Result || guard.CleanWhen != outcome) continue;
            var checkedValue = guard.Arg < 0 ? ThisOperation(call) : SinkConditions.ArgumentValue(call, guard.Arg);
            if (checkedValue != null && Holds(guard, call, checkedValue, state)) Clean(checkedValue, new[] { rule }, state, ref refined);
        }

        if (outcome && _ctx.Sinks.AllowListRules.Length > 0 && method.Name is "Contains" or "ContainsKey")
        {
            var (table, value) = call.Instance != null
                ? (call.Instance, call.Arguments.Length > 0 ? call.Arguments[0].Value : null)
                : (call.Arguments.Length > 1 ? call.Arguments[0].Value : null, call.Arguments.Length > 1 ? call.Arguments[1].Value : null);
            if (value != null && _ctx.AllowLists.IsTable(table, Model()?.Compilation)) Clean(value, _ctx.Sinks.AllowListRules, state, ref refined);
        }
    }

    /// A null check of `checkedLocal`: where it is not null, the `not-null` guards of the call it was assigned clean that
    /// call's checked argument.
    private void NullCheck(IOperation checkedLocal, bool notNull, TaintState state, ref TaintState? refined)
    {
        if (!notNull) return;
        while (checkedLocal is IConversionOperation c) checkedLocal = c.Operand;
        if (checkedLocal is not ILocalReferenceOperation local || Assignments(local.Local) is not [var assigned]) return;
        if (Awaited(assigned) is not { } call) return;
        foreach (var (rule, guard) in _ctx.Sinks.Guards.Match(call.TargetMethod, Access.Call))
        {
            if (guard.Kind != GuardKind.NotNull) continue;
            if (SinkConditions.ArgumentValue(call, guard.Arg) is { } checkedValue && Holds(guard, call, checkedValue, state))
                Clean(checkedValue, new[] { rule }, state, ref refined);
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

    /// A guard's conditions (`when:`) at a call.
    private bool Holds(GuardModel guard, IInvocationOperation call, IOperation checkedValue, TaintState state)
    {
        foreach (var c in guard.When)
        {
            switch (c.Kind)
            {
                case GuardConditionKind.AssignedFrom:
                {
                    var value = checkedValue;
                    while (value is IConversionOperation conversion) value = conversion.Operand;
                    if (value is not ILocalReferenceOperation local || Assignments(local.Local) is not { Count: > 0 } all) return false;
                    if (!all.All(a => Awaited(a) is { } from && SymbolMatch.Matches(c.Member!, from.TargetMethod))) return false;
                    break;
                }
                case GuardConditionKind.ArgumentText:
                {
                    if (SinkConditions.ArgumentValue(call, c.Arg) is not { } argument) return false;
                    if (Value(argument, state.Clone()).Request) return false;
                    var text = new System.Text.StringBuilder();
                    GuardText(argument, text, 0);
                    if (!c.Pattern!.IsMatch(text.ToString())) return false;
                    break;
                }
            }
        }
        return true;
    }

    /// The text a guard's argument is built from in place: constants, both sides of a string `+`, the text and holes of an
    /// interpolated string, Path.DirectorySeparatorChar and AltDirectorySeparatorChar as '/'; any other value as Hole.
    private static void GuardText(IOperation? op, System.Text.StringBuilder text, int depth)
    {
        while (op is IConversionOperation c) op = c.Operand;
        if (op == null || depth > 32) return;
        if (op.ConstantValue is { HasValue: true, Value: string or char })
        {
            text.Append(Convert.ToString(op.ConstantValue.Value, System.Globalization.CultureInfo.InvariantCulture));
            return;
        }
        switch (op)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } b:
                GuardText(b.LeftOperand, text, depth + 1);
                GuardText(b.RightOperand, text, depth + 1);
                break;
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                {
                    if (part is IInterpolatedStringTextOperation t) GuardText(t.Text, text, depth + 1);
                    else if (part is IInterpolationOperation hole) GuardText(hole.Expression, text, depth + 1);
                }
                break;
            case IFieldReferenceOperation { Field: { Name: "DirectorySeparatorChar" or "AltDirectorySeparatorChar", ContainingType: { } type } }
                when SymbolMatch.MetadataName(type) == "System.IO.Path":
                text.Append('/');
                break;
            default:
                text.Append(Hole);
                break;
        }
    }

    /// What a local is assigned in this body (its declaration's initializer too); null when it is also written otherwise
    /// (a `ref` or `out` argument, a compound assignment, a deconstruction, an increment).
    private List<IOperation>? Assignments(ILocalSymbol local)
    {
        if (_assignments == null)
        {
            _assignments = new Dictionary<ILocalSymbol, List<IOperation>?>(SymbolEqualityComparer.Default);
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
                case ISimpleAssignmentOperation { Target: ILocalReferenceOperation l } a:
                    Add(l.Local, a.Value);
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
                    break;
            }
        }

        void Add(ILocalSymbol l, IOperation value)
        {
            if (!_assignments!.TryGetValue(l, out var list)) _assignments[l] = list = new List<IOperation>();
            list?.Add(value);
        }

        void Spoil(ILocalSymbol l) => _assignments![l] = null;
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

    /// The value is a constant on this branch: clean for every rule (its labels too).
    private void CleanAll(IOperation value, TaintState state, ref TaintState? refined)
    {
        foreach (var key in Keys(value))
        {
            refined ??= state.Clone();
            refined.Set(key, TaintValue.Clean);
        }
    }

    /// The value is clean for these rules on this branch.
    private void Clean(IOperation value, IReadOnlyCollection<string> rules, TaintState state, ref TaintState? refined)
    {
        foreach (var key in Keys(value))
        {
            var current = (refined ?? state).Get(key);
            if (!current.Any) continue;
            refined ??= state.Clone();
            refined.Set(key, current.CleanedFor(rules));
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
