using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// What every method analysis of one run shares: the models (as indexes), the findings and the counters.
internal sealed class AnalysisContext
{
    private readonly Dictionary<(string Rule, string Path, TextSpan Span), Finding> _findings = new();
    private readonly HashSet<(SyntaxTree, TextSpan)> _unmodelledSites = new();
    private readonly Dictionary<ISymbol, string> _names = new(SymbolEqualityComparer.Default);

    public AnalysisContext(ModelSet models, TaintEngineOptions options)
    {
        Options = options;
        Sources = new SourceFinder(models.Sources);
        Sinks = new SinkFinder(models.Rules);
        foreach (var p in models.Propagators) Propagators.Add(p.Member, p);
        UnmodelledPasses = models.UnmodelledExternal == "string-or-collection-return";
    }

    public TaintEngineOptions Options { get; }

    public SourceFinder Sources { get; }

    public SinkFinder Sinks { get; }

    /// The conditions of conditional sinks (`when:`), with the body facts they read.
    public SinkConditions Conditions { get; } = new();

    public MemberTable<PropagatorModel> Propagators { get; } = new();

    /// The allow-list tables (`allow-list: literal-tables`), found once per field.
    public AllowLists AllowLists { get; } = new();

    /// The `unmodelled-external` policy: an external member no propagator names passes its receiver's and arguments'
    /// taint to a string-like or collection result.
    public bool UnmodelledPasses { get; }

    public IEnumerable<Finding> Findings => _findings.Values;

    public int UnmodelledExternalCalls => _unmodelledSites.Count;

    public void CountUnmodelled(SyntaxNode site) => _unmodelledSites.Add((site.SyntaxTree, site.Span));

    /// One finding per rule and sink site (the site's syntax: an argument or an assignment); the first path is kept.
    public void Report(string rule, SyntaxNode site, TaintValue value, ISymbol member)
    {
        var key = (rule, site.SyntaxTree.FilePath ?? "", site.Span);
        if (_findings.ContainsKey(key)) return;
        var sink = site.GetLocation();
        var path = value.Path.Add(new PathStep(sink, $"reaches the {rule} sink {Name(member)}")).ToList();
        var others = value.Sources.Where(s => !s.Equals(path[0].Location)).OrderBy(s => s.SourceSpan.Start).ToList();
        _findings[key] = new Finding(rule, sink, path, others);
    }

    /// A member's short name for path messages (`SqlCommand.SqlCommand(string, SqlConnection)`), cached.
    public string Name(ISymbol member)
    {
        if (_names.TryGetValue(member, out var name)) return name;
        name = member.ToDisplayString(SymbolDisplayFormat.CSharpShortErrorMessageFormat);
        _names[member] = name;
        return name;
    }
}

/// The taint analysis of one control-flow graph (a method, accessor, initializer, lambda or local function body; spec
/// §5): a forward dataflow over its basic blocks to a fixed point, with a TaintState per block entry. Within a block the
/// operations are evaluated in order; Value() is the transfer function of an operation (side effects on the state,
/// sinks reported on the way) and returns the operation's TaintValue. The interprocedural side (Task 8) is the body's
/// SummaryComputer.BodyRun: the body's parameters carry labels, and what reaches its return value, its sinks, its
/// receiver, its ref and out parameters and the heap becomes its summary.
///
/// - Join at block entries: TaintState.JoinWith. A block that ends in a condition passes each successor the state
///   refined by what the condition says on that branch (guards, allow-lists, equality: MethodAnalyzer.Guards.cs).
/// - Exception regions: the first block of a catch, filter or finally gets the state at every point of its try region
///   (each block's entry and the state after each of its operations); the code a finally leaves to (the destinations
///   of the branches that run it) also gets the finally's exit state.
/// - Assignments through flow captures: the CFG spills the target of an assignment whose value has control flow
///   (`x = c ? a : b`, `??`, switch expressions, `?.`, `??=`) into a capture; an assignment to that capture assigns the
///   captured variable (strong for a local, a parameter, a static field or a field of `this`).
/// - `this` is the label of the receiver; a field or auto-property read is its instance's value (element-insensitive
///   objects: `this` for an own one), its state in this body (strong updates for own and static ones), and the heap's
///   request data for it (Heap: field-based, across methods and projects). A write of a source field or
///   auto-property taints its symbol only (its state here, the heap), never the object holding it; other members
///   (tuple elements, external structs) are written into their instance.
/// - Values of a scalar type (sources.yml `scalars`, enums, void) are always clean.
/// - Calls and property accessors of members declared in source: their targets (Dispatch: class hierarchy) apply their
///   summaries: the arguments are substituted for the callee's labels in its local effects (result, receiver, ref and
///   out parameters), and passed to its parameters for its global effects (request data seeds them, a label becomes a
///   call edge of its body; SummaryComputer reports the callee's sinks at their site); a member in source without a
///   body (abstract with no implementation, synthesized) passes its receiver and arguments to its result; an
///   auto-property is a heap location. Delegate invocations pass the delegate's and the arguments' taint.
/// - Calls of external (metadata-only) members: the propagators of propagators.yml (review note M2: only external
///   members), else the `unmodelled-external` default; a collection or interpolated-string-handler write
///   (`list.Add(x)`, `dict[k] = x`, `arr[i] = x`, `handler.AppendFormatted(x)`) taints the collection (engine policy,
///   not the models: open item (a) of Task 7).
/// - Lambdas and method groups given to a call get the call's receiver and other arguments in their parameters (a
///   method group: its summary applied to them); a lambda's value is what it returns.
/// - Sources: parameters (seeded at the entry), source members (sources.yml (6)) and bound properties (sources.yml (3))
///   at their reads. Sanitizers clean their result for their rule; `string-prefix:` sanitizers clean a value by the text
///   before it in a string built in place (StringValue), `lookup:` sanitizers the result of a body-less lookup.
/// - Sinks: the arguments at a sink's ordinals, and the value assigned to a property-set sink (for `+=` the joined
///   value): reported when request data reaches them; a label that reaches them is a sink of the label's body. A
///   conditional sink (`when:`) applies only where SinkConditions finds its conditions hold, possibly element by element.
internal sealed partial class MethodAnalyzer
{
    private readonly AnalysisContext _ctx;
    private readonly ControlFlowGraph _cfg;
    private readonly SummaryComputer.BodyRun _body;

    /// What each flow capture captured (a capture is assigned in several blocks for `c ? a : b`).
    private readonly Dictionary<CaptureId, List<IOperation>> _captured = new();

    /// The calls (invocations) evaluated here that had no body to analyse (for awaited `lookup:` sanitizers).
    private readonly HashSet<IOperation> _bodyless = new();

    public MethodAnalyzer(AnalysisContext ctx, ControlFlowGraph cfg, SummaryComputer.BodyRun body)
    {
        _ctx = ctx;
        _cfg = cfg;
        _body = body;
        foreach (var block in cfg.Blocks)
        {
            foreach (var operation in block.Operations) Collect(operation);
            if (block.BranchValue != null) Collect(block.BranchValue);
        }

        void Collect(IOperation root)
        {
            foreach (var capture in root.DescendantsAndSelf().OfType<IFlowCaptureOperation>())
            {
                if (!_captured.TryGetValue(capture.Id, out var list)) _captured[capture.Id] = list = new List<IOperation>(1);
                list.Add(capture.Value);
            }
        }
    }

    /// False when the fixed point hit its iteration cap (the result is then partial).
    public bool Complete { get; private set; } = true;

    /// The join of the values the body returns (`return x`, an expression body, `yield return x`).
    public TaintValue ReturnValue { get; private set; } = TaintValue.Clean;

    /// The state at the body's exit (null when the exit is unreachable).
    public TaintState? ExitState { get; private set; }

    /// Runs the dataflow from `entry`. With `collectAll`, returns the join of the states at every block entry and exit
    /// (what a lambda or local function declared here may capture); null otherwise.
    public TaintState? Run(TaintState entry, bool collectAll)
    {
        var blocks = _cfg.Blocks;
        var inStates = new TaintState?[blocks.Length];
        var outStates = collectAll ? new TaintState?[blocks.Length] : null;
        var (feeds, finallyExits) = Regions(blocks);
        var worklist = new SortedSet<int> { 0 };
        inStates[0] = entry;
        var cap = Math.Max(1000, blocks.Length * Math.Max(1, _ctx.Options.MaxIterationsPerScc));
        var visits = 0;

        while (worklist.Count > 0)
        {
            var ordinal = worklist.Min;
            worklist.Remove(ordinal);
            if (++visits > cap)
            {
                Complete = false;
                break;
            }
            var block = blocks[ordinal];
            var state = inStates[ordinal]!.Clone();
            var handlers = feeds[ordinal];
            Feed(handlers, state);
            foreach (var operation in block.Operations)
            {
                Value(operation, state);
                Feed(handlers, state);
            }
            if (block.BranchValue != null)
            {
                var value = Value(block.BranchValue, state);
                if (block.FallThroughSuccessor?.Semantics == ControlFlowBranchSemantics.Return) ReturnValue = ReturnValue.Join(value);
                Feed(handlers, state);
            }
            if (outStates != null) outStates[ordinal] = state;

            // A conditional branch is taken when the branch value equals ConditionKind; the fall-through otherwise. Each
            // successor gets the state as the condition leaves it on that branch (guards).
            var conditional = block.BranchValue != null && block.ConditionKind != ControlFlowConditionKind.None;
            var jumpOutcome = block.ConditionKind == ControlFlowConditionKind.WhenTrue;
            if (block.FallThroughSuccessor?.Destination is { } next) Flow(next.Ordinal, conditional ? Refine(block.BranchValue!, !jumpOutcome, state) : state);
            if (block.ConditionalSuccessor?.Destination is { } jump) Flow(jump.Ordinal, conditional ? Refine(block.BranchValue!, jumpOutcome, state) : state);
            if (finallyExits.TryGetValue(ordinal, out var after))
                foreach (var destination in after) Flow(destination, state);
        }
        ExitState = inStates[blocks.Length - 1];

        if (!collectAll) return null;
        var all = new TaintState();
        foreach (var s in inStates) if (s != null) all.JoinWith(s);
        foreach (var s in outStates!) if (s != null) all.JoinWith(s);
        return all;

        void Feed(List<int>? handlers, TaintState state)
        {
            if (handlers == null) return;
            foreach (var h in handlers) Flow(h, state);
        }

        void Flow(int destination, TaintState state)
        {
            if (inStates[destination] is not { } existing)
            {
                inStates[destination] = state.Clone();
                worklist.Add(destination);
            }
            else if (existing.JoinWith(state))
            {
                worklist.Add(destination);
            }
        }
    }

    /// The handler entries each block feeds (the first blocks of the catch, filter and finally regions whose try region
    /// holds it; a handler whose try region is not found is fed by every block), and, for the last block of each finally
    /// region, the destinations of the branches that leave through it.
    private static (List<int>?[] Feeds, Dictionary<int, List<int>> FinallyExits) Regions(ImmutableArray<BasicBlock> blocks)
    {
        var feeds = new List<int>?[blocks.Length];
        foreach (var h in blocks)
        {
            if (h.Kind != BasicBlockKind.Block || !h.Predecessors.IsEmpty || !h.IsReachable) continue;
            var protectedRegion = ProtectedRegion(h);
            var first = protectedRegion?.FirstBlockOrdinal ?? 0;
            var last = protectedRegion?.LastBlockOrdinal ?? blocks.Length - 1;
            for (var o = first; o <= last; o++)
                if (o != h.Ordinal) (feeds[o] ??= new List<int>()).Add(h.Ordinal);
        }
        var exits = new Dictionary<int, List<int>>();
        foreach (var b in blocks)
        {
            foreach (var branch in new[] { b.FallThroughSuccessor, b.ConditionalSuccessor })
            {
                if (branch?.Destination is not { } destination) continue;
                foreach (var f in branch.FinallyRegions)
                {
                    if (!exits.TryGetValue(f.LastBlockOrdinal, out var list)) exits[f.LastBlockOrdinal] = list = new List<int>();
                    if (!list.Contains(destination.Ordinal)) list.Add(destination.Ordinal);
                }
            }
        }
        return (feeds, exits);
    }

    /// The try region a handler entry block protects: its catch, filter or finally region's sibling Try region.
    private static ControlFlowRegion? ProtectedRegion(BasicBlock handler)
    {
        for (var r = handler.EnclosingRegion; r != null && r.FirstBlockOrdinal == handler.Ordinal; r = r.EnclosingRegion)
        {
            var owner = r.Kind switch
            {
                ControlFlowRegionKind.Catch or ControlFlowRegionKind.Finally or ControlFlowRegionKind.FilterAndHandler => r.EnclosingRegion,
                ControlFlowRegionKind.Filter => r.EnclosingRegion?.EnclosingRegion,
                _ => null,
            };
            if (owner != null) return owner.NestedRegions.FirstOrDefault(n => n.Kind == ControlFlowRegionKind.Try);
            if (r.Kind != ControlFlowRegionKind.LocalLifetime) return null;
        }
        return null;
    }

    // ---- Expressions ----

    private TaintValue Value(IOperation? operation, TaintState state)
    {
        if (operation == null) return TaintValue.Clean;
        var value = Transfer(operation, state);
        return value.Any && operation.Type is { } type && _ctx.Sources.IsScalar(type) ? TaintValue.Clean : value;
    }

    private TaintValue Transfer(IOperation operation, TaintState state)
    {
        switch (operation)
        {
            case ILiteralOperation:
            case IDefaultValueOperation:
            case ITypeOfOperation:
            case ISizeOfOperation:
            case INameOfOperation:
            case ICaughtExceptionOperation:
            case IMethodReferenceOperation:
            case IAnonymousFunctionOperation:
            case IInterpolatedStringTextOperation:
            case IInterpolatedStringHandlerArgumentPlaceholderOperation:
            case IStaticLocalInitializationSemaphoreOperation:
            case IDiscardOperation:
                return TaintValue.Clean;

            case IInstanceReferenceOperation instance:
                return instance.ReferenceKind == InstanceReferenceKind.ContainingTypeInstance ? _body.This : TaintValue.Clean;
            case IFlowAnonymousFunctionOperation lambda:
                return _body.LambdaReturn(lambda.Symbol);
            case IDelegateCreationOperation creation:
                return Value(creation.Target, state);

            case ILocalReferenceOperation local:
                return _body.Local(local.Local, state.Get(local.Local));
            case IParameterReferenceOperation parameter:
                return _body.Local(parameter.Parameter, state.Get(parameter.Parameter));
            case IFlowCaptureReferenceOperation capture:
                return state.Get(capture.Id);
            case IFieldReferenceOperation field:
                return ReadMember(field, field.Field, Value(field.Instance, state), state);

            case IFlowCaptureOperation capture:
                state.Set(capture.Id, Value(capture.Value, state));
                return TaintValue.Clean;

            case ISimpleAssignmentOperation assignment:
            {
                var value = Value(assignment.Value, state);
                Assign(assignment.Target, value, state, assignment);
                return value;
            }
            case ICompoundAssignmentOperation compound:
            {
                var current = Read(compound.Target, state);
                var value = current.Join(Value(compound.Value, state));
                if (compound.Type is { } type && _ctx.Sources.IsScalar(type)) value = TaintValue.Clean;
                Assign(compound.Target, value, state, compound);
                return value;
            }
            case ICoalesceAssignmentOperation coalesce:
            {
                // The CFG lowers `??=` into captures and a simple assignment; this is for an operation tree left whole.
                var value = Read(coalesce.Target, state).Join(Value(coalesce.Value, state));
                Assign(coalesce.Target, value, state, coalesce);
                return value;
            }
            case IDeconstructionAssignmentOperation deconstruction:
            {
                var value = Value(deconstruction.Value, state);
                Assign(deconstruction.Target, value, state, deconstruction);
                return value;
            }
            case IIncrementOrDecrementOperation increment:
                Value(increment.Target, state);
                return TaintValue.Clean;

            case IVariableDeclaratorOperation declarator:
            {
                var value = Value(declarator.Initializer?.Value, state);
                SetLocal(declarator.Symbol, Named(LocalValue(declarator.Symbol, value), declarator, declarator.Symbol.Name), state);
                return TaintValue.Clean;
            }

            case IPropertyReferenceOperation property:
                return ReadProperty(property, state);
            case IArrayElementReferenceOperation element:
            {
                var array = Value(element.ArrayReference, state);
                foreach (var index in element.Indices) Value(index, state);
                return array;
            }
            case IInvocationOperation invocation:
                return Call(invocation, invocation.TargetMethod, invocation.Instance, invocation.Arguments, state, invocation.IsVirtual);
            case IObjectCreationOperation creation:
            {
                var value = Call(creation, creation.Constructor, null, creation.Arguments, state, false);
                // The CFG lowers initializers into assignments on a flow capture; one left here is evaluated as such.
                if (creation.Initializer != null) value = value.Join(Value(creation.Initializer, state));
                return value;
            }

            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } concatenation:
                return StringValue(concatenation, state, new System.Text.StringBuilder());
            case IBinaryOperation binary:
            {
                var left = Value(binary.LeftOperand, state);
                var right = Value(binary.RightOperand, state);
                return left.Join(right);
            }
            case IUnaryOperation unary:
                return Value(unary.Operand, state);
            case IConversionOperation conversion:
            {
                // A user-defined conversion to a string is a call of its operator method: its sanitizers clean the result
                // (PathString's text). A conversion to another type (a string made into a PathString) keeps the value.
                var value = Value(conversion.Operand, state);
                return conversion.OperatorMethod is { } op && value.Any && conversion.Type?.SpecialType == SpecialType.System_String
                    ? value.CleanedFor(_ctx.Sinks.Sanitizes(op, Access.Call))
                    : value;
            }
            case IAwaitOperation await:
            {
                // An awaited `lookup:` (`awaited: true`): what a call without a body so named gives, awaited (also through
                // ConfigureAwait), is stored data for those rules.
                var value = Value(await.Operation, state);
                if (value.Any && _ctx.Sinks.HasAwaitedLookups && Awaited(await) is { } lookup && _bodyless.Contains(lookup))
                    value = value.CleanedFor(_ctx.Sinks.AwaitedLookups(lookup.TargetMethod.Name));
                return value;
            }
            case IConditionalOperation conditional:
                Value(conditional.Condition, state);
                return Value(conditional.WhenTrue, state).Join(Value(conditional.WhenFalse, state));
            case ICoalesceOperation coalesce:
                return Value(coalesce.Value, state).Join(Value(coalesce.WhenNull, state));
            case IIsPatternOperation isPattern:
                Bind(isPattern.Pattern, Value(isPattern.Value, state), state);
                return TaintValue.Clean;
            case IIsNullOperation isNull:
                Value(isNull.Operand, state);
                return TaintValue.Clean;
            case IThrowOperation thrown:
                Value(thrown.Exception, state);
                return TaintValue.Clean;

            case IInterpolatedStringOperation interpolated:
                return StringValue(interpolated, state, new System.Text.StringBuilder());
            case IInterpolatedStringHandlerCreationOperation handler:
                Value(handler.HandlerCreation, state);
                return Value(handler.Content, state);

            case IArgumentOperation argument:
                return Value(argument.Value, state);
            case IDeclarationExpressionOperation declaration:
                return Value(declaration.Expression, state);
            case IArrayCreationOperation array:
                foreach (var size in array.DimensionSizes) Value(size, state);
                return Value(array.Initializer, state);
            case IAnonymousObjectCreationOperation anonymous:
            {
                var value = TaintValue.Clean;
                foreach (var initializer in anonymous.Initializers)
                    value = value.Join(initializer is ISimpleAssignmentOperation a ? Value(a.Value, state) : Value(initializer, state));
                return value;
            }

            case IReturnOperation ret:
            {
                var value = Value(ret.ReturnedValue, state);
                // The CFG turns `return x` into a branch value; `yield return x` stays an operation.
                if (ret.Kind == OperationKind.YieldReturn) ReturnValue = ReturnValue.Join(value);
                return value;
            }

            default:
            {
                // Unmodelled operation kinds (tuples, collection expressions, spreads, ranges, `with`, dynamic and
                // invalid operations, ...): conservatively the join of their children.
                var value = TaintValue.Clean;
                foreach (var child in operation.ChildOperations) value = value.Join(Value(child, state));
                return value;
            }
        }
    }

    /// The character an earlier value stands for in the text before a value (`string-prefix:` sanitizers).
    internal const char Hole = '￼';

    /// The value of a string built in place (string `+`, an interpolated string, nested in each other), its parts in
    /// order: `prefix` collects the text before each part (constants as they are, values as Hole), and each value is
    /// cleaned for the rules whose `string-prefix:` sanitizers match the text before it. An object's text is its
    /// ToString() (ImplicitToString).
    private TaintValue StringValue(IOperation operation, TaintState state, System.Text.StringBuilder prefix)
    {
        switch (operation)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } b:
                return StringValue(b.LeftOperand, state, prefix).Join(StringValue(b.RightOperand, state, prefix));
            case IInterpolatedStringOperation interpolated:
            {
                var value = TaintValue.Clean;
                foreach (var part in interpolated.Parts)
                {
                    switch (part)
                    {
                        case IInterpolatedStringTextOperation text:
                            prefix.Append(text.Text.ConstantValue.Value as string);
                            break;
                        case IInterpolationOperation i:
                            value = value.Join(Placed(i.Expression, Value(i.Expression, state), state, prefix)).Join(Value(i.Alignment, state));
                            break;
                        // A handler's AppendLiteral(text) and AppendFormatted(x): the formatted values reach the string.
                        case IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation { TargetMethod.Name: "AppendLiteral" } literal }:
                            foreach (var a in literal.Arguments) prefix.Append(a.Value.ConstantValue.Value as string);
                            value = value.Join(JoinArguments(literal.Arguments, state));
                            break;
                        case IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation call }:
                            value = value.Join(call.Arguments.Length == 0
                                ? TaintValue.Clean
                                : Placed(call.Arguments[0].Value, JoinArguments(call.Arguments, state), state, prefix));
                            break;
                        default:
                            value = value.Join(Value(part, state));
                            break;
                    }
                }
                return value;
            }
            default:
                if (operation.ConstantValue is { HasValue: true } constant)
                {
                    prefix.Append(constant.Value as string ?? Convert.ToString(constant.Value, System.Globalization.CultureInfo.InvariantCulture));
                    return TaintValue.Clean;
                }
                return Placed(operation, Value(operation, state), state, prefix);
        }
    }

    /// A value placed into a string after `prefix`: with its ToString() text, cleaned for the rules whose
    /// `string-prefix:` sanitizers match; the prefix then gets a Hole for it.
    private TaintValue Placed(IOperation expression, TaintValue value, TaintState state, System.Text.StringBuilder prefix)
    {
        value = value.Join(ImplicitToString(expression, value, state));
        if (value.Any)
        {
            while (expression is IConversionOperation { IsImplicit: true, OperatorMethod: null, Operand: { } inner }) expression = inner;
            value = value.CleanedFor(ToStringSanitizers(expression.Type));
            if (_ctx.Sinks.HasStringSanitizers) value = value.CleanedFor(_ctx.Sinks.CleanInString(prefix.ToString(), expression.Type));
        }
        prefix.Append(Hole);
        return value;
    }

    /// The rules a value's text is clean for when an object of this type is turned into text in a string (its
    /// ToString() is called): the sanitizers of that ToString (`T.ToString` in a model; PathString's is URI-escaped).
    private IReadOnlyCollection<string> ToStringSanitizers(ITypeSymbol? type)
    {
        if (type is not INamedTypeSymbol || type.SpecialType != SpecialType.None) return Array.Empty<string>();
        for (var t = type; t != null; t = t.BaseType)
        {
            var toString = t.GetMembers("ToString").OfType<IMethodSymbol>().FirstOrDefault(m => m.Parameters.Length == 0 && !m.IsStatic);
            if (toString != null) return toString.ContainingType.SpecialType == SpecialType.None ? _ctx.Sinks.Sanitizes(toString, Access.Call) : Array.Empty<string>();
        }
        return Array.Empty<string>();
    }

    /// The text of an object used where a string is built (`$"{t}"`, `"x" + t`) is its ToString() result: for a value whose
    /// type declares a ToString override with a body, that body's summary applied to the object (Task 8 review N1). The value
    /// of the expression itself is joined by the caller.
    private TaintValue ImplicitToString(IOperation expression, TaintValue value, TaintState state)
    {
        // `"x" + t` converts t to object first: the type that matters is the operand's own.
        while (expression is IConversionOperation { IsImplicit: true, Operand: { } inner } && !SymbolEqualityComparer.Default.Equals(inner.Type, expression.Type)) expression = inner;
        var type = expression.Type;
        if (type == null || type.SpecialType != SpecialType.None || type.TypeKind is TypeKind.Enum or TypeKind.Delegate or TypeKind.Dynamic or TypeKind.Array) return TaintValue.Clean;
        if (type.SpecialType == SpecialType.System_String) return TaintValue.Clean;
        IMethodSymbol? toString = null;
        for (var t = type; t != null && toString == null; t = t.BaseType)
            toString = t.GetMembers("ToString").OfType<IMethodSymbol>().FirstOrDefault(m => m.Parameters.Length == 0 && !m.IsStatic);
        if (toString == null || toString.ContainingType.SpecialType != SpecialType.None) return TaintValue.Clean;
        var result = TaintValue.Clean;
        foreach (var target in _body.Targets(toString, true, type))
            if (target.Kind == TargetKind.Body)
                result = result.Join(Apply(target.Body!, expression, toString, slot => slot == -1 ? value : TaintValue.Clean, null, Array.Empty<Input>(), false, state));
        return result;
    }

    private TaintValue JoinArguments(ImmutableArray<IArgumentOperation> arguments, TaintState state)
    {
        var value = TaintValue.Clean;
        foreach (var a in arguments) value = value.Join(Value(a.Value, state));
        return value;
    }

    /// The value a pattern's declared variables get: the tested value (a property sub-pattern's variable too).
    private void Bind(IPatternOperation pattern, TaintValue value, TaintState state)
    {
        switch (pattern)
        {
            case IDeclarationPatternOperation { DeclaredSymbol: ILocalSymbol local }:
                SetLocal(local, LocalValue(local, value), state);
                break;
            case IRecursivePatternOperation recursive:
                if (recursive.DeclaredSymbol is ILocalSymbol r) SetLocal(r, LocalValue(r, value), state);
                foreach (var p in recursive.DeconstructionSubpatterns) Bind(p, value, state);
                foreach (var p in recursive.PropertySubpatterns) Bind(p.Pattern, value, state);
                break;
            case IListPatternOperation list:
                if (list.DeclaredSymbol is ILocalSymbol l) SetLocal(l, LocalValue(l, value), state);
                foreach (var p in list.Patterns) Bind(p, value, state);
                break;
            case ISlicePatternOperation { Pattern: { } inner }:
                Bind(inner, value, state);
                break;
            case IBinaryPatternOperation binary:
                Bind(binary.LeftPattern, value, state);
                Bind(binary.RightPattern, value, state);
                break;
            case INegatedPatternOperation negated:
                Bind(negated.Pattern, value, state);
                break;
        }
    }

    private TaintValue LocalValue(ILocalSymbol local, TaintValue value) =>
        _ctx.Sources.IsScalar(local.Type) ? TaintValue.Clean : value;

    /// A strong update of a local or parameter (a captured one is also a captured write of this body).
    private void SetLocal(ISymbol symbol, TaintValue value, TaintState state)
    {
        state.Set(symbol, value);
        _body.Assigned(symbol, value);
    }

    // ---- Fields and auto-properties ----

    /// A field of the analysed object or a static one (`this._f`, `_f`, `T._s`): tracked by its symbol in this body.
    private static bool IsOwn(IOperation? instance) =>
        instance is null or IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance };

    /// The value of a field or auto-property: its instance's (the object, element-insensitive; `this` for an own one),
    /// its state in this body, and the heap's request data for it. An own member of a type that is never request data
    /// (sources.yml `parameter-types`: an interface is a DI service, a scalar) does not take the receiver's value: a
    /// request-bound object's data members carry it, its injected services do not.
    private TaintValue ReadMember(IOperation operation, ISymbol member, TaintValue instance, TaintState state)
    {
        if (instance.Any && member is IFieldSymbol or IPropertySymbol && !member.IsStatic
            && _ctx.Sources.IsNeverSourceType(member is IFieldSymbol f ? f.Type : ((IPropertySymbol)member).Type))
            instance = TaintValue.Clean;
        var value = instance.Join(state.Get(member.OriginalDefinition));
        if (_body.IsHeapMember(member))
        {
            var heap = _body.HeapRead(member);
            if (heap.Any) value = value.Join(heap.Step(operation.Syntax.GetLocation(), $"read from {_ctx.Name(member)}"));
        }
        return value;
    }

    /// An assignment of a field or auto-property (its instance already evaluated). A heap member (a field or
    /// auto-property declared in source; spec §5 "fields and properties by symbol") is tainted by its symbol only: the
    /// heap write and, for an own one, a strong update of its state in this body; the object that holds it is not
    /// written (fix round 1 of Task 8, I1: its other members stay clean). Any other member (a tuple element, an external
    /// struct's field) is written into its instance as before (element-insensitive, Task 7 I3).
    private void AssignMember(ISymbol member, IOperation? instance, TaintValue value, TaintState state, IOperation assignment)
    {
        var named = Named(value, assignment, member.Name);
        if (_body.IsHeapMember(member))
        {
            if (IsOwn(instance)) state.Set(member.OriginalDefinition, named);
            _body.HeapWrite(member, named);
            return;
        }
        if (IsOwn(instance))
        {
            state.Set(member.OriginalDefinition, named);
            if (instance != null) _body.RecordThis(named);
        }
        else
        {
            Write(instance!, named, state);
        }
        _body.HeapWrite(member, named);
    }

    // ---- Assignments ----

    /// The current value of an assignment's target (the read half of `x += v`; M1: a property's get patterns).
    private TaintValue Read(IOperation target, TaintState state) => target switch
    {
        IPropertyReferenceOperation property => ReadProperty(property, state),
        _ => Value(target, state),
    };

    private void Assign(IOperation target, TaintValue value, TaintState state, IOperation assignment)
    {
        switch (target)
        {
            case ILocalReferenceOperation local:
                SetLocal(local.Local, Named(value, assignment, local.Local.Name), state);
                break;
            case IParameterReferenceOperation parameter:
                SetLocal(parameter.Parameter, Named(value, assignment, parameter.Parameter.Name), state);
                break;
            case IFlowCaptureReferenceOperation capture:
            {
                state.Set(capture.Id, value);
                // An lvalue capture: the CFG spilled the assignment's target; assign the variable itself.
                if (!_captured.TryGetValue(capture.Id, out var targets)) break;
                if (targets.Count == 1)
                {
                    if (IsVariable(targets[0])) Assign(targets[0], value, state, assignment);
                }
                else
                {
                    foreach (var t in targets) if (IsVariable(t)) Write(t, value, state);
                }
                break;
            }
            case IFieldReferenceOperation field:
                Value(field.Instance, state);
                AssignMember(field.Field, field.Instance, value, state, assignment);
                break;
            case IPropertyReferenceOperation property:
                AssignProperty(property, value, state, assignment);
                break;
            case IArrayElementReferenceOperation element:
                foreach (var index in element.Indices) Value(index, state);
                Write(element.ArrayReference, value, state);
                break;
            case IDeclarationExpressionOperation declaration:
                Assign(declaration.Expression, value, state, assignment);
                break;
            case ITupleOperation tuple:
                // Deconstruction: element-insensitive, every target gets the value.
                foreach (var element in tuple.Elements) Assign(element, value, state, assignment);
                break;
            case IConversionOperation conversion:
                Assign(conversion.Operand, value, state, assignment);
                break;
            default:
                Value(target, state);
                break;
        }
    }

    private static bool IsVariable(IOperation operation) => operation is ILocalReferenceOperation or IParameterReferenceOperation
        or IFieldReferenceOperation or IFlowCaptureReferenceOperation or IPropertyReferenceOperation or IArrayElementReferenceOperation;

    private TaintValue Named(TaintValue value, IOperation assignment, string name) =>
        value.Any ? value.Step(assignment.Syntax.GetLocation(), $"assigned to '{name}'") : value;

    /// A weak write into what `operation` refers to (a collection, a builder, a tuple or object in a variable): the
    /// variable that holds it, a flow capture and what it captured, a field or auto-property (its state, its instance,
    /// the heap), the receiver (`this`), or the receiver of a fluent call that returns its receiver (a propagator to
    /// both `this` and `return`: `sb.Append(a).Append(b)`).
    private void Write(IOperation operation, TaintValue value, TaintState state)
    {
        if (!value.Any) return;
        switch (operation)
        {
            case ILocalReferenceOperation l:
                state.Add(l.Local, value);
                _body.Assigned(l.Local, state.Get(l.Local));
                break;
            case IParameterReferenceOperation p:
                state.Add(p.Parameter, value);
                _body.Assigned(p.Parameter, state.Get(p.Parameter));
                break;
            case IFieldReferenceOperation f:
                WriteMember(f.Field, f.Instance, value, state);
                break;
            case IPropertyReferenceOperation p when _body.IsHeapMember(p.Property):
                WriteMember(p.Property, p.Instance, value, state);
                break;
            case IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }:
                _body.RecordThis(value);
                break;
            case IFlowCaptureReferenceOperation c:
                state.Add(c.Id, value);
                if (_captured.TryGetValue(c.Id, out var captured))
                    foreach (var t in captured) Write(t, value, state);
                break;
            case IConversionOperation conversion:
                Write(conversion.Operand, value, state);
                break;
            case IInvocationOperation invocation when IsFluent(invocation.TargetMethod) && ThisOperation(invocation) is { } receiver:
                Write(receiver, value, state);
                break;
        }
    }

    /// A weak write (a collection write) into a field or auto-property: a heap member is tainted by its symbol only
    /// (`_db.Orders.Add(o)` taints Orders, not `_db`); any other member is written into its instance.
    private void WriteMember(ISymbol member, IOperation? instance, TaintValue value, TaintState state)
    {
        if (_body.IsHeapMember(member))
        {
            if (IsOwn(instance)) state.Add(member.OriginalDefinition, value);
            _body.HeapWrite(member, value);
            return;
        }
        if (IsOwn(instance))
        {
            state.Add(member.OriginalDefinition, value);
            if (instance != null) _body.RecordThis(value);
        }
        else
        {
            Write(instance!, value, state);
        }
        _body.HeapWrite(member, value);
    }

    /// What a callee writes into its receiver (its ToThis) reaches the variable that holds the receiver in this body: a
    /// local, a parameter, a capture, `this`; for a field or auto-property only its state in this body, never the heap
    /// (I1: a service in a field does not become request data for every method that reads the field).
    private void WriteReceiver(IOperation receiver, TaintValue value, TaintState state)
    {
        switch (receiver)
        {
            case IConversionOperation conversion:
                WriteReceiver(conversion.Operand, value, state);
                break;
            case IFieldReferenceOperation f when IsOwn(f.Instance):
                state.Add(f.Field.OriginalDefinition, value);
                break;
            case IPropertyReferenceOperation p when IsOwn(p.Instance) && _body.IsHeapMember(p.Property):
                state.Add(p.Property.OriginalDefinition, value);
                break;
            case IFieldReferenceOperation or IPropertyReferenceOperation:
                break;
            default:
                Write(receiver, value, state);
                break;
        }
    }

    private bool IsFluent(IMethodSymbol method)
    {
        if (SymbolKeys.InSource(method)) return false;
        foreach (var p in _ctx.Propagators.Match(method, Access.Call))
            if (p.To.Contains("this") && p.To.Contains("return")) return true;
        return false;
    }

    private static IOperation? ThisOperation(IInvocationOperation invocation) =>
        invocation.Instance ?? (invocation.TargetMethod.IsExtensionMethod && invocation.Arguments.Length > 0 ? invocation.Arguments[0].Value : null);

    // ---- Sinks ----

    /// A value reaches a sink: its request data is a finding, each label tainted for the rule a sink of its body.
    private void SinkReached(string rule, SyntaxNode site, TaintValue value, ISymbol member)
    {
        if (value.TaintedFor(rule)) _ctx.Report(rule, site, value, member);
        foreach (var label in value.Labels)
            if (label.TaintedFor(rule)) _body.RecordSink(label, rule, site, member);
    }

    /// The semantic model of the body's original operation tree (a lambda's or local function's graph: its enclosing
    /// graph's).
    private SemanticModel? Model()
    {
        for (var g = _cfg; g != null; g = g.Parent)
            if (g.OriginalOperation.SemanticModel is { } model) return model;
        return null;
    }

    /// A sink argument reached by a tainted value: a plain sink reports it; a conditional one (`when:`) only where its
    /// conditions hold, either as a whole or element by element (the elements after a switch of a vector written in
    /// place, evaluated in this state from the original operation tree).
    private void ConditionalSink(SinkHit hit, IOperation operation, Input input, IMethodSymbol method, TaintState state)
    {
        if (hit.Sink.When.Count == 0)
        {
            SinkReached(hit.RuleId, input.Site, input.Value, method);
            return;
        }
        var decision = _ctx.Conditions.Check(hit.Sink, operation, input.Ordinal, Model());
        if (!decision.Holds) return;
        if (decision.Elements == null)
        {
            SinkReached(hit.RuleId, input.Site, input.Value, method);
            return;
        }
        foreach (var element in decision.Elements)
        {
            var value = Value(element, state);
            if (value.Any) SinkReached(hit.RuleId, element.Syntax, value, method);
        }
    }

    // ---- Properties ----

    private TaintValue ReadProperty(IPropertyReferenceOperation operation, TaintState state)
    {
        var property = operation.Property;
        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(property, Access.Get) != null)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(property)}");
        if (_ctx.Sources.IsBoundProperty(property))
            result = result.Join(TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: bound property {_ctx.Name(property)}"));

        var receiver = Value(operation.Instance, state);
        var isVirtual = Dispatch.IsVirtualAccess(property, operation.Instance);
        if (SymbolKeys.InSource(property) && !isVirtual && _body.IsHeapMember(property))
        {
            foreach (var a in operation.Arguments) Value(a.Value, state);
            result = result.Join(ReadMember(operation, property, receiver, state));
        }
        else if (SymbolKeys.InSource(property) && property.GetMethod is { } getter)
        {
            var inputs = IndexInputs(operation, state, null);
            foreach (var target in _body.Targets(getter, isVirtual, operation.Instance?.Type))
            {
                result = result.Join(target.Kind switch
                {
                    TargetKind.Body => Apply(target.Body!, operation, property, Arguments(receiver, inputs), operation.Instance, inputs, false, state),
                    TargetKind.Auto => ReadMember(operation, target.Method.AssociatedSymbol!, receiver, state),
                    TargetKind.External => ExternalRead((IPropertySymbol?)target.Method.AssociatedSymbol ?? property, operation, receiver, inputs),
                    _ => Through(operation, property, receiver.Join(JoinInputs(inputs))),
                });
            }
        }
        else
        {
            result = result.Join(ExternalRead(property, operation, receiver, IndexInputs(operation, state, null)));
        }
        // An element of an allow-list table is one of its constants (`allow-list: literal-tables`).
        if (property.IsIndexer && result.Any && _ctx.Sinks.AllowListRules.Length > 0 && _ctx.AllowLists.IsTable(operation.Instance, Model()?.Compilation))
            result = result.CleanedFor(_ctx.Sinks.AllowListRules);
        return result.CleanedFor(_ctx.Sinks.Sanitizes(property, Access.Get));
    }

    /// A read of an external property: its `Get` propagators (from this, args or an index ordinal), else the
    /// `unmodelled-external` default for a string-like or collection type.
    private TaintValue ExternalRead(IPropertySymbol property, IPropertyReferenceOperation operation, TaintValue receiver, Input[] index)
    {
        var result = TaintValue.Clean;
        var propagators = _ctx.Propagators.Match(property, Access.Get);
        if (propagators.Length > 0)
        {
            foreach (var p in propagators)
            {
                if (!p.To.Contains("return")) continue;
                foreach (var f in p.From)
                {
                    if (f == "this") result = result.Join(receiver);
                    else foreach (var i in index) if (f == "args" || IsOrdinal(f, i.Ordinal)) result = result.Join(i.Value);
                }
            }
        }
        else if (_ctx.UnmodelledPasses && _ctx.Sources.IsStringOrCollection(property.Type))
        {
            _ctx.CountUnmodelled(operation.Syntax);
            result = receiver.Join(JoinInputs(index));
        }
        return result;
    }

    /// The index arguments of a property access as inputs (by the property parameter's ordinal), plus the assigned
    /// value as the setter's last parameter when `value` is given.
    private Input[] IndexInputs(IPropertyReferenceOperation operation, TaintState state, (TaintValue Value, IOperation Site)? assigned)
    {
        var count = operation.Arguments.Length + (assigned == null ? 0 : 1);
        if (count == 0) return Array.Empty<Input>();
        var inputs = new Input[count];
        var n = 0;
        foreach (var a in operation.Arguments)
            inputs[n++] = new Input(a.Parameter?.Ordinal ?? -2, a.Parameter, a.Value, a.Syntax, Value(a.Value, state), RefKind.None);
        if (assigned is { } v) inputs[n] = new Input(operation.Property.Parameters.Length, null, v.Site, v.Site.Syntax, v.Value, RefKind.None);
        return inputs;
    }

    private void AssignProperty(IPropertyReferenceOperation operation, TaintValue value, TaintState state, IOperation assignment)
    {
        var property = operation.Property;
        var receiver = Value(operation.Instance, state);
        var inputs = IndexInputs(operation, state, (value, assignment));
        foreach (var hit in _ctx.Sinks.Sinks(property, Access.Set))
            if (value.Any && (hit.Sink.When.Count == 0 || _ctx.Conditions.Check(hit.Sink, assignment, -1, Model()).Holds))
                SinkReached(hit.RuleId, assignment.Syntax, value, property);

        if (SymbolKeys.InSource(property))
        {
            var isVirtual = Dispatch.IsVirtualAccess(property, operation.Instance);
            if (property.SetMethod is not { } setter || (!isVirtual && _body.IsHeapMember(property)))
            {
                // A get-only auto-property assigned in a constructor has no setter: its hidden field is written.
                if (_body.IsHeapMember(property)) AssignMember(property, operation.Instance, value, state, assignment);
                else if (operation.Instance != null) Write(operation.Instance, value, state);
                return;
            }
            foreach (var target in _body.Targets(setter, isVirtual, operation.Instance?.Type))
            {
                switch (target.Kind)
                {
                    case TargetKind.Body:
                        Apply(target.Body!, assignment, property, Arguments(receiver, inputs), operation.Instance, inputs, false, state);
                        break;
                    case TargetKind.Auto:
                        AssignMember(target.Method.AssociatedSymbol!, operation.Instance, value, state, assignment);
                        break;
                    default:
                        if (operation.Instance != null) Write(operation.Instance, value, state);
                        break;
                }
            }
        }
        else if (property.IsIndexer && operation.Instance != null)
        {
            // An indexer write is a collection write (`dict[k] = v`).
            Write(operation.Instance, value, state);
        }
    }

    // ---- Calls ----

    /// One argument of a call, by the ordinal of its parameter in the member's definition (an extension method's `this`
    /// is 0, also when the call names the reduced form); Site is the syntax a sink finding is reported at.
    private readonly record struct Input(int Ordinal, IParameterSymbol? Parameter, IOperation Operation, SyntaxNode Site, TaintValue Value, RefKind RefKind);

    private static TaintValue JoinInputs(Input[] inputs)
    {
        var value = TaintValue.Clean;
        foreach (var i in inputs) if (i.RefKind != RefKind.Out) value = value.Join(i.Value);
        return value;
    }

    /// The argument values of a callee's parameter slots (−1: the receiver; several inputs of one ordinal: a params array).
    private static Func<int, TaintValue> Arguments(TaintValue receiver, Input[] inputs) => slot =>
    {
        if (slot == -1) return receiver;
        var value = TaintValue.Clean;
        foreach (var i in inputs) if (i.Ordinal == slot && i.RefKind != RefKind.Out) value = value.Join(i.Value);
        return value;
    };

    /// What passes through a member that has no body to analyse: its receiver and arguments, to its result.
    private TaintValue Through(IOperation site, ISymbol member, TaintValue inputs) =>
        inputs.Any ? inputs.Step(site.Syntax.GetLocation(), $"passed to {_ctx.Name(member)}") : inputs;

    private TaintValue Call(IOperation operation, IMethodSymbol? method, IOperation? instance, ImmutableArray<IArgumentOperation> arguments, TaintState state, bool isVirtual)
    {
        var definition = method == null ? null : (IMethodSymbol)SymbolKeys.Definition(method);
        var reduced = method?.ReducedFrom != null;
        var receiver = TaintValue.Clean;
        var instanceValue = TaintValue.Clean;
        IOperation? thisOperation = null;
        var inputs = new Input[arguments.Length + (reduced && instance != null ? 1 : 0)];
        var n = 0;
        if (instance != null)
        {
            var value = Value(instance, state);
            if (reduced && definition!.Parameters.Length > 0)
                inputs[n++] = new Input(0, definition.Parameters[0], instance, instance.Syntax, value, RefKind.None);
            else
                instanceValue = value;
            receiver = value;
            thisOperation = instance;
        }
        foreach (var a in arguments)
        {
            var refKind = a.Parameter?.RefKind ?? RefKind.None;
            var value = refKind == RefKind.Out ? TaintValue.Clean : Value(a.Value, state);
            var ordinal = (a.Parameter?.Ordinal ?? -2) + (reduced ? 1 : 0);
            var parameter = definition != null && ordinal >= 0 && ordinal < definition.Parameters.Length ? definition.Parameters[ordinal] : null;
            inputs[n++] = new Input(ordinal, parameter, a.Value, a.IsImplicit ? a.Value.Syntax : a.Syntax, value, refKind);
        }
        if (n < inputs.Length) Array.Resize(ref inputs, n);
        if (_ctx.Sinks.HasStringSanitizers && method is { Name: "Format", ContainingType.SpecialType: SpecialType.System_String }) FormatPlaced(inputs);
        HigherOrder(inputs, instanceValue, state);

        var all = JoinInputs(inputs);
        if (method == null || definition == null) return all;
        if (instance != null && !reduced) all = all.Join(receiver);
        if (instance == null && method.IsExtensionMethod && inputs.Length > 0)
        {
            receiver = inputs[0].Value;
            thisOperation = inputs[0].Operation;
        }

        // Sinks.
        foreach (var hit in _ctx.Sinks.Sinks(method, Access.Call))
            foreach (var i in inputs)
                if (i.Parameter != null && i.Value.Any && SinkFinder.IsSinkArgument(hit.Sink, i.Parameter))
                    ConditionalSink(hit, operation, i, method, state);

        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(method, Access.Call) != null)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(method)}");

        // Out arguments are overwritten by the call.
        foreach (var i in inputs) if (i.RefKind == RefKind.Out) Assign(i.Operation, TaintValue.Clean, state, i.Operation);

        if (method.MethodKind == MethodKind.DelegateInvoke)
        {
            // The delegate's value (what its lambdas return) and the arguments reach the result.
            var through = Through(operation, method, all);
            result = result.Join(through);
            foreach (var i in inputs)
                if (i.RefKind is RefKind.Out or RefKind.Ref) Assign(i.Operation, through, state, i.Operation);
        }
        else
        {
            var constructor = method.MethodKind == MethodKind.Constructor;
            var anyBody = false;
            foreach (var target in _body.Targets(method, isVirtual, instance?.Type))
            {
                switch (target.Kind)
                {
                    case TargetKind.Body:
                        anyBody = true;
                        result = result.Join(Apply(target.Body!, operation, method, Arguments(instanceValue, inputs), reduced ? null : instance, inputs, constructor, state));
                        break;
                    case TargetKind.External:
                        result = External(target.Method, operation, inputs, receiver, thisOperation, reduced && instance != null, all, result, state);
                        break;
                    default:
                    {
                        var through = Through(operation, method, all);
                        result = result.Join(through);
                        foreach (var i in inputs)
                            if (i.RefKind is RefKind.Out or RefKind.Ref) Assign(i.Operation, through, state, i.Operation);
                        break;
                    }
                }
            }
            // `lookup:` sanitizers: what a method the engine cannot see into returns under a lookup's name (a record
            // found by an id) is stored data for those rules; a method with a body is followed instead.
            if (!anyBody && result.Any && method.MethodKind == MethodKind.Ordinary) result = result.CleanedFor(_ctx.Sinks.Lookups(method.Name));
            if (!anyBody && method.MethodKind == MethodKind.Ordinary && _ctx.Sinks.HasAwaitedLookups) _bodyless.Add(operation);
        }

        if (_ctx.Sinks.AllowListRules.Length > 0 && method.Name is "GetValueOrDefault" or "TryGetValue" && thisOperation != null
            && _ctx.AllowLists.IsTable(thisOperation, Model()?.Compilation))
            result = TableLookup(method, inputs, result, state);

        result = result.CleanedFor(_ctx.Sinks.Sanitizes(method, Access.Call));
        if (result.Any)
        {
            result = result.CleanedFor(_ctx.Sinks.SanitizesByName(method));
            var receiverOperation = instance;
            while (receiverOperation is IConversionOperation { Operand: { } inner }) receiverOperation = inner;
            result = result.CleanedFor(_ctx.Sinks.SanitizesOnReceiver(method, receiverOperation?.Type));
        }
        return result;
    }

    /// A lookup in an allow-list table: GetValueOrDefault gives one of its constants or the default value given (the
    /// default's own value); TryGetValue's out value is one of its constants.
    private TaintValue TableLookup(IMethodSymbol method, Input[] inputs, TaintValue result, TaintState state)
    {
        var rules = _ctx.Sinks.AllowListRules;
        if (method.Name == "TryGetValue")
        {
            foreach (var i in inputs)
                if (i.RefKind == RefKind.Out && Value(i.Operation, state) is { Any: true } v) Assign(i.Operation, v.CleanedFor(rules), state, i.Operation);
            return result;
        }
        var fallback = TaintValue.Clean;
        foreach (var i in inputs)
            if (i.Parameter?.Name == "defaultValue") fallback = fallback.Join(i.Value);
        return result.CleanedFor(rules).Join(fallback);
    }

    /// string.Format with a constant format: each of arg0, arg1 and arg2 is cleaned as a value placed after the format's
    /// text before its first placeholder (earlier placeholders read as Hole). A params array is left as it is.
    private void FormatPlaced(Input[] inputs)
    {
        string? format = null;
        foreach (var i in inputs)
            if (i.Parameter?.Name == "format" && i.Operation.ConstantValue is { HasValue: true, Value: string f }) format = f;
        if (format == null) return;
        for (var k = 0; k < inputs.Length; k++)
        {
            var i = inputs[k];
            if (!i.Value.Any || i.Parameter?.Name is not ("arg0" or "arg1" or "arg2")) continue;
            if (FormatPrefix(format, i.Parameter.Name[3] - '0') is not { } prefix) continue;
            var expression = i.Operation;
            while (expression is IConversionOperation { IsImplicit: true, Operand: { } inner }) expression = inner;
            inputs[k] = i with { Value = i.Value.CleanedFor(_ctx.Sinks.CleanInString(prefix, expression.Type)) };
        }
    }

    /// The text of a composite format before its first placeholder `{index}` (escaped braces unescaped, other
    /// placeholders as Hole), or null when it has none.
    internal static string? FormatPrefix(string format, int index)
    {
        var text = new System.Text.StringBuilder();
        for (var p = 0; p < format.Length; p++)
        {
            var c = format[p];
            if ((c == '{' || c == '}') && p + 1 < format.Length && format[p + 1] == c)
            {
                text.Append(c);
                p++;
                continue;
            }
            if (c != '{')
            {
                text.Append(c);
                continue;
            }
            var end = format.IndexOf('}', p);
            if (end < 0) return null;
            var spec = format[(p + 1)..end];
            var digits = new string(spec.TakeWhile(char.IsDigit).ToArray());
            if (digits.Length > 0 && int.Parse(digits, System.Globalization.CultureInfo.InvariantCulture) == index) return text.ToString();
            text.Append(Hole);
            p = end;
        }
        return null;
    }

    /// Applies a callee's summary at a call or accessor site. Its global effects (sinks, heap writes, its own calls)
    /// are not copied: each argument is passed to the callee's parameter (request data as a seed of that parameter,
    /// SummaryComputer.Seed; a label as a call edge of the label's body). Its local effects are substituted: the result
    /// (the callee's return value, a constructor's object), what it writes into its receiver, its ref and out
    /// parameters.
    private TaintValue Apply(Body callee, IOperation site, ISymbol member, Func<int, TaintValue> argument, IOperation? receiverOperation,
        Input[] inputs, bool constructor, TaintState state)
    {
        _body.Depend(callee);
        Location? location = null;
        var name = _ctx.Name(callee.Symbol ?? member);
        if (callee.Symbol is { } symbol)
        {
            for (var slot = symbol.IsStatic || constructor ? 0 : -1; slot < symbol.Parameters.Length; slot++)
            {
                if (slot >= 0 && symbol.Parameters[slot].RefKind == RefKind.Out) continue;
                var v = argument(slot);
                if (!v.Any) continue;
                location ??= site.Syntax.GetLocation();
                _body.Pass(callee, slot, v.Step(location, $"passed to {name}"));
            }
        }
        var s = callee.Summary;
        if (s.NoLocalEffects) return TaintValue.Clean;
        location ??= site.Syntax.GetLocation();
        var result = BodySummary.Substitute(s.Return, callee.Id, argument, location, name, _body.Keeps);
        if (s.ToThis.Any)
        {
            var written = BodySummary.Substitute(s.ToThis, callee.Id, argument, location, name, _body.Keeps);
            if (constructor) result = result.Join(written);
            else if (receiverOperation != null) WriteReceiver(receiverOperation, written, state);
        }
        foreach (var (ordinal, symbolic) in s.Refs)
        {
            var v = BodySummary.Substitute(symbolic, callee.Id, argument, location, name, _body.Keeps);
            foreach (var i in inputs)
                if (i.Ordinal == ordinal && i.RefKind is RefKind.Ref or RefKind.Out) Assign(i.Operation, v, state, i.Operation);
        }
        return result;
    }

    /// Lambdas and method groups given to a call get the join of the call's receiver and other arguments in their
    /// parameters (open item (b) of Task 7, for external and source callees alike): a lambda through its seed, a method
    /// group by applying its targets' summaries to it (that result is then the argument's value).
    private void HigherOrder(Input[] inputs, TaintValue receiver, TaintState state)
    {
        var any = false;
        foreach (var i in inputs) if (DelegateOf(i.Operation) != null) any = true;
        if (!any) return;
        var others = receiver;
        foreach (var i in inputs)
            if (i.RefKind != RefKind.Out && DelegateOf(i.Operation) == null) others = others.Join(i.Value);
        for (var k = 0; k < inputs.Length; k++)
        {
            switch (DelegateOf(inputs[k].Operation))
            {
                case IFlowAnonymousFunctionOperation lambda:
                    _body.Seed(lambda.Symbol, others);
                    break;
                case IMethodReferenceOperation reference when others.Any:
                {
                    var instance = Value(reference.Instance, state);
                    var value = TaintValue.Clean;
                    foreach (var target in _body.Targets(reference.Method, reference.IsVirtual, reference.Instance?.Type))
                    {
                        value = value.Join(target.Kind == TargetKind.Body
                            ? Apply(target.Body!, inputs[k].Operation, reference.Method, slot => slot == -1 ? instance : others, reference.Instance, Array.Empty<Input>(), false, state)
                            : _ctx.Sources.IsScalar(reference.Method.ReturnType) ? TaintValue.Clean : others);
                    }
                    inputs[k] = inputs[k] with { Value = inputs[k].Value.Join(value) };
                    break;
                }
            }
        }
    }

    /// The lambda or method group an argument is (through conversions, delegate creations and a single capture).
    private IOperation? DelegateOf(IOperation operation)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            switch (operation)
            {
                case IConversionOperation c:
                    operation = c.Operand;
                    continue;
                case IDelegateCreationOperation d:
                    operation = d.Target;
                    continue;
                case IFlowCaptureReferenceOperation r when _captured.TryGetValue(r.Id, out var list) && list.Count == 1:
                    operation = list[0];
                    continue;
                case IFlowAnonymousFunctionOperation or IMethodReferenceOperation:
                    return operation;
                default:
                    return null;
            }
        }
        return null;
    }

    /// An external call (review note M2: propagators only here): its propagators, else the `unmodelled-external`
    /// default; a collection or interpolated-string-handler write taints the receiver.
    private TaintValue External(IMethodSymbol method, IOperation operation, Input[] inputs, TaintValue receiver, IOperation? thisOperation,
        bool reducedThis, TaintValue all, TaintValue result, TaintState state)
    {
        var propagators = _ctx.Propagators.Match(method, Access.Call);
        if (propagators.Length > 0)
        {
            foreach (var p in propagators) result = Propagate(p, operation, method, inputs, receiver, thisOperation, reducedThis, result, state);
        }
        else
        {
            var resultType = method.MethodKind == MethodKind.Constructor ? method.ContainingType : method.ReturnType;
            if (_ctx.UnmodelledPasses && resultType != null && _ctx.Sources.IsStringOrCollection(resultType))
            {
                _ctx.CountUnmodelled(operation.Syntax);
                result = result.Join(all);
            }
        }

        // Collection and interpolated-string-handler writes taint their receiver.
        if (thisOperation != null && all.Any && IsCollectionWrite(method))
        {
            var written = TaintValue.Clean;
            foreach (var i in inputs)
                if (i.RefKind != RefKind.Out && !ReferenceEquals(i.Operation, thisOperation)) written = written.Join(i.Value);
            Write(thisOperation, written, state);
        }
        return result;
    }

    /// One propagator of an external call: the join of its `from` positions reaches its `to` positions.
    private TaintValue Propagate(
        PropagatorModel p, IOperation operation, IMethodSymbol method, Input[] inputs, TaintValue receiver, IOperation? thisOperation,
        bool reducedThis, TaintValue result, TaintState state)
    {
        var from = TaintValue.Clean;
        foreach (var f in p.From)
        {
            if (f == "this")
            {
                from = from.Join(receiver);
                continue;
            }
            foreach (var i in inputs)
            {
                if (f == "args" ? i.RefKind != RefKind.Out && !(reducedThis && i.Ordinal == 0) : IsOrdinal(f, i.Ordinal))
                    from = from.Join(i.Value);
            }
        }
        if (!from.Any) return result;
        from = from.Step(operation.Syntax.GetLocation(), $"passed through {_ctx.Name(method)}");
        foreach (var t in p.To)
        {
            switch (t)
            {
                case "return":
                    result = result.Join(from);
                    break;
                case "this":
                    if (thisOperation != null) Write(thisOperation, from, state);
                    break;
                case "out":
                    foreach (var i in inputs)
                    {
                        if (i.RefKind == RefKind.Out) Assign(i.Operation, from, state, i.Operation);
                        else if (i.RefKind == RefKind.Ref) Write(i.Operation, from, state);
                    }
                    break;
                default:
                    foreach (var i in inputs)
                        if (IsOrdinal(t, i.Ordinal)) Write(i.Operation, from, state);
                    break;
            }
        }
        return result;
    }

    /// A propagator position (`from`/`to`) that is this parameter ordinal.
    private static bool IsOrdinal(string position, int ordinal) =>
        int.TryParse(position, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) && n == ordinal;

    private static readonly string[] CollectionWriteNames =
    {
        "Add", "AddRange", "Insert", "InsertRange", "Push", "Enqueue", "TryAdd", "AddOrUpdate", "GetOrAdd", "UnionWith",
        "SymmetricExceptWith",
    };

    private static readonly string[] HandlerWriteNames = { "AppendLiteral", "AppendFormatted" };

    /// A method that stores its arguments in its receiver: one of CollectionWriteNames on a collection (a type that
    /// implements IEnumerable, string aside), or an Append of an interpolated string handler.
    private static bool IsCollectionWrite(IMethodSymbol method)
    {
        var type = method.IsExtensionMethod ? (method.ReducedFrom ?? method).Parameters.FirstOrDefault()?.Type : method.ContainingType;
        if (type == null || type.SpecialType == SpecialType.System_String) return false;
        if (Array.IndexOf(HandlerWriteNames, method.Name) >= 0)
            return type.GetAttributes().Any(a => a.AttributeClass?.Name == "InterpolatedStringHandlerAttribute");
        return Array.IndexOf(CollectionWriteNames, method.Name) >= 0
            && (type.SpecialType == SpecialType.System_Collections_IEnumerable
                || type.AllInterfaces.Any(i => i.SpecialType == SpecialType.System_Collections_IEnumerable));
    }
}

/// The key comparer of the state's holders: symbols by SymbolEqualityComparer.Default, CaptureIds (and anything else)
/// by value.
internal static class SymbolOrCapture
{
    public static readonly IEqualityComparer<object> Comparer = new KeyComparer();

    private sealed class KeyComparer : IEqualityComparer<object>
    {
        public new bool Equals(object? x, object? y) =>
            x is ISymbol sx && y is ISymbol sy ? SymbolEqualityComparer.Default.Equals(sx, sy) : object.Equals(x, y);

        public int GetHashCode(object obj) => obj is ISymbol s ? SymbolEqualityComparer.Default.GetHashCode(s) : obj.GetHashCode();
    }
}
