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

    public MemberTable<PropagatorModel> Propagators { get; } = new();

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
        var path = value.Path.Add(new PathStep(sink, $"reaches the {rule} sink {Name(member)}"));
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

/// The intraprocedural taint analysis of one control-flow graph (a method, accessor, initializer, lambda or local
/// function body; spec §5): a forward dataflow over its basic blocks to a fixed point, with a TaintState per block
/// entry. Within a block the operations are evaluated in order; Value() is the transfer function of an operation
/// (side effects on the state, sinks reported on the way) and returns the operation's TaintValue.
///
/// - Join at block entries: TaintState.JoinWith. Branches are not yet told apart (guards: Task 11).
/// - Exception regions: the first block of a catch, filter or finally gets the state at every point of its try region
///   (each block's entry and the state after each of its operations); the code a finally leaves to (the destinations
///   of the branches that run it) also gets the finally's exit state.
/// - Assignments through flow captures: the CFG spills the target of an assignment whose value has control flow
///   (`x = c ? a : b`, `??`, switch expressions, `?.`, `??=`) into a capture; an assignment to that capture assigns the
///   captured variable (strong for a local, a parameter, a static field or a field of `this`).
/// - Fields: of `this` or static, by symbol within this body (the heap across methods is Task 8); of another instance (a
///   tuple element, a struct or object in a variable) the instance's value, element-insensitive, and a write into it.
/// - Values of a scalar type (sources.yml `scalars`, enums, void) are always clean.
/// - Calls of members declared in source and delegate invocations: TEMPORARY (Task 7, until Task 8's summaries) the
///   result is the join of the receiver's and the arguments' taint (InSourceResult, the one hook to replace), also
///   written to out and ref arguments; properties declared in source likewise return their object's taint.
/// - Calls of external (metadata-only) members: the propagators of propagators.yml (review note M2: only external
///   members), else the `unmodelled-external` default; a collection or interpolated-string-handler write
///   (`list.Add(x)`, `dict[k] = x`, `arr[i] = x`, `handler.AppendFormatted(x)`) taints the collection.
/// - Sources: parameters (seeded at the entry by the engine), source members (sources.yml (6)) and bound properties
///   (sources.yml (3)) at their reads. Sanitizers clean their result for their rule.
/// - Sinks: the arguments at a sink's ordinals, and the value assigned to a property-set sink (for `+=` the joined
///   value), reported when tainted for the sink's rule at the argument's (or assignment's) location.
internal sealed class MethodAnalyzer
{
    private readonly AnalysisContext _ctx;
    private readonly ControlFlowGraph _cfg;

    /// What each flow capture captured (a capture is assigned in several blocks for `c ? a : b`).
    private readonly Dictionary<CaptureId, List<IOperation>> _captured = new();

    public MethodAnalyzer(AnalysisContext ctx, ControlFlowGraph cfg)
    {
        _ctx = ctx;
        _cfg = cfg;
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
                Value(block.BranchValue, state);
                Feed(handlers, state);
            }
            if (outStates != null) outStates[ordinal] = state;

            if (block.FallThroughSuccessor?.Destination is { } next) Flow(next.Ordinal, state);
            if (block.ConditionalSuccessor?.Destination is { } jump) Flow(jump.Ordinal, state);
            if (finallyExits.TryGetValue(ordinal, out var after))
                foreach (var destination in after) Flow(destination, state);
        }

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
        return value.Request && operation.Type is { } type && _ctx.Sources.IsScalar(type) ? TaintValue.Clean : value;
    }

    private TaintValue Transfer(IOperation operation, TaintState state)
    {
        switch (operation)
        {
            case ILiteralOperation:
            case IInstanceReferenceOperation:
            case IDefaultValueOperation:
            case ITypeOfOperation:
            case ISizeOfOperation:
            case INameOfOperation:
            case ICaughtExceptionOperation:
            case IMethodReferenceOperation:
            case IFlowAnonymousFunctionOperation:
            case IAnonymousFunctionOperation:
            case IDelegateCreationOperation:
            case IInterpolatedStringTextOperation:
            case IInterpolatedStringHandlerArgumentPlaceholderOperation:
            case IStaticLocalInitializationSemaphoreOperation:
            case IDiscardOperation:
                return TaintValue.Clean;

            case ILocalReferenceOperation local:
                return state.Get(local.Local);
            case IParameterReferenceOperation parameter:
                return state.Get(parameter.Parameter);
            case IFlowCaptureReferenceOperation capture:
                return state.Get(capture.Id);
            case IFieldReferenceOperation field:
            {
                var instance = Value(field.Instance, state);
                var own = state.Get(field.Field.OriginalDefinition);
                return IsOwnField(field) ? own : instance.Join(own);
            }

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
                state.Set(declarator.Symbol, Named(LocalValue(declarator.Symbol, value), declarator, declarator.Symbol.Name));
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
                return Call(invocation, invocation.TargetMethod, invocation.Instance, invocation.Arguments, state);
            case IObjectCreationOperation creation:
            {
                var value = Call(creation, creation.Constructor, null, creation.Arguments, state);
                // The CFG lowers initializers into assignments on a flow capture; one left here is evaluated as such.
                if (creation.Initializer != null) value = value.Join(Value(creation.Initializer, state));
                return value;
            }

            case IBinaryOperation binary:
                return Value(binary.LeftOperand, state).Join(Value(binary.RightOperand, state));
            case IUnaryOperation unary:
                return Value(unary.Operand, state);
            case IConversionOperation conversion:
                return Value(conversion.Operand, state);
            case IAwaitOperation await:
                return Value(await.Operation, state);
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
            {
                var value = TaintValue.Clean;
                foreach (var part in interpolated.Parts)
                {
                    value = value.Join(part switch
                    {
                        IInterpolationOperation i => Value(i.Expression, state).Join(Value(i.Alignment, state)),
                        // A handler's AppendFormatted(x): the formatted values reach the string.
                        IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation call } => JoinArguments(call.Arguments, state),
                        _ => Value(part, state),
                    });
                }
                return value;
            }
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
                return Value(ret.ReturnedValue, state);

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
                state.Set(local, LocalValue(local, value));
                break;
            case IRecursivePatternOperation recursive:
                if (recursive.DeclaredSymbol is ILocalSymbol r) state.Set(r, LocalValue(r, value));
                foreach (var p in recursive.DeconstructionSubpatterns) Bind(p, value, state);
                foreach (var p in recursive.PropertySubpatterns) Bind(p.Pattern, value, state);
                break;
            case IListPatternOperation list:
                if (list.DeclaredSymbol is ILocalSymbol l) state.Set(l, LocalValue(l, value));
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

    // ---- Assignments ----

    /// The current value of an assignment's target (the read half of `x += v`; M1: a property's get patterns).
    private TaintValue Read(IOperation target, TaintState state) => target switch
    {
        IPropertyReferenceOperation property => ReadProperty(property, state),
        _ => Value(target, state),
    };

    /// A field of the analysed object or a static field: tracked by its symbol.
    private static bool IsOwnField(IFieldReferenceOperation field) => field.Instance is null or IInstanceReferenceOperation;

    private void Assign(IOperation target, TaintValue value, TaintState state, IOperation assignment)
    {
        switch (target)
        {
            case ILocalReferenceOperation local:
                state.Set(local.Local, Named(value, assignment, local.Local.Name));
                break;
            case IParameterReferenceOperation parameter:
                state.Set(parameter.Parameter, Named(value, assignment, parameter.Parameter.Name));
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
            {
                Value(field.Instance, state);
                var named = Named(value, assignment, field.Field.Name);
                // A static field or one of `this`: a strong update of its symbol (within this body; the heap across
                // methods is Task 8). Another instance's field: a write into that instance (element-insensitive).
                if (IsOwnField(field)) state.Set(field.Field.OriginalDefinition, named);
                else Write(field.Instance!, named, state);
                break;
            }
            case IPropertyReferenceOperation property:
            {
                Value(property.Instance, state);
                foreach (var a in property.Arguments) Value(a.Value, state);
                foreach (var hit in _ctx.Sinks.Sinks(property.Property, Access.Set))
                    if (value.TaintedFor(hit.RuleId)) _ctx.Report(hit.RuleId, assignment.Syntax, value, property.Property);
                // An indexer write is a collection write (`dict[k] = v`).
                if (property.Property.IsIndexer && property.Instance != null) Write(property.Instance, value, state);
                break;
            }
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
        value.Request ? value.Step(assignment.Syntax.GetLocation(), $"assigned to '{name}'") : value;

    /// What holds the value of an operation in the state, when it is a variable this body tracks: a local, a parameter,
    /// a static field or a field of `this`.
    internal static object? Holder(IOperation operation) => operation switch
    {
        ILocalReferenceOperation l => l.Local,
        IParameterReferenceOperation p => p.Parameter,
        IFieldReferenceOperation f when IsOwnField(f) => f.Field.OriginalDefinition,
        IConversionOperation c => Holder(c.Operand),
        _ => null,
    };

    /// A weak write into what `operation` refers to (a collection, a builder, a tuple or object in a variable): the
    /// variable that holds it, a flow capture and what it captured, the instance of another object's field, or the
    /// receiver of a fluent call that returns its receiver (a propagator to both `this` and `return`:
    /// `sb.Append(a).Append(b)`).
    private void Write(IOperation operation, TaintValue value, TaintState state)
    {
        if (!value.Request) return;
        switch (operation)
        {
            case ILocalReferenceOperation l:
                state.Add(l.Local, value);
                break;
            case IParameterReferenceOperation p:
                state.Add(p.Parameter, value);
                break;
            case IFieldReferenceOperation f:
                if (IsOwnField(f)) state.Add(f.Field.OriginalDefinition, value);
                else Write(f.Instance!, value, state);
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

    private bool IsFluent(IMethodSymbol method)
    {
        if (IsInSource(method)) return false;
        foreach (var p in _ctx.Propagators.Match(method, Access.Call))
            if (p.To.Contains("this") && p.To.Contains("return")) return true;
        return false;
    }

    private static IOperation? ThisOperation(IInvocationOperation invocation) =>
        invocation.Instance ?? (invocation.TargetMethod.IsExtensionMethod && invocation.Arguments.Length > 0 ? invocation.Arguments[0].Value : null);

    // ---- Members ----

    private static bool IsInSource(ISymbol member) => MemberTable<object>.Definition(member).DeclaringSyntaxReferences.Length > 0;

    /// TEMPORARY (Task 7): what a call or property read of a member declared in source (or a delegate invocation)
    /// gives: the join of its receiver's and arguments' taint. The one place Task 8 replaces with summaries.
    private TaintValue InSourceResult(IOperation site, ISymbol member, TaintValue inputs) =>
        inputs.Request ? inputs.Step(site.Syntax.GetLocation(), $"passed to {_ctx.Name(member)}") : inputs;

    private TaintValue ReadProperty(IPropertyReferenceOperation operation, TaintState state)
    {
        var property = operation.Property;
        var receiver = Value(operation.Instance, state);
        var index = TaintValue.Clean;
        foreach (var a in operation.Arguments) index = index.Join(Value(a.Value, state));

        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(property, Access.Get) != null)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(property)}");
        if (_ctx.Sources.IsBoundProperty(property))
            result = result.Join(TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: bound property {_ctx.Name(property)}"));

        if (IsInSource(property))
        {
            result = result.Join(InSourceResult(operation, property, receiver.Join(index)));
        }
        else
        {
            var propagators = _ctx.Propagators.Match(property, Access.Get);
            if (propagators.Length > 0)
            {
                foreach (var p in propagators)
                {
                    if (!p.To.Contains("return")) continue;
                    foreach (var f in p.From)
                        result = result.Join(f switch { "this" => receiver, "args" => index, _ => IndexArgument(operation, f, state) });
                }
            }
            else if (_ctx.UnmodelledPasses && _ctx.Sources.IsStringOrCollection(property.Type))
            {
                _ctx.CountUnmodelled(operation.Syntax);
                result = result.Join(receiver.Join(index));
            }
        }
        return result.CleanedFor(_ctx.Sinks.Sanitizes(property, Access.Get));
    }

    private TaintValue IndexArgument(IPropertyReferenceOperation operation, string ordinal, TaintState state)
    {
        foreach (var a in operation.Arguments)
            if (a.Parameter != null && IsOrdinal(ordinal, a.Parameter.Ordinal)) return Value(a.Value, state);
        return TaintValue.Clean;
    }

    /// One argument of a call, by the ordinal of its parameter in the member's definition (an extension method's `this`
    /// is 0, also when the call names the reduced form); Site is the syntax a sink finding is reported at.
    private readonly record struct Input(int Ordinal, IParameterSymbol? Parameter, IOperation Operation, SyntaxNode Site, TaintValue Value, RefKind RefKind);

    private TaintValue Call(IOperation operation, IMethodSymbol? method, IOperation? instance, ImmutableArray<IArgumentOperation> arguments, TaintState state)
    {
        var definition = method == null ? null : (IMethodSymbol)MemberTable<object>.Definition(method);
        var reduced = method?.ReducedFrom != null;
        var receiver = TaintValue.Clean;
        IOperation? thisOperation = null;
        var inputs = new Input[arguments.Length + (reduced && instance != null ? 1 : 0)];
        var n = 0;
        if (instance != null)
        {
            var value = Value(instance, state);
            if (reduced && definition!.Parameters.Length > 0)
                inputs[n++] = new Input(0, definition.Parameters[0], instance, instance.Syntax, value, RefKind.None);
            receiver = value;
            thisOperation = instance;
        }
        foreach (var a in arguments)
        {
            var refKind = a.Parameter?.RefKind ?? RefKind.None;
            var value = refKind == RefKind.Out ? TaintValue.Clean : Value(a.Value, state);
            var ordinal = (a.Parameter?.Ordinal ?? -1) + (reduced ? 1 : 0);
            var parameter = definition != null && ordinal >= 0 && ordinal < definition.Parameters.Length ? definition.Parameters[ordinal] : null;
            inputs[n++] = new Input(ordinal, parameter, a.Value, a.IsImplicit ? a.Value.Syntax : a.Syntax, value, refKind);
        }
        if (n < inputs.Length) Array.Resize(ref inputs, n);

        var all = TaintValue.Clean;
        foreach (var i in inputs) if (i.RefKind != RefKind.Out) all = all.Join(i.Value);
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
                if (i.Parameter != null && i.Value.TaintedFor(hit.RuleId) && SinkFinder.IsSinkArgument(hit.Sink, i.Parameter))
                    _ctx.Report(hit.RuleId, i.Site, i.Value, method);

        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(method, Access.Call) != null)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(method)}");

        // Out arguments are overwritten by the call.
        foreach (var i in inputs) if (i.RefKind == RefKind.Out) Assign(i.Operation, TaintValue.Clean, state, i.Operation);

        if (IsInSource(method) || method.MethodKind == MethodKind.DelegateInvoke)
        {
            var through = InSourceResult(operation, method, all);
            result = result.Join(through);
            foreach (var i in inputs)
                if (i.RefKind is RefKind.Out or RefKind.Ref) Assign(i.Operation, through, state, i.Operation);
        }
        else
        {
            var propagators = _ctx.Propagators.Match(method, Access.Call);
            if (propagators.Length > 0)
            {
                foreach (var p in propagators) result = Propagate(p, operation, method, inputs, receiver, thisOperation, reduced && instance != null, result, state);
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
            if (thisOperation != null && all.Request && IsCollectionWrite(method))
            {
                var written = TaintValue.Clean;
                foreach (var i in inputs)
                    if (i.RefKind != RefKind.Out && !ReferenceEquals(i.Operation, thisOperation)) written = written.Join(i.Value);
                Write(thisOperation, written, state);
            }
        }

        return result.CleanedFor(_ctx.Sinks.Sanitizes(method, Access.Call));
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
        if (!from.Request) return result;
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
