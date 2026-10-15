using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// What every method analysis of one run shares: the models (as indexes), the findings and the counters.
internal sealed class AnalysisContext
{
    private readonly Dictionary<(string Rule, SyntaxTree Tree, TextSpan Span), Finding> _findings = new();
    private readonly HashSet<(SyntaxTree, TextSpan)> _unmodelledSites = new();
    private readonly Dictionary<ISymbol, string> _names = new(SymbolEqualityComparer.Default);

    public AnalysisContext(ModelSet models, TaintEngineOptions options)
    {
        Options = options;
        Sources = new SourceFinder(models.Sources, models.Rules);
        Sinks = new SinkFinder(models.Rules);
        foreach (var p in models.Propagators) Propagators.Add(p.Member, p);
        UnmodelledPasses = models.UnmodelledExternal == "string-or-collection-return";
        RuleIds = models.Rules.Select(r => r.RuleId).ToArray();
        KnownTexts = models.KnownTexts;
        Validation = new ModelValidation(models.Sources.Validation, models.Rules, RuleIds);
    }

    /// Model validation as a sanitizer (Task 31, decision R-12): the validation facts of bound members.
    public ModelValidation Validation { get; }

    /// Every rule id of the models.
    public string[] RuleIds { get; }

    /// The text of external static string members (`known-text:`, Task 29), by `Type.Member`.
    public IReadOnlyDictionary<string, string> KnownTexts { get; }

    private readonly Dictionary<string, string[]> _allBut = new(StringComparer.Ordinal);

    /// Every rule id but `rules`: what request data that is request data for `rules` only is clean for (a rule's own
    /// source, an `only-for:` propagator).
    public string[] AllBut(IReadOnlyCollection<string> rules)
    {
        var key = string.Join(",", rules.OrderBy(r => r, StringComparer.Ordinal));
        if (_allBut.TryGetValue(key, out var hit)) return hit;
        hit = RuleIds.Where(r => !rules.Contains(r)).ToArray();
        _allBut[key] = hit;
        return hit;
    }

    public TaintEngineOptions Options { get; }

    public SourceFinder Sources { get; }

    public SinkFinder Sinks { get; }

    /// The conditions of conditional sinks (`when:`), with the body facts they read.
    public SinkConditions Conditions { get; } = new();

    public MemberTable<PropagatorModel> Propagators { get; } = new();

    /// The allow-list tables (`allow-list: literal-tables`), found once per field.
    public AllowLists AllowLists { get; } = new();

    /// The types each type reaches (guards on members: what a call given a value may change).
    public TypeReach TypeReach { get; } = new();

    /// The view-model entries of types (Task 22), cached for the run.
    public ModelKeys ModelKeys { get; } = new();

    /// The abstract objects and member slots of the run (Task 27).
    public ObjectTable Objects { get; } = new();

    /// The `unmodelled-external` policy: an external member no propagator names passes its receiver's and arguments'
    /// taint to a string-like or collection result.
    public bool UnmodelledPasses { get; }

    public IEnumerable<Finding> Findings => _findings.Values;

    public int UnmodelledExternalCalls => _unmodelledSites.Count;

    public void CountUnmodelled(SyntaxNode site) => _unmodelledSites.Add((site.SyntaxTree, site.Span));

    private readonly Dictionary<IMethodSymbol, int[]?> _factories = new(SymbolEqualityComparer.Default);

    /// The value factory parameters of a project method shaped like a cache's `T Get(key, Func<T> acquire)` (rulings
    /// R-E18, R-E23; MethodAnalyzer.Apply drops from its result what only a lookup key gave it): it returns a type parameter T (or a Task or ValueTask of one), takes a delegate
    /// returning T (or a Task or ValueTask of it) and at least one parameter that is no delegate (the key); null for any
    /// other method. By the method's definition.
    public int[]? ValueFactories(IMethodSymbol definition)
    {
        if (_factories.TryGetValue(definition, out var cached)) return cached;
        int[]? result = null;
        if (definition.MethodKind == MethodKind.Ordinary && SymbolKeys.InSource(definition) && Produces(definition.ReturnType) is ITypeParameterSymbol produced)
        {
            var factories = definition.Parameters
                .Where(p => p.Type is INamedTypeSymbol { DelegateInvokeMethod: { } invoke }
                    && SymbolEqualityComparer.Default.Equals(Produces(invoke.ReturnType), produced))
                .Select(p => p.Ordinal).ToArray();
            // A value of T given besides the factory (`Pick(T fallback, Func<T> make)`) may be returned itself: no factory shape.
            var others = definition.Parameters.Where(p => p.Type.TypeKind != TypeKind.Delegate).ToList();
            if (factories.Length > 0 && others.Count > 0 && !others.Any(p => Mentions(p.Type, produced))) result = factories;
        }
        _factories[definition] = result;
        return result;

        static bool Mentions(ITypeSymbol type, ITypeSymbol t) => SymbolEqualityComparer.Default.Equals(type, t)
            || (type is IArrayTypeSymbol a && Mentions(a.ElementType, t))
            || (type is INamedTypeSymbol n && n.TypeArguments.Any(x => Mentions(x, t)));

        // The type a value of this type gives: T of Task<T> or ValueTask<T>, else the type itself.
        static ITypeSymbol Produces(ITypeSymbol type) =>
            type is INamedTypeSymbol { TypeArguments.Length: 1 } t
            && SymbolMatch.MetadataName(t.OriginalDefinition) is "System.Threading.Tasks.Task`1" or "System.Threading.Tasks.ValueTask`1"
                ? t.TypeArguments[0]
                : type;
    }

    /// One finding per rule and sink site (the site's syntax: an argument or an assignment) of a syntax tree; the first
    /// path is kept, unless a later one is high and it is not (R-9: a finding is medium only when no high path is
    /// found). The same file in several compilations (target frameworks) is deduplicated by TaintEngine.
    public void Report(string rule, SyntaxNode site, TaintValue value, ISymbol member)
    {
        var key = (rule, site.SyntaxTree, site.Span);
        if (_findings.TryGetValue(key, out var old) && (old.Confidence == Confidence.High || value.Path.Medium)) return;
        var sink = site.GetLocation();
        var trail = value.Path.Add(new PathStep(sink, $"reaches the {rule} sink {Name(member)}"));
        var path = trail.ToList();
        var others = value.Sources.Where(s => !s.Equals(path[0].Location)).OrderBy(s => s.SourceSpan.Start).ToList();
        _findings[key] = new Finding(rule, sink, path, others)
        {
            Message = Sinks.MessageFor(rule, member),
            Confidence = trail.Medium ? Confidence.Medium : Confidence.High,
        };
    }

    /// A misuse rule's finding at `at` (in source), its one path step saying what was found there.
    public void ReportMisuse(string rule, Location at, string message)
    {
        if (at.SourceTree is not { } tree) return;
        var key = (rule, tree, at.SourceSpan);
        if (_findings.ContainsKey(key)) return;
        _findings[key] = new Finding(rule, at, new[] { new PathStep(at, message) }, Array.Empty<Location>());
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
///   request data for it (Heap: across methods and projects, scoped to the request entry point, per abstract object
///   where the instance's objects are known: Task 27, "Objects and strong updates" below). A write of a source field or
///   auto-property taints its symbol only (its state here, the heap), never the object holding it; other members
///   (tuple elements, external structs) are written into their instance.
/// - Objects (Task 27, decision R-8): a value carries the abstract objects it may be (an allocation site, a bound model,
///   a parameter's own object in a symbolic body; at most ObjSet.MaxObjects, else unknown) and the members it is known to
///   hold exactly; variables keep them as facts (points-to facts, strong updates of `v.M`). Only operations whose value
///   is the object they were given keep them (KeepsIdentity).
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

    /// The join of the values the body returns (`return x`, an expression body, `yield return x`); Bottom before the
    /// first (Task 27: the objects and members of what it returns are joined over its returns).
    public TaintValue ReturnValue { get; private set; } = TaintValue.Bottom;

    /// Whether ReturnText is kept (a string method's body).
    public bool TrackReturnText { get; init; }

    /// The text every string the body returns starts with (BodySummary.JoinText of KnownText at each return), null when
    /// no return was seen.
    public string? ReturnText { get; private set; }

    /// The state at the body's exit (null when the exit is unreachable).
    public TaintState? ExitState { get; private set; }

    /// Runs the dataflow from `entry`. With `collectAll`, returns the join of the states at every block entry and exit
    /// (what a lambda or local function declared here may capture); null otherwise.
    public TaintState? Run(TaintState entry, bool collectAll)
    {
        SeedValidation(entry);
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
                if (block.FallThroughSuccessor?.Semantics == ControlFlowBranchSemantics.Return)
                {
                    ReturnValue = ReturnValue.Join(value);
                    if (TrackReturnText) ReturnText = BodySummary.JoinText(ReturnText, KnownText(block.BranchValue) ?? HoleText);
                }
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
        // Task 27: only an operation whose value is the object it was given (a variable, a conversion, a branch, a call's
        // returned object, an allocation, a member's exactly known value) keeps objects and members.
        if (value.HasIdentity && !KeepsIdentity(operation)) value = value.WithoutIdentity();
        return value.Any && operation.Type is { } type && _ctx.Sources.IsScalar(type) ? TaintValue.Clean : value;
    }

    private static bool KeepsIdentity(IOperation operation) => operation is ILocalReferenceOperation or IParameterReferenceOperation
        or IFlowCaptureReferenceOperation or IInstanceReferenceOperation or IConversionOperation { OperatorMethod: null } or IAwaitOperation
        or IConditionalOperation or ICoalesceOperation or IInvocationOperation or IObjectCreationOperation or IAnonymousObjectCreationOperation
        or IArrayCreationOperation or ICollectionExpressionOperation or IPropertyReferenceOperation or IFieldReferenceOperation
        or ISimpleAssignmentOperation or IArgumentOperation or IDeclarationExpressionOperation or ILiteralOperation or IDefaultValueOperation;

    private TaintValue Transfer(IOperation operation, TaintState state)
    {
        switch (operation)
        {
            // Task 27: null is no object (every member of it known: the identity of a join).
            case ILiteralOperation { ConstantValue: { HasValue: true, Value: null } }:
            case IDefaultValueOperation { Type.IsReferenceType: true }:
                return TaintValue.Bottom;
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
                return instance.ReferenceKind == InstanceReferenceKind.ContainingTypeInstance ? Identity(AccessPath.This, _body.This, state) : TaintValue.Clean;
            case IFlowAnonymousFunctionOperation lambda:
                return _body.LambdaReturn(lambda.Symbol);
            case IDelegateCreationOperation creation:
                return Value(creation.Target, state);

            case ILocalReferenceOperation local:
                return Identity(local.Local, _body.Local(local.Local, state.Get(local.Local)), state);
            case IParameterReferenceOperation parameter:
                return Identity(parameter.Parameter, _body.Local(parameter.Parameter, state.Get(parameter.Parameter)), state);
            case IFlowCaptureReferenceOperation capture:
                return Identity(capture.Id, state.Get(capture.Id), state);
            case IFieldReferenceOperation field:
                return Guarded(field, ReadMember(field, field.Field, Value(field.Instance, state), state), state);

            case IFlowCaptureOperation capture:
            {
                var value = Value(capture.Value, state);
                if (state.HasFacts) state.Forget(p => SymbolOrCapture.Comparer.Equals(p.Root, capture.Id));
                state.Set(capture.Id, value);
                RecordIdentity(capture.Id, capture.Value.Type, value, state);
                return TaintValue.Clean;
            }

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
                ForgetWritten(increment.Target, state);
                return TaintValue.Clean;

            case IVariableDeclaratorOperation declarator:
            {
                var value = Value(declarator.Initializer?.Value, state);
                SetLocal(declarator.Symbol, Named(LocalValue(declarator.Symbol, value), declarator, declarator.Symbol.Name), state);
                return TaintValue.Clean;
            }

            case IPropertyReferenceOperation property:
                if (_validatedPaths != null && MayChangeModelState(property)) ModelStateTouched(state);
                return Guarded(property, ReadProperty(property, state), state);
            case IArrayElementReferenceOperation element:
            {
                var array = Value(element.ArrayReference, state);
                foreach (var index in element.Indices) Value(index, state);
                return array;
            }
            case IInvocationOperation invocation:
                if (_validatedPaths != null && MayChangeModelState(invocation)) ModelStateTouched(state);
                return Call(invocation, invocation.TargetMethod, invocation.Instance, invocation.Arguments, state, invocation.IsVirtual);
            case IObjectCreationOperation creation:
            {
                var value = Call(creation, creation.Constructor, null, creation.Arguments, state, false);
                // The CFG lowers initializers into assignments on a flow capture; one left here is evaluated as such.
                if (creation.Initializer != null) value = value.Join(Value(creation.Initializer, state));
                // Task 27: the object made here is its allocation site; its constructor's strong updates of `this` are known.
                return value with { Objects = _ctx.Objects.Single(_ctx.Objects.Site(creation.Syntax)), Members = value.Members };
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
                // A task started earlier (held in a variable, or given to the awaited call) may change anything it was
                // given while the method waits: every member fact ends (fix round 1, M3).
                if (state.HasFacts && !AwaitsFreshCall(await.Operation)) state.ForgetAll();
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
                return Value(array.Initializer, state).WithoutIdentity() with { Objects = _ctx.Objects.Single(_ctx.Objects.Site(array.Syntax)) };
            case IAnonymousObjectCreationOperation anonymous:
            {
                var value = TaintValue.Clean;
                foreach (var initializer in anonymous.Initializers)
                    value = value.Join(initializer is ISimpleAssignmentOperation a ? Value(a.Value, state) : Value(initializer, state));
                return value.WithoutIdentity() with { Objects = _ctx.Objects.Single(_ctx.Objects.Site(anonymous.Syntax)) };
            }
            case ICollectionExpressionOperation collection:
            {
                var value = TaintValue.Clean;
                foreach (var child in collection.ChildOperations) value = value.Join(Value(child, state));
                return value.WithoutIdentity() with { Objects = _ctx.Objects.Single(_ctx.Objects.Site(collection.Syntax)) };
            }

            case IDynamicMemberReferenceOperation member when KeyedStores.IsViewBag(member.Instance):
                Value(member.Instance, state);
                return Keyed(KeyedStores.ViewBagLocation(member.MemberName), member);
            case IDynamicInvocationOperation dynamic:
            {
                // A call bound at run time (an argument is dynamic: `Html.Raw(ViewBag.K)`): the join of its parts, the
                // sinks of its candidate members (Task 22), and every member fact ends (fix round 1 of Task 21, M2).
                var value = Value(dynamic.Operation, state);
                var arguments = new TaintValue[dynamic.Arguments.Length];
                for (var k = 0; k < arguments.Length; k++) value = value.Join(arguments[k] = Value(dynamic.Arguments[k], state));
                if (_body.RootSymbolic)
                {
                    Escape(dynamic.Operation, value);
                    for (var k = 0; k < arguments.Length; k++) Escape(dynamic.Arguments[k], arguments[k]);
                }
                DynamicSinks(dynamic, dynamic.Arguments, k => dynamic.GetArgumentName(k), arguments);
                state.ForgetAll();
                return value;
            }
            case IDynamicObjectCreationOperation creation:
            {
                // A constructor bound at run time (`new HtmlString(ViewBag.K)`): as a dynamic call, its candidates are the
                // type's constructors (Task 22 fix round 1, M2).
                var arguments = new TaintValue[creation.Arguments.Length];
                var value = TaintValue.Clean;
                for (var k = 0; k < arguments.Length; k++) value = value.Join(arguments[k] = Value(creation.Arguments[k], state));
                if (_body.RootSymbolic)
                    for (var k = 0; k < arguments.Length; k++) Escape(creation.Arguments[k], arguments[k]);
                if (creation.Initializer != null) value = value.Join(Value(creation.Initializer, state));
                DynamicSinks(creation, creation.Arguments, k => creation.GetArgumentName(k), arguments);
                state.ForgetAll();
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
                // A call the engine does not bind (dynamic, a function pointer) may change anything: every member fact
                // ends (fix round 1, M2), and what it is given escapes (Task 27).
                var unbound = operation is IDynamicInvocationOperation or IDynamicObjectCreationOperation or IDynamicIndexerAccessOperation
                    or IFunctionPointerInvocationOperation;
                foreach (var child in operation.ChildOperations)
                {
                    var v = Value(child, state);
                    if (unbound && _body.RootSymbolic) Escape(child, v);
                    value = value.Join(v);
                }
                if (unbound) state.ForgetAll();
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
        // The value's own text when it is known (a constant in all but name, a helper's returned text: Task 23).
        prefix.Append(_ctx.Sinks.HasStringSanitizers ? KnownText(expression) ?? HoleText : HoleText);
        return value;
    }

    private static readonly string HoleText = Hole.ToString();

    /// The text a string expression is known to have, a Hole standing for any text (the value of an earlier part), or null
    /// when nothing is known (Task 23): a constant; a static readonly field or get-only static property initialised with a
    /// literal (KeyedStores.NamedConstant); a string `+` or an interpolated string of known parts; a call of a method or a
    /// read of a property declared in source, whose bodies' summaries know the text they return (BodySummary.ReturnText,
    /// joined over the dispatch targets); a flow capture of known values (`c ? a : b`), an awaited known call.
    private string? KnownText(IOperation? operation, int depth = 0)
    {
        if (operation == null || depth > 16) return null;
        while (operation is IConversionOperation { OperatorMethod: null } c && c.Type?.SpecialType is SpecialType.System_String or SpecialType.System_Object)
            operation = c.Operand;
        if (operation.ConstantValue is { HasValue: true } constant)
            return constant.Value as string ?? Convert.ToString(constant.Value, System.Globalization.CultureInfo.InvariantCulture) ?? "";
        switch (operation)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } b:
                return Known((KnownText(b.LeftOperand, depth + 1) ?? HoleText) + (KnownText(b.RightOperand, depth + 1) ?? HoleText));
            case IInterpolatedStringOperation interpolated:
            {
                var text = new System.Text.StringBuilder();
                foreach (var part in interpolated.Parts)
                {
                    text.Append(part switch
                    {
                        IInterpolatedStringTextOperation t => t.Text.ConstantValue.Value as string,
                        IInterpolationOperation { Alignment: null, FormatString: null } i => KnownText(i.Expression, depth + 1) ?? HoleText,
                        IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation { TargetMethod.Name: "AppendLiteral" } l } =>
                            string.Concat(l.Arguments.Select(a => a.Value.ConstantValue.Value as string)),
                        IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation { Arguments.Length: 1 } f } => KnownText(f.Arguments[0].Value, depth + 1) ?? HoleText,
                        _ => HoleText,
                    });
                }
                return Known(text.ToString());
            }
            case IFlowCaptureReferenceOperation capture when _captured.TryGetValue(capture.Id, out var values):
            {
                string? text = null;
                foreach (var v in values)
                {
                    if (KnownText(v, depth + 1) is not { } t) return null;
                    text = BodySummary.JoinText(text, t);
                }
                return Known(text);
            }
            case IAwaitOperation await:
                return KnownText(await.Operation, depth + 1);
            case IInvocationOperation invocation:
                return ReturnedText(invocation.TargetMethod, invocation.IsVirtual, invocation.Instance?.Type);
            case IPropertyReferenceOperation { Property: { IsIndexer: false } property } read:
                return KeyedStores.NamedConstant(read) is { } named ? named
                    : ExternalText(property) is { } external ? external
                    : property.GetMethod is { } getter ? ReturnedText(getter, Dispatch.IsVirtualAccess(property, read.Instance), read.Instance?.Type) : null;
            case IFieldReferenceOperation field:
                return KeyedStores.NamedConstant(field) ?? ExternalText(field.Field);
            default:
                return null;
        }

        // A text that starts with a Hole tells nothing.
        static string? Known(string? text) => text is { Length: > 0 } && text[0] == Hole ? null : text;
    }

    /// The text of an external static string field or property the models know (`known-text:` of propagators.yml, Task 29:
    /// `Uri.SchemeDelimiter` is "://"), or null.
    private string? ExternalText(ISymbol member)
    {
        if (!member.IsStatic || SymbolKeys.InSource(member) || _ctx.KnownTexts.Count == 0 || member.ContainingType == null) return null;
        return _ctx.KnownTexts.TryGetValue(SymbolMatch.MetadataName(member.ContainingType) + "." + member.Name, out var text) ? text : null;
    }

    /// The text a member declared in source returns: the join of its targets' ReturnText, null when one of them is no
    /// body or has none.
    private string? ReturnedText(IMethodSymbol method, bool isVirtual, ITypeSymbol? receiverType)
    {
        if (!SymbolKeys.InSource(method)) return null;
        string? text = null;
        foreach (var target in _body.Targets(method, isVirtual, receiverType))
        {
            if (target.Kind != TargetKind.Body) return null;
            _body.Depend(target.Body!);
            if (target.Body!.Summary.ReturnText is not { } t) return null;
            text = BodySummary.JoinText(text, t);
        }
        return text is { Length: > 0 } && text[0] == Hole ? null : text;
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
                result = result.Join(Apply(target.Body!, expression, toString, slot => slot == -1 ? value : TaintValue.Clean, null, Array.Empty<Input>(), false, state, kind: target.StepKind));
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

    /// A strong update of a local or parameter (a captured one is also a captured write of this body); the objects and
    /// members it now holds are its facts (Task 27).
    private void SetLocal(ISymbol symbol, TaintValue value, TaintState state)
    {
        ForgetRoot(symbol, state);
        state.Set(symbol, value);
        _body.Assigned(symbol, value);
        if (symbol is ILocalSymbol { RefKind: RefKind.None } or IParameterSymbol { RefKind: RefKind.None })
            RecordIdentity(symbol, symbol is ILocalSymbol l ? l.Type : ((IParameterSymbol)symbol).Type, value, state);
    }

    // ---- Objects and strong updates (Task 27, decision R-8) ----

    /// A variable's value (a local, a parameter, a flow capture, `this`) with what it is known to hold: its objects (the
    /// points-to fact; `this`: the body's own object, when its callers' objects stand for it) and the members its strong
    /// updates fix (`v.M` paths).
    private TaintValue Identity(object root, TaintValue value, TaintState state)
    {
        var objects = ReferenceEquals(root, AccessPath.This) ? _body.This.Objects : state.PointsTo(root);
        MemberMap? members = null;
        if (state.HasFacts && state.HasHolds)
        {
            ImmutableDictionary<ISymbol, TaintValue>.Builder? known = null;
            foreach (var f in state.Facts)
            {
                if (f.Holds == null || f.Path.Members.Length != 1 || !SymbolOrCapture.Comparer.Equals(f.Path.Root, root)) continue;
                (known ??= ImmutableDictionary.CreateBuilder<ISymbol, TaintValue>(SymbolEqualityComparer.Default))[f.Path.Members[0]] = f.Holds;
            }
            if (known != null) members = MemberMap.Of(known.ToImmutable());
        }
        if (objects == null && members == null) return value.HasIdentity ? value.WithoutIdentity() : value;
        return value with { Objects = objects, Members = members };
    }

    /// Records what a variable was assigned: its objects (none recorded when a lambda or local function of the method
    /// may assign it) and the members the value is known to hold, as strong updates of `root.M`.
    private void RecordIdentity(object root, ITypeSymbol? type, TaintValue value, TaintState state)
    {
        _nestedEffects ??= NestedEffects();
        var nested = _nestedEffects.Contains(root);
        state.SetPointsTo(root, nested ? null : value.Objects);
        if (nested || value.Members is not { IsAll: false } members) return;
        foreach (var (member, v) in members.Values)
            if (state.Facts.Length < MaxHolds && MemberPath(root, type, member) is { } path && CanHold(path)) state.SetHolds(path, v);
    }

    /// Strong updates are recorded while the state holds fewer facts (guards keep the rest of MemberFacts.MaxFacts).
    private const int MaxHolds = MemberFacts.MaxFacts - 16;

    /// The access path `root.M`.
    private static AccessPath MemberPath(object root, ITypeSymbol? type, ISymbol member)
    {
        var types = new List<ITypeSymbol>(2);
        if (type != null && (ReferenceEquals(root, AccessPath.This) || MemberFacts.IsChangeable(type))) types.Add(type);
        var memberType = member is IFieldSymbol f ? f.Type : (member as IPropertySymbol)?.Type;
        if (MemberFacts.IsChangeable(memberType)) types.Add(memberType!);
        return new AccessPath(root, ImmutableArray.Create(member.OriginalDefinition), types.ToImmutableArray());
    }

    /// The variable an operation is (a local, a value parameter, `this`, a flow capture), with its type, or null.
    private static (object Root, ITypeSymbol? Type)? RootOf(IOperation? operation)
    {
        while (operation is IConversionOperation { OperatorMethod: null } c) operation = c.Operand;
        return operation switch
        {
            ILocalReferenceOperation { Local: { RefKind: RefKind.None } l } => (l, l.Type),
            IParameterReferenceOperation { Parameter: { RefKind: RefKind.None } p } => (p, p.Type),
            IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance } i => (AccessPath.This, i.Type),
            IFlowCaptureReferenceOperation r => (r.Id, r.Type),
            _ => null,
        };
    }

    /// The objects an operation's value holds, read without evaluating it again: a variable's points-to fact, `this`'s
    /// own object; unknown (null) for anything else.
    private TaintValue? KnownIdentity(IOperation? operation, TaintState state)
    {
        while (operation is IConversionOperation { OperatorMethod: null } c) operation = c.Operand;
        return RootOf(operation) is { } root
            ? Identity(root.Root, TaintValue.Clean, state)
            : null;
    }

    /// Whether every object of a known set is a parameter object of a body of this unit (a member read through it is a
    /// member slot).
    private bool AllKeptParams(ObjSet objects)
    {
        foreach (var o in objects.Ids)
        {
            var (kind, owner, _) = _ctx.Objects.Describe(o);
            if (kind != ObjKind.Param || !_body.Keeps(owner)) return false;
        }
        return true;
    }

    /// The heap's part of a member read through `objects`: unknown objects (null), a static member or a member of a
    /// type that is never request data read the member's field location; known objects their locations and the writes
    /// through unknown objects; a parameter object of this unit's bodies is the member slot of that parameter (a label,
    /// substituted at each call). Empty objects (null itself) read nothing.
    private TaintValue MemberHeap(ISymbol member, ObjSet? objects, IOperation at, bool neverSource)
    {
        var heap = TaintValue.Clean;
        var labels = TaintValue.Clean;
        // No object at all (a view model no write has reached yet, null) is read as unknown, as before Task 27.
        var unknown = member.IsStatic || objects == null || objects.IsEmpty;
        var concrete = false;
        if (!unknown)
        {
            foreach (var o in objects!.Ids)
            {
                var (kind, owner, slot) = _ctx.Objects.Describe(o);
                if (kind != ObjKind.Param) concrete = true;
                else if (!neverSource && _body.Keeps(owner)) labels = labels.Join(_ctx.Objects.SlotLabel(owner, _ctx.Objects.MemberSlot(slot, SymbolKeys.Definition(member))));
                else unknown = true;
            }
        }
        if (unknown) heap = _body.HeapRead(member);
        else if (concrete) heap = _body.HeapRead(member, objects);
        // A member read from the heap (its field or object locations) is a heap read (R-9, R-E29). A parameter object's
        // member slot is plain: the call site gives what the argument holds there (MemberArg tags an exact member).
        var location = at.Syntax.GetLocation();
        var message = $"read from {_ctx.Name(member)}";
        return (heap.Any ? heap.Step(location, message, StepKind.HeapRead) : heap).Join(labels.Any ? labels.Step(location, message) : labels);
    }

    /// The kind of a read of a strong update this body holds for `path` (Task 27; ruling R-E35): exact within this method
    /// is plain (an own or static member, or a path rooted at a local whose objects this method allocates); a member
    /// through any other object is a heap read (R-9, R-E29). A strong update a callee's exit gave the caller carries its
    /// own heap-read step (Apply), so a read after such a call stays medium.
    private StepKind HoldsKind(AccessPath path, TaintState state)
    {
        if (path.Members.Length == 1 && (path.Root == AccessPath.This || path.Root == AccessPath.Static)) return StepKind.Plain;
        return path.Root is ILocalSymbol && AllocatedHere(state.PointsTo(path.Root)) ? StepKind.Plain : StepKind.HeapRead;
    }

    /// The kind of a read of a member the instance holds exactly (Task 27; ruling R-E35): plain through `this` or a local
    /// whose objects this method allocates; a heap read through any other instance (a parameter, a field's object, a view's
    /// model, a factory's result).
    private StepKind ExactKind(IOperation operation, TaintValue instance)
    {
        var receiver = operation switch
        {
            IFieldReferenceOperation f => f.Instance,
            IPropertyReferenceOperation p => p.Instance,
            _ => null,
        };
        while (receiver is IConversionOperation { Operand: { } inner }) receiver = inner;
        if (IsOwn(receiver)) return StepKind.Plain;
        return receiver is ILocalReferenceOperation && AllocatedHere(instance.Objects) ? StepKind.Plain : StepKind.HeapRead;
    }

    /// Whether every object of a set is an allocation site in the analysed method (ruling R-E35).
    private bool AllocatedHere(ObjSet? objects)
    {
        if (objects is not { IsEmpty: false }) return false;
        var body = _cfg.OriginalOperation.Syntax;
        foreach (var o in objects.Ids)
            if (!_ctx.Objects.AllocatedIn(o, body)) return false;
        return true;
    }

    /// A view's known model members joined with what is written into those members of the model's objects.
    private MemberMap? KnownLater(MemberMap known, ObjSet? objects, IOperation at)
    {
        var builder = ImmutableDictionary.CreateBuilder<ISymbol, TaintValue>(SymbolEqualityComparer.Default);
        foreach (var (member, value) in known.Values)
        {
            var type = member is IFieldSymbol f ? f.Type : (member as IPropertySymbol)?.Type;
            var neverSource = type != null && _ctx.Sources.IsNeverSourceType(type);
            builder[member] = _body.IsHeapMember(member) ? value.Join(MemberHeap(member, objects, at, neverSource)) : value;
        }
        return MemberMap.Of(builder.ToImmutable());
    }

    private static TaintValue IdentityOf(TaintValue value) => value.HasIdentity ? TaintValue.Clean with { Objects = value.Objects, Members = value.Members } : TaintValue.Clean;

    // ---- Fields and auto-properties ----

    /// A field of the analysed object or a static one (`this._f`, `_f`, `T._s`): tracked by its symbol in this body.
    private static bool IsOwn(IOperation? instance) =>
        instance is null or IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance };

    /// The value of a field or auto-property: its instance's (the object, element-insensitive; `this` for an own one),
    /// its state in this body, and the heap's request data for it. An own member of a type that is never request data
    /// (sources.yml `parameter-types`: an interface is a DI service, a scalar) does not take the receiver's value: a
    /// request-bound object's data members carry it, its injected services do not.
    ///
    /// Task 27: a member the instance is known to hold exactly (its strong update) is that value alone. Otherwise the heap's part goes through the instance's objects (MemberHeap); a read through only
    /// this unit's parameter objects is that parameter's member slot, which stands for the instance's value too (a call
    /// site gives its argument's whole taint when the member is not known exactly).
    private TaintValue ReadMember(IOperation operation, ISymbol member, TaintValue instance, TaintState state)
    {
        var definition = member.OriginalDefinition;
        // (All: nothing known yet, e.g. a view's model no write has reached: read as unknown.)
        if (!member.IsStatic && instance.Members is { IsAll: false } known && known.TryGet(definition, out var exact))
            return exact.Any ? exact.Step(operation.Syntax.GetLocation(), $"read from {_ctx.Name(member)}", ExactKind(operation, instance)) : exact;
        if (state.HasFacts && PathOf(operation, true) is { } path && state.Fact(path)?.Holds is { } holds)
            return holds.Any ? holds.Step(operation.Syntax.GetLocation(), $"read from {_ctx.Name(member)}", HoldsKind(path, state)) : holds;
        var neverSource = member is IFieldSymbol or IPropertySymbol && !member.IsStatic
            && _ctx.Sources.IsNeverSourceType(member is IFieldSymbol f ? f.Type : ((IPropertySymbol)member).Type);
        var heapMember = _body.IsHeapMember(member);
        var objects = member.IsStatic ? null : instance.Objects;
        var slotOnly = heapMember && !neverSource && objects is { IsEmpty: false } && AllKeptParams(objects);
        var value = instance.Any && !neverSource && !slotOnly ? instance.WithoutIdentity() : TaintValue.Clean;
        value = value.Join(state.Get(definition));
        if (heapMember) value = value.Join(MemberHeap(member, objects, operation, neverSource));
        return value;
    }

    /// An assignment of a field or auto-property (its instance already evaluated). A heap member (a field or
    /// auto-property declared in source; spec §5 "fields and properties by symbol") is tainted by its symbol only: the
    /// heap write and, for an own one, a strong update of its state in this body; the object that holds it is not
    /// written (fix round 1 of Task 8, I1: its other members stay clean). Any other member (a tuple element, an external
    /// struct's field) is written into its instance as before (element-insensitive, Task 7 I3).
    ///
    /// Task 27: the write goes to the instance's objects (Body.HeapWrite); the written path (`x.M`, `this.M`, a capture's
    /// member) holds exactly the value until something may change it (a strong update: the facts of every path that
    /// mentions the member were already forgotten by ForgetWritten).
    private void AssignMember(ISymbol member, IOperation? instance, TaintValue instanceValue, TaintValue value, TaintState state, IOperation assignment, IOperation? target)
    {
        var named = Named(value, assignment, member.Name);
        if (_body.IsHeapMember(member))
        {
            if (IsOwn(instance)) state.Set(member.OriginalDefinition, named);
            _body.HeapWrite(member, named, member.IsStatic ? null : instanceValue.Objects);
            if (target != null && state.Facts.Length < MaxHolds && PathOf(target, true) is { } path && CanHold(path)) state.SetHolds(path, named);
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
        IPropertyReferenceOperation property => Guarded(property, ReadProperty(property, state), state),
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
                RecordIdentity(capture.Id, capture.Type, value, state);
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
                var instance = Value(field.Instance, state);
                ForgetWritten(field, state);
                AssignMember(field.Field, field.Instance, instance, value, state, assignment, field);
                break;
            }
            case IPropertyReferenceOperation property:
                ForgetWritten(property, state);
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
            case IDynamicMemberReferenceOperation member when KeyedStores.IsViewBag(member.Instance):
                // `ViewBag.K = v` sets the ViewData entry K (Task 22); it runs no code of the application.
                Value(member.Instance, state);
                KeyedWrite(KeyedStores.ViewBagLocation(member.MemberName), Named(value, assignment, "ViewBag." + member.MemberName), assignment);
                break;
            default:
                // A target the engine does not follow (a dynamic member, an event, a ref): what it changes is unknown.
                state.ForgetAll();
                state.ForgetPointsTo();
                Value(target, state);
                break;
        }
    }

    private static bool IsVariable(IOperation operation) => operation is ILocalReferenceOperation or IParameterReferenceOperation
        or IFieldReferenceOperation or IFlowCaptureReferenceOperation or IPropertyReferenceOperation or IArrayElementReferenceOperation;

    private TaintValue Named(TaintValue value, IOperation assignment, string name, StepKind kind = StepKind.Plain) =>
        value.Any ? value.Step(assignment.Syntax.GetLocation(), $"assigned to '{name}'", kind) : value;

    /// The kind of a write to a keyed store entry: medium under the store's "any key" (R-E29).
    private static StepKind AnyKey(KeyedLocation location) => location.Key == null ? StepKind.AnyKeyEntry : StepKind.Plain;

    /// A weak write into what `operation` refers to (a collection, a builder, a tuple or object in a variable): the
    /// variable that holds it, a flow capture and what it captured, a field or auto-property (its state, its instance,
    /// the heap), the receiver (`this`), or the receiver of a fluent call that returns its receiver (a propagator to
    /// both `this` and `return`: `sb.Append(a).Append(b)`).
    private void Write(IOperation operation, TaintValue value, TaintState state)
    {
        ForgetWritten(operation, state);
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
            _body.HeapWrite(member, value, member.IsStatic ? null : KnownIdentity(instance, state)?.Objects);
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

    // ---- Keyed request stores (Task 22) ----

    /// The request data of a keyed store entry for this body, with a path step at the read (R-9, R-E29): a constant key's
    /// entry and a view model are high (value passing within the request: what was written under the store's "any key"
    /// carries its medium write step), a read with a key that is not a constant medium; the part of the data this body
    /// shares with its writers only through fallback edges is medium (Task 32: StepKind.ViewFallback for an unresolved view
    /// name's, StepKind.DispatchFallback when a fallback dispatch call is all that is missing).
    private TaintValue Keyed(KeyedLocation location, IOperation read)
    {
        var value = _body.KeyedRead(location);
        if (!value.Any) return value;
        var at = read.Syntax.GetLocation();
        var message = $"read from {Describe(location)}";
        if (location.Key == null) return value.Step(at, message, StepKind.AnyKeyEntry);
        var kind = location.Store == KeyedStore.ViewModel ? StepKind.ViewModel : StepKind.KeyedEntry;
        var (precise, rest) = _body.ThroughResolvedEdges(value);
        if (ReferenceEquals(precise, value)) return value.Step(at, message, kind);
        var fallback = value.Step(at, message, rest);
        return precise.Any ? precise.Step(at, message, kind).Join(fallback) : fallback;
    }

    /// A write to a keyed store entry; under the store's "any key" (a key that is not a constant, a model of type object)
    /// it is a medium step (R-9, R-E29), so every read that joins that entry carries it. Under a constant key (or a typed
    /// view model) the request data this body writes only for the entry points that reach it through fallback edges is
    /// a medium step too (Task 32 fix round 1, I2: a helper only a fallback dispatch call reaches, a partial only a run-time
    /// view name reaches); the rest keeps the value-passing edge.
    private void KeyedWrite(KeyedLocation location, TaintValue value, IOperation at)
    {
        // A value without taint still goes to the body (a view model's objects and members: Task 27).
        if (value.Any && location.Key == null)
        {
            value = value.Step(at.Syntax.GetLocation(), $"written to {Describe(location)}", StepKind.AnyKeyEntry);
        }
        else if (value.Request && !ReferenceEquals(location, KeyedLocation.Generic))
        {
            var (precise, others) = _body.WrittenThroughResolvedEdges(value);
            if (!ReferenceEquals(precise, value))
            {
                // Only the request part takes the medium step: the labels go to the callers' substitution (their own edges).
                var rest = value.RequestPart.Step(at.Syntax.GetLocation(), $"written to {Describe(location)}", others);
                // With no precise part, the rest keeps the model's objects and members (a join with the label part alone
                // would make them unknown: fix round 2, RR-M1).
                value = precise.Any ? precise.Join(rest) : rest.WithTaintOf(value.LabelPart);
            }
        }
        _body.KeyedWrite(location, value);
    }

    /// The view's model read under its type's entries (Task 27: what all of them know of its members). The view-model
    /// edge is high (R-E29), but for what the view shares with its writer only through fallback edges (as Keyed).
    private TaintValue Keyed(IEnumerable<KeyedLocation> locations, IOperation read)
    {
        var value = _body.KeyedRead(locations);
        if (!value.Any) return value;
        var at = read.Syntax.GetLocation();
        const string message = "read from the view's model";
        var (precise, rest) = _body.ThroughResolvedEdges(value);
        if (ReferenceEquals(precise, value)) return value.Step(at, message, StepKind.ViewModel);
        var fallback = value.Step(at, message, rest);
        return precise.Any ? precise.Step(at, message, StepKind.ViewModel).Join(fallback) : fallback;
    }

    /// A callee that gives a type-parameter-typed parameter to a view as its model (KeyedLocation.Generic in its summary):
    /// the argument is written as the view model under the argument's own static type.
    private void GenericModels(BodySummary summary, Body callee, IOperation site, string name, Input[] inputs, StepKind kind)
    {
        if (!summary.Heap.TryGetValue(KeyedLocation.Generic, out var entry)) return;
        foreach (var label in entry.Value.Labels)
        {
            if (label.Owner != callee.Id) continue;
            foreach (var i in inputs)
            {
                if (i.Ordinal != label.Slot || i.RefKind == RefKind.Out || !i.Value.Any) continue;
                var stepped = i.Value.Step(site.Syntax.GetLocation(), $"passed to {name}", kind);
                var value = TaintValue.Clean;
                foreach (var path in label.AllPaths) value = value.Join(stepped.Extend(path.Path).CleanedFor(path.CleanFor));
                if (!value.Any) continue;
                foreach (var model in _ctx.ModelKeys.Writes(StaticType(i.Operation))) KeyedWrite(model, value, site);
            }
        }
    }

    /// The static type of a value before its implicit conversions (a model given to `View(object model)`).
    private static ITypeSymbol? StaticType(IOperation? operation)
    {
        while (operation is IConversionOperation { IsImplicit: true, Operand: { } inner }) operation = inner;
        return operation?.Type;
    }

    private static string Describe(KeyedLocation location) => location.Store switch
    {
        KeyedStore.ViewData => location.Key == null ? "ViewData (a key built at run time)" : $"ViewData[\"{location.Key}\"]",
        KeyedStore.Items => location.Key == null ? "HttpContext.Items (a key built at run time)" : $"HttpContext.Items[\"{location.Key}\"]",
        _ => location.Key == null ? "the view's model (of no known type)" : "the view's model",
    };

    /// The keyed-store effects of a call: the model a view is rendered with (`View(model)`, `PartialView(model)`, a view
    /// component's `View(model)`, `Html.Partial*(name, model)`) is the view model; a dictionary method of ViewData or
    /// HttpContext.Items (`Add`, `TryAdd`: the value is written under the key; `TryGetValue`: the entry reaches the out
    /// value, joined after the call has overwritten it).
    private void KeyedCall(IOperation operation, IMethodSymbol method, IOperation? instance, Input[] inputs, TaintState state)
    {
        var model = KeyedStores.ModelParameter(method);
        if (model >= 0)
        {
            foreach (var i in inputs)
            {
                // Task 27: also a model without request data (what it knows of its members reaches the view).
                if (i.Ordinal != model) continue;
                var named = Named(i.Value, operation, "the view's model");
                foreach (var entry in _ctx.ModelKeys.Writes(StaticType(i.Operation))) KeyedWrite(entry, named, operation);
            }
            return;
        }
        if (KeyedStores.MethodStore(method, instance, Model()?.Compilation) is not { } store) return;
        IOperation? key = null;
        foreach (var i in inputs) if (i.Ordinal == 0) key = i.Operation;
        var location = KeyedStores.Location(store, key);
        foreach (var i in inputs)
        {
            if (i.Ordinal != 1) continue;
            if (method.Name == "TryGetValue")
            {
                if (i.RefKind == RefKind.Out && Keyed(location, operation) is { Any: true } read) Assign(i.Operation, Value(i.Operation, state).Join(read), state, operation);
            }
            else if (i.Value.Any)
            {
                KeyedWrite(location, Named(i.Value, operation, Describe(location), AnyKey(location)), operation);
            }
        }
    }

    /// The sinks of a call or constructor bound at run time: Roslyn's candidate members of the call (late bound; for a
    /// constructor, the type's constructors of that arity) whose sink argument at the same position is given request data. Only unconditional sinks (a `when:` condition reads the call's own
    /// operation tree); an argument passed by name is not matched.
    private void DynamicSinks(IOperation operation, ImmutableArray<IOperation> operands, Func<int, string?> argumentName, TaintValue[] arguments)
    {
        if (!Array.Exists(arguments, a => a.Any)) return;
        var candidates = Model()?.GetSymbolInfo(operation.Syntax).CandidateSymbols ?? ImmutableArray<ISymbol>.Empty;
        // A constructor bound at run time: the constructors of the type created that take that many arguments.
        if (candidates.IsEmpty && operation is IDynamicObjectCreationOperation { Type: INamedTypeSymbol created })
            candidates = created.InstanceConstructors.Where(c => c.Parameters.Length == arguments.Length).Cast<ISymbol>().ToImmutableArray();
        foreach (var candidate in candidates.OfType<IMethodSymbol>())
        {
            foreach (var hit in _ctx.Sinks.Sinks(candidate, Access.Call))
            {
                if (hit.Sink.When.Count > 0) continue;
                for (var k = 0; k < arguments.Length; k++)
                {
                    if (!arguments[k].Any || argumentName(k) != null) continue;
                    if (k < candidate.Parameters.Length && SinkFinder.IsSinkArgument(hit.Sink, candidate.Parameters[k]))
                        SinkReached(hit.RuleId, operands[k].Syntax, arguments[k], candidate);
                }
            }
        }
    }

    // ---- Sinks ----

    /// A value reaches a sink: its request data is a finding, each label tainted for the rule a sink of its body.
    private void SinkReached(string rule, SyntaxNode site, TaintValue value, ISymbol member)
    {
        if (value.TaintedFor(rule)) _ctx.Report(rule, site, value.WitnessFor(_body.Reach, rule), member);
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
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(property)}").ScopedTo(_body.WriteReach);
        if (_ctx.Sources.IsBoundProperty(property))
            result = result.Join(TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: bound property {_ctx.Name(property)}").ScopedTo(_body.WriteReach));
        var ownSource = RuleSource(property, Access.Get, operation.Instance, operation);

        var receiver = Value(operation.Instance, state);
        var isVirtual = Dispatch.IsVirtualAccess(property, operation.Instance);
        // Task 27: what the property's value is known to be (objects, members), from the member read or the getters.
        TaintValue? identity = null;
        var unknownIdentity = false;
        TaintValue Note(TaintValue v)
        {
            if (v.HasIdentity) identity = identity == null ? IdentityOf(v) : identity.Join(IdentityOf(v));
            else unknownIdentity = true;
            return v.WithoutIdentity();
        }
        if (SymbolKeys.InSource(property) && !isVirtual && _body.IsHeapMember(property))
        {
            foreach (var a in operation.Arguments) Value(a.Value, state);
            result = result.Join(Note(ReadMember(operation, property, receiver, state)));
        }
        else if (SymbolKeys.InSource(property) && property.GetMethod is { } getter)
        {
            var inputs = IndexInputs(operation, state, null);
            var targets = _body.Targets(getter, isVirtual, operation.Instance?.Type);
            if (state.HasFacts || _body.RootSymbolic) CallEffects(operation.Instance, receiver, inputs, state, targets, guards: false);
            foreach (var target in targets)
            {
                result = result.Join(Note(target.Kind switch
                {
                    TargetKind.Body => Apply(target.Body!, operation, property, Arguments(receiver, inputs), operation.Instance, inputs, false, state, exits: targets.Count == 1, kind: target.StepKind),
                    TargetKind.Auto => ThroughFallback(target, operation, property, ReadMember(operation, target.Method.AssociatedSymbol!, receiver, state)),
                    TargetKind.External => ThroughFallback(target, operation, property, ExternalRead((IPropertySymbol?)target.Method.AssociatedSymbol ?? property, operation, receiver, inputs)),
                    _ => Through(operation, property, receiver.Join(JoinInputs(inputs)), target.StepKind),
                }));
            }
        }
        else
        {
            unknownIdentity = true;
            result = result.Join(ExternalRead(property, operation, receiver, IndexInputs(operation, state, null)));
        }
        // A keyed request store entry (ViewData, HttpContext.Items) or the view's model (Task 22).
        if (KeyedStores.IndexerStore(operation, Model()?.Compilation) is { } store)
        {
            result = result.Join(Keyed(KeyedStores.Location(store, operation.Arguments[0].Value), operation));
        }
        else if (KeyedStores.IsViewModel(property))
        {
            // The model given to the view, with the members every model it may render is known to hold (Task 27).
            var model = Keyed(_ctx.ModelKeys.Reads(operation.Type), operation);
            // A member known when View() was called may be written later (in the action, a filter, the view itself):
            // what was written into the model's objects joins it (fix round 1, I2).
            if (model.Members is { IsAll: false } known)
                model = model with { Members = KnownLater(known, model.Objects, operation) };
            result = result.Join(model.WithoutIdentity());
            identity = IdentityOf(model);
            unknownIdentity = !model.HasIdentity;
        }
        if (!unknownIdentity && identity != null) result = result with { Objects = identity.Objects, Members = identity.Members };
        // An element of an allow-list table is one of its constants (`allow-list: literal-tables`).
        if (property.IsIndexer && result.Any && _ctx.Sinks.AllowListRules.Length > 0 && _ctx.AllowLists.IsTable(operation.Instance, Model()?.Compilation))
            result = result.CleanedFor(_ctx.Sinks.AllowListRules);
        // A keyed read the rule takes for no request data (`key:`/`key-is:` sanitizers: the request's Host header, R-E22).
        if (property.IsIndexer && result.Any && operation.Arguments.Length > 0)
            result = result.CleanedFor(_ctx.Sinks.SanitizesKey(property, operation.Arguments[0].Value));
        return result.CleanedFor(_ctx.Sinks.Sanitizes(property, Access.Get)).WithTaintOf(ownSource);
    }

    /// The request data a read or call is for the rules whose own source it is (a rule's `sources:`, Task 29): request
    /// data clean for every other rule, or clean when it is no rule's own source.
    private TaintValue RuleSource(ISymbol member, Access access, IOperation? instance, IOperation operation)
    {
        var rules = _ctx.Sources.RuleSourceOf(member, access, instance);
        if (rules.Count == 0) return TaintValue.Clean;
        return TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(member)}")
            .ScopedTo(_body.WriteReach).CleanedFor(_ctx.AllBut(rules));
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
                // A lookup key reaches only an element that can carry an injection by itself (ruling R-E18); its path is
                // a medium step (R-9, R-E29).
                if (p.Keys.Count > 0 && _ctx.Sources.CanCarryInjection(operation.Type))
                {
                    var later = _ctx.Sources.CarriesOnlyAsTypeParameter(operation.Type);
                    foreach (var i in index)
                    {
                        if (!p.Keys.Contains(i.Ordinal) || !i.Value.Any) continue;
                        var key = i.Value.Step(operation.Syntax.GetLocation(), $"looked up by key in {_ctx.Name(property)}", StepKind.KeyLookup);
                        result = result.Join(later ? key.ViaKey() : key);
                    }
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
        if (KeyedStores.IndexerStore(operation, Model()?.Compilation) is { } store)
        {
            var location = KeyedStores.Location(store, operation.Arguments[0].Value);
            KeyedWrite(location, Named(value, assignment, Describe(location), AnyKey(location)), assignment);
        }
        else if ((value.Any || value.HasIdentity) && (KeyedStores.IsPartialModel(property) || (KeyedStores.IsViewModel(property) && KeyedStores.IsViewData(operation.Instance?.Type))))
        {
            // `<partial model="…">` gives the partial its model; `ViewData.Model = m` sets the view's model. A view data
            // dictionary given an object or dynamic model is a view engine's own plumbing (a shape renderer that every
            // view goes through): not written, or every view of the solution would read it (fix round 1, M1).
            var model = assignment is ISimpleAssignmentOperation simple ? simple.Value : null;
            var type = StaticType(model);
            if (KeyedStores.IsPartialModel(property) || !(type == null || type.SpecialType == SpecialType.System_Object || type.TypeKind is TypeKind.Dynamic or TypeKind.Error))
            {
                var named = Named(value, assignment, "the view's model");
                foreach (var location in _ctx.ModelKeys.Writes(type)) KeyedWrite(location, named, assignment);
            }
        }
        // A setter other than an auto-property's runs code on its receiver: as a call given the receiver (Task 21).
        var setters = SymbolKeys.InSource(property) && property.SetMethod is { } setterMethod ? _body.Targets(setterMethod, Dispatch.IsVirtualAccess(property, operation.Instance), operation.Instance?.Type) : null;
        if ((state.HasFacts || _body.RootSymbolic) && !(SymbolKeys.InSource(property) && _body.IsHeapMember(property))) CallEffects(operation.Instance, receiver, inputs, state, setters);
        foreach (var hit in _ctx.Sinks.Sinks(property, Access.Set))
            if (value.Any && (hit.Sink.When.Count == 0 || _ctx.Conditions.Check(hit.Sink, assignment, -1, Model()).Holds))
                SinkReached(hit.RuleId, assignment.Syntax, value, property);

        if (SymbolKeys.InSource(property))
        {
            var isVirtual = Dispatch.IsVirtualAccess(property, operation.Instance);
            if (property.SetMethod is not { } setter || (!isVirtual && _body.IsHeapMember(property)))
            {
                // A get-only auto-property assigned in a constructor has no setter: its hidden field is written.
                if (_body.IsHeapMember(property)) AssignMember(property, operation.Instance, receiver, value, state, assignment, operation);
                else if (operation.Instance != null) Write(operation.Instance, value, state);
                return;
            }
            var targets = setters ?? _body.Targets(setter, isVirtual, operation.Instance?.Type);
            foreach (var target in targets)
            {
                switch (target.Kind)
                {
                    case TargetKind.Body:
                        Apply(target.Body!, assignment, property, Arguments(receiver, inputs), operation.Instance, inputs, false, state, exits: targets.Count == 1, kind: target.StepKind);
                        break;
                    case TargetKind.Auto:
                        AssignMember(target.Method.AssociatedSymbol!, operation.Instance, receiver, value, state, assignment, targets.Count == 1 ? operation : null);
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
        TaintValue? value = null;
        foreach (var i in inputs) if (i.Ordinal == slot && i.RefKind != RefKind.Out) value = value == null ? i.Value : value.Join(i.Value);
        return value ?? TaintValue.Clean;
    };

    /// The value an auto-property or external target gives a call the class-hierarchy fallback resolved to it (fix round
    /// 1 of Task 28, M2): with a dispatch-fallback step, as a body target's call steps have (R-9); other targets as is.
    private TaintValue ThroughFallback(Target target, IOperation site, ISymbol member, TaintValue value) =>
        target.Fallback && value.Any ? value.Step(site.Syntax.GetLocation(), $"passed through {_ctx.Name(member)}", StepKind.DispatchFallback) : value;

    /// What passes through a member that has no body to analyse: its receiver and arguments, to its result.
    private TaintValue Through(IOperation site, ISymbol member, TaintValue inputs, StepKind kind = StepKind.Plain) =>
        inputs.Any ? inputs.Step(site.Syntax.GetLocation(), $"passed to {_ctx.Name(member)}", kind) : inputs;

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
        var format = _ctx.Sinks.HasStringSanitizers && method is { Name: "Format", ContainingType.SpecialType: SpecialType.System_String } ? FormatText(arguments) : null;
        foreach (var a in arguments)
        {
            var refKind = a.Parameter?.RefKind ?? RefKind.None;
            var value = refKind == RefKind.Out ? TaintValue.Clean
                : format != null && a.ArgumentKind is ArgumentKind.ParamArray or ArgumentKind.ParamCollection ? FormatParams(a.Value, format, state)
                : Value(a.Value, state);
            var ordinal = (a.Parameter?.Ordinal ?? -2) + (reduced ? 1 : 0);
            var parameter = definition != null && ordinal >= 0 && ordinal < definition.Parameters.Length ? definition.Parameters[ordinal] : null;
            inputs[n++] = new Input(ordinal, parameter, a.Value, a.IsImplicit ? a.Value.Syntax : a.Syntax, value, refKind);
        }
        if (n < inputs.Length) Array.Resize(ref inputs, n);
        if (format != null) FormatPlaced(inputs, format);
        var targets = method == null || method.MethodKind == MethodKind.DelegateInvoke ? null : _body.Targets(method, isVirtual, instance?.Type);
        // A record's `with` copies its receiver (ruling R-E31): it changes nothing; the copy is a new allocation site whose
        // members start as the source's.
        var copy = instance != null && method is { Name: "<Clone>$", Parameters.Length: 0 };
        if (copy) return CopyOf(operation, receiver);
        if (state.HasFacts || _body.RootSymbolic) CallEffects(instance, receiver, inputs, state, targets);
        if (method != null) GuardArguments(operation, method, inputs, state);
        HigherOrder(inputs, instanceValue, state, definition);

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
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(method)}").ScopedTo(_body.WriteReach);
        var ownSource = RuleSource(method, Access.Call, instance, operation);
        var sourced = result;

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
            // Task 27: the objects and members of the result, from the bodies' summaries (unknown when another target runs).
            var identity = TaintValue.Bottom;
            var unknownIdentity = false;
            foreach (var target in targets!)
            {
                switch (target.Kind)
                {
                    case TargetKind.Body:
                    {
                        anyBody = true;
                        var applied = Apply(target.Body!, operation, method, Arguments(instanceValue, inputs), reduced ? null : instance, inputs, constructor, state,
                            dropViaKey: _ctx.ValueFactories(definition) != null, exits: targets!.Count == 1, kind: target.StepKind);
                        identity = identity.Join(IdentityOf(applied));
                        result = result.Join(applied.WithoutIdentity());
                        break;
                    }
                    case TargetKind.External:
                        unknownIdentity = true;
                        result = target.Fallback
                            ? result.Join(ThroughFallback(target, operation, method, External(target.Method, operation, inputs, receiver, thisOperation, reduced && instance != null, all, TaintValue.Clean, state)))
                            : External(target.Method, operation, inputs, receiver, thisOperation, reduced && instance != null, all, result, state);
                        break;
                    default:
                    {
                        unknownIdentity = true;
                        var through = Through(operation, method, all.WithoutIdentity(), target.StepKind);
                        result = result.Join(through);
                        foreach (var i in inputs)
                            if (i.RefKind is RefKind.Out or RefKind.Ref) Assign(i.Operation, through, state, i.Operation);
                        break;
                    }
                }
            }
            if (!unknownIdentity && !ReferenceEquals(identity, TaintValue.Bottom) && identity.HasIdentity)
                result = result with { Objects = identity.Objects, Members = identity.Members };
            // A LINQ projection gives what its selector returns, a value factory cache what its factory makes (Task 23).
            if (Produced(definition, inputs) is { } produced)
                result = sourced.Join(produced.Any ? produced.Step(operation.Syntax.GetLocation(), $"returned by {_ctx.Name(method)}") : produced);
            // `lookup:` sanitizers: what a method the engine cannot see into returns under a lookup's name (a record
            // found by an id) is stored data for those rules; a method with a body is followed instead.
            if (!anyBody && result.Any && method.MethodKind == MethodKind.Ordinary) result = result.CleanedFor(_ctx.Sinks.Lookups(method.Name));
            if (!anyBody && method.MethodKind == MethodKind.Ordinary && _ctx.Sinks.HasAwaitedLookups) _bodyless.Add(operation);
        }

        if (_ctx.Sinks.AllowListRules.Length > 0 && method.Name is "GetValueOrDefault" or "TryGetValue" && thisOperation != null
            && _ctx.AllowLists.IsTable(thisOperation, Model()?.Compilation))
            result = TableLookup(method, inputs, result, state);

        // A keyed read through a method (`Headers.TryGetValue("Host", out v)`): its out values are clean for the rules
        // whose keyed method sanitizers it is (R-E22, M1 of the Task 29 review).
        var keyIndex = _ctx.Sinks.HasKeyCalls && instance != null && !reduced ? Array.FindIndex(inputs, i => i.Ordinal == 0 && i.RefKind != RefKind.Out) : -1;
        if (keyIndex >= 0)
        {
            var receiverOperation = instance;
            while (receiverOperation is IConversionOperation { Operand: { } inner }) receiverOperation = inner;
            var rules = _ctx.Sinks.SanitizesKeyCall(method, receiverOperation!.Type, inputs[keyIndex].Operation);
            if (rules.Count > 0)
                foreach (var i in inputs)
                    if (i.RefKind == RefKind.Out && Value(i.Operation, state) is { Any: true } v) Assign(i.Operation, v.CleanedFor(rules), state, i.Operation);
        }

        KeyedCall(operation, method, instance, inputs, state);
        if (IsUpdateModel(method)) UpdateModel(operation, method, inputs, state);
        result = result.CleanedFor(_ctx.Sinks.Sanitizes(method, Access.Call));
        if (result.Any)
        {
            result = result.CleanedFor(_ctx.Sinks.SanitizesByName(method));
            var receiverOperation = instance;
            while (receiverOperation is IConversionOperation { Operand: { } inner }) receiverOperation = inner;
            result = result.CleanedFor(_ctx.Sinks.SanitizesOnReceiver(method, receiverOperation?.Type));
        }
        return result.WithTaintOf(ownSource);
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

    /// The known text of string.Format's `format` argument (a constant, or a helper's returned text: KnownText), or null.
    private string? FormatText(ImmutableArray<IArgumentOperation> arguments)
    {
        foreach (var a in arguments)
            if (a.Parameter?.Name == "format") return KnownText(a.Value);
        return null;
    }

    /// The values given to string.Format's params array (`params object[]`, `params ReadOnlySpan<object>`): each element
    /// cleaned as a value placed after the format's text before its placeholder (as FormatPlaced), joined.
    private TaintValue FormatParams(IOperation operation, string format, TaintState state)
    {
        IEnumerable<IOperation>? elements = operation switch
        {
            IArrayCreationOperation { Initializer: { } initializer } => initializer.ElementValues,
            ICollectionExpressionOperation collection => collection.Elements,
            _ => null,
        };
        if (elements == null) return Value(operation, state);
        var value = TaintValue.Clean;
        var index = 0;
        foreach (var element in elements)
        {
            var v = Value(element, state);
            if (v.Any && FormatPrefix(format, index) is { } prefix)
            {
                var expression = element;
                while (expression is IConversionOperation { IsImplicit: true, Operand: { } inner }) expression = inner;
                v = v.CleanedFor(_ctx.Sinks.CleanInString(prefix, expression.Type));
            }
            value = value.Join(v);
            index++;
        }
        return value;
    }

    /// string.Format with a known format (a constant, or a helper's text): each of arg0, arg1 and arg2 is cleaned as a
    /// value placed after the format's text before its first placeholder (earlier placeholders read as Hole); the
    /// elements of a params array are cleaned likewise (FormatParams).
    private void FormatPlaced(Input[] inputs, string format)
    {
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
    /// With `dropViaKey` (a value-factory shaped call, ruling R-E23) the result loses what reached the callee's return
    /// only as the key of a type-parameter-typed lookup (Label.ViaKey); the rest of its return is kept. `kind`: the kind
    /// of the call's path steps (Target.StepKind: medium for a class-hierarchy fallback, R-9).
    ///
    /// Task 27 (decision R-8): a constructor's receiver is the object its `new` makes; a member slot of the callee is what
    /// the call's argument holds in that member (MemberArg); the callee's ObjWrites are written into the objects its
    /// arguments hold; with `exits` (the call's only target), its ParamExit members hold exactly in the arguments that are
    /// variables (a constructor's: in the object made) after the call.
    private TaintValue Apply(Body callee, IOperation site, ISymbol member, Func<int, TaintValue> argument, IOperation? receiverOperation,
        Input[] inputs, bool constructor, TaintState state, bool dropViaKey = false, bool exits = false, StepKind kind = StepKind.Plain)
    {
        _body.Depend(callee);
        Location? location = null;
        var name = _ctx.Name(callee.Symbol ?? member);
        var s = callee.Summary;
        if (constructor && site is IObjectCreationOperation)
        {
            var created = TaintValue.Clean with { Objects = _ctx.Objects.Single(_ctx.Objects.Site(site.Syntax)) };
            var given = argument;
            argument = slot => slot == -1 ? created : given(slot);
        }
        var raw = argument;
        Dictionary<int, TaintValue>? members = null;
        argument = slot =>
        {
            if (!ObjectTable.IsMemberSlot(slot)) return raw(slot);
            members ??= new Dictionary<int, TaintValue>();
            if (members.TryGetValue(slot, out var v)) return v;
            members[slot] = TaintValue.Clean; // a write of the member that reads it (`p.M += x`) asks for it again
            return members[slot] = MemberArg(slot, raw, site, callee, argument!);
        };
        if (callee.Symbol is { } symbol)
        {
            for (var slot = symbol.IsStatic || constructor ? 0 : -1; slot < symbol.Parameters.Length; slot++)
            {
                if (slot >= 0 && symbol.Parameters[slot].RefKind == RefKind.Out) continue;
                var v = argument(slot).WithoutIdentity();
                if (!v.Any) continue;
                location ??= site.Syntax.GetLocation();
                _body.Pass(callee, slot, v.Step(location, $"passed to {name}", kind));
            }
        }
        foreach (var slot in s.MemberSlots)
        {
            var v = argument(slot);
            if (!v.Any) continue;
            location ??= site.Syntax.GetLocation();
            _body.Pass(callee, slot, v.Step(location, $"passed to {name}", kind));
        }
        if (!s.Heap.IsEmpty) GenericModels(s, callee, site, name, inputs, kind);
        if (s.NoLocalEffects) return TaintValue.Clean;
        location ??= site.Syntax.GetLocation();
        var result = BodySummary.Substitute(s.Return, callee.Id, argument, location, name, _body.Keeps, _body.WriteReach, dropViaKey, _ctx.Objects, kind);
        foreach (var ((slot, _), (written, symbolic)) in s.ObjWrites)
        {
            var v = BodySummary.Substitute(symbolic, callee.Id, argument, location, name, _body.Keeps, _body.WriteReach, kind: kind).WithoutIdentity();
            if (v.Any) _body.HeapWrite(written, v, argument(slot).Objects);
        }
        if (exits && s.ParamExit is { Count: > 0 } paramExit && (callee.Symbol is not { IsAsync: true } || AwaitedDirectly(site)))
        {
            foreach (var (slot, fixedMembers) in paramExit)
            {
                // What the callee's exit leaves in the caller's members is a heap read there (ruling R-E35, as MemberArg).
                var exitAt = location;
                var substituted = fixedMembers.Select(v =>
                {
                    var x = BodySummary.Substitute(v, callee.Id, argument, exitAt, name, _body.Keeps, _body.WriteReach, false, _ctx.Objects, kind);
                    return x.Any ? x.Step(exitAt, $"written by {name}", StepKind.HeapRead) : x;
                });
                if (substituted is not { IsAll: false } known) continue;
                if (slot == -1 && constructor && site is IObjectCreationOperation)
                {
                    result = result with { Members = known };
                    continue;
                }
                IOperation? given = slot == -1 ? receiverOperation : null;
                if (slot >= 0)
                    foreach (var i in inputs)
                        if (i.Ordinal == slot && i.RefKind == RefKind.None) given = given == null ? i.Operation : null;
                if (RootOf(given) is not { } root) continue;
                foreach (var (m, v) in known.Values)
                    if (state.Facts.Length < MaxHolds && MemberPath(root.Root, root.Type, m) is { } path && CanHold(path)) state.SetHolds(path, v);
            }
        }
        if (s.ToThis.Any)
        {
            var written = BodySummary.Substitute(s.ToThis, callee.Id, argument, location, name, _body.Keeps, _body.WriteReach, kind: kind);
            if (constructor) result = result.Join(written);
            else if (receiverOperation != null) WriteReceiver(receiverOperation, written, state);
        }
        foreach (var (ordinal, symbolic) in s.Refs)
        {
            var v = BodySummary.Substitute(symbolic, callee.Id, argument, location, name, _body.Keeps, _body.WriteReach, kind: kind);
            foreach (var i in inputs)
                if (i.Ordinal == ordinal && i.RefKind is RefKind.Ref or RefKind.Out) Assign(i.Operation, v, state, i.Operation);
        }
        return result;
    }

    /// A record copy (`source with { ... }`, ruling R-E31): the source's taint, a new allocation site whose members start
    /// as the source's (its objects too, so a read of a member the copy did not set reads the source's; a write through
    /// the copy reaches them as well, weakly) and the members the source knew exactly. The initializer's assignments
    /// follow on the copy.
    private TaintValue CopyOf(IOperation operation, TaintValue source)
    {
        var site = _ctx.Objects.Single(_ctx.Objects.Site(operation.Syntax));
        return source.WithoutIdentity() with { Objects = source.Objects == null ? null : ObjSet.Union(site, source.Objects), Members = source.Members is { IsAll: false } m ? m : null };
    }

    /// `TryUpdateModelAsync(model, ...)` of a controller or page model: the model binder sets the model's members from the
    /// request (ruling R-E31).
    private static bool IsUpdateModel(IMethodSymbol method) =>
        method.Name is "TryUpdateModelAsync" or "TryUpdateModel" && !SymbolKeys.InSource(method)
        && method.ContainingType is { } type && SymbolMatch.MetadataName(type.OriginalDefinition) is
            "Microsoft.AspNetCore.Mvc.ControllerBase" or "Microsoft.AspNetCore.Mvc.RazorPages.PageModel";

    /// The model given to the binder (its first argument) holds request data in every member, as a bound parameter does:
    /// the variable as a whole, and each instance field and auto-property of its type declared in source through its
    /// known objects (fix round 2, R1-M1: in a helper that is a write into its parameter's objects, which its callers
    /// get; unknown objects are not written member by member, which would reach every object of the type).
    private void UpdateModel(IOperation operation, IMethodSymbol method, Input[] inputs, TaintState state)
    {
        foreach (var i in inputs)
        {
            if (i.Ordinal != 0 || i.RefKind == RefKind.Out) continue;
            var bound = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(method)}").ScopedTo(_body.WriteReach);
            Write(i.Operation, bound, state);
            if (i.Value.Objects is not { IsEmpty: false } objects || StaticType(i.Operation) is not INamedTypeSymbol type) continue;
            for (var t = type; t != null && SymbolKeys.InSource(t); t = t.BaseType)
                foreach (var member in t.GetMembers())
                    if (member is IFieldSymbol or IPropertySymbol && !member.IsStatic && _body.IsHeapMember(member))
                        _body.HeapWrite(member, bound, objects);
        }
    }

    /// What a call's argument holds in member M, for the callee's member slot of (k, M) (Task 27): the member's exact
    /// value when the argument knows it; else the argument's whole taint (unless the member's type is
    /// never request data) and the heap's part of the member through the argument's objects (MemberHeap: a parameter
    /// object of the caller becomes the caller's own member slot).
    ///
    /// The exact member stands only when the callee cannot change it on its way (fix round 1 of Task 27, C2): its summary
    /// writes no (k, M) into the parameter's objects, its component writes no M through unknown objects, and k does not
    /// escape. Otherwise the exact value is joined with what the callee writes there and with the heap's part.
    private TaintValue MemberArg(int slot, Func<int, TaintValue> argument, IOperation site, Body callee, Func<int, TaintValue> substituted)
    {
        var (k, member) = _ctx.Objects.OfMemberSlot(slot);
        var a = argument(k);
        var type = member is IFieldSymbol f ? f.Type : (member as IPropertySymbol)?.Type;
        var neverSource = type != null && _ctx.Sources.IsNeverSourceType(type);
        if (a.Members is { IsAll: false } known && known.TryGet(member, out var exact))
        {
            var s = callee.Summary;
            TaintValue? written = null;
            foreach (var ((wslot, _), (symbol, value)) in s.ObjWrites)
                if (wslot == k && SymbolEqualityComparer.Default.Equals(symbol, member)) written = value;
            var top = s.TopWrites?.Contains(SymbolKeys.Of(member)) == true;
            // A member the caller wrote into a known object, read in the callee: a heap read (R-9, R-E29).
            var held = exact.WithoutIdentity();
            if (held.Any) held = held.Step(site.Syntax.GetLocation(), $"read from {_ctx.Name(member)}", StepKind.HeapRead);
            if (written == null && !top && !s.Escapes.Contains(k)) return held;
            var joined = held.Join(MemberHeap(member, a.Objects, site, neverSource));
            if (written != null)
                joined = joined.Join(BodySummary.Substitute(written, callee.Id, substituted, site.Syntax.GetLocation(), _ctx.Name(callee.Symbol ?? member), _body.Keeps, _body.WriteReach).WithoutIdentity());
            return joined;
        }
        var whole = neverSource ? TaintValue.Clean : a.WithoutIdentity();
        return whole.Join(MemberHeap(member, a.Objects, site, neverSource));
    }

    /// Whether a call is awaited where it is made (an async callee's writes are done when the await returns).
    private static bool AwaitedDirectly(IOperation call)
    {
        var parent = call.Parent;
        while (parent is IConversionOperation or IInvocationOperation { TargetMethod.Name: "ConfigureAwait" }) parent = parent.Parent;
        return parent is IAwaitOperation;
    }

    /// Lambdas and method groups given to a call get the join of the call's receiver and other arguments in their
    /// parameters (open item (b) of Task 7, for external and source callees alike): a lambda through its seed, a method
    /// group by applying its targets' summaries to it (that result is then the argument's value). SelectMany's result
    /// selector also gets what its collection selector returns, the elements it pairs with each source element (fix
    /// round 1 of Task 23, I1: the compiled form of a query with two `from` clauses).
    private void HigherOrder(Input[] inputs, TaintValue receiver, TaintState state, IMethodSymbol? definition = null)
    {
        var any = false;
        foreach (var i in inputs) if (DelegateOf(i.Operation) != null) any = true;
        if (!any) return;
        var others = receiver;
        foreach (var i in inputs)
            if (i.RefKind != RefKind.Out && DelegateOf(i.Operation) == null) others = others.Join(i.Value);
        var (collection, resultSelector) = definition == null ? (-1, -1) : SelectManyPair(definition);
        var outer = others;
        for (var k = 0; k < inputs.Length; k++)
        {
            others = outer;
            if (inputs[k].Ordinal == resultSelector)
                foreach (var c in inputs) if (c.Ordinal == collection) others = others.Join(c.Value);
            switch (DelegateOf(inputs[k].Operation))
            {
                case IFlowAnonymousFunctionOperation lambda:
                    _body.Seed(lambda.Symbol, others);
                    break;
                case IMethodReferenceOperation reference:
                {
                    // Its value is what the method returns given them (also with clean inputs: what it reads itself); an
                    // external method passes them unless it returns a scalar, cleaned as its sanitizers clean (Task 23).
                    var instance = Value(reference.Instance, state);
                    var value = TaintValue.Clean;
                    foreach (var target in _body.Targets(reference.Method, reference.IsVirtual, reference.Instance?.Type))
                    {
                        value = value.Join(target.Kind == TargetKind.Body
                            ? Apply(target.Body!, inputs[k].Operation, reference.Method, slot => slot == -1 ? instance : others, reference.Instance, Array.Empty<Input>(), false, state, kind: target.StepKind)
                            : _ctx.Sources.IsScalar(reference.Method.ReturnType) || !others.Any ? TaintValue.Clean
                            : ThroughFallback(target, inputs[k].Operation, reference.Method,
                                others.CleanedFor(_ctx.Sinks.Sanitizes(reference.Method, Access.Call)).CleanedFor(_ctx.Sinks.SanitizesByName(reference.Method))));
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
            foreach (var p in propagators)
            {
                if (!OverloadFits(p, method)) continue;
                // `only-for:` (Task 29): what the propagator returns stays request data for those rules only.
                result = p.OnlyFor.Count == 0
                    ? Propagate(p, operation, method, inputs, receiver, thisOperation, reducedThis, result, state)
                    : result.Join(Propagate(p, operation, method, inputs, receiver, thisOperation, reducedThis, TaintValue.Clean, state).CleanedFor(_ctx.AllBut(p.OnlyFor)));
            }
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

        // Collection and interpolated-string-handler writes taint their receiver. A dictionary's key is not written into
        // it (as for `d[k] = v`): what a lookup finds is the value stored (ruling R-E18), so a cache keyed by request data
        // does not make every element it holds request data.
        if (thisOperation != null && all.Any && IsCollectionWrite(method))
        {
            var dictionary = IsDictionary(method.IsExtensionMethod ? (method.ReducedFrom ?? method).Parameters.FirstOrDefault()?.Type : method.ContainingType);
            var written = TaintValue.Clean;
            foreach (var i in inputs)
                if (i.RefKind != RefKind.Out && !ReferenceEquals(i.Operation, thisOperation) && !(dictionary && i.Parameter?.Name == "key")) written = written.Join(i.Value);
            Write(thisOperation, written, state);
        }
        return result;
    }

    /// Whether a propagator's `param-types:` (Task 29) admit this overload: each of its `from` ordinals names a parameter
    /// of one of those types (in the method's definition; an extension method's `this` is 0).
    private static bool OverloadFits(PropagatorModel p, IMethodSymbol method)
    {
        if (p.ParamTypes.Count == 0) return true;
        var parameters = (method.ReducedFrom ?? method).OriginalDefinition.Parameters;
        foreach (var f in p.From)
        {
            if (!int.TryParse(f, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var ordinal)
                || ordinal >= parameters.Length || !p.ParamTypes.Contains(SymbolMatch.MetadataName(parameters[ordinal].Type))) return false;
        }
        return true;
    }

    /// A dictionary: a type that is or implements IDictionary<K, V> or IReadOnlyDictionary<K, V>.
    private static bool IsDictionary(ITypeSymbol? type)
    {
        if (type == null) return false;
        static bool Named(ITypeSymbol t) => SymbolMatch.MetadataName(t.OriginalDefinition) is
            "System.Collections.Generic.IDictionary`2" or "System.Collections.Generic.IReadOnlyDictionary`2";
        return Named(type) || type.AllInterfaces.Any(Named);
    }

    /// What a call gives back when it is a LINQ projection (Task 23): the join of the values of its selectors (a lambda's
    /// return, a method group's result), or null when it is none, or when a selector is not a lambda or method group
    /// given here (ruling R-E23: a delegate parameter, field or local was not seeded with this call's elements):
    /// System.Linq.Enumerable's Select (its selector), SelectMany (its result selector, else its collection selector),
    /// ToDictionary and ToLookup with an element selector (the key and element selectors); the other operators keep their
    /// source's elements and pass the source on (propagators.yml). A value-factory shaped project method (AnalysisContext.
    /// ValueFactories) is applied as any call, without what only a lookup key gave its result (Apply, dropViaKey).
    private TaintValue? Produced(IMethodSymbol definition, Input[] inputs)
    {
        var ordinals = LinqSelectors(definition);
        if (ordinals == null) return null;
        var value = TaintValue.Clean;
        var found = false;
        foreach (var i in inputs)
        {
            if (Array.IndexOf(ordinals, i.Ordinal) < 0) continue;
            // Ruling R-E23: only a lambda or a method group given here is a known selector (seeded with this call's
            // source); a delegate parameter, field or local keeps the old rule, the source sequence passing on.
            if (DelegateOf(i.Operation) == null) return null;
            value = value.Join(i.Value);
            found = true;
        }
        return found ? value : null;
    }

    private static int[]? LinqSelectors(IMethodSymbol definition)
    {
        if (definition.Name is not ("Select" or "SelectMany" or "ToDictionary" or "ToLookup")) return null;
        if (definition.ContainingType is not { } type || SymbolMatch.MetadataName(type) != "System.Linq.Enumerable") return null;
        int Ordinal(string name) => definition.Parameters.FirstOrDefault(p => p.Name == name)?.Ordinal ?? -1;
        return definition.Name switch
        {
            "Select" => new[] { Ordinal("selector") },
            "SelectMany" => Ordinal("resultSelector") is var r and >= 0 ? new[] { r } : new[] { Ordinal("selector"), Ordinal("collectionSelector") },
            _ => Ordinal("elementSelector") is var e and >= 0 ? new[] { Ordinal("keySelector"), e } : null,
        };
    }

    /// SelectMany's collection selector and result selector ordinals, or (-1, -1).
    private static (int Collection, int Result) SelectManyPair(IMethodSymbol definition)
    {
        if (definition.Name != "SelectMany" || definition.ContainingType is not { } type || SymbolMatch.MetadataName(type) != "System.Linq.Enumerable")
            return (-1, -1);
        int Ordinal(string name) => definition.Parameters.FirstOrDefault(p => p.Name == name)?.Ordinal ?? -1;
        var result = Ordinal("resultSelector");
        return result < 0 ? (-1, -1) : (Ordinal("collectionSelector"), result);
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
        // A lookup key (`key:`) reaches a `return` or `out` value only when that value can carry an injection by itself
        // (ruling R-E18): an object found by a request key is not request data.
        var key = TaintValue.Clean;
        foreach (var i in inputs)
            if (i.RefKind != RefKind.Out && p.Keys.Contains(i.Ordinal)) key = key.Join(i.Value);
        if (!from.Any && !key.Any) return result;
        var site = operation.Syntax.GetLocation();
        var through = $"passed through {_ctx.Name(method)}";
        from = from.Any ? from.Step(site, through) : from;
        // What only the key gives the element found is a medium step (R-9, R-E29); the collection's own data stays high.
        var byKey = key.Any ? key.Step(site, $"looked up by key in {_ctx.Name(method)}", StepKind.KeyLookup) : TaintValue.Clean;
        var keyed = key.Any ? from.Join(byKey) : TaintValue.Clean;
        var keyedLater = key.Any ? from.Join(byKey.ViaKey()) : TaintValue.Clean;
        // An element typed by a type parameter may or may not carry: the key's labels pass marked (Label.ViaKey, R-E23).
        TaintValue For(ITypeSymbol? type) => !key.Any || !_ctx.Sources.CanCarryInjection(type) ? from
            : _ctx.Sources.CarriesOnlyAsTypeParameter(type) ? keyedLater : keyed;
        foreach (var t in p.To)
        {
            switch (t)
            {
                case "return":
                    result = result.Join(For(operation.Type));
                    break;
                case "this":
                    if (thisOperation != null && from.Any) Write(thisOperation, from, state);
                    break;
                case "out":
                    foreach (var i in inputs)
                    {
                        if (i.RefKind == RefKind.Out) Assign(i.Operation, For(i.Operation.Type), state, i.Operation);
                        else if (i.RefKind == RefKind.Ref && from.Any) Write(i.Operation, from, state);
                    }
                    break;
                default:
                    foreach (var i in inputs)
                        if (from.Any && IsOrdinal(t, i.Ordinal)) Write(i.Operation, from, state);
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
