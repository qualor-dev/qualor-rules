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

    /// One finding per rule and sink site; the first path found is kept.
    public void Report(string rule, Location sink, TaintValue value, ISymbol member)
    {
        var key = (rule, sink.SourceTree?.FilePath ?? "", sink.SourceSpan);
        if (_findings.ContainsKey(key)) return;
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
/// - Join at block entries: TaintState.JoinWith. Branches are not yet told apart (guards: Task 11); a catch, filter or
///   finally block (no predecessors in the graph) starts from the join of every block's exit state.
/// - Values of a scalar type (sources.yml `scalars`, enums, void) are always clean.
/// - Calls of members declared in source and delegate invocations: TEMPORARY (Task 7, until Task 8's summaries) the
///   result is the join of the receiver's and the arguments' taint, which is also written to out and ref arguments;
///   properties declared in source likewise return their object's and index arguments' taint.
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
    private readonly Dictionary<CaptureId, HashSet<object>> _aliases = new();

    public MethodAnalyzer(AnalysisContext ctx, ControlFlowGraph cfg)
    {
        _ctx = ctx;
        _cfg = cfg;
    }

    /// False when the fixed point hit its iteration cap (the result is then partial).
    public bool Complete { get; private set; } = true;

    /// Runs the dataflow from `entry`; returns the join of the states at every program point (what a lambda or local
    /// function declared here may capture).
    public TaintState Run(TaintState entry)
    {
        var blocks = _cfg.Blocks;
        var inStates = new TaintState?[blocks.Length];
        var outStates = new TaintState?[blocks.Length];
        var handlerEntries = blocks.Where(b => b.Kind == BasicBlockKind.Block && b.Predecessors.IsEmpty && b.IsReachable)
            .Select(b => b.Ordinal).ToArray();
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
            foreach (var operation in block.Operations) Value(operation, state);
            if (block.BranchValue != null) Value(block.BranchValue, state);
            outStates[ordinal] = state;

            if (block.FallThroughSuccessor?.Destination is { } next) Flow(next.Ordinal, state);
            if (block.ConditionalSuccessor?.Destination is { } jump) Flow(jump.Ordinal, state);
            foreach (var handler in handlerEntries) Flow(handler, state);
        }

        var all = new TaintState();
        foreach (var s in inStates) if (s != null) all.JoinWith(s);
        foreach (var s in outStates) if (s != null) all.JoinWith(s);
        return all;

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
                Value(field.Instance, state);
                return state.Get(field.Field.OriginalDefinition);

            case IFlowCaptureOperation capture:
            {
                var value = Value(capture.Value, state);
                state.Set(capture.Id, value);
                if (Holder(capture.Value) is { } holder)
                {
                    if (!_aliases.TryGetValue(capture.Id, out var set)) _aliases[capture.Id] = set = new HashSet<object>(SymbolOrCapture.Comparer);
                    set.Add(holder);
                }
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
                state.Set(capture.Id, value);
                break;
            case IFieldReferenceOperation field:
            {
                Value(field.Instance, state);
                var named = Named(value, assignment, field.Field.Name);
                // Fields by symbol, within this method only (the heap across methods is Task 8): a strong update for a
                // static field or one of `this`, a weak one through another instance.
                if (field.Instance is null or IInstanceReferenceOperation) state.Set(field.Field.OriginalDefinition, named);
                else state.Add(field.Field.OriginalDefinition, named);
                break;
            }
            case IPropertyReferenceOperation property:
            {
                Value(property.Instance, state);
                foreach (var a in property.Arguments) Value(a.Value, state);
                foreach (var hit in _ctx.Sinks.Sinks(property.Property, Access.Set))
                    if (value.TaintedFor(hit.RuleId)) _ctx.Report(hit.RuleId, assignment.Syntax.GetLocation(), value, property.Property);
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

    private TaintValue Named(TaintValue value, IOperation assignment, string name) =>
        value.Request ? value.Step(assignment.Syntax.GetLocation(), $"assigned to '{name}'") : value;

    /// What holds the value of an operation, when it is a variable the state tracks: a local, a parameter, a field, a
    /// flow capture.
    private static object? Holder(IOperation operation) => operation switch
    {
        ILocalReferenceOperation l => l.Local,
        IParameterReferenceOperation p => p.Parameter,
        IFieldReferenceOperation f => f.Field.OriginalDefinition,
        IConversionOperation c => Holder(c.Operand),
        _ => null,
    };

    /// A weak write into what `operation` refers to (a collection, a builder): the variable that holds it, a flow capture
    /// and the variables it captured, or the receiver of a fluent call that returns its receiver (a propagator to both
    /// `this` and `return`: `sb.Append(a).Append(b)`).
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
                state.Add(f.Field.OriginalDefinition, value);
                break;
            case IFlowCaptureReferenceOperation c:
                state.Add(c.Id, value);
                if (_aliases.TryGetValue(c.Id, out var holders))
                    foreach (var h in holders) state.Add(h, value);
                break;
            case IConversionOperation conversion:
                Write(conversion.Operand, value, state);
                break;
            case IInvocationOperation invocation when IsFluent(invocation.TargetMethod) && ThisOperation(invocation) is { } receiver:
                Write(receiver, value, state);
                break;
        }
    }

    private bool IsFluent(IMethodSymbol method) =>
        !IsInSource(method) && _ctx.Propagators.Match(method, Access.Call).Any(p => p.To.Contains("this") && p.To.Contains("return"));

    private static IOperation? ThisOperation(IInvocationOperation invocation) =>
        invocation.Instance ?? (invocation.TargetMethod.IsExtensionMethod && invocation.Arguments.Length > 0 ? invocation.Arguments[0].Value : null);

    // ---- Members ----

    private static bool IsInSource(ISymbol member) => MemberTable<object>.Definition(member).DeclaringSyntaxReferences.Length > 0;

    private TaintValue ReadProperty(IPropertyReferenceOperation operation, TaintState state)
    {
        var property = operation.Property;
        var receiver = Value(operation.Instance, state);
        var index = TaintValue.Clean;
        foreach (var a in operation.Arguments) index = index.Join(Value(a.Value, state));

        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(property, Access.Get) is { } source)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(property)}");
        if (_ctx.Sources.IsBoundProperty(property))
            result = result.Join(TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: bound property {_ctx.Name(property)}"));

        if (IsInSource(property))
        {
            // TEMPORARY (Task 7): a property declared in source returns its object's taint (Task 8: summaries, heap).
            result = result.Join(receiver.Join(index));
        }
        else
        {
            var propagators = _ctx.Propagators.Match(property, Access.Get);
            if (propagators.Length > 0)
            {
                foreach (var p in propagators)
                {
                    var from = TaintValue.Clean;
                    foreach (var f in p.From)
                        from = from.Join(f switch { "this" => receiver, "args" => index, _ => IndexArgument(operation, f, state) });
                    if (p.To.Contains("return")) result = result.Join(from);
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
        var a = operation.Arguments.FirstOrDefault(x => x.Parameter != null && IsOrdinal(ordinal, x.Parameter.Ordinal));
        return a == null ? TaintValue.Clean : Value(a.Value, state);
    }

    /// One argument of a call, by the ordinal of its parameter in the member's definition (an extension method's `this`
    /// is 0, also when the call names the reduced form).
    private readonly record struct Input(int Ordinal, IParameterSymbol? Parameter, IOperation Operation, Location Location, TaintValue Value, RefKind RefKind);

    private TaintValue Call(IOperation operation, IMethodSymbol? method, IOperation? instance, ImmutableArray<IArgumentOperation> arguments, TaintState state)
    {
        var definition = method == null ? null : (IMethodSymbol)MemberTable<object>.Definition(method);
        var reduced = method?.ReducedFrom != null;
        var receiver = TaintValue.Clean;
        IOperation? thisOperation = null;
        var inputs = new List<Input>(arguments.Length + 1);
        if (instance != null)
        {
            var value = Value(instance, state);
            if (reduced && definition!.Parameters.Length > 0)
                inputs.Add(new Input(0, definition.Parameters[0], instance, instance.Syntax.GetLocation(), value, RefKind.None));
            receiver = value;
            thisOperation = instance;
        }
        foreach (var a in arguments)
        {
            var refKind = a.Parameter?.RefKind ?? RefKind.None;
            var value = refKind == RefKind.Out ? TaintValue.Clean : Value(a.Value, state);
            var ordinal = (a.Parameter?.Ordinal ?? -1) + (reduced ? 1 : 0);
            var parameter = definition != null && ordinal >= 0 && ordinal < definition.Parameters.Length ? definition.Parameters[ordinal] : null;
            var location = (a.IsImplicit ? a.Value.Syntax : a.Syntax).GetLocation();
            inputs.Add(new Input(ordinal, parameter, a.Value, location, value, refKind));
        }
        if (method == null || definition == null)
        {
            var any = TaintValue.Clean;
            foreach (var i in inputs) any = any.Join(i.Value);
            return any;
        }
        if (instance == null && method.IsExtensionMethod && inputs.Count > 0)
        {
            receiver = inputs[0].Value;
            thisOperation = inputs[0].Operation;
        }

        // Sinks.
        foreach (var hit in _ctx.Sinks.Sinks(method, Access.Call))
            foreach (var i in inputs)
                if (i.Parameter != null && SinkFinder.IsSinkArgument(hit.Sink, i.Parameter) && i.Value.TaintedFor(hit.RuleId))
                    _ctx.Report(hit.RuleId, i.Location, i.Value, method);

        var all = TaintValue.Clean;
        foreach (var i in inputs) if (i.RefKind != RefKind.Out) all = all.Join(i.Value);
        if (instance != null && !reduced) all = all.Join(receiver);

        var result = TaintValue.Clean;
        if (_ctx.Sources.SourceMember(method, Access.Call) is { } source)
            result = TaintValue.Source(operation.Syntax.GetLocation(), $"request data enters here: {_ctx.Name(method)}");

        // Out arguments are overwritten by the call.
        foreach (var i in inputs) if (i.RefKind == RefKind.Out) Assign(i.Operation, TaintValue.Clean, state, i.Operation);

        var resultType = method.MethodKind == MethodKind.Constructor ? method.ContainingType : method.ReturnType;
        if (IsInSource(method) || method.MethodKind == MethodKind.DelegateInvoke)
        {
            // TEMPORARY (Task 7): until Task 8's summaries, a call of a method declared in source (or of a delegate)
            // returns the join of its receiver's and arguments' taint and writes it to its out and ref arguments.
            var through = all.Request ? all.Step(operation.Syntax.GetLocation(), $"passed to {_ctx.Name(method)}") : all;
            result = result.Join(through);
            foreach (var i in inputs)
                if (i.RefKind is RefKind.Out or RefKind.Ref) Assign(i.Operation, through, state, i.Operation);
        }
        else
        {
            var propagators = _ctx.Propagators.Match(method, Access.Call);
            if (propagators.Length > 0)
            {
                foreach (var p in propagators)
                {
                    var from = TaintValue.Clean;
                    foreach (var f in p.From)
                    {
                        from = from.Join(f switch
                        {
                            "this" => receiver,
                            "args" => Join(inputs.Where(i => i.RefKind != RefKind.Out && !(reduced && i.Ordinal == 0 && instance != null))),
                            _ => Join(inputs.Where(i => IsOrdinal(f, i.Ordinal))),
                        });
                    }
                    if (!from.Request) continue;
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
                                foreach (var i in inputs.Where(i => IsOrdinal(t, i.Ordinal)))
                                    Write(i.Operation, from, state);
                                break;
                        }
                    }
                }
            }
            else if (_ctx.UnmodelledPasses && resultType != null && _ctx.Sources.IsStringOrCollection(resultType))
            {
                _ctx.CountUnmodelled(operation.Syntax);
                result = result.Join(all);
            }

            // Collection and interpolated-string-handler writes taint their receiver.
            if (thisOperation != null && IsCollectionWrite(method))
            {
                var written = Join(inputs.Where(i => i.RefKind != RefKind.Out && !ReferenceEquals(i.Operation, thisOperation)));
                Write(thisOperation, written, state);
            }
        }

        return result.CleanedFor(_ctx.Sinks.Sanitizes(method, Access.Call));
    }

    /// A propagator position (`from`/`to`) that is this parameter ordinal.
    private static bool IsOrdinal(string position, int ordinal) =>
        int.TryParse(position, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) && n == ordinal;

    private static TaintValue Join(IEnumerable<Input> inputs)
    {
        var value = TaintValue.Clean;
        foreach (var i in inputs) value = value.Join(i.Value);
        return value;
    }

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

/// The key comparer of the state's holders, for alias sets.
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
