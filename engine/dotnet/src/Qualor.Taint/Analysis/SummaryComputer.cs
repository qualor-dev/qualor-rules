using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// What a call may run, for MethodAnalyzer: a body with a summary; an auto-property accessor (a heap read or write);
/// a member declared in source without a body to analyse (abstract with no implementation, extern, a record's or a
/// primary constructor's synthesized members: its receiver and arguments reach its result); an external member (its
/// propagator models or the `unmodelled-external` default).
internal enum TargetKind { Body, Auto, Opaque, External }

internal readonly record struct Target(TargetKind Kind, IMethodSymbol Method, Body? Body);

/// The interprocedural analysis (spec §5): summaries computed bottom-up over the call graph's strongly connected
/// components (CallGraph.Sccs) with a worklist ordered by component, to the joint fixed point of the summaries, the
/// seeds and the heap:
/// - every unit is analysed once in bottom-up order; a unit is analysed again when the local effects of a body it
///   applied grow (Body.Callers, recorded at each call site, so a missing edge of the call graph costs order, never
///   results), and in the next heap round when a heap symbol it read grows (Heap readers);
/// - inside a component this iterates to a fixed point; the analyses of one component in one heap round are capped at
///   MaxIterationsPerScc per unit, and on the cap the run is incomplete ("iteration cap in <method>"); heap rounds are
///   capped likewise;
/// - request data passed to a body's parameter is a seed of that parameter: it reports the body's sinks of that
///   parameter, writes its heap writes, and seeds the callees its call edges lead to; a seed runs again when it or the
///   body's global effects grow (Drain), so findings in callees never wait for their callers to be analysed again;
/// - a unit's lambdas and local functions are analysed after its root with the root's states (their captures), and the
///   unit iterates (capped likewise) until what they tell each other stops growing (Unit: lambda seeds and returns,
///   captured writes, local functions' summaries);
/// - a failed body is skipped and counted (ruling R-E10); the bodies nested in it are still analysed.
internal sealed class SummaryComputer
{
    /// Ruling R-E10: failed bodies are skipped; above this share of all bodies the run is incomplete.
    private const double MaxFailedShare = 0.01;

    /// Control-flow graphs kept between analyses of their unit (the most recent ones).
    private const int MaxCachedGraphs = 512;

    private readonly AnalysisContext _ctx;
    private readonly CallGraph _graph;
    private readonly Dispatch _dispatch;
    private readonly Heap _heap;
    private readonly EntryPoints _entries;
    private readonly Budget _budget;
    private readonly Action<IMethodSymbol?>? _beforeBody;
    private readonly Action? _beforeSeed;
    private readonly HashSet<int> _analysed = new();
    private readonly HashSet<int> _failed = new();
    private readonly List<string> _errors = new();
    private readonly LinkedList<Unit> _cached = new();
    private readonly Dictionary<int, SummaryBuilder> _builders = new();

    public SummaryComputer(AnalysisContext ctx, CallGraph graph, Dispatch dispatch, EntryPoints entries, Budget budget,
        Action<IMethodSymbol?>? beforeBody, Action? beforeSeed = null)
    {
        _entries = entries;
        _beforeSeed = beforeSeed;
        _ctx = ctx;
        _graph = graph;
        _dispatch = dispatch;
        _heap = new Heap(dispatch);
        _budget = budget;
        _beforeBody = beforeBody;
    }

    public int Methods => _analysed.Count;

    public int Failed => _failed.Count;

    public int Analyses { get; private set; }

    public IReadOnlyList<string> Errors => _errors;

    public Heap Heap => _heap;

    /// The first reason the result is partial that is not a budget or failures: an iteration cap.
    public string? Incomplete { get; private set; }

    /// Why the failures make the run incomplete (more than 1 % of the bodies analysed or failed), or null.
    public string? FailureReason()
    {
        var total = Methods + Failed;
        return Failed > 0 && Failed > MaxFailedShare * total
            ? $"{Failed} of {total} bodies failed (more than 1 %); first: {_errors[0]}"
            : null;
    }

    /// The worklist in rounds: a round analyses its units in bottom-up order, the callers of a summary that grew within
    /// the round (the components' fixed points); the readers of heap symbols that grew are the next round's units (each
    /// analysed once per round however many of its symbols grew). The run ends when a round taints no new heap symbol;
    /// rounds are capped at MaxIterationsPerScc too ("heap rounds cap").
    public void Run(CancellationToken ct)
    {
        var worklist = new SortedSet<(int Scc, int Unit)>();
        foreach (var u in _graph.Units) worklist.Add((u.Scc, u.Id));
        var runs = new int[_graph.Sccs.Count];
        var capped = new bool[_graph.Sccs.Count];
        var cap = Math.Max(1, _ctx.Options.MaxIterationsPerScc);
        var dirty = new HashSet<Unit>();
        for (var round = 1; ; round++)
        {
            Array.Clear(runs);
            while (worklist.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                if (!_budget.Check()) return;
                var next = worklist.Min;
                worklist.Remove(next);
                var unit = _graph.Units[next.Unit];
                if (capped[unit.Scc]) continue;
                if (runs[unit.Scc] >= cap * _graph.Sccs[unit.Scc].Count)
                {
                    capped[unit.Scc] = true;
                    Incomplete ??= $"iteration cap in {UnitName(unit)}";
                    continue;
                }
                runs[unit.Scc]++;
                Analyses++;
                if (AnalyzeUnit(unit, ct))
                    foreach (var caller in unit.RootBody.Callers) worklist.Add((caller.Scc, caller.Id));
                Drain();
                dirty.UnionWith(_heap.TakeDirtyReaders());
            }
            HeapRounds = round;
            if (dirty.Count == 0) return;
            if (round >= cap)
            {
                Incomplete ??= $"heap rounds cap ({cap}) reached";
                return;
            }
            foreach (var reader in dirty) worklist.Add((reader.Scc, reader.Id));
            dirty.Clear();
        }
    }

    /// The rounds the last run took (1 when no heap symbol read before it was written).
    public int HeapRounds { get; private set; }

    /// The most global effects (sinks, call edges, heap writes) one summary holds.
    public int MaxGlobalEffects() =>
        _graph.AllBodies.Select(b => b.Summary.Sinks.Count + b.Summary.Calls.Count + b.Summary.Heap.Count).DefaultIfEmpty(0).Max();

    /// The brief's view of every summary that is not empty, by body symbol (a parameter's sinks and heap symbols
    /// include its callees', along the call edges).
    public IReadOnlyDictionary<IMethodSymbol, Summary> Summaries()
    {
        var result = new Dictionary<IMethodSymbol, Summary>(SymbolEqualityComparer.Default);
        foreach (var body in _graph.AllBodies)
        {
            if (body.Symbol == null || body.Summary.IsEmpty) continue;
            var s = body.Summary;
            var slots = new SortedSet<int>();
            foreach (var l in s.Return.Labels) if (l.Owner == body.Id) slots.Add(l.Slot);
            foreach (var e in s.Sinks.Values) slots.Add(e.Slot);
            foreach (var c in s.Calls.Values) slots.Add(c.Slot);
            foreach (var (_, v) in s.Heap.Values) foreach (var l in v.Labels) if (l.Owner == body.Id) slots.Add(l.Slot);
            var effects = new Dictionary<int, ParamEffect>();
            foreach (var slot in slots)
            {
                var toReturn = s.Return.Labels.FirstOrDefault(l => l.Owner == body.Id && l.Slot == slot);
                var (sinks, heap) = Reach(body, slot);
                effects[slot] = new ParamEffect(toReturn != null, sinks, heap, toReturn?.CleanFor ?? ImmutableHashSet<string>.Empty);
            }
            result.TryAdd(body.Symbol, new Summary(effects, s.Return.Request, s.RequestHeap.Values.ToList()));
        }
        return result;
    }

    /// The sinks and heap symbols a parameter reaches in its body and, along the call edges, in the callees.
    private (List<(string, Location, IReadOnlyList<PathStep>)> Sinks, List<ISymbol> Heap) Reach(Body body, int slot)
    {
        var sinks = new List<(string, Location, IReadOnlyList<PathStep>)>();
        var heap = new List<ISymbol>();
        var seen = new HashSet<(int, int)>();
        var work = new Stack<(Body Body, int Slot, Trail Path, ImmutableHashSet<string> CleanFor)>();
        work.Push((body, slot, Trail.Empty, ImmutableHashSet<string>.Empty));
        while (work.Count > 0)
        {
            var (b, k, path, cleanFor) = work.Pop();
            if (!seen.Add((b.Id, k))) continue;
            foreach (var e in b.Summary.Sinks.Values)
                if (e.Slot == k && !cleanFor.Contains(e.RuleId)) sinks.Add((e.RuleId, e.Site.GetLocation(), path.Concat(e.Path).ToList()));
            foreach (var (member, v) in b.Summary.Heap.Values)
                if (v.Labels.Any(l => l.Owner == b.Id && l.Slot == k) && !heap.Contains(member, SymbolEqualityComparer.Default)) heap.Add(member);
            foreach (var c in b.Summary.Calls.Values)
                if (c.Slot == k) work.Push((c.Callee, c.CalleeSlot, path.Concat(c.Path), cleanFor.Union(c.CleanFor)));
        }
        return (sinks, heap);
    }

    // ---- Seeds: request data at a body's parameters ----

    private readonly Dictionary<(int Body, int Slot), TaintValue> _seeds = new();
    private readonly Dictionary<int, HashSet<int>> _seededSlots = new();
    private readonly Queue<(int Body, int Slot)> _queue = new();
    private readonly HashSet<(int Body, int Slot)> _queued = new();

    /// Request data reaches parameter `slot` of `body` (from a call site, or along a call edge): joined into the seed;
    /// when that grows, the body's global effects run for it (Drain).
    internal void Seed(Body body, int slot, TaintValue value)
    {
        if (!value.Request) return;
        value = value.RequestPart;
        var key = (body.Id, slot);
        if (_seeds.TryGetValue(key, out var old))
        {
            var joined = old.Join(value);
            if (ReferenceEquals(joined, old)) return;
            _seeds[key] = joined;
            if (joined.SameFlow(old)) return;
        }
        else
        {
            _seeds[key] = value;
            if (!_seededSlots.TryGetValue(body.Id, out var slots)) _seededSlots[body.Id] = slots = new HashSet<int>();
            slots.Add(slot);
        }
        if (_queued.Add(key)) _queue.Enqueue(key);
    }

    /// A body's global effects grew: its seeds run again.
    private void Reseed(Body body)
    {
        if (!_seededSlots.TryGetValue(body.Id, out var slots)) return;
        foreach (var slot in slots)
            if (_queued.Add((body.Id, slot))) _queue.Enqueue((body.Id, slot));
    }

    /// Runs the seeds' global effects: a sink of the parameter reports the request data (with the path from its source
    /// through the calls into the body to the sink), a heap write of it writes the heap, a call edge seeds the callee.
    /// The budget is checked per seed (ruling R-E12): over it, the rest stays queued and the run stops incomplete.
    private void Drain()
    {
        while (_queue.Count > 0)
        {
            _beforeSeed?.Invoke();
            if (!_budget.Check()) return;
            var key = _queue.Dequeue();
            _queued.Remove(key);
            var body = _graph.Body(key.Body);
            var value = _seeds[key];
            var summary = body.Summary;
            foreach (var e in summary.Sinks.Values)
            {
                if (e.Slot != key.Slot || !value.TaintedFor(e.RuleId)) continue;
                _ctx.Report(e.RuleId, e.Site, value.Extend(e.Path), e.Member);
            }
            foreach (var (member, symbolic) in summary.Heap.Values)
            {
                var written = BodySummary.Through(symbolic, body.Id, key.Slot, value);
                if (written.Request) _heap.Write(member, written, _entries.Of(body));
            }
            foreach (var c in summary.Calls.Values)
                if (c.Slot == key.Slot) Seed(c.Callee, c.CalleeSlot, value.Extend(c.Path).CleanedFor(c.CleanFor));
        }
    }

    private string UnitName(Unit unit) => unit.Symbol == null
        ? $"a body of {unit.Root.SyntaxTree.FilePath}:{unit.Root.GetLocation().GetLineSpan().StartLinePosition.Line + 1}"
        : _ctx.Name(unit.Symbol);

    // ---- One unit ----

    /// Analyses a unit (its root, then its lambdas and local functions, to their fixed point); true when the root's
    /// summary grew (its callers must be analysed again).
    private bool AnalyzeUnit(Unit unit, CancellationToken ct)
    {
        var cfg = GraphOf(unit, ct);
        if (cfg == null) return false;
        var cap = Math.Max(1, _ctx.Options.MaxIterationsPerScc);
        for (var round = 1; ; round++)
        {
            _builders.Clear();
            var changed = false;
            AnalyzeGraph(cfg, unit.RootBody, unit, null, ref changed, ct);
            foreach (var (id, builder) in _builders)
            {
                if (id == unit.RootBody.Id) continue;
                var body = _graph.Body(id);
                var joined = body.Summary.Join(builder.Build());
                if (!joined.SameLocalEffects(body.Summary)) changed = true;
                if (!joined.SameGlobalEffects(body.Summary)) Reseed(body);
                body.Summary = joined;
            }
            if (!changed) break;
            if (round >= cap)
            {
                Incomplete ??= $"iteration cap in {UnitName(unit)}";
                break;
            }
        }
        var root = unit.RootBody;
        if (!_builders.TryGetValue(root.Id, out var rootBuilder)) return false;
        var summary = root.Summary.Join(rootBuilder.Build());
        var grew = !summary.SameLocalEffects(root.Summary);
        if (!summary.SameGlobalEffects(root.Summary)) Reseed(root);
        root.Summary = summary;
        return grew;
    }

    /// The unit's control-flow graph, from the cache or bound again; null when binding fails (counted once).
    private ControlFlowGraph? GraphOf(Unit unit, CancellationToken ct)
    {
        if (unit.Graph != null)
        {
            _cached.Remove(unit.CacheNode!);
            _cached.AddFirst(unit.CacheNode!);
            return unit.Graph;
        }
        ControlFlowGraph? cfg;
        try
        {
            var model = unit.Compilation.GetSemanticModel(unit.Root.SyntaxTree);
            cfg = CallGraph.Graph(model.GetOperation(unit.Root, ct), ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Fail(unit.RootBody, unit.Root, e);
            return null;
        }
        if (cfg == null) return null;
        unit.Graph = cfg;
        unit.CacheNode = _cached.AddFirst(unit);
        if (_cached.Count > MaxCachedGraphs)
        {
            var last = _cached.Last!.Value;
            _cached.RemoveLast();
            last.CacheNode = null;
            last.Graph = null;
        }
        return cfg;
    }

    /// Analyses one graph, then the lambdas and local functions declared in it (each from this graph's states: what
    /// they may capture). `changed`: something the unit's bodies tell each other grew.
    private void AnalyzeGraph(ControlFlowGraph cfg, Body body, Unit unit, TaintState? enclosing, ref bool changed, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        TaintState? all = null;
        var nested = Nested(cfg, out var nestedError);
        try
        {
            if (nestedError != null) throw nestedError;
            _beforeBody?.Invoke(body.Symbol);
            var run = new BodyRun(this, unit, body);
            var entry = new TaintState();
            if (enclosing != null)
                foreach (var (key, value) in enclosing.Entries)
                    if (key is ISymbol) entry.Set(key, value);
            if (body.Symbol is { } method)
            {
                var seed = body.IsLambda && unit.LambdaSeeds.TryGetValue(SymbolKeys.Of(method), out var s) ? s : TaintValue.Clean;
                foreach (var p in method.Parameters)
                {
                    if (_ctx.Sources.IsScalar(p.Type)) continue;
                    var value = TaintValue.Clean;
                    if (_ctx.Sources.IsSourceParameter(p))
                    {
                        var location = p.Locations.FirstOrDefault(l => l.IsInSource) ?? Location.None;
                        value = TaintValue.Source(location, $"request data enters here: parameter '{p.Name}' of {_ctx.Name(method)}").ScopedTo(run.Reach);
                    }
                    if (body.IsLambda) value = value.Join(seed);
                    else if (p.RefKind != RefKind.Out) value = value.Join(TaintValue.Param(body.Id, p.Ordinal));
                    if (value.Any) entry.Set(p, value);
                }
            }

            var analyzer = new MethodAnalyzer(_ctx, cfg, run);
            all = analyzer.Run(entry, collectAll: nested.Count > 0);
            var builder = Builder(body.Id);
            builder.Return = builder.Return.Join(analyzer.ReturnValue);
            if (analyzer.ExitState is { } exit && body.Symbol != null)
            {
                foreach (var p in body.Symbol.Parameters)
                {
                    if (p.RefKind is not (RefKind.Ref or RefKind.Out)) continue;
                    var v = exit.Get(p);
                    if (v.Any) builder.Refs[p.Ordinal] = builder.Refs.TryGetValue(p.Ordinal, out var old) ? old.Join(v) : v;
                }
            }
            if (body.IsLambda)
            {
                var key = SymbolKeys.Of(body.Symbol!);
                var old = unit.LambdaReturns.TryGetValue(key, out var r) ? r : TaintValue.Clean;
                var joined = old.Join(analyzer.ReturnValue);
                if (!joined.SameFlow(old)) changed = true;
                unit.LambdaReturns[key] = joined;
            }
            if (run.CapturedChanged) changed = true;
            _analysed.Add(body.Id);
            if (!analyzer.Complete) Incomplete ??= $"iteration cap in {(body.Symbol == null ? UnitName(unit) : _ctx.Name(body.Symbol))}";
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // Ruling R-E10: this body is skipped and counted; the bodies nested in it are still analysed (N1 of Task 7),
            // without the states they would capture.
            Fail(body, cfg.OriginalOperation.Syntax, e);
            all = null;
        }

        foreach (var (graph, symbol) in nested)
        {
            ControlFlowGraph inner;
            try
            {
                inner = graph();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Fail(_graph.Nested(unit, symbol), symbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(ct) ?? cfg.OriginalOperation.Syntax, e);
                continue;
            }
            AnalyzeGraph(inner, _graph.Nested(unit, symbol), unit, all, ref changed, ct);
        }
    }

    /// The lambdas and local functions declared directly in a graph, with a way to get each one's graph.
    private static List<(Func<ControlFlowGraph> Graph, IMethodSymbol Symbol)> Nested(ControlFlowGraph cfg, out Exception? error)
    {
        var list = new List<(Func<ControlFlowGraph>, IMethodSymbol)>();
        error = null;
        try
        {
            foreach (var local in cfg.LocalFunctions) list.Add((() => cfg.GetLocalFunctionControlFlowGraph(local), local));
            foreach (var block in cfg.Blocks)
            {
                foreach (var operation in block.Operations) Add(operation);
                if (block.BranchValue != null) Add(block.BranchValue);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            error = e;
        }
        return list;

        void Add(IOperation root)
        {
            foreach (var f in root.DescendantsAndSelf().OfType<IFlowAnonymousFunctionOperation>())
                list.Add((() => cfg.GetAnonymousFunctionControlFlowGraph(f), f.Symbol));
        }
    }

    /// An exception in one body (a Roslyn or engine bug): the body is skipped and counted once (ruling R-E10).
    private void Fail(Body body, SyntaxNode node, Exception e)
    {
        if (!_failed.Add(body.Id)) return;
        if (_errors.Count >= AnalysisStats.MaxErrors) return;
        var line = node.GetLocation().GetLineSpan();
        _errors.Add($"{line.Path}:{line.StartLinePosition.Line + 1}: {e.GetType().Name}: {e.Message}");
    }

    internal SummaryBuilder Builder(int owner)
    {
        if (!_builders.TryGetValue(owner, out var builder)) _builders[owner] = builder = new SummaryBuilder();
        return builder;
    }

    // ---- What MethodAnalyzer asks ----

    /// The interprocedural side of one body's analysis: its labels, its summary's builders, call targets, the heap, and
    /// what the unit's bodies tell each other.
    internal sealed class BodyRun
    {
        private readonly SummaryComputer _computer;
        private readonly Unit _unit;
        private readonly Body _body;

        public BodyRun(SummaryComputer computer, Unit unit, Body body)
        {
            _computer = computer;
            _unit = unit;
            _body = body;
            var root = unit.RootBody;
            This = root.Symbol is { IsStatic: false } ? TaintValue.Param(root.Id, -1) : TaintValue.Clean;
            Reach = computer._entries.Of(body);
        }

        /// The entry points that reach this body (EntryPoints.Of).
        public Reach Reach { get; }

        /// The value of `this`: the label of the unit root's receiver (a lambda's `this` is its enclosing member's).
        public TaintValue This { get; }

        public bool CapturedChanged { get; private set; }

        private AnalysisContext Ctx => _computer._ctx;

        /// The value of a local or parameter: its state joined with what the unit's lambdas and local functions write to
        /// it (captured writes, flow-insensitive).
        public TaintValue Local(ISymbol symbol, TaintValue value) =>
            _unit.HasCapturedWrites ? value.Join(_unit.CapturedWrites.Get(symbol)) : value;

        /// A local or parameter was assigned (or written into): a captured variable of an enclosing body records it.
        public void Assigned(ISymbol symbol, TaintValue value)
        {
            if (!_body.Nested || !value.Any) return;
            if (SymbolEqualityComparer.Default.Equals(symbol.ContainingSymbol, _body.Symbol)) return;
            var old = _unit.CapturedWrites.Get(symbol);
            var joined = old.Join(value);
            if (joined.SameFlow(old)) return;
            _unit.CapturedWrites.Set(symbol, joined);
            _unit.HasCapturedWrites = true;
            CapturedChanged = true;
        }

        /// What a lambda returns (its value as a delegate).
        public TaintValue LambdaReturn(IMethodSymbol lambda) =>
            _unit.LambdaReturns.TryGetValue(SymbolKeys.Of(lambda), out var v) ? v : TaintValue.Clean;

        /// A lambda is given to a call whose other inputs are `value`: its parameters get it.
        public void Seed(IMethodSymbol lambda, TaintValue value)
        {
            if (!value.Any) return;
            var key = SymbolKeys.Of(lambda);
            _unit.LambdaSeeds[key] = _unit.LambdaSeeds.TryGetValue(key, out var old) ? old.Join(value) : value;
        }

        /// The targets of a call or accessor (Dispatch), as bodies, auto-property accessors, opaque or external members.
        public IReadOnlyList<Target> Targets(IMethodSymbol method, bool isVirtual, ITypeSymbol? receiverType)
        {
            var methods = _computer._dispatch.Targets(method, isVirtual, receiverType);
            // The call's own target keeps its constructed form (an external member's result type, `Task<string>` of
            // `Task.FromResult<string>`, decides the unmodelled default).
            if (methods.Count == 1)
                return new[] { TargetOf(SymbolEqualityComparer.Default.Equals(methods[0], SymbolKeys.Definition(method)) ? method : methods[0]) };
            if (methods.Count == 0) return new[] { new Target(TargetKind.Opaque, method, null) };
            var targets = new Target[methods.Count];
            for (var i = 0; i < methods.Count; i++) targets[i] = TargetOf(methods[i]);
            return targets;
        }

        private Target TargetOf(IMethodSymbol method)
        {
            var body = method.MethodKind == MethodKind.LocalFunction ? _computer._graph.Nested(_unit, method) : _computer._graph.BodyOf(method);
            if (body != null) return new Target(TargetKind.Body, method, body);
            if (!SymbolKeys.InSource(method)) return new Target(TargetKind.External, method, null);
            if (method.AssociatedSymbol is IPropertySymbol property && Heap.IsAutoProperty(property)) return new Target(TargetKind.Auto, method, null);
            return new Target(TargetKind.Opaque, method, null);
        }

        /// The current body applies `callee`'s summary: it is analysed again when that grows.
        public void Depend(Body callee) => callee.Callers.Add(_unit);

        /// Whether a label's owner is a body of this unit (labels of other bodies are never kept).
        public bool Keeps(int owner) => _unit.BodyIds.Contains(owner);

        /// A value is passed to parameter `slot` of `callee` (its call step added): its request data seeds the callee's
        /// parameter, each label becomes a call edge of its body.
        public void Pass(Body callee, int slot, TaintValue value)
        {
            if (value.Request) _computer.Seed(callee, slot, value);
            foreach (var l in value.Labels)
                if (Keeps(l.Owner)) _computer.Builder(l.Owner).AddCall(l.Slot, callee, slot, l.CleanFor, l.Path);
        }

        public void RecordSink(Label label, string rule, SyntaxNode site, ISymbol member)
        {
            if (Keeps(label.Owner)) _computer.Builder(label.Owner).AddSink(label.Slot, rule, site, member, label.Path);
        }

        /// Something is written into the receiver object (`this._f = v`, `this.P = v`, a collection write into a field).
        public void RecordThis(TaintValue value)
        {
            if (!value.Any || This.Labels.Length == 0) return;
            var builder = _computer.Builder(_unit.RootBody.Id);
            builder.ToThis = builder.ToThis.Join(value);
        }

        public bool IsHeapMember(ISymbol member) => _computer._heap.IsMember(member);

        public TaintValue HeapRead(ISymbol member) => _computer._heap.Read(member, _unit, Reach);

        /// A write to a heap symbol: its request data to the heap, its labels to their owners' summaries.
        public void HeapWrite(ISymbol member, TaintValue value)
        {
            if (!value.Any || !IsHeapMember(member)) return;
            var heap = _computer._heap;
            if (value.Request)
            {
                heap.Write(member, value, Reach);
                _computer.Builder(_body.Id).RequestHeap.TryAdd(heap.Key(member), member);
            }
            if (value.Labels.Length == 0) return;
            var key = heap.Key(member);
            var labels = value.LabelPart;
            int? last = null;
            foreach (var l in value.Labels)
            {
                if (l.Owner == last || !Keeps(l.Owner)) continue;
                last = l.Owner;
                _computer.Builder(l.Owner).AddHeap(key, member, labels);
            }
        }

        public string Name(ISymbol symbol) => Ctx.Name(symbol);
    }
}
