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

/// Fallback: the call that runs it was resolved by the class-hierarchy fallback to several implementations
/// (Dispatch.IsFallback): the call's path steps are medium (R-9).
internal readonly record struct Target(TargetKind Kind, IMethodSymbol Method, Body? Body, bool Fallback = false)
{
    /// The kind of the path steps of a call to this target.
    public StepKind StepKind => Fallback ? StepKind.DispatchFallback : StepKind.Plain;
}

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
            if (body.Symbol == null || body.Summary.NoTaint) continue;
            var s = body.Summary;
            var slots = new SortedSet<int>();
            foreach (var l in s.Return.Labels) if (l.Owner == body.Id) slots.Add(l.Slot);
            foreach (var e in s.Sinks.Values) slots.Add(e.Slot);
            foreach (var c in s.Calls.Values) slots.Add(c.Slot);
            foreach (var (_, v) in s.Heap.Values) foreach (var l in v.Labels) if (l.Owner == body.Id) slots.Add(l.Slot);
            foreach (var (_, v) in s.ObjWrites.Values) foreach (var l in v.Labels) if (l.Owner == body.Id) slots.Add(l.Slot);
            // A member slot (Task 27: a member read through a parameter) is part of that parameter's effect.
            var effects = new Dictionary<int, ParamEffect>();
            foreach (var slot in slots)
            {
                var toReturn = s.Return.Labels.FirstOrDefault(l => l.Owner == body.Id && l.Slot == slot);
                var (sinks, heap) = Reach(body, slot);
                foreach (var (member, v) in s.ObjWrites.Values)
                    if (v.Labels.Any(l => l.Owner == body.Id && l.Slot == slot) && !heap.Contains(member, SymbolEqualityComparer.Default)) heap.Add(member);
                var key = ObjectTable.IsMemberSlot(slot) ? _ctx.Objects.OfMemberSlot(slot).Slot : slot;
                var effect = new ParamEffect(toReturn != null, sinks, heap, toReturn?.CleanFor ?? ImmutableHashSet<string>.Empty);
                if (effects.TryGetValue(key, out var old))
                    effect = new ParamEffect(old.ToReturn || effect.ToReturn, old.ToSinks.Concat(effect.ToSinks).ToList(),
                        old.ToHeap.Concat(effect.ToHeap.Where(h => !old.ToHeap.Contains(h, SymbolEqualityComparer.Default))).ToList(),
                        old.ToReturn && effect.ToReturn ? old.CleanFor.Intersect(effect.CleanFor) : old.ToReturn ? old.CleanFor : effect.CleanFor);
                effects[key] = effect;
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
            foreach (var (location, v) in b.Summary.Heap.Values)
            {
                var member = location as ISymbol ?? (location is ObjLocation at ? at.Symbol : null);
                if (member != null && v.Labels.Any(l => l.Owner == b.Id && l.Slot == k) && !heap.Contains(member, SymbolEqualityComparer.Default)) heap.Add(member);
            }
            foreach (var c in b.Summary.Calls.Values)
                if (c.Slot == k) work.Push((c.Callee, c.CalleeSlot, path.Concat(c.Path), cleanFor.Union(c.CleanFor)));
        }
        return (sinks, heap);
    }

    // ---- Objects (Task 27) ----

    private readonly Dictionary<int, bool> _symbolic = new();
    private readonly Dictionary<int, HashSet<object>> _topWrites = new();

    private readonly Dictionary<int, Dictionary<HashSet<object>, int>> _absorbed = new();

    /// The callee components' sets a component has taken in, with their sizes then.
    internal Dictionary<HashSet<object>, int> Absorbed(int scc)
    {
        if (!_absorbed.TryGetValue(scc, out var set)) _absorbed[scc] = set = new Dictionary<HashSet<object>, int>(ReferenceEqualityComparer.Instance);
        return set;
    }

    /// The members written through unknown objects in a unit's component (Task 27): one set per component, which every
    /// body of it records into, so it is complete when the component's fixed point is (a cycle of a thousand bodies
    /// would otherwise pass a growing set around it member by member). It holds every such write, request data or not.
    internal HashSet<object> TopWritesOf(Unit unit)
    {
        if (!_topWrites.TryGetValue(unit.Scc, out var set)) _topWrites[unit.Scc] = set = new HashSet<object>();
        _builders.TryGetValue(unit.RootBody.Id, out var builder);
        if (builder != null) builder.TopWrites = set;
        return set;
    }

    /// Whether a body's parameters and `this` stand for the objects its calls give (Task 27): a member's body (not a
    /// lambda or local function) that other code of the solution calls, where no entry point starts (the framework calls
    /// those), that is no method group (a delegate: anything calls it) and overrides or implements no external member (an
    /// external caller gives objects no call site of ours substitutes). Its reads of members through them are member
    /// slots and its writes ObjWrites, both resolved at each call site; any other body reads and writes such members at
    /// their field locations.
    internal bool IsSymbolic(Body body)
    {
        if (_symbolic.TryGetValue(body.Id, out var cached)) return cached;
        var result = !body.Nested && body.Symbol is { } method
            && method.MethodKind is MethodKind.Ordinary or MethodKind.Constructor or MethodKind.PropertyGet or MethodKind.PropertySet
                or MethodKind.ExplicitInterfaceImplementation
            && _graph.IsCalled(body.Unit) && !_entries.StartsAt(body.Unit) && !_graph.IsMethodGroup(method) && !OverridesExternal(method);
        _symbolic[body.Id] = result;
        return result;
    }

    private static bool OverridesExternal(IMethodSymbol method)
    {
        for (var m = method.OverriddenMethod; m != null; m = m.OverriddenMethod)
            if (!SymbolKeys.InSource(m)) return true;
        if (method.ExplicitInterfaceImplementations.Any(i => !SymbolKeys.InSource(i))) return true;
        if (method.ContainingType is not { } type) return false;
        foreach (var i in type.AllInterfaces)
        {
            if (SymbolKeys.InSource(i)) continue;
            foreach (var member in i.GetMembers())
                if (member is IMethodSymbol && SymbolEqualityComparer.Default.Equals(type.FindImplementationForInterfaceMember(member), method)) return true;
        }
        return false;
    }

    /// The objects a body's parameter holds at its entry: the binder's object for a bound parameter of an action (one per
    /// entry point), the parameter's own object for a symbolic body, else unknown.
    private ObjSet? EntryObjects(Body body, IParameterSymbol p, bool symbolic)
    {
        if (!MemberFacts.MayHold(p.Type) || p.RefKind != RefKind.None) return null;
        if (_ctx.Sources.IsSourceParameter(p)) return _ctx.Objects.Single(_ctx.Objects.Bound(body.Id, p.Ordinal));
        return symbolic ? _ctx.Objects.Single(_ctx.Objects.Param(body.Id, p.Ordinal)) : null;
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
            var (sinks, calls, heap) = body.Summary.EffectsOf(key.Slot, body.Id);
            foreach (var e in sinks)
            {
                if (!value.TaintedFor(e.RuleId)) continue;
                _ctx.Report(e.RuleId, e.Site, value.WitnessFor(_entries.Of(body), e.RuleId).Extend(e.Path), e.Member);
            }
            foreach (var (location, symbolic) in heap)
            {
                var written = BodySummary.Through(symbolic, body.Id, key.Slot, value);
                if (written.Request) _heap.Write(location, written, _entries.WriteReach(body));
            }
            foreach (var c in calls) Seed(c.Callee, c.CalleeSlot, value.Extend(c.Path).CleanedFor(c.CleanFor));
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
            var symbolic = IsSymbolic(body);
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
                        value = TaintValue.Source(location, $"request data enters here: parameter '{p.Name}' of {_ctx.Name(method)}").ScopedTo(run.WriteReach);
                    }
                    if (body.IsLambda) value = value.Join(seed);
                    else if (p.RefKind != RefKind.Out) value = value.Join(TaintValue.Param(body.Id, p.Ordinal));
                    if (value.Any) entry.Set(p, value);
                    if (!body.IsLambda && EntryObjects(body, p, symbolic) is { } objects) entry.SetPointsTo(p, objects);
                }
            }

            var analyzer = new MethodAnalyzer(_ctx, cfg, run) { TrackReturnText = !body.IsLambda && body.Symbol is { } m && ReturnsString(m) };
            all = analyzer.Run(entry, collectAll: nested.Count > 0);
            var builder = Builder(body.Id);
            builder.Symbolic |= symbolic;
            if (symbolic) TopWritesOf(unit);
            // An iterator's value is the sequence, not what it yields: no objects or members of it are known.
            var returned = body.Symbol is { IsIterator: true } ? analyzer.ReturnValue.WithoutIdentity() : analyzer.ReturnValue;
            builder.Return = builder.Return.Join(returned);
            if (symbolic && analyzer.ExitState is { } exitState && body.Symbol is { IsIterator: false } owner) builder.ParamExit = ParamExit(owner, exitState, analyzer);
            if (analyzer.TrackReturnText) builder.ReturnText = BodySummary.JoinText(builder.ReturnText, analyzer.ReturnText);
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

    /// The members of each parameter's object (and `this`'s) the body overwrote on every path to its exit (Task 27): the
    /// strong updates at its exit of a path `p.M` whose root parameter the body never assigns.
    private static Dictionary<int, MemberMap> ParamExit(IMethodSymbol method, TaintState exit, MethodAnalyzer analyzer)
    {
        var builders = new Dictionary<int, ImmutableDictionary<ISymbol, TaintValue>.Builder>();
        foreach (var fact in exit.Facts)
        {
            if (fact.Holds == null || fact.Path.Members.Length != 1) continue;
            int slot;
            if (ReferenceEquals(fact.Path.Root, AccessPath.This) && !method.IsStatic) slot = -1;
            // A parameter passed by value that is no reference (a struct, an unconstrained type parameter) is the caller's
            // copy (fix round 1, I1); `this` of a struct is the caller's variable itself.
            else if (fact.Path.Root is IParameterSymbol { RefKind: RefKind.None, Type.IsReferenceType: true } p && SymbolEqualityComparer.Default.Equals(p.ContainingSymbol, method) && !analyzer.IsReassigned(p)) slot = p.Ordinal;
            else continue;
            if (!builders.TryGetValue(slot, out var b)) builders[slot] = b = ImmutableDictionary.CreateBuilder<ISymbol, TaintValue>(SymbolEqualityComparer.Default);
            b[fact.Path.Members[0]] = fact.Holds;
        }
        var result = new Dictionary<int, MemberMap>();
        foreach (var (slot, b) in builders)
            if (MemberMap.Of(b.ToImmutable()) is { } map) result[slot] = map;
        return result;
    }

    /// A method that returns a string (also as a Task's or ValueTask's result): its returned text is kept (Task 23).
    private static bool ReturnsString(IMethodSymbol method)
    {
        var type = method.ReturnType;
        if (type is INamedTypeSymbol { TypeArguments.Length: 1 } t
            && SymbolMatch.MetadataName(t.OriginalDefinition) is "System.Threading.Tasks.Task`1" or "System.Threading.Tasks.ValueTask`1")
            type = t.TypeArguments[0];
        return type.SpecialType == SpecialType.System_String;
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
            if (root.Symbol is { IsStatic: false } && computer.IsSymbolic(root)) This = This with { Objects = computer._ctx.Objects.Single(computer._ctx.Objects.Param(root.Id, -1)) };
            Reach = computer._entries.Of(body);
            WriteReach = computer._entries.WriteReach(body);
        }

        /// The run's abstract objects and member slots (Task 27).
        public ObjectTable Objects => _computer._ctx.Objects;

        /// Whether a body's parameter objects stand for its callers' (SummaryComputer.IsSymbolic).
        public bool IsSymbolic(Body body) => _computer.IsSymbolic(body);

        /// The summary of the unit's root records a member written through unknown objects (a call may end a strong
        /// update of it) and the parameters whose objects reach calls whose effects are unknown (Task 27).
        public void RecordTopWrite(ISymbol member) => TopWrites.Add(SymbolKeys.Of(SymbolKeys.Definition(member)));

        /// The members written through unknown objects in this body's component of the call graph (and what it calls).
        public HashSet<object> TopWrites => _computer.TopWritesOf(_unit);

        /// Adds a callee component's set to this component's, again only when it grew (a component's set is complete when a
        /// caller outside it runs; it holds every write whatever its value).
        public void AbsorbTopWrites(HashSet<object> callee)
        {
            if (ReferenceEquals(callee, TopWrites)) return;
            var absorbed = _computer.Absorbed(_unit.Scc);
            if (absorbed.TryGetValue(callee, out var count) && count == callee.Count) return;
            absorbed[callee] = callee.Count;
            TopWrites.UnionWith(callee);
        }

        /// Whether a body is in this body's component of the call graph (its summary is not final while this runs).
        public bool SameComponent(Body body) => body.Unit.Scc == _unit.Scc;

        /// A value given to a call whose effects are unknown: the root's parameters it holds the objects of, or whose
        /// labels (a parameter, a member read through one) it carries, escape.
        public void RecordEscape(TaintValue value)
        {
            var root = _unit.RootBody;
            var builder = _computer.Builder(root.Id);
            if (value.Objects is { } objects)
            {
                foreach (var o in objects.Ids)
                {
                    var (kind, owner, slot) = Objects.Describe(o);
                    if (kind == ObjKind.Param && owner == root.Id) builder.Escapes.Add(slot);
                }
            }
            foreach (var l in value.Labels)
                if (l.Owner == root.Id) builder.Escapes.Add(ObjectTable.IsMemberSlot(l.Slot) ? Objects.OfMemberSlot(l.Slot).Slot : l.Slot);
        }

        /// Whether the unit's root is symbolic: its effects on objects are recorded for its callers (Task 27).
        public bool RootSymbolic => _computer.IsSymbolic(_unit.RootBody);

        /// The unit's root body.
        public Body Root => _unit.RootBody;

        /// The entry points that reach this body (EntryPoints.Of): what it reads the heap under.
        public Reach Reach { get; }

        /// The entry points this body's writes and request data are valid for (EntryPoints.WriteReach: widened to every
        /// entry point for code around every action).
        public Reach WriteReach { get; }

        /// The value of `this`: the label of the unit root's receiver (a lambda's `this` is its enclosing member's).
        public TaintValue This { get; }

        public bool CapturedChanged { get; private set; }

        private AnalysisContext Ctx => _computer._ctx;

        /// The value of a local or parameter: its state joined with what the unit's lambdas and local functions write to
        /// it (captured writes, flow-insensitive).
        public TaintValue Local(ISymbol symbol, TaintValue value)
        {
            if (!_unit.HasCapturedWrites) return value;
            var written = _unit.CapturedWrites.Get(symbol);
            return written.Any ? value.Join(written) : value;
        }

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
            value = value.WithoutIdentity();
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
            for (var i = 0; i < methods.Count; i++)
                targets[i] = TargetOf(methods[i]) with { Fallback = _computer._dispatch.IsFallback(method, isVirtual, receiverType, methods[i]) };
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
            // The label's path for this rule (RR1): the best one not cleaned for it.
            if (Keeps(label.Owner)) _computer.Builder(label.Owner).AddSink(label.Slot, rule, site, member, label.PathFor(rule));
        }

        /// Something is written into the receiver object (`this._f = v`, `this.P = v`, a collection write into a field).
        public void RecordThis(TaintValue value)
        {
            if (!value.Any || This.Labels.Length == 0) return;
            var builder = _computer.Builder(_unit.RootBody.Id);
            builder.ToThis = builder.ToThis.Join(value);
        }

        public bool IsHeapMember(ISymbol member) => _computer._heap.IsMember(member);

        /// The request data of a member for this body (Heap.Read): through unknown objects (null) its field location,
        /// through known objects (the parameter objects aside, which the caller substitutes) theirs and the writes through
        /// unknown objects.
        public TaintValue HeapRead(ISymbol member, ObjSet? objects = null)
        {
            var value = _computer._heap.Read(member, _unit, Reach, objects, Objects);
            // Code around every action reads heap data in every request.
            if (value.Scope is not { } scope) return value;
            var widened = _computer._entries.Widen(scope);
            return ReferenceEquals(widened, scope) ? value : value with { Scope = widened };
        }

        /// The request data of a keyed store entry (ViewData, HttpContext.Items, the view model; Task 22), as HeapRead.
        public TaintValue KeyedRead(KeyedLocation location) => Widened(_computer._heap.Read(location, _unit, Reach));

        /// The view model read under several entries at once (what all of them know of its members: Task 27).
        public TaintValue KeyedRead(IEnumerable<KeyedLocation> locations) => Widened(_computer._heap.Read(locations, _unit, Reach));

        private TaintValue Widened(TaintValue value)
        {
            if (value.Scope is not { } scope) return value;
            var widened = _computer._entries.Widen(scope);
            return ReferenceEquals(widened, scope) ? value : value with { Scope = widened };
        }

        /// The part of keyed data read here (KeyedRead) that this body shares with its writers over resolved edges (R-9):
        /// the value itself when this body has no unresolved view name's fallback edge behind it (or the data is
        /// unscoped), else the value narrowed to the entry points that reach it over resolved edges (clean when none).
        public TaintValue ThroughResolvedEdges(TaintValue value)
        {
            if (!value.Request || value.Scope is not { } scope) return value;
            var precise = _computer._entries.PreciseOf(_body);
            if (ReferenceEquals(precise, Reach)) return value;
            return scope.Intersects(precise) ? value.Narrowed(precise) : TaintValue.Clean;
        }

        /// A write to a heap symbol: its request data to the heap, its labels to their owners' summaries. Through known
        /// objects (Task 27): each concrete object's member location; a parameter object's member is an ObjWrite of its
        /// body (written by each call site into the objects the call gives); unknown objects: the member's field location.
        public void HeapWrite(ISymbol member, TaintValue value, ObjSet? objects = null)
        {
            if (!IsHeapMember(member)) return;
            // A write through unknown objects, whatever its value, may end a caller's strong update of the member.
            if (objects == null && RootSymbolic) RecordTopWrite(member);
            if (!value.Any) return;
            value = value.WithoutIdentity();
            if (objects == null)
            {
                Store(member, value);
                return;
            }
            var heap = _computer._heap;
            var definition = SymbolKeys.Definition(member);
            foreach (var o in objects.Ids)
            {
                var (kind, owner, slot) = Objects.Describe(o);
                if (kind == ObjKind.Param)
                {
                    // Another body's parameter object (none is known to reach here): the member's field location.
                    if (Keeps(owner)) _computer.Builder(owner).AddObjWrite(slot, heap.Key(member), definition, value);
                    else Store(member, value);
                }
                else
                {
                    Store(new ObjLocation(o, heap.Key(member), definition), value, member);
                }
            }
        }

        /// A write to a keyed store entry, as HeapWrite. A view model is written also without request data (what it knows
        /// of its members: Task 27).
        public void KeyedWrite(KeyedLocation location, TaintValue value)
        {
            if (location.Store == KeyedStore.ViewModel && value.Objects is { } objects)
            {
                // The model's objects go with it (fix round 1, I2: a view reads what is written into them after View());
                // a parameter object is this body's own, unknown anywhere else.
                foreach (var o in objects.Ids)
                    if (Objects.IsParam(o))
                    {
                        value = value with { Objects = null };
                        break;
                    }
            }
            if (value.Any || location.Store == KeyedStore.ViewModel) Store(location, value);
        }

        private void Store(object location, TaintValue value, ISymbol? symbol = null)
        {
            var heap = _computer._heap;
            if (value.Request || location is KeyedLocation { Store: KeyedStore.ViewModel })
            {
                heap.Write(location, value, WriteReach);
                if ((symbol ?? location as ISymbol) is { } member && value.Request) _computer.Builder(_body.Id).RequestHeap.TryAdd(heap.Key(member), member);
            }
            if (value.Labels.Length == 0) return;
            var key = heap.Key(location);
            var labels = value.LabelPart;
            int? last = null;
            foreach (var l in value.Labels)
            {
                if (l.Owner == last || !Keeps(l.Owner)) continue;
                last = l.Owner;
                _computer.Builder(l.Owner).AddHeap(key, location, labels);
            }
        }

        public string Name(ISymbol symbol) => Ctx.Name(symbol);
    }
}
