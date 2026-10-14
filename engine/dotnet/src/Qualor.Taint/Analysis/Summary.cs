using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// What a method does with request data and with its parameters, for its callers (spec §5 "Interprocedural"; the
/// brief's shape, a view of the engine's BodySummary): per parameter ordinal (−1 is `this`) its effect, whether the
/// method returns request data it read itself (a source, or a tainted heap symbol), and the fields and properties it
/// taints with such data itself.
public sealed record Summary(
    IReadOnlyDictionary<int, ParamEffect> Params,
    bool ReturnsRequest,
    IReadOnlyList<ISymbol> WritesHeapFromRequest);

/// One parameter's effect: whether it reaches the return value, the sinks it reaches inside the method (or its callees)
/// with the path from the parameter to there, the heap symbols it is written to (by the method or its callees), and the
/// rules it is cleaned for on its way to the return value.
public sealed record ParamEffect(
    bool ToReturn,
    IReadOnlyList<(string RuleId, Location Sink, IReadOnlyList<PathStep> Path)> ToSinks,
    IReadOnlyList<ISymbol> ToHeap,
    ImmutableHashSet<string> CleanFor);

/// A parameter of a body reaches a sink in the body itself (or in a lambda or local function nested in it): Slot the
/// parameter (−1 `this`), Site the sink argument's syntax (or the assignment of a property sink), Member the sink
/// member, Path the steps inside the body from its entry.
internal sealed record SinkEffect(int Slot, string RuleId, SyntaxNode Site, ISymbol Member, Trail Path);

/// A parameter of a body is passed to a parameter of a callee (CalleeSlot of Callee), cleaned on its way for CleanFor;
/// Path the steps inside the body from its entry to the callee's entry. The callee's own effects are not copied into
/// the caller: request data that reaches the parameter flows on along these edges (SummaryComputer.Seed).
internal sealed record CallEffect(int Slot, Body Callee, int CalleeSlot, ImmutableHashSet<string> CleanFor, Trail Path)
{
    /// `old` joined with another edge of the same parameters: CleanFor intersected, the first path kept unless the other
    /// is high and it is not (R-9); null when nothing changes.
    public static CallEffect? Joined(CallEffect old, ImmutableHashSet<string> cleanFor, Trail path)
    {
        var narrower = !old.CleanFor.IsSubsetOf(cleanFor);
        var better = old.Path.Medium && !path.Medium;
        if (!narrower && !better) return null;
        return old with { CleanFor = narrower ? old.CleanFor.Intersect(cleanFor) : old.CleanFor, Path = better ? path : old.Path };
    }
}

/// The engine's summary of one body, in the body's own parameter labels (TaintValue.Labels whose owner is the body;
/// a local function's summary may also hold labels of the body it is nested in, its captures, which a call site keeps).
///
/// Local effects, which a call site substitutes its arguments into:
/// - Return: the value returned (its request part is data the body reads itself: ReturnsRequest);
/// - ToThis: what is written into the receiver object (a constructor's: the object created);
/// - Refs: the value of each ref and out parameter at the exit.
///
/// - ReturnText: the text every value the body returns starts with (a string method's; Task 23), for `string-prefix:`
///   sanitizers at its callers (MethodAnalyzer.KnownText).
///
/// Global effects, which request data reaching a parameter triggers (SummaryComputer.Seed), so a summary's size does not
/// grow with what its callees do (a chain of N calls costs N edges, not N² copied sinks):
/// - Sinks: the parameters that reach a sink in this body;
/// - Calls: the parameters passed on to a callee's parameters;
/// - Heap: the label part this body writes to each heap location, a member or a keyed store entry (the request part goes
///   to the Heap at once).
///
/// Objects (Task 27, decision R-8), for a body whose parameters and `this` stand for the objects its calls give (a body
/// SummaryComputer.IsSymbolic: called from source and not by the framework):
/// - Return carries the objects the body returns (its own parameter objects among them) and the members of the returned
///   object it knows exactly;
/// - a slot may be a member slot (ObjectTable.MemberSlot: member M of parameter k's objects), read where the body reads a
///   member through its parameter: a call site gives what its argument holds in M;
/// - ObjWrites: what the body writes into member M of parameter k's objects (a call site writes it into its argument's
///   objects); ParamExit: the members of parameter k's object the body overwrote on every path (the call site's argument
///   holds them exactly after the call); TopWrites: the members written through unknown objects by the body, its
///   component of the call graph and what that calls (one set per component, shared by its bodies); Escapes: the
///   parameters whose objects (or what the body read from them) it gives to calls whose effects are unknown (External, a
///   delegate, a dynamic call, a body not summarised so, a body of its own component). The last three tell a call site
///   outside the component which strong updates the call may end.
internal sealed class BodySummary
{
    public static readonly BodySummary Empty = new();

    public TaintValue Return { get; init; } = TaintValue.Bottom;

    public TaintValue ToThis { get; init; } = TaintValue.Clean;

    public ImmutableDictionary<int, TaintValue> Refs { get; init; } = ImmutableDictionary<int, TaintValue>.Empty;

    /// The text the body's returned strings are known to have, a Hole (MethodAnalyzer.Hole) standing for any text; a
    /// lone Hole when nothing is known, null when no return has been seen (or the body returns no string).
    public string? ReturnText { get; init; }

    public ImmutableDictionary<(int Slot, string Rule, SyntaxTree Tree, TextSpan Span), SinkEffect> Sinks { get; init; } =
        ImmutableDictionary<(int, string, SyntaxTree, TextSpan), SinkEffect>.Empty;

    public ImmutableDictionary<(int Slot, int Callee, int CalleeSlot), CallEffect> Calls { get; init; } =
        ImmutableDictionary<(int, int, int), CallEffect>.Empty;

    public ImmutableDictionary<object, (object Location, TaintValue Value)> Heap { get; init; } =
        ImmutableDictionary<object, (object, TaintValue)>.Empty;

    /// Heap symbols the body writes request data of its own to (for the public view).
    public ImmutableDictionary<object, ISymbol> RequestHeap { get; init; } = ImmutableDictionary<object, ISymbol>.Empty;

    /// Whether the body's parameters and `this` are its own objects (Task 27): its effects on them are in ObjWrites,
    /// ParamExit, TopWrites and GivenTypes.
    public bool Symbolic { get; init; }

    public ImmutableDictionary<(int Slot, object Member), (ISymbol Symbol, TaintValue Value)> ObjWrites { get; init; } =
        ImmutableDictionary<(int, object), (ISymbol, TaintValue)>.Empty;

    /// Null: not analysed yet (every member known: the identity of a join).
    public ImmutableDictionary<int, MemberMap>? ParamExit { get; init; }

    /// The member keys (SymbolKeys.Of) of the body's component (SummaryComputer: complete once the component's fixed
    /// point is done, which a caller outside it waits for); null before the body is analysed.
    public HashSet<object>? TopWrites { get; init; }

    /// The parameter slots (−1: `this`) whose objects, or what the body read from them, reach calls whose effects are
    /// unknown.
    public ImmutableHashSet<int> Escapes { get; init; } = ImmutableHashSet<int>.Empty;

    /// The member slots the global effects use (a call site passes its argument's member for each).
    public ImmutableArray<int> MemberSlots { get; init; } = ImmutableArray<int>.Empty;

    /// No local effect: a call site gets nothing back (a generic helper's view model aside, which the call site writes).
    public bool NoLocalEffects => !Return.Any && !ToThis.Any && Refs.IsEmpty && !Return.KnowsIdentity && ObjWrites.IsEmpty && (ParamExit == null || ParamExit.IsEmpty);

    public bool IsEmpty => NoTaint && ReturnText == null && ParamExit == null && !Return.KnowsIdentity && TopWrites == null && Escapes.IsEmpty && ObjWrites.IsEmpty;

    /// No effect on taint at all (the public view lists only the bodies that have one).
    public bool NoTaint => !Return.Any && !ToThis.Any && Refs.IsEmpty && ObjWrites.IsEmpty && Sinks.IsEmpty && Calls.IsEmpty && Heap.IsEmpty && RequestHeap.IsEmpty;

    /// The text two sets of strings both start with: the common start of the two texts, followed by a Hole where they
    /// differ (a Hole in either ends the common part); null is no string at all.
    public static string? JoinText(string? a, string? b)
    {
        if (a == null || a == b) return b;
        if (b == null) return a;
        var n = 0;
        while (n < a.Length && n < b.Length && a[n] == b[n] && a[n] != MethodAnalyzer.Hole) n++;
        return a[..n] + MethodAnalyzer.Hole;
    }

    /// This summary joined with `other` (a body's summaries only grow, so the fixed point ends).
    public BodySummary Join(BodySummary other)
    {
        if (ReferenceEquals(this, other) || other.IsEmpty) return this;
        if (IsEmpty) return other;
        var refs = Refs;
        foreach (var (k, v) in other.Refs) refs = refs.SetItem(k, refs.TryGetValue(k, out var old) ? old.Join(v) : v);
        var sinks = Sinks;
        foreach (var (k, v) in other.Sinks)
        {
            // The first path is kept, unless the other one is high and it is not (R-9).
            if (!sinks.TryGetValue(k, out var old)) sinks = sinks.Add(k, v);
            else if (old.Path.Medium && !v.Path.Medium) sinks = sinks.SetItem(k, v);
        }
        var calls = Calls;
        foreach (var (k, v) in other.Calls)
        {
            if (!calls.TryGetValue(k, out var old)) calls = calls.Add(k, v);
            else if (CallEffect.Joined(old, v.CleanFor, v.Path) is { } joined) calls = calls.SetItem(k, joined);
        }
        var heap = Heap;
        foreach (var (k, v) in other.Heap) heap = heap.SetItem(k, heap.TryGetValue(k, out var old) ? (old.Location, old.Value.Join(v.Value)) : v);
        var requestHeap = RequestHeap;
        foreach (var (k, v) in other.RequestHeap) if (!requestHeap.ContainsKey(k)) requestHeap = requestHeap.Add(k, v);
        var objWrites = ObjWrites;
        foreach (var (k, v) in other.ObjWrites) objWrites = objWrites.SetItem(k, objWrites.TryGetValue(k, out var old) ? (old.Symbol, old.Value.Join(v.Value)) : v);
        var paramExit = ParamExit;
        if (paramExit == null) paramExit = other.ParamExit;
        else if (other.ParamExit != null && !ReferenceEquals(paramExit, other.ParamExit))
        {
            var met = ImmutableDictionary<int, MemberMap>.Empty;
            foreach (var (slot, members) in paramExit)
                if (other.ParamExit.TryGetValue(slot, out var theirs) && MemberMap.Meet(members, theirs) is { } m) met = met.Add(slot, m);
            paramExit = met;
        }
        var summary = new BodySummary
        {
            Return = Return.Join(other.Return),
            ToThis = ToThis.Join(other.ToThis),
            Refs = refs,
            Sinks = sinks,
            Calls = calls,
            Heap = heap,
            RequestHeap = requestHeap,
            ReturnText = JoinText(ReturnText, other.ReturnText),
            Symbolic = Symbolic || other.Symbolic,
            ObjWrites = objWrites,
            ParamExit = paramExit,
            TopWrites = TopWrites ?? other.TopWrites,
            Escapes = Escapes.Union(other.Escapes),
        };
        return summary.WithMemberSlots();
    }

    private Dictionary<int, (List<SinkEffect> Sinks, List<CallEffect> Calls, List<(object Location, TaintValue Value)> Heap)>? _bySlot;

    /// The global effects of one slot (a seed of it runs these): an index built once per summary (Task 27: member slots
    /// make many seeds per body, each of which would otherwise scan all the body's effects).
    public (List<SinkEffect> Sinks, List<CallEffect> Calls, List<(object Location, TaintValue Value)> Heap) EffectsOf(int slot, int owner)
    {
        if (_bySlot == null)
        {
            var index = new Dictionary<int, (List<SinkEffect>, List<CallEffect>, List<(object, TaintValue)>)>();
            (List<SinkEffect>, List<CallEffect>, List<(object, TaintValue)>) Of(int k)
            {
                if (!index.TryGetValue(k, out var e)) index[k] = e = (new List<SinkEffect>(), new List<CallEffect>(), new List<(object, TaintValue)>());
                return e;
            }
            foreach (var e in Sinks.Values) Of(e.Slot).Item1.Add(e);
            foreach (var c in Calls.Values) Of(c.Slot).Item2.Add(c);
            foreach (var h in Heap.Values)
            {
                var seen = new HashSet<int>();
                foreach (var l in h.Value.Labels)
                    if (l.Owner == owner && seen.Add(l.Slot)) Of(l.Slot).Item3.Add(h);
            }
            _bySlot = index;
        }
        return _bySlot.TryGetValue(slot, out var effects) ? effects : (EmptySinks, EmptyCalls, EmptyHeap);
    }

    private static readonly List<SinkEffect> EmptySinks = new();
    private static readonly List<CallEffect> EmptyCalls = new();
    private static readonly List<(object, TaintValue)> EmptyHeap = new();

    /// The summary with MemberSlots computed from its global effects.
    public BodySummary WithMemberSlots()
    {
        if (MemberSlots.IsEmpty && !Sinks.Values.Any(e => ObjectTable.IsMemberSlot(e.Slot)) && !Calls.Values.Any(c => ObjectTable.IsMemberSlot(c.Slot))
            && !Heap.Values.Any(h => h.Value.Labels.Any(l => ObjectTable.IsMemberSlot(l.Slot))))
            return this;
        var slots = new SortedSet<int>();
        foreach (var e in Sinks.Values) if (ObjectTable.IsMemberSlot(e.Slot)) slots.Add(e.Slot);
        foreach (var c in Calls.Values) if (ObjectTable.IsMemberSlot(c.Slot)) slots.Add(c.Slot);
        foreach (var (_, v) in Heap.Values)
            foreach (var l in v.Labels)
                if (ObjectTable.IsMemberSlot(l.Slot)) slots.Add(l.Slot);
        if (slots.Count == MemberSlots.Length && slots.SequenceEqual(MemberSlots)) return this;
        return new BodySummary
        {
            Return = Return, ToThis = ToThis, Refs = Refs, Sinks = Sinks, Calls = Calls, Heap = Heap, RequestHeap = RequestHeap,
            ReturnText = ReturnText, Symbolic = Symbolic, ObjWrites = ObjWrites, ParamExit = ParamExit, TopWrites = TopWrites,
            Escapes = Escapes, MemberSlots = slots.ToImmutableArray(),
        };
    }

    /// Equal in the local effects (paths and source locations aside): what decides whether callers are analysed again.
    public bool SameLocalEffects(BodySummary other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (!Return.SameFlow(other.Return) || !ToThis.SameFlow(other.ToThis) || Refs.Count != other.Refs.Count) return false;
        if (ReturnText != other.ReturnText) return false;
        foreach (var (k, v) in Refs) if (!other.Refs.TryGetValue(k, out var o) || !v.SameFlow(o)) return false;
        // Task 27: the objects and members a call gets back, what it writes into its arguments' objects, the strong updates
        // it may end, and the member slots its global effects ask the call sites for.
        if (!Return.SameIdentity(other.Return) || ObjWrites.Count != other.ObjWrites.Count
            || Escapes.Count != other.Escapes.Count || !MemberSlots.SequenceEqual(other.MemberSlots)) return false;
        foreach (var (k, v) in ObjWrites)
            if (!other.ObjWrites.TryGetValue(k, out var o) || !v.Value.SameFlow(o.Value)) return false;
        if ((ParamExit == null) != (other.ParamExit == null)) return false;
        if (ParamExit != null)
        {
            if (ParamExit.Count != other.ParamExit!.Count) return false;
            foreach (var (k, v) in ParamExit) if (!other.ParamExit.TryGetValue(k, out var o) || !v.SameFlow(o)) return false;
        }
        // A generic helper's view model is written at its callers (MethodAnalyzer.GenericModels): a change of it is a
        // change of what a call site does (Task 22 fix round 1, I2).
        var mine = Heap.TryGetValue(KeyedLocation.Generic, out var a);
        var theirs = other.Heap.TryGetValue(KeyedLocation.Generic, out var b);
        return mine == theirs && (!mine || a.Value.SameFlow(b.Value));
    }

    /// Equal in the global effects: what decides whether the request data at the body's parameters flows on again.
    public bool SameGlobalEffects(BodySummary other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (Sinks.Count != other.Sinks.Count || Calls.Count != other.Calls.Count || Heap.Count != other.Heap.Count) return false;
        // A path that became high is a change (R-9): the seeds report it again.
        foreach (var (k, v) in Sinks) if (!other.Sinks.TryGetValue(k, out var o) || v.Path.Medium != o.Path.Medium) return false;
        foreach (var (k, v) in Calls)
            if (!other.Calls.TryGetValue(k, out var o) || !v.CleanFor.SetEquals(o.CleanFor) || v.Path.Medium != o.Path.Medium) return false;
        foreach (var (k, v) in Heap) if (!other.Heap.TryGetValue(k, out var o) || !v.Value.SameFlow(o.Value)) return false;
        return true;
    }

    /// The value a call gets for a symbolic value of the callee `owner`: its request part (data the callee reads itself),
    /// and for each of the callee's labels the argument at that slot, through the callee's steps and cleaned as the
    /// callee cleans it. A label of another body (a local function's capture of its enclosing body) is kept when
    /// `keep` accepts its owner. Request data the callee read from the heap reaches the call only for the entry points
    /// that also reach the caller (`caller`; TaintValue.Scope).
    /// `kind`: the kind of the call's steps (StepKind.DispatchFallback for a call resolved by the class-hierarchy
    /// fallback, R-9).
    public static TaintValue Substitute(TaintValue symbolic, int owner, Func<int, TaintValue> argument, Location site, string name, Func<int, bool> keep,
        Reach caller, bool dropViaKey = false, ObjectTable? objects = null, StepKind kind = StepKind.Plain)
    {
        if (!symbolic.Any) return symbolic.HasIdentity && objects != null ? SubstituteIdentity(TaintValue.Clean, symbolic, owner, argument, site, name, keep, caller, objects, kind) : TaintValue.Clean;
        var result = SubstituteTaint(symbolic, owner, argument, site, name, keep, caller, dropViaKey, kind);
        return symbolic.HasIdentity && objects != null ? SubstituteIdentity(result, symbolic, owner, argument, site, name, keep, caller, objects, kind) : result;
    }

    /// The objects and members of a symbolic value at a call (Task 27): the callee's parameter objects become the objects
    /// its arguments hold (unknown when an argument's are); another body's parameter objects are kept when `keep`
    /// accepts the body (a capture of the enclosing body), else unknown; each known member's value is substituted.
    private static TaintValue SubstituteIdentity(TaintValue result, TaintValue symbolic, int owner, Func<int, TaintValue> argument, Location site, string name,
        Func<int, bool> keep, Reach caller, ObjectTable objects, StepKind kind)
    {
        var objs = symbolic.Objects?.SelectMany(id =>
        {
            var (kind, body, slot) = objects.Describe(id);
            if (kind != ObjKind.Param) return objects.Single(id);
            if (body == owner) return argument(slot).Objects;
            return keep(body) ? objects.Single(id) : null;
        });
        var members = symbolic.Members?.Select(v => Substitute(v, owner, argument, site, name, keep, caller, false, objects, kind));
        return result with { Objects = objs, Members = members };
    }

    private static TaintValue SubstituteTaint(TaintValue symbolic, int owner, Func<int, TaintValue> argument, Location site, string name, Func<int, bool> keep,
        Reach caller, bool dropViaKey, StepKind kind)
    {
        var own = symbolic.RequestPart.WithoutIdentity().Within(caller);
        if (dropViaKey && own.KeyOnly) own = TaintValue.Clean;
        var result = own.Request ? own.Step(site, $"returned by {name}", kind) : TaintValue.Clean;
        foreach (var label in symbolic.Labels)
        {
            if (label.Owner == owner)
            {
                // A value-factory call (dropViaKey) loses what reached the result only as a lookup key (R-E23); any other
                // call keeps it, its labels still marked so a caller's value-factory shape can drop them in turn.
                if (label.ViaKey && dropViaKey) continue;
                var a = argument(label.Slot).WithoutIdentity();
                if (!a.Any) continue;
                var v = a.Step(site, $"passed to {name}", kind).Extend(label.Path).CleanedFor(label.CleanFor);
                result = result.Join(label.ViaKey ? v.ViaKey() : v);
            }
            else if (keep(label.Owner))
            {
                result = result.Join(TaintValue.Clean with { Labels = ImmutableArray.Create(label) });
            }
        }
        return result;
    }

    /// The request data a symbolic value of `owner` holds when `value` reaches parameter `slot` (its other labels
    /// clean): what a seed writes to the heap.
    public static TaintValue Through(TaintValue symbolic, int owner, int slot, TaintValue value)
    {
        var result = TaintValue.Clean;
        foreach (var label in symbolic.Labels)
            if (label.Owner == owner && label.Slot == slot) result = result.Join(value.Extend(label.Path).CleanedFor(label.CleanFor));
        return result;
    }
}

/// The summary of one body while it is analysed (and the bodies nested in it record effects on its labels).
internal sealed class SummaryBuilder
{
    public TaintValue Return = TaintValue.Bottom;
    public TaintValue ToThis = TaintValue.Clean;
    public string? ReturnText;
    public readonly Dictionary<int, TaintValue> Refs = new();
    public readonly Dictionary<(int Slot, string Rule, SyntaxTree Tree, TextSpan Span), SinkEffect> Sinks = new();
    public readonly Dictionary<(int Slot, int Callee, int CalleeSlot), CallEffect> Calls = new();
    public readonly Dictionary<object, (object Location, TaintValue Value)> Heap = new();
    public readonly Dictionary<object, ISymbol> RequestHeap = new();
    public readonly Dictionary<(int Slot, object Member), (ISymbol Symbol, TaintValue Value)> ObjWrites = new();
    public Dictionary<int, MemberMap>? ParamExit;
    public HashSet<object>? TopWrites;
    public readonly HashSet<int> Escapes = new();
    public bool Symbolic;

    public void AddObjWrite(int slot, object key, ISymbol member, TaintValue value)
    {
        if (!value.Any) return;
        value = value.WithoutIdentity();
        ObjWrites[(slot, key)] = ObjWrites.TryGetValue((slot, key), out var old) ? (old.Symbol, old.Value.Join(value)) : (member, value);
    }

    /// The first path of a sink is kept, unless a later one is high and it is not (R-9).
    public void AddSink(int slot, string rule, SyntaxNode site, ISymbol member, Trail path)
    {
        var key = (slot, rule, site.SyntaxTree, site.Span);
        if (!Sinks.TryGetValue(key, out var old) || (old.Path.Medium && !path.Medium)) Sinks[key] = new SinkEffect(slot, rule, site, member, path);
    }

    public void AddCall(int slot, Body callee, int calleeSlot, ImmutableHashSet<string> cleanFor, Trail path)
    {
        var key = (slot, callee.Id, calleeSlot);
        if (!Calls.TryGetValue(key, out var old)) Calls[key] = new CallEffect(slot, callee, calleeSlot, cleanFor, path);
        else if (CallEffect.Joined(old, cleanFor, path) is { } joined) Calls[key] = joined;
    }

    public void AddHeap(object key, object location, TaintValue labels)
    {
        if (!labels.Any) return;
        Heap[key] = Heap.TryGetValue(key, out var old) ? (old.Location, old.Value.Join(labels)) : (location, labels);
    }

    public BodySummary Build()
    {
        return new BodySummary
        {
            Return = Return,
            ToThis = ToThis,
            Refs = Refs.ToImmutableDictionary(),
            Sinks = Sinks.ToImmutableDictionary(),
            Calls = Calls.ToImmutableDictionary(),
            Heap = Heap.ToImmutableDictionary(),
            RequestHeap = RequestHeap.ToImmutableDictionary(),
            ReturnText = ReturnText,
            Symbolic = Symbolic,
            ObjWrites = ObjWrites.ToImmutableDictionary(),
            ParamExit = Symbolic ? (ParamExit ?? new Dictionary<int, MemberMap>()).ToImmutableDictionary() : null,
            TopWrites = TopWrites,
            Escapes = Escapes.ToImmutableHashSet(),
        }.WithMemberSlots();
    }
}
