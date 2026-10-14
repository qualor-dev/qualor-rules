using System.Collections.Immutable;
using System.Numerics;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// A path as an immutable rope of steps (Task 8): adding a step and appending another trail (a callee's steps after a
/// call) are O(1) and share structure, so the paths of summaries applied along deep call chains cost a node each; a
/// trail is flattened only when a finding is reported (at most MaxReported steps: the first and last ones).
internal sealed class Trail
{
    /// A trail stops growing at this many steps (a soft cap against pathological recursion).
    public const int MaxSteps = 4096;

    /// The most steps a reported path shows; the middle of a longer one is replaced by one "steps omitted" step.
    public const int MaxReported = 64;

    public static readonly Trail Empty = new(null, null, null, 0, null);

    private readonly Trail? _left;
    private readonly Trail? _right;
    private readonly PathStep? _step;

    private Trail(Trail? left, Trail? right, PathStep? step, int count, PathStep? last)
    {
        _left = left;
        _right = right;
        _step = step;
        Count = count;
        Last = last;
    }

    public int Count { get; }

    public PathStep? Last { get; }

    public static Trail Of(PathStep step) => new(null, null, step, 1, step);

    public Trail Add(PathStep step) => Count == 0 ? Of(step) : Count >= MaxSteps ? this : new Trail(this, Of(step), null, Count + 1, step);

    public Trail Concat(Trail other) =>
        other.Count == 0 ? this : Count == 0 ? other : Count + other.Count > MaxSteps ? this : new Trail(this, other, null, Count + other.Count, other.Last);

    /// The steps in order (a longer trail: its first and last MaxReported / 2 steps around one omission step).
    public ImmutableList<PathStep> ToList()
    {
        var all = new List<PathStep>(Count);
        var stack = new Stack<Trail>();
        stack.Push(this);
        while (stack.Count > 0)
        {
            var t = stack.Pop();
            if (t._step != null) all.Add(t._step);
            if (t._right != null) stack.Push(t._right);
            if (t._left != null) stack.Push(t._left);
        }
        if (all.Count <= MaxReported) return all.ToImmutableList();
        var half = MaxReported / 2;
        var omitted = all.Count - 2 * half;
        return all.Take(half)
            .Append(new PathStep(all[half].Location, $"... {omitted} steps omitted ..."))
            .Concat(all.Skip(all.Count - half + 1))
            .ToImmutableList();
    }
}

/// A parameter label (Task 8, spec §5 "summaries"): the value derives from parameter Slot of the body Owner (−1 is
/// `this`), cleaned on its way for CleanFor; Path is the steps inside that body since its entry. A body's summary is its
/// return value, sinks and heap writes expressed in its own labels; a call site substitutes its arguments for them.
internal sealed class Label
{
    public Label(int owner, int slot, ImmutableHashSet<string> cleanFor, Trail path, bool viaKey = false)
    {
        Owner = owner;
        Slot = slot;
        CleanFor = cleanFor;
        Path = path;
        ViaKey = viaKey;
    }

    /// The parameter reaches the value only as the key of a lookup whose element is typed by a type parameter (fix round
    /// 1 of Task 23, ruling R-E23): whether the key carries depends on the type argument. A call of a value-factory
    /// shaped method drops such labels from its result; any other call keeps them. A join keeps the flag only when both
    /// sides have it (a plain flow of the parameter wins).
    public bool ViaKey { get; }

    public int Owner { get; }

    public int Slot { get; }

    public ImmutableHashSet<string> CleanFor { get; }

    public Trail Path { get; }

    public bool TaintedFor(string rule) => !CleanFor.Contains(rule);

    public int CompareKey(Label other) => Owner != other.Owner ? Owner.CompareTo(other.Owner) : Slot.CompareTo(other.Slot);
}

/// The abstract value of an expression or a variable (spec §5): whether it carries request data (Request) and, if so,
/// the rules it has been cleaned for by a sanitizer (CleanFor: the value is dirty for every other rule). Path is one
/// witness from a source to here; Sources the source locations whose data it carries (at most MaxSources). Labels
/// (Task 8): the parameters of the analysed body (and of the bodies it is nested in) the value derives from, sorted by
/// owner and slot, one per parameter.
///
/// The lattice: a clean value (Request false, no labels) is the bottom; a request value is above it, and the smaller
/// its CleanFor, the higher; labels form a set lattice of their own (per label, the smaller its CleanFor, the higher).
/// Join is the union of the request flags and the intersection of CleanFor (over the request values only: a clean
/// operand does not make a cleaned one dirty); Sources are united; labels are united, CleanFor intersected per label.
/// Paths do not take part in the order (they are witnesses, the shorter one is kept), so the fixed point ends when
/// Request, CleanFor, Scope, Sources and labels stop changing.
///
/// Scope (Task 20, the request-scoped heap): the entry points the request data is valid for — those that reach the body
/// that read it from the request (ScopedTo), or, for data read from the heap, the writers' entry points the reading body
/// shares (Heap.Read); null: every one. A summary's request part reaches a caller only for the entry points that reach
/// the caller too (BodySummary.Substitute); a heap write records it under those entry points only. Join unites scopes
/// (null, unscoped, is the top). FromHeap: every part of the data was read from the heap; such data never reaches a
/// caller no entry point reaches (the spec: that code reads the heap clean), while data a helper read from the request
/// does (a caller the call graph cannot connect, a typed HTTP client built by DI, still runs in the request that built
/// it). FromHeap joins by "and".
///
/// Witnesses (fix round 1, I4): Path is one witness, valid for Scope. When request data of different scopes is joined,
/// Witnesses keeps up to MaxWitnesses (scope, shortest path) pairs, Path the shortest of them; every narrowing (Within,
/// a heap read or write) drops the witnesses whose scope it leaves, so a reported path (WitnessFor) starts in a request
/// that reaches the sink. Witnesses, like paths, do not take part in the order.
internal readonly record struct Witness(Reach? Scope, Trail Path);

internal sealed record TaintValue(bool Request, ImmutableHashSet<string> CleanFor, Trail Path)
{
    public const int MaxSources = 16;

    public static readonly TaintValue Clean = new(false, ImmutableHashSet<string>.Empty, Trail.Empty);

    public ImmutableHashSet<Location> Sources { get; init; } = ImmutableHashSet<Location>.Empty;

    public ImmutableArray<Label> Labels { get; init; } = ImmutableArray<Label>.Empty;

    /// The entry points the request data is valid for (null: every one); see the type's documentation.
    public Reach? Scope { get; init; }

    /// Whether every part of the request data was read from the heap (see the type's documentation).
    public bool FromHeap { get; init; }

    /// The request data reached this value only as the key of a lookup whose element is typed by a type parameter (the
    /// request counterpart of Label.ViaKey, R-E23): a value-factory shaped call drops it from its result. A join keeps
    /// it only when both request parts have it.
    public bool KeyOnly { get; init; }

    public const int MaxWitnesses = 4;

    /// The alternative witnesses (scope, path), shortest first, Path the first; empty: Path is the only one, valid for
    /// Scope.
    public ImmutableArray<Witness> Witnesses { get; init; } = ImmutableArray<Witness>.Empty;

    private ImmutableArray<Witness> AllWitnesses => Witnesses.IsDefaultOrEmpty ? ImmutableArray.Create(new Witness(Scope, Path)) : Witnesses;

    /// The request data narrowed to the entry points of `reach` (assumed to share some with Scope): its scope and its
    /// witnesses (those whose scope shares none are dropped, unless none would be left).
    public TaintValue Narrowed(Reach reach)
    {
        if (!Request) return this;
        var scope = Scope == null ? reach : Scope.Intersect(reach);
        if (Witnesses.IsDefaultOrEmpty) return ReferenceEquals(scope, Scope) ? this : this with { Scope = scope };
        var kept = ImmutableArray.CreateBuilder<Witness>(Witnesses.Length);
        foreach (var w in Witnesses)
        {
            if (w.Scope == null) kept.Add(new Witness(reach, w.Path));
            else if (w.Scope.Intersects(reach)) kept.Add(new Witness(w.Scope.Intersect(reach), w.Path));
        }
        if (kept.Count == 0) return this with { Scope = scope, Witnesses = ImmutableArray<Witness>.Empty };
        var witnesses = Merge(kept, ImmutableArray<Witness>.Empty);
        return this with { Scope = scope, Path = witnesses[0].Path, Witnesses = witnesses.Length > 1 ? witnesses : ImmutableArray<Witness>.Empty };
    }

    /// This value with the path of a witness whose scope shares an entry point with `reach` (the sink's body): what a
    /// finding reports.
    public TaintValue WitnessFor(Reach reach)
    {
        if (!Request || Witnesses.IsDefaultOrEmpty) return this;
        var target = Scope == null ? reach : Scope.Intersect(reach);
        foreach (var w in Witnesses)
            if (w.Scope == null || w.Scope.Intersects(target))
                return ReferenceEquals(w.Path, Path) ? this : this with { Path = w.Path };
        return this;
    }

    /// Two witness lists merged: one per scope (the shorter path), shortest first, at most MaxWitnesses.
    private static ImmutableArray<Witness> Merge(IEnumerable<Witness> a, IEnumerable<Witness> b)
    {
        var byScope = new List<Witness>();
        foreach (var w in a.Concat(b))
        {
            var i = byScope.FindIndex(x => Equals(x.Scope, w.Scope));
            if (i < 0) byScope.Add(w);
            else if (w.Path.Count < byScope[i].Path.Count) byScope[i] = w;
        }
        byScope.Sort((x, y) => x.Path.Count.CompareTo(y.Path.Count));
        if (byScope.Count > MaxWitnesses) byScope.RemoveRange(MaxWitnesses, byScope.Count - MaxWitnesses);
        return byScope.ToImmutableArray();
    }

    private static bool SameWitnesses(ImmutableArray<Witness> a, ImmutableArray<Witness> b)
    {
        if (a.IsDefaultOrEmpty || b.IsDefaultOrEmpty) return a.IsDefaultOrEmpty && b.IsDefaultOrEmpty;
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
            if (!ReferenceEquals(a[i].Path, b[i].Path) || !Equals(a[i].Scope, b[i].Scope)) return false;
        return true;
    }

    /// Request data read from the request in a body that `reach` reaches: valid in those requests only (an empty reach,
    /// which EntryPoints never gives a body that reads the request, leaves it unscoped).
    public TaintValue ScopedTo(Reach reach) =>
        !Request || reach.IsEmpty ? this : this with { Scope = reach, FromHeap = false, Witnesses = ImmutableArray<Witness>.Empty };

    /// The request data restricted to the entry points of `reach`: none when it shares no entry point with the scope
    /// and was read from the heap; unscoped data, and data read from the request that shares none (a caller the call
    /// graph does not connect), are kept as they are.
    public TaintValue Within(Reach reach)
    {
        if (!Request || Scope == null) return this;
        var scope = Scope.Intersect(reach);
        if (scope.IsEmpty) return FromHeap ? LabelPart : this;
        return ReferenceEquals(scope, Scope) ? this : Narrowed(reach);
    }

    /// Request data or a parameter label: anything a later step must carry.
    public bool Any => Request || Labels.Length > 0;

    /// Request data that enters at `location` (a source).
    public static TaintValue Source(Location location, string message) =>
        new(true, ImmutableHashSet<string>.Empty, Trail.Of(new PathStep(location, message)))
        {
            Sources = ImmutableHashSet.Create(location),
        };

    /// The label of parameter `slot` (−1: `this`) of body `owner`.
    public static TaintValue Param(int owner, int slot) =>
        Clean with { Labels = ImmutableArray.Create(new Label(owner, slot, ImmutableHashSet<string>.Empty, Trail.Empty)) };

    /// This value with every label marked as reaching it only through a type-parameter-typed key lookup (Label.ViaKey).
    public TaintValue ViaKey()
    {
        var value = Request && !KeyOnly ? this with { KeyOnly = true } : this;
        return value.Labels.Length == 0 || value.Labels.All(l => l.ViaKey) ? value
            : value with { Labels = value.Labels.Select(l => l.ViaKey ? l : new Label(l.Owner, l.Slot, l.CleanFor, l.Path, true)).ToImmutableArray() };
    }

    /// The request data of this value, without its labels.
    public TaintValue RequestPart => Labels.Length == 0 ? this : Request ? this with { Labels = ImmutableArray<Label>.Empty } : Clean;

    /// The labels of this value, without its request data.
    public TaintValue LabelPart => !Request ? this : Labels.Length == 0 ? Clean : Clean with { Labels = Labels };

    public bool TaintedFor(string rule) => Request && !CleanFor.Contains(rule);

    public TaintValue Join(TaintValue other)
    {
        if (ReferenceEquals(this, other) || !other.Any) return this;
        if (!Any) return other;
        bool request;
        ImmutableHashSet<string> cleanFor;
        ImmutableHashSet<Location> sources;
        Trail path;
        var requestChanged = false;
        var scope = Scope;
        var fromHeap = FromHeap;
        var keyOnly = KeyOnly;
        var witnesses = Witnesses;
        if (Request && other.Request)
        {
            request = true;
            scope = Scope == null || other.Scope == null ? null : Scope.Union(other.Scope);
            fromHeap = FromHeap && other.FromHeap;
            keyOnly = KeyOnly && other.KeyOnly;
            cleanFor = CleanFor.Count == 0 || other.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : CleanFor.Intersect(other.CleanFor);
            sources = Sources;
            foreach (var s in other.Sources)
            {
                if (sources.Count >= MaxSources) break;
                sources = sources.Add(s);
            }
            path = other.Path.Count < Path.Count ? other.Path : Path;
            if (scope == null)
            {
                // Unscoped data is valid everywhere: its shortest witness is the one kept.
                witnesses = ImmutableArray<Witness>.Empty;
                var best = (Trail?)null;
                foreach (var w in AllWitnesses.Concat(other.AllWitnesses))
                    if (w.Scope == null && (best == null || w.Path.Count < best.Count)) best = w.Path;
                if (best != null) path = best;
            }
            else if (!Witnesses.IsDefaultOrEmpty || !other.Witnesses.IsDefaultOrEmpty || !ReferenceEquals(Scope, other.Scope))
            {
                var merged = Merge(AllWitnesses, other.AllWitnesses);
                path = merged[0].Path;
                witnesses = merged.Length > 1 ? merged : ImmutableArray<Witness>.Empty;
            }
            requestChanged = cleanFor.Count != CleanFor.Count || !ReferenceEquals(sources, Sources) || !ReferenceEquals(path, Path)
                || !ReferenceEquals(scope, Scope) || fromHeap != FromHeap || keyOnly != KeyOnly || !SameWitnesses(witnesses, Witnesses);
            if (cleanFor.Count == CleanFor.Count) cleanFor = CleanFor;
        }
        else if (other.Request)
        {
            request = true;
            cleanFor = other.CleanFor;
            sources = other.Sources;
            path = other.Path;
            scope = other.Scope;
            fromHeap = other.FromHeap;
            keyOnly = other.KeyOnly;
            witnesses = other.Witnesses;
            requestChanged = true;
        }
        else
        {
            request = Request;
            cleanFor = CleanFor;
            sources = Sources;
            path = Path;
        }
        var labels = MergeLabels(Labels, other.Labels, out var labelsChanged);
        if (!requestChanged && !labelsChanged) return this;
        return new TaintValue(request, cleanFor, path) { Sources = sources, Labels = labels, Scope = scope, FromHeap = fromHeap, KeyOnly = keyOnly, Witnesses = witnesses };
    }

    /// The union of two sorted label arrays (one label per owner and slot: CleanFor intersected, the shorter path);
    /// `a` itself when nothing changes.
    private static ImmutableArray<Label> MergeLabels(ImmutableArray<Label> a, ImmutableArray<Label> b, out bool changed)
    {
        changed = false;
        if (b.Length == 0) return a;
        if (a.Length == 0)
        {
            changed = true;
            return b;
        }
        var result = new List<Label>(a.Length + b.Length);
        int i = 0, j = 0;
        while (i < a.Length || j < b.Length)
        {
            var c = i >= a.Length ? 1 : j >= b.Length ? -1 : a[i].CompareKey(b[j]);
            if (c < 0)
            {
                result.Add(a[i++]);
            }
            else if (c > 0)
            {
                result.Add(b[j++]);
                changed = true;
            }
            else
            {
                var x = a[i++];
                var y = b[j++];
                var cf = x.CleanFor.Count == 0 || y.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : x.CleanFor.Intersect(y.CleanFor);
                var p = y.Path.Count < x.Path.Count ? y.Path : x.Path;
                var viaKey = x.ViaKey && y.ViaKey;
                if (cf.Count != x.CleanFor.Count || !ReferenceEquals(p, x.Path) || viaKey != x.ViaKey)
                {
                    result.Add(new Label(x.Owner, x.Slot, cf.Count == x.CleanFor.Count ? x.CleanFor : cf, p, viaKey));
                    changed = true;
                }
                else
                {
                    result.Add(x);
                }
            }
        }
        return changed ? result.ToImmutableArray() : a;
    }

    /// Equal in the lattice (paths aside).
    public bool SameTaint(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Sources.SetEquals(other.Sources) && Equals(Scope, other.Scope) && FromHeap == other.FromHeap && KeyOnly == other.KeyOnly))
            && SameLabels(other));

    /// Equal in the lattice, paths and source locations aside: what decides whether a summary or the heap changed.
    public bool SameFlow(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Equals(Scope, other.Scope) && FromHeap == other.FromHeap && KeyOnly == other.KeyOnly)) && SameLabels(other));

    private bool SameLabels(TaintValue other)
    {
        if (Labels.Length != other.Labels.Length) return false;
        for (var k = 0; k < Labels.Length; k++)
        {
            var x = Labels[k];
            var y = other.Labels[k];
            if (x.Owner != y.Owner || x.Slot != y.Slot || x.ViaKey != y.ViaKey || !x.CleanFor.SetEquals(y.CleanFor)) return false;
        }
        return true;
    }

    /// The value cleaned for these rules (a sanitizer's result): its request data and each label.
    public TaintValue CleanedFor(IReadOnlyCollection<string> rules)
    {
        if (!Any || rules.Count == 0) return this;
        var value = this;
        if (Request && !rules.All(CleanFor.Contains)) value = value with { CleanFor = CleanFor.Union(rules) };
        if (Labels.Length > 0 && Labels.Any(l => !rules.All(l.CleanFor.Contains)))
        {
            value = value with
            {
                Labels = Labels.Select(l => rules.All(l.CleanFor.Contains) ? l : new Label(l.Owner, l.Slot, l.CleanFor.Union(rules), l.Path, l.ViaKey)).ToImmutableArray(),
            };
        }
        return value;
    }

    /// The value with one more path step (on the request path and on each label's; a step at the last step's location
    /// is not repeated).
    public TaintValue Step(Location location, string message)
    {
        if (!Any) return this;
        PathStep? step = null;
        var value = this;
        if (Request && Fits(Path, location))
        {
            step = new PathStep(location, message);
            if (Witnesses.IsDefaultOrEmpty)
            {
                value = value with { Path = Path.Add(step) };
            }
            else
            {
                var s0 = step;
                var witnesses = Witnesses.Select(w => Fits(w.Path, location) ? new Witness(w.Scope, w.Path.Add(s0)) : w).ToImmutableArray();
                value = value with { Path = witnesses[0].Path, Witnesses = witnesses };
            }
        }
        if (Labels.Length > 0 && Labels.Any(l => Fits(l.Path, location)))
        {
            var s = step ?? new PathStep(location, message);
            value = value with { Labels = Labels.Select(l => Fits(l.Path, location) ? new Label(l.Owner, l.Slot, l.CleanFor, l.Path.Add(s), l.ViaKey) : l).ToImmutableArray() };
        }
        return value;
    }

    private static bool Fits(Trail path, Location location) => path.Last == null || !path.Last.Location.Equals(location);

    /// The value with these steps appended to its request path and to each label's (a callee's steps, after a call).
    public TaintValue Extend(Trail steps)
    {
        if (!Any || steps.Count == 0) return this;
        var value = this;
        if (Request)
        {
            if (Witnesses.IsDefaultOrEmpty)
            {
                value = value with { Path = Path.Concat(steps) };
            }
            else
            {
                var witnesses = Witnesses.Select(w => new Witness(w.Scope, w.Path.Concat(steps))).ToImmutableArray();
                value = value with { Path = witnesses[0].Path, Witnesses = witnesses };
            }
        }
        if (Labels.Length > 0) value = value with { Labels = Labels.Select(l => new Label(l.Owner, l.Slot, l.CleanFor, l.Path.Concat(steps), l.ViaKey)).ToImmutableArray() };
        return value;
    }
}


/// The abstract state at a program point: a map from what holds a value (a local, a parameter, a field by symbol, a
/// flow capture of the control-flow graph by its CaptureId) to its TaintValue; an absent key is clean.
///
/// The map is persistent (ruling R-E11): a hash array mapped trie whose nodes never change once built, so Clone is
/// O(1), an update copies one path, and a join walks only the subtrees the two states do not share (a block that
/// changes two variables of a thousand costs two paths, not a thousand entries).
///
/// Member facts (Task 21): what guards established for access paths (`x.M`), must-hold, so a join keeps only the facts
/// both sides hold (MemberFacts); an empty list (most states) costs nothing.
internal sealed class TaintState
{
    private object? _root;

    private ImmutableArray<MemberFact> _facts = ImmutableArray<MemberFact>.Empty;

    public TaintState() { }

    private TaintState(object? root, ImmutableArray<MemberFact> facts)
    {
        _root = root;
        _facts = facts;
    }

    public bool HasFacts => !_facts.IsEmpty;

    public ImmutableArray<MemberFact> Facts => _facts;

    public MemberFact? Fact(AccessPath path) => _facts.IsEmpty ? null : MemberFacts.Find(_facts, path);

    /// Records what a guard established for a path on this branch (united with what was known).
    public void AddFact(MemberFact fact) => _facts = MemberFacts.Add(_facts, fact);

    /// Forgets the facts of the paths `predicate` holds for (a write or a call that may change them).
    public void Forget(Func<AccessPath, bool> predicate) => _facts = MemberFacts.RemoveWhere(_facts, predicate);

    public void ForgetAll() => _facts = ImmutableArray<MemberFact>.Empty;

    public IEnumerable<KeyValuePair<object, TaintValue>> Entries =>
        TaintMap.Entries(_root).Select(e => new KeyValuePair<object, TaintValue>(e.Key, e.Value));

    public TaintValue Get(object key) => TaintMap.Get(_root, key, TaintMap.Hash(key), 0)?.Value ?? TaintValue.Clean;

    /// A strong update (an assignment).
    public void Set(object key, TaintValue value)
    {
        var hash = TaintMap.Hash(key);
        if (!value.Any)
        {
            _root = TaintMap.Remove(_root, key, hash, 0);
            return;
        }
        var old = TaintMap.Get(_root, key, hash, 0);
        if (old != null && ReferenceEquals(old.Value, value)) return;
        _root = TaintMap.Set(_root, new TaintMap.Entry(key, hash, value), 0);
    }

    /// A weak update (a write into a collection or a builder the key holds): the old value joined with the new.
    public void Add(object key, TaintValue value)
    {
        if (!value.Any) return;
        var hash = TaintMap.Hash(key);
        var old = TaintMap.Get(_root, key, hash, 0);
        if (old == null)
        {
            _root = TaintMap.Set(_root, new TaintMap.Entry(key, hash, value), 0);
            return;
        }
        var joined = old.Value.Join(value);
        if (!joined.SameTaint(old.Value)) _root = TaintMap.Set(_root, new TaintMap.Entry(key, hash, joined), 0);
    }

    public TaintState Clone() => new(_root, _facts);

    /// Joins `other` into this state; true when this state changed (in the lattice: a value rose or a member fact was
    /// lost).
    public bool JoinWith(TaintState other)
    {
        var changed = false;
        _root = TaintMap.Join(_root, other._root, 0, ref changed);
        if (!_facts.IsEmpty && _facts != other._facts)
        {
            _facts = MemberFacts.Meet(_facts, other._facts, out var lost);
            changed |= lost;
        }
        return changed;
    }
}

/// The persistent hash array mapped trie of TaintState. A slot is an Entry, a Collision (the entries of one full hash)
/// or a Node (a branch on 5 bits of the hash per level, compressed by a bitmap). Only tainted values (request data or labels) are stored.
internal static class TaintMap
{
    private const int Bits = 5;

    internal sealed record Entry(object Key, uint Hash, TaintValue Value);

    private sealed record Collision(uint Hash, Entry[] Items);

    private sealed record Node(uint Bitmap, object[] Slots);

    public static uint Hash(object key) => (uint)SymbolOrCapture.Comparer.GetHashCode(key);

    private static bool Same(object a, object b) => SymbolOrCapture.Comparer.Equals(a, b);

    private static uint Bit(uint hash, int depth) => 1u << (int)((hash >> (Bits * depth)) & 31);

    private static int Index(uint bitmap, uint bit) => BitOperations.PopCount(bitmap & (bit - 1));

    public static Entry? Get(object? slot, object key, uint hash, int depth)
    {
        while (true)
        {
            switch (slot)
            {
                case Entry e:
                    return e.Hash == hash && Same(e.Key, key) ? e : null;
                case Collision c:
                    if (c.Hash != hash) return null;
                    foreach (var e in c.Items) if (Same(e.Key, key)) return e;
                    return null;
                case Node n:
                    var bit = Bit(hash, depth);
                    if ((n.Bitmap & bit) == 0) return null;
                    slot = n.Slots[Index(n.Bitmap, bit)];
                    depth++;
                    continue;
                default:
                    return null;
            }
        }
    }

    public static object Set(object? slot, Entry entry, int depth)
    {
        switch (slot)
        {
            case null:
                return entry;
            case Entry e when e.Hash == entry.Hash:
                return Same(e.Key, entry.Key) ? entry : new Collision(e.Hash, new[] { e, entry });
            case Collision c when c.Hash == entry.Hash:
            {
                var i = Array.FindIndex(c.Items, x => Same(x.Key, entry.Key));
                Entry[] items;
                if (i < 0)
                {
                    items = new Entry[c.Items.Length + 1];
                    c.Items.CopyTo(items, 0);
                    items[^1] = entry;
                }
                else
                {
                    items = (Entry[])c.Items.Clone();
                    items[i] = entry;
                }
                return new Collision(c.Hash, items);
            }
            case Node n:
            {
                var bit = Bit(entry.Hash, depth);
                var index = Index(n.Bitmap, bit);
                if ((n.Bitmap & bit) == 0)
                {
                    var inserted = new object[n.Slots.Length + 1];
                    Array.Copy(n.Slots, inserted, index);
                    inserted[index] = entry;
                    Array.Copy(n.Slots, index, inserted, index + 1, n.Slots.Length - index);
                    return new Node(n.Bitmap | bit, inserted);
                }
                var slots = (object[])n.Slots.Clone();
                slots[index] = Set(n.Slots[index], entry, depth + 1);
                return new Node(n.Bitmap, slots);
            }
            default:
            {
                // An Entry or a Collision of another hash: push it one level down into a new Node (two different 32-bit
                // hashes differ within the 7 levels of 5 bits).
                var hash = slot is Entry other ? other.Hash : ((Collision)slot).Hash;
                return Set(new Node(Bit(hash, depth), new[] { slot }), entry, depth);
            }
        }
    }

    public static object? Remove(object? slot, object key, uint hash, int depth)
    {
        switch (slot)
        {
            case Entry e:
                return e.Hash == hash && Same(e.Key, key) ? null : e;
            case Collision c:
            {
                if (c.Hash != hash) return c;
                var rest = c.Items.Where(x => !Same(x.Key, key)).ToArray();
                return rest.Length == c.Items.Length ? c : rest.Length == 1 ? rest[0] : new Collision(c.Hash, rest);
            }
            case Node n:
            {
                var bit = Bit(hash, depth);
                if ((n.Bitmap & bit) == 0) return n;
                var index = Index(n.Bitmap, bit);
                var child = Remove(n.Slots[index], key, hash, depth + 1);
                if (ReferenceEquals(child, n.Slots[index])) return n;
                if (child != null)
                {
                    var slots = (object[])n.Slots.Clone();
                    slots[index] = child;
                    return new Node(n.Bitmap, slots);
                }
                if (n.Slots.Length == 1) return null;
                var removed = new object[n.Slots.Length - 1];
                Array.Copy(n.Slots, removed, index);
                Array.Copy(n.Slots, index + 1, removed, index, n.Slots.Length - index - 1);
                return new Node(n.Bitmap & ~bit, removed);
            }
            default:
                return null;
        }
    }

    /// The join of two slots at one depth: `a` itself (and `changed` untouched) when nothing of `b` raises it in the
    /// lattice; subtrees the two share are not visited.
    public static object? Join(object? a, object? b, int depth, ref bool changed)
    {
        if (ReferenceEquals(a, b) || b == null) return a;
        if (a == null)
        {
            changed = true;
            return b;
        }
        if (a is Node na && b is Node nb)
        {
            var bits = na.Bitmap | nb.Bitmap;
            object[]? slots = null;
            var k = 0;
            for (var rest = bits; rest != 0; rest &= rest - 1, k++)
            {
                var bit = rest & (~rest + 1);
                var sa = (na.Bitmap & bit) != 0 ? na.Slots[Index(na.Bitmap, bit)] : null;
                var sb = (nb.Bitmap & bit) != 0 ? nb.Slots[Index(nb.Bitmap, bit)] : null;
                var r = Join(sa, sb, depth + 1, ref changed);
                if (slots == null && !ReferenceEquals(r, sa))
                {
                    // The first difference: copy the slots decided so far (all of them a's).
                    slots = new object[BitOperations.PopCount(bits)];
                    var j = 0;
                    for (var done = bits; j < k; done &= done - 1, j++) slots[j] = na.Slots[Index(na.Bitmap, done & (~done + 1))];
                }
                if (slots != null) slots[k] = r!;
            }
            return slots == null ? a : new Node(bits, slots);
        }
        // An Entry or a Collision on one side: b's entries joined into a one by one.
        var result = a;
        foreach (var e in Entries(b))
        {
            var old = Get(result, e.Key, e.Hash, depth);
            if (old == null)
            {
                result = Set(result, e, depth);
                changed = true;
                continue;
            }
            var joined = old.Value.Join(e.Value);
            if (joined.SameTaint(old.Value)) continue;
            result = Set(result, new Entry(e.Key, e.Hash, joined), depth);
            changed = true;
        }
        return result;
    }

    public static IEnumerable<Entry> Entries(object? slot)
    {
        switch (slot)
        {
            case Entry e:
                yield return e;
                break;
            case Collision c:
                foreach (var e in c.Items) yield return e;
                break;
            case Node n:
                foreach (var child in n.Slots)
                    foreach (var e in Entries(child)) yield return e;
                break;
        }
    }
}
