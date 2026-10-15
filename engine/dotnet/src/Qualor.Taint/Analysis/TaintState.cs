using System.Collections.Immutable;
using System.Numerics;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// A path as an immutable rope of steps (Task 8): adding a step and appending another trail (a callee's steps after a
/// call) are O(1) and share structure, so the paths of summaries applied along deep call chains cost a node each; a
/// trail is flattened only when a finding is reported (at most MaxReported steps: the first and last ones).
///
/// Medium (R-9): whether any step of the trail crosses a medium edge (StepKind.IsMedium), kept per node so a finding's
/// confidence costs nothing and survives the steps a long path omits; a capped trail still records a medium step it
/// could not add.
internal sealed class Trail
{
    /// A trail stops growing at this many steps (a soft cap against pathological recursion).
    public const int MaxSteps = 4096;

    /// The most steps a reported path shows; the middle of a longer one is replaced by one "steps omitted" step.
    public const int MaxReported = 64;

    public static readonly Trail Empty = new(null, null, null, 0, null, false);

    private readonly Trail? _left;
    private readonly Trail? _right;
    private readonly PathStep? _step;

    private Trail(Trail? left, Trail? right, PathStep? step, int count, PathStep? last, bool medium)
    {
        _left = left;
        _right = right;
        _step = step;
        Count = count;
        Last = last;
        Medium = medium;
    }

    public int Count { get; }

    public PathStep? Last { get; }

    /// Whether a step of the trail crosses a medium edge (R-9).
    public bool Medium { get; }

    public static Trail Of(PathStep step) => new(null, null, step, 1, step, step.Kind.IsMedium());

    public Trail Add(PathStep step) =>
        Count == 0 ? Of(step) : Count >= MaxSteps ? Capped(step.Kind.IsMedium()) : new Trail(this, Of(step), null, Count + 1, step, Medium || step.Kind.IsMedium());

    public Trail Concat(Trail other) =>
        other.Count == 0 ? (other.Medium ? Capped(true) : this) : Count == 0 ? other
        : Count + other.Count > MaxSteps ? Capped(other.Medium)
        : new Trail(this, other, null, Count + other.Count, other.Last, Medium || other.Medium);

    /// This trail, marked medium when a step it cannot take any more was (the steps stay as they are).
    private Trail Capped(bool medium) => !medium || Medium ? this : new Trail(this, null, null, Count, Last, true);

    /// Whether `a` is the better witness than `b` (R-9): a high path before a medium one, then the shorter.
    public static bool Better(Trail a, Trail b) => a.Medium != b.Medium ? !a.Medium : a.Count < b.Count;

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
///
/// Alternatives (fix round 2 of Task 28, RR1): as request data keeps witnesses, a label keeps its paths of different
/// cleanliness (Witness with no scope), best first, Path the first, bounded as TaintValue.Merge bounds witnesses; empty:
/// Path is the only one, valid for CleanFor. A sink effect records the path for its rule (PathFor), and a call site
/// substitutes the argument through each path with its own cleanliness, and a call edge is kept per path. The lattice
/// compares a label's Path.Medium, CleanFor and HighClean (fix round 3, RM1).
internal sealed class Label
{
    public Label(int owner, int slot, ImmutableHashSet<string> cleanFor, Trail path, bool viaKey = false, ImmutableArray<Witness> alternatives = default,
        bool keyDerived = false, bool dropsKeyDerived = false)
    {
        DropsKeyDerived = dropsKeyDerived;
        Owner = owner;
        Slot = slot;
        CleanFor = cleanFor;
        Path = path;
        ViaKey = viaKey;
        KeyDerived = keyDerived || viaKey;
        Alternatives = alternatives.IsDefault ? ImmutableArray<Witness>.Empty : alternatives;
    }

    /// The label's paths of different cleanliness, best first (see the type's documentation).
    public ImmutableArray<Witness> Alternatives { get; }

    /// Every path with its cleanliness: the alternatives, or Path with CleanFor.
    public ImmutableArray<Witness> AllPaths => Alternatives.IsEmpty ? ImmutableArray.Create(new Witness(null, Path, CleanFor)) : Alternatives;

    /// The rules no high path of the label is a path for (the intersection of its high paths' CleanFor); null when no
    /// path is high. Part of the lattice (TaintValue.SameLabels), as TaintValue.HighClean is for request data.
    public ImmutableHashSet<string>? HighClean
    {
        get
        {
            if (Alternatives.IsEmpty) return Path.Medium ? null : CleanFor;
            ImmutableHashSet<string>? h = null;
            foreach (var w in Alternatives)
                if (!w.Path.Medium) h = h == null ? w.CleanFor : h.Count == 0 || w.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : h.Intersect(w.CleanFor);
            return h;
        }
    }

    /// The path a sink of `rule` records: the best one (high, then shortest) not cleaned for `rule`, else Path.
    public Trail PathFor(string rule)
    {
        if (Alternatives.IsEmpty) return Path;
        Trail? best = null;
        foreach (var w in Alternatives)
            if (!w.CleanFor.Contains(rule) && (best == null || Trail.Better(w.Path, best))) best = w.Path;
        return best ?? Path;
    }

    /// This label with each path mapped by `map` (its cleanliness unchanged); `cleanFor` the label's new CleanFor.
    public Label Map(Func<Trail, Trail> map, ImmutableHashSet<string>? cleanFor = null, bool? viaKey = null, bool? keyDerived = null,
        bool? dropsKeyDerived = null)
    {
        var alternatives = Alternatives.IsEmpty ? Alternatives : Alternatives.Select(w => w with { Path = map(w.Path) }).ToImmutableArray();
        return new Label(Owner, Slot, cleanFor ?? CleanFor, alternatives.IsEmpty ? map(Path) : alternatives[0].Path, viaKey ?? ViaKey, alternatives,
            keyDerived ?? KeyDerived, dropsKeyDerived ?? DropsKeyDerived);
    }

    /// This label cleaned for `rules` (each path too).
    public Label Cleaned(IReadOnlyCollection<string> rules)
    {
        var alternatives = Alternatives.IsEmpty ? Alternatives
            : Alternatives.Select(w => rules.All(w.CleanFor.Contains) ? w : w with { CleanFor = w.CleanFor.Union(rules) }).ToImmutableArray();
        return new Label(Owner, Slot, CleanFor.Union(rules), Path, ViaKey, alternatives, KeyDerived, DropsKeyDerived);
    }

    /// The parameter reaches the value only as the key of a lookup whose element is typed by a type parameter (fix round
    /// 1 of Task 23, ruling R-E23): whether the key carries depends on the type argument. A call of a value-factory
    /// shaped method drops such labels from its result; any other call keeps them. A join keeps the flag only when both
    /// sides have it (a plain flow of the parameter wins).
    public bool ViaKey { get; }

    /// The parameter reaches the value only as the key of a lookup, whatever the element's type (ruling R-E39; ViaKey implies
    /// it): a deserializer (`drop-key-only:`) does not pass it on. A join keeps the flag only when both sides have it.
    public bool KeyDerived { get; }

    /// The parameter reaches the value only through a deserializer (`drop-key-only:`, R-E39): a call site substitutes the
    /// argument without what reached it only through a lookup key (a project's own deserializing wrapper given cached
    /// text). A join keeps the flag only when both sides have it (a plain flow of the parameter wins).
    public bool DropsKeyDerived { get; }

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
/// Paths take part in the order only by their confidence (R-9): HighClean, the rules no high witness is request data
/// for (null: no high witness), is part of the lattice. A join intersects it (a rule gains a high witness and never
/// loses it: Merge's bound keeps one per rule), so the order is lexicographic on (CleanFor, then HighClean, each the
/// smaller the higher) and well-founded. A value's confidence can fall again only when its CleanFor strictly shrinks
/// (a dirtier part joins) or a transfer step takes a medium step anew; the fixed point ends when Request, CleanFor,
/// Scope, Sources, labels and HighClean stop changing.
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
/// Witnesses (fix round 1 of Task 20, I4; Task 28 fix round 1, R-E32 revised): Path is one witness, valid for Scope and
/// the value's CleanFor. When request data of different scopes or of different cleanliness is joined, Witnesses keeps
/// (scope, best path, CleanFor) triples, one per scope and cleanliness, best first (high, then shortest), Path the first:
/// at most MaxWitnesses, plus those that keep a witness, and a high one, for every rule some witness had one for. Every
/// narrowing (Within, a heap read or write) drops the witnesses whose scope it leaves, so a reported path
/// (WitnessFor(reach, rule)) starts in a request that reaches the sink and is not cleaned for the finding's rule.
internal readonly record struct Witness(Reach? Scope, Trail Path, ImmutableHashSet<string> CleanFor);

internal sealed record TaintValue(bool Request, ImmutableHashSet<string> CleanFor, Trail Path)
{
    public const int MaxSources = 16;

    public static readonly TaintValue Clean = new(false, ImmutableHashSet<string>.Empty, Trail.Empty);

    /// The identity of a join (Task 27): no request data, no labels, no object, every member known. What a value not yet
    /// seen starts from (a body's returned value before its first return); a null literal is it too. Never stored.
    public static readonly TaintValue Bottom = new(false, ImmutableHashSet<string>.Empty, Trail.Empty) { Objects = ObjSet.Empty, Members = MemberMap.All };

    /// The abstract objects the value may be (Task 27, decision R-8): null when they are not known (the value may be any
    /// object: its members are read and written at their field locations). Clean's are unknown, Bottom's empty. A join
    /// unites them (beyond ObjSet.MaxObjects: unknown).
    public ObjSet? Objects { get; init; }

    /// The members of the object the value is that are known to hold exactly a value (Task 27, strong updates; a must
    /// map: a join keeps only what both sides know). Clean knows none, Bottom all.
    public MemberMap? Members { get; init; }

    /// Whether the value carries objects or members (Clean does not).
    public bool HasIdentity => Objects != null || Members != null;

    /// Whether the value tells something of its objects or members (Bottom tells nothing yet).
    public bool KnowsIdentity => HasIdentity && !ReferenceEquals(this, Bottom);

    /// The value without its objects and members (what is stored where only taint matters, or a value that is not the
    /// same object as the operand it was computed from).
    public TaintValue WithoutIdentity() => HasIdentity ? this with { Objects = null, Members = null } : this;

    /// This value with `other`'s request data and labels joined in, keeping this value's objects and members: what adds a
    /// source to a value without changing which object it is (Task 27 at the rebase onto Task 29: a rule's own source joined
    /// into a call's result; Clean added nothing, and a plain Join with Clean would make the result's objects unknown).
    ///
    /// Exact members are kept beside the added taint (fix round 2, R1-M3): a member read of the result then gives the
    /// member's exact value without the added whole-value taint. Rule sources are external members whose results carry
    /// no identity, so this does not arise today; if a source ever adds taint to a value that knows members, drop
    /// `Members` here when `other.Any`.
    public TaintValue WithTaintOf(TaintValue other)
    {
        if (!other.Any) return this;
        var joined = WithoutIdentity().Join(other.WithoutIdentity());
        return HasIdentity ? joined with { Objects = Objects, Members = Members } : joined;
    }

    /// Equal objects and members (members' values in the lattice).
    public bool SameIdentity(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Equals(Objects, other.Objects) && (ReferenceEquals(Members, other.Members) || (Members != null && Members.SameFlow(other.Members))));

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

    /// The request data reached this value only as the key of a lookup, whatever the element's type (ruling R-E39; KeyOnly
    /// implies it): a deserializer (`drop-key-only:`) does not pass it on, so JSON text found in a cache by a request key does
    /// not make the object read from it request data. A join keeps it only when both request parts have it.
    public bool KeyDerived { get; init; }

    public const int MaxWitnesses = 4;

    /// Whether the witness bound ever dropped a witness of the request data (Task 32 fix round 2, RR1): a dropped
    /// witness's scope and cleanliness are lost, so narrowing may not take the kept witnesses' cleanliness for the
    /// value's. Joins unite it; ScopedTo (fresh data, one witness) clears it.
    public bool Truncated { get; init; }

    /// The alternative witnesses (scope, path, cleanliness), best first (Trail.Better), Path the first; empty: Path is the
    /// only one, valid for Scope and CleanFor.
    public ImmutableArray<Witness> Witnesses { get; init; } = ImmutableArray<Witness>.Empty;

    private ImmutableArray<Witness> AllWitnesses => Witnesses.IsDefaultOrEmpty ? ImmutableArray.Create(new Witness(Scope, Path, CleanFor)) : Witnesses;

    /// The rules no high witness of the request data is request data for (the intersection of the high witnesses'
    /// CleanFor); null when no witness is high. Part of the lattice (see the type's documentation).
    public ImmutableHashSet<string>? HighClean
    {
        get
        {
            if (!Request) return null;
            if (Witnesses.IsDefaultOrEmpty) return Path.Medium ? null : CleanFor;
            ImmutableHashSet<string>? h = null;
            foreach (var w in Witnesses)
                if (!w.Path.Medium) h = h == null ? w.CleanFor : Intersect(h, w.CleanFor);
            return h;
        }
    }

    private static ImmutableHashSet<string> Intersect(ImmutableHashSet<string> a, ImmutableHashSet<string> b) =>
        a.Count == 0 || b.Count == 0 ? ImmutableHashSet<string>.Empty : ReferenceEquals(a, b) ? a : a.Intersect(b);

    private static bool SameHigh(TaintValue a, TaintValue b)
    {
        var x = a.HighClean;
        var y = b.HighClean;
        return x == null ? y == null : y != null && x.SetEquals(y);
    }

    /// The request data narrowed to the entry points of `reach` (assumed to share some with Scope): its scope and its
    /// witnesses (those whose scope shares none are dropped, unless none would be left). When no witness was ever dropped
    /// by the witness bound (Truncated), the value is also cleaned for what every kept witness is cleaned for (Task 32 fix
    /// round 1, I1): the witnesses narrowing drops carry the only dirtier data, and it is out of `reach`. A value the bound
    /// truncated keeps its CleanFor (a dropped witness's dirtier data may be in `reach`; fix round 2, RR1).
    public TaintValue Narrowed(Reach reach)
    {
        if (!Request) return this;
        var scope = Scope == null ? reach : Scope.Intersect(reach);
        if (Witnesses.IsDefaultOrEmpty) return ReferenceEquals(scope, Scope) ? this : this with { Scope = scope };
        var kept = ImmutableArray.CreateBuilder<Witness>(Witnesses.Length);
        foreach (var w in Witnesses)
        {
            if (w.Scope == null) kept.Add(new Witness(reach, w.Path, w.CleanFor));
            else if (w.Scope.Intersects(reach)) kept.Add(new Witness(w.Scope.Intersect(reach), w.Path, w.CleanFor));
        }
        if (kept.Count == 0) return this with { Scope = scope, Witnesses = ImmutableArray<Witness>.Empty };
        var (witnesses, dropped) = Merge(kept, ImmutableArray<Witness>.Empty);
        var cleanFor = CleanFor;
        if (!Truncated)
        {
            // Merge's cover keeps the intersection of the kept witnesses' cleanliness when it drops some here.
            var clean = witnesses[0].CleanFor;
            for (var i = 1; i < witnesses.Length; i++) clean = Intersect(clean, witnesses[i].CleanFor);
            if (clean.Count > 0 && !clean.IsSubsetOf(CleanFor)) cleanFor = CleanFor.Union(clean);
        }
        return this with
        {
            Scope = scope, CleanFor = cleanFor, Path = witnesses[0].Path, Truncated = Truncated || dropped,
            Witnesses = witnesses.Length > 1 ? witnesses : ImmutableArray<Witness>.Empty,
        };
    }

    /// This value with the path a finding of `rule` in a body `reach` reaches reports (R-E32 revised): the best witness
    /// (high, then shortest) whose scope shares an entry point with `reach` and that is not cleaned for `rule`; else the
    /// best one in reach (with no rule: any).
    public TaintValue WitnessFor(Reach reach, string? rule = null)
    {
        if (!Request || Witnesses.IsDefaultOrEmpty) return this;
        var target = Scope == null ? reach : Scope.Intersect(reach);
        Witness? best = null, any = null;
        foreach (var w in Witnesses)
        {
            if (w.Scope != null && !w.Scope.Intersects(target)) continue;
            if (any == null || Trail.Better(w.Path, any.Value.Path)) any = w;
            if ((rule == null || !w.CleanFor.Contains(rule)) && (best == null || Trail.Better(w.Path, best.Value.Path))) best = w;
        }
        var chosen = best ?? any;
        return chosen == null || ReferenceEquals(chosen.Value.Path, Path) ? this : this with { Path = chosen.Value.Path };
    }

    /// Two witness lists merged: one per scope and cleanliness (the better path: high, then shorter), best first (the
    /// unscoped ones first when `unscopedFirst`), at most MaxWitnesses plus those that keep, for every rule, a witness
    /// and a high witness the full list has for it (so HighClean and the per-rule choice survive the bound).
    /// Dropped: whether the bound dropped a witness.
    private static (ImmutableArray<Witness> Witnesses, bool Dropped) Merge(IEnumerable<Witness> a, IEnumerable<Witness> b, bool unscopedFirst = false)
    {
        var all = new List<Witness>();
        foreach (var w in a.Concat(b))
        {
            var i = all.FindIndex(x => Equals(x.Scope, w.Scope) && (ReferenceEquals(x.CleanFor, w.CleanFor) || x.CleanFor.SetEquals(w.CleanFor)));
            if (i < 0) all.Add(w);
            else if (Trail.Better(w.Path, all[i].Path)) all[i] = w;
        }
        all.Sort((x, y) =>
            unscopedFirst && (x.Scope == null) != (y.Scope == null) ? (x.Scope == null ? -1 : 1)
            : x.Path.Medium != y.Path.Medium ? (x.Path.Medium ? 1 : -1)
            : x.Path.Count.CompareTo(y.Path.Count));
        if (all.Count <= MaxWitnesses) return (all.ToImmutableArray(), false);
        var kept = all.Take(MaxWitnesses).ToList();
        Cover(all, kept, high: true);
        Cover(all, kept, high: false);
        kept.Sort((x, y) => all.IndexOf(x).CompareTo(all.IndexOf(y)));
        return (kept.ToImmutableArray(), kept.Count < all.Count);
    }

    /// Adds to `kept`, in `all`'s order, witnesses of `all` until every rule some witness of `all` (a high one, when
    /// `high`) is request data for has such a witness in `kept`.
    private static void Cover(List<Witness> all, List<Witness> kept, bool high)
    {
        ImmutableHashSet<string>? CleanOf(IEnumerable<Witness> ws)
        {
            ImmutableHashSet<string>? h = null;
            foreach (var w in ws)
                if (!high || !w.Path.Medium) h = h == null ? w.CleanFor : Intersect(h, w.CleanFor);
            return h;
        }
        var target = CleanOf(all);
        if (target == null) return;
        var have = CleanOf(kept);
        foreach (var w in all)
        {
            if (have != null && have.SetEquals(target)) return;
            if ((high && w.Path.Medium) || kept.Contains(w)) continue;
            // A witness that is request data for a rule `kept` has none for.
            if (have == null || have.Any(r => !w.CleanFor.Contains(r)))
            {
                kept.Add(w);
                have = have == null ? w.CleanFor : Intersect(have, w.CleanFor);
            }
        }
    }

    private static bool SameWitnesses(ImmutableArray<Witness> a, ImmutableArray<Witness> b)
    {
        if (a.IsDefaultOrEmpty || b.IsDefaultOrEmpty) return a.IsDefaultOrEmpty && b.IsDefaultOrEmpty;
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
            if (!ReferenceEquals(a[i].Path, b[i].Path) || !Equals(a[i].Scope, b[i].Scope) || !ReferenceEquals(a[i].CleanFor, b[i].CleanFor)) return false;
        return true;
    }

    /// Request data read from the request in a body that `reach` reaches: valid in those requests only (an empty reach,
    /// which EntryPoints never gives a body that reads the request, leaves it unscoped).
    public TaintValue ScopedTo(Reach reach) =>
        !Request || reach.IsEmpty ? this : this with { Scope = reach, FromHeap = false, Truncated = false, Witnesses = ImmutableArray<Witness>.Empty };

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
        var value = Request && !(KeyOnly && KeyDerived) ? this with { KeyOnly = true, KeyDerived = true } : this;
        return value.Labels.Length == 0 || value.Labels.All(l => l.ViaKey) ? value
            : value with { Labels = value.Labels.Select(l => l.ViaKey ? l : l.Map(p => p, viaKey: true)).ToImmutableArray() };
    }

    /// This value with its request data and every label marked as reaching it only through a lookup key (R-E39).
    public TaintValue KeyDerivedMark()
    {
        var value = Request && !KeyDerived ? this with { KeyDerived = true } : this;
        return value.Labels.Length == 0 || value.Labels.All(l => l.KeyDerived) ? value
            : value with { Labels = value.Labels.Select(l => l.KeyDerived ? l : l.Map(p => p, keyDerived: true)).ToImmutableArray() };
    }

    /// This value without what reached it only through a lookup key (R-E39): its request data unless that came by a key,
    /// and its labels that did not.
    public TaintValue WithoutKeyDerived()
    {
        if (!Any) return this;
        var value = Request && KeyDerived ? LabelPart : this;
        if (value.Labels.Length == 0 || value.Labels.All(l => l.DropsKeyDerived && !l.KeyDerived)) return value;
        // The labels kept are marked: their arguments lose their key-only part at the call site (Summary substitution).
        var labels = value.Labels.Where(l => !l.KeyDerived).Select(l => l.DropsKeyDerived ? l : l.Map(p => p, dropsKeyDerived: true)).ToImmutableArray();
        return value.Request || labels.Length > 0 ? value with { Labels = labels } : Clean;
    }

    /// The request data of this value, without its labels.
    public TaintValue RequestPart => Labels.Length == 0 ? this : Request ? this with { Labels = ImmutableArray<Label>.Empty } : Clean;

    /// The labels of this value, without its request data.
    public TaintValue LabelPart => !Request ? this : Labels.Length == 0 ? Clean : Clean with { Labels = Labels };

    public bool TaintedFor(string rule) => Request && !CleanFor.Contains(rule);

    /// The join: request data and labels as the lattice above; objects united, members met (Task 27). Clean contributes
    /// unknown objects and no members, so a join with Clean keeps only the taint; Bottom is the identity of a join.
    public TaintValue Join(TaintValue other)
    {
        if (ReferenceEquals(this, other)) return this;
        if (Objects == null && Members == null && other.Objects == null && other.Members == null) return JoinTaint(other);
        var taint = JoinTaint(other);
        var objects = ObjSet.Union(Objects, other.Objects);
        var members = MemberMap.Meet(Members, other.Members);
        return ReferenceEquals(objects, taint.Objects) && ReferenceEquals(members, taint.Members) ? taint : taint with { Objects = objects, Members = members };
    }

    private TaintValue JoinTaint(TaintValue other)
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
        var truncated = Truncated;
        var keyDerived = KeyDerived;
        var witnesses = Witnesses;
        if (Request && other.Request)
        {
            request = true;
            scope = Scope == null || other.Scope == null ? null : Scope.Union(other.Scope);
            fromHeap = FromHeap && other.FromHeap;
            keyOnly = KeyOnly && other.KeyOnly;
            truncated = Truncated || other.Truncated;
            keyDerived = KeyDerived && other.KeyDerived;
            cleanFor = CleanFor.Count == 0 || other.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : CleanFor.Intersect(other.CleanFor);
            sources = Sources;
            foreach (var s in other.Sources)
            {
                if (sources.Count >= MaxSources) break;
                sources = sources.Add(s);
            }
            path = Trail.Better(other.Path, Path) ? other.Path : Path;
            var mine = AllWitnesses;
            var theirs = other.AllWitnesses;
            // One cleanliness on both sides: unscoped data keeps its best unscoped witness (valid everywhere) as before.
            var oneCleanliness = mine.Concat(theirs).All(w => w.CleanFor.SetEquals(CleanFor));
            if (scope == null && oneCleanliness)
            {
                witnesses = ImmutableArray<Witness>.Empty;
                var best = (Trail?)null;
                foreach (var w in mine.Concat(theirs))
                    if (w.Scope == null && (best == null || Trail.Better(w.Path, best))) best = w.Path;
                if (best != null) path = best;
            }
            else if (!Witnesses.IsDefaultOrEmpty || !other.Witnesses.IsDefaultOrEmpty || !Equals(Scope, other.Scope) || !oneCleanliness)
            {
                // Both sides' witnesses, each with its scope and cleanliness: a finding picks the one for its request
                // and its rule (WitnessFor; R-E32 revised).
                var (merged, dropped) = Merge(mine, theirs, unscopedFirst: scope == null);
                truncated |= dropped;
                path = merged[0].Path;
                witnesses = merged.Length > 1 ? merged : ImmutableArray<Witness>.Empty;
            }
            requestChanged = cleanFor.Count != CleanFor.Count || !ReferenceEquals(sources, Sources) || !ReferenceEquals(path, Path)
                || !ReferenceEquals(scope, Scope) || fromHeap != FromHeap || keyOnly != KeyOnly || truncated != Truncated || keyDerived != KeyDerived || !SameWitnesses(witnesses, Witnesses);
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
            truncated = other.Truncated;
            keyDerived = other.KeyDerived;
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
        return new TaintValue(request, cleanFor, path) { Sources = sources, Labels = labels, Scope = scope, FromHeap = fromHeap, KeyOnly = keyOnly, Truncated = truncated, KeyDerived = keyDerived, Witnesses = witnesses };
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
                var viaKey = x.ViaKey && y.ViaKey;
                var keyDerived = x.KeyDerived && y.KeyDerived;
                var dropsKeyDerived = x.DropsKeyDerived && y.DropsKeyDerived;
                // Paths of one cleanliness: the better one; else both sides' paths, each with its cleanliness (RR1).
                Trail p;
                var alternatives = ImmutableArray<Witness>.Empty;
                if (x.Alternatives.IsEmpty && y.Alternatives.IsEmpty && x.CleanFor.SetEquals(y.CleanFor))
                {
                    p = Trail.Better(y.Path, x.Path) ? y.Path : x.Path;
                }
                else
                {
                    // A label's paths have no scope: no narrowing chooses among them, and Merge's cover keeps the
                    // intersection of their cleanliness, so a dropped path needs no Truncated flag (RR1).
                    var (merged, _) = Merge(x.AllPaths, y.AllPaths);
                    p = merged[0].Path;
                    if (merged.Length > 1) alternatives = merged;
                }
                if (cf.Count != x.CleanFor.Count || !ReferenceEquals(p, x.Path) || viaKey != x.ViaKey || keyDerived != x.KeyDerived
                    || dropsKeyDerived != x.DropsKeyDerived || !SameWitnesses(alternatives, x.Alternatives))
                {
                    result.Add(new Label(x.Owner, x.Slot, cf.Count == x.CleanFor.Count ? x.CleanFor : cf, p, viaKey, alternatives, keyDerived, dropsKeyDerived));
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

    /// Whether data cleaned for `a` is request data for strictly more rules than data cleaned for `b` (a ⊂ b): its path
    /// is a witness for every rule the other's is (a label has one path: MergeLabels keeps the dirtier side's).
    private static bool Dirtier(ImmutableHashSet<string> a, ImmutableHashSet<string> b) => a.Count < b.Count && a.IsSubsetOf(b);

    /// Equal in the lattice (paths aside but for their confidence, R-9).
    public bool SameTaint(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Sources.SetEquals(other.Sources) && Equals(Scope, other.Scope) && FromHeap == other.FromHeap && KeyOnly == other.KeyOnly && Truncated == other.Truncated && KeyDerived == other.KeyDerived && SameHigh(this, other)))
            && SameLabels(other));

    /// Equal in the lattice, paths (but for their confidence) and source locations aside: what decides whether a summary
    /// or the heap changed.
    public bool SameFlow(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Equals(Scope, other.Scope) && FromHeap == other.FromHeap && KeyOnly == other.KeyOnly && Truncated == other.Truncated && KeyDerived == other.KeyDerived && SameHigh(this, other))) && SameLabels(other));

    private bool SameLabels(TaintValue other)
    {
        if (Labels.Length != other.Labels.Length) return false;
        for (var k = 0; k < Labels.Length; k++)
        {
            var x = Labels[k];
            var y = other.Labels[k];
            if (x.Owner != y.Owner || x.Slot != y.Slot || x.ViaKey != y.ViaKey || x.KeyDerived != y.KeyDerived || x.DropsKeyDerived != y.DropsKeyDerived || x.Path.Medium != y.Path.Medium || !x.CleanFor.SetEquals(y.CleanFor)) return false;
            // A rule's path that turned high is a change (fix round 3 of Task 28, RM1), as for request data (SameHigh).
            var hx = x.HighClean;
            var hy = y.HighClean;
            if (hx == null ? hy != null : hy == null || !hx.SetEquals(hy)) return false;
        }
        return true;
    }

    /// The value cleaned for these rules (a sanitizer's result): its request data and each label.
    public TaintValue CleanedFor(IReadOnlyCollection<string> rules)
    {
        if (!Any || rules.Count == 0) return this;
        var value = this;
        if (Request && !rules.All(CleanFor.Contains))
        {
            value = value with { CleanFor = CleanFor.Union(rules) };
            // Each witness is cleaned too (its cleanliness is a superset of the value's).
            if (!Witnesses.IsDefaultOrEmpty)
                value = value with { Witnesses = Witnesses.Select(w => rules.All(w.CleanFor.Contains) ? w : w with { CleanFor = w.CleanFor.Union(rules) }).ToImmutableArray() };
        }
        if (Labels.Length > 0 && Labels.Any(l => !rules.All(l.CleanFor.Contains)))
        {
            value = value with
            {
                Labels = Labels.Select(l => rules.All(l.CleanFor.Contains) ? l : l.Cleaned(rules)).ToImmutableArray(),
            };
        }
        return value;
    }

    /// The value with its request data cleaned for these rules, and its labels (what callers pass) as they are: model
    /// validation (Task 31, review C1) constrains the values binding gave the action, not a value project code passes when
    /// it calls the action itself.
    public TaintValue RequestCleanedFor(IReadOnlyCollection<string> rules)
    {
        if (!Request || rules.Count == 0 || rules.All(CleanFor.Contains)) return this;
        var value = this with { CleanFor = CleanFor.Union(rules) };
        if (!Witnesses.IsDefaultOrEmpty)
            value = value with { Witnesses = Witnesses.Select(w => rules.All(w.CleanFor.Contains) ? w : w with { CleanFor = w.CleanFor.Union(rules) }).ToImmutableArray() };
        return value;
    }

    /// The value with one more path step of `kind` (on the request path and on each label's; a step at the last step's
    /// location is not repeated, unless it is a medium step a high path would otherwise lose: R-9).
    public TaintValue Step(Location location, string message, StepKind kind = StepKind.Plain)
    {
        if (!Any) return this;
        PathStep? step = null;
        var medium = kind.IsMedium();
        var value = this;
        if (Request && Fits(Path, location, medium))
        {
            step = new PathStep(location, message, kind);
            if (Witnesses.IsDefaultOrEmpty)
            {
                value = value with { Path = Path.Add(step) };
            }
            else
            {
                var s0 = step;
                var witnesses = Witnesses.Select(w => Fits(w.Path, location, medium) ? w with { Path = w.Path.Add(s0) } : w).ToImmutableArray();
                value = value with { Path = witnesses[0].Path, Witnesses = witnesses };
            }
        }
        if (Labels.Length > 0 && Labels.Any(l => l.AllPaths.Any(w => Fits(w.Path, location, medium))))
        {
            var s = step ?? new PathStep(location, message, kind);
            value = value with
            {
                Labels = Labels.Select(l => l.AllPaths.Any(w => Fits(w.Path, location, medium)) ? l.Map(p => Fits(p, location, medium) ? p.Add(s) : p) : l).ToImmutableArray(),
            };
        }
        return value;
    }

    private static bool Fits(Trail path, Location location, bool medium) =>
        path.Last == null || !path.Last.Location.Equals(location) || (medium && !path.Medium);

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
                var witnesses = Witnesses.Select(w => w with { Path = w.Path.Concat(steps) }).ToImmutableArray();
                value = value with { Path = witnesses[0].Path, Witnesses = witnesses };
            }
        }
        if (Labels.Length > 0) value = value with { Labels = Labels.Select(l => l.Map(p => p.Concat(steps))).ToImmutableArray() };
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
///
/// Points-to facts (Task 27): the objects a variable (a local, a parameter, a flow capture) is known to hold, must-hold
/// like member facts (a join keeps a variable only both sides know, its objects united); a variable without one holds
/// unknown objects. Kept apart from the map, whose missing entries are clean, so an unknown object never meets a known
/// one as if it were none.
internal sealed class TaintState
{
    public const int MaxPointsTo = 64;

    private object? _root;

    private ImmutableArray<MemberFact> _facts = ImmutableArray<MemberFact>.Empty;

    private static readonly ImmutableDictionary<object, ObjSet> NoPoints = ImmutableDictionary.Create<object, ObjSet>(SymbolOrCapture.Comparer);

    private ImmutableDictionary<object, ObjSet> _points = NoPoints;

    public TaintState() { }

    private TaintState(object? root, ImmutableArray<MemberFact> facts, ImmutableDictionary<object, ObjSet> points)
    {
        _root = root;
        _facts = facts;
        _points = points;
    }

    /// Whether a fact holds a strong update (Identity skips its scan otherwise).
    public bool HasHolds
    {
        get
        {
            foreach (var f in _facts) if (f.Holds != null) return true;
            return false;
        }
    }

    /// The objects a variable is known to hold (null: unknown).
    public ObjSet? PointsTo(object key) => _points.Count == 0 ? null : _points.TryGetValue(key, out var o) ? o : null;

    /// Records the objects a variable holds after an assignment (null: unknown).
    public void SetPointsTo(object key, ObjSet? objects)
    {
        if (objects == null)
        {
            if (_points.Count > 0) _points = _points.Remove(key);
            return;
        }
        if (_points.TryGetValue(key, out var old))
        {
            if (!Equals(old, objects)) _points = _points.SetItem(key, objects);
            return;
        }
        if (_points.Count < MaxPointsTo) _points = _points.Add(key, objects);
    }

    /// Records a strong update of a member path (Task 27).
    public void SetHolds(AccessPath path, TaintValue value) => _facts = MemberFacts.SetHolds(_facts, path, value);

    /// Forgets the guard parts of the facts `guards` holds for and the strong updates `holds` holds for.
    public void ForgetParts(Func<AccessPath, bool> guards, Func<AccessPath, bool> holds) => _facts = MemberFacts.RemoveParts(_facts, guards, holds);

    public bool HasFacts => !_facts.IsEmpty;

    public ImmutableArray<MemberFact> Facts => _facts;

    public MemberFact? Fact(AccessPath path) => _facts.IsEmpty ? null : MemberFacts.Find(_facts, path);

    /// Records what a guard established for a path on this branch (united with what was known).
    public void AddFact(MemberFact fact) => _facts = MemberFacts.Add(_facts, fact);

    /// Forgets the facts of the paths `predicate` holds for (a write or a call that may change them).
    public void Forget(Func<AccessPath, bool> predicate) => _facts = MemberFacts.RemoveWhere(_facts, predicate);

    public void ForgetAll() => _facts = ImmutableArray<MemberFact>.Empty;

    /// Forgets what every variable holds (a write through a `ref` may assign any of them).
    public void ForgetPointsTo() => _points = NoPoints;

    public IEnumerable<KeyValuePair<object, TaintValue>> Entries =>
        TaintMap.Entries(_root).Select(e => new KeyValuePair<object, TaintValue>(e.Key, e.Value));

    public TaintValue Get(object key) => TaintMap.Get(_root, key, TaintMap.Hash(key), 0)?.Value ?? TaintValue.Clean;

    /// A strong update (an assignment). The map keeps taint only (objects and members are facts: Task 27).
    public void Set(object key, TaintValue value)
    {
        value = value.WithoutIdentity();
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
        value = value.WithoutIdentity();
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

    public TaintState Clone() => new(_root, _facts, _points);

    /// Joins `other` into this state; true when this state changed (in the lattice: a value rose or a member fact or a
    /// points-to fact was lost or grew).
    public bool JoinWith(TaintState other)
    {
        var changed = false;
        _root = TaintMap.Join(_root, other._root, 0, ref changed);
        if (!_facts.IsEmpty && _facts != other._facts)
        {
            _facts = MemberFacts.Meet(_facts, other._facts, out var lost);
            changed |= lost;
        }
        if (_points.Count > 0 && !ReferenceEquals(_points, other._points))
        {
            var met = _points;
            foreach (var (key, objects) in _points)
            {
                var theirs = other.PointsTo(key);
                var united = theirs == null ? null : ObjSet.Union(objects, theirs);
                if (ReferenceEquals(united, objects)) continue;
                met = united == null ? met.Remove(key) : met.SetItem(key, united);
            }
            if (!ReferenceEquals(met, _points))
            {
                _points = met;
                changed = true;
            }
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
