using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// A bounded set of abstract objects (Task 27, decision R-8): the objects a value may be, by their numbers in the run's
/// ObjectTable, sorted. At most MaxObjects; a union that would hold more is unknown (null where a set is expected: the
/// value may be any object, and its members are read and written at their field locations). Empty: no object (null, a
/// value not yet known).
internal sealed class ObjSet : IEquatable<ObjSet>
{
    /// k of decision R-8.
    public const int MaxObjects = 8;

    public static readonly ObjSet Empty = new(Array.Empty<int>());

    private readonly int[] _ids;

    private ObjSet(int[] ids) => _ids = ids;

    public static ObjSet Of(int id) => new(new[] { id });

    public int Count => _ids.Length;

    public bool IsEmpty => _ids.Length == 0;

    public ReadOnlySpan<int> Ids => _ids;

    public bool Contains(int id) => Array.BinarySearch(_ids, id) >= 0;

    /// The union, or null (unknown) beyond MaxObjects.
    public static ObjSet? Union(ObjSet? a, ObjSet? b)
    {
        if (a == null || b == null) return null;
        if (ReferenceEquals(a, b) || b.IsEmpty) return a;
        if (a.IsEmpty) return b;
        var merged = new List<int>(a.Count + b.Count);
        int i = 0, j = 0;
        while (i < a._ids.Length || j < b._ids.Length)
        {
            var x = i < a._ids.Length ? a._ids[i] : int.MaxValue;
            var y = j < b._ids.Length ? b._ids[j] : int.MaxValue;
            if (x == y)
            {
                merged.Add(x);
                i++;
                j++;
            }
            else if (x < y)
            {
                merged.Add(x);
                i++;
            }
            else
            {
                merged.Add(y);
                j++;
            }
            if (merged.Count > MaxObjects) return null;
        }
        if (merged.Count == a.Count) return a;
        if (merged.Count == b.Count) return b;
        return new ObjSet(merged.ToArray());
    }

    /// The set with the objects `map` gives for each (a map result of null: unknown, so the whole set is unknown).
    public ObjSet? SelectMany(Func<int, ObjSet?> map)
    {
        ObjSet? result = Empty;
        foreach (var id in _ids)
        {
            result = Union(result, map(id));
            if (result == null) return null;
        }
        return result;
    }

    public bool Equals(ObjSet? other) => other != null && (ReferenceEquals(this, other) || _ids.AsSpan().SequenceEqual(other._ids));

    public override bool Equals(object? obj) => obj is ObjSet s && Equals(s);

    public override int GetHashCode()
    {
        var h = 17;
        foreach (var id in _ids) h = (h * 31) + id;
        return h;
    }

    public override string ToString() => "{" + string.Join(",", _ids) + "}";
}

/// The members of an object a value is known to hold exactly (Task 27, strong updates): member (its definition) to its
/// value. A must-hold map: a join keeps a member only both sides know (their values joined); All is the bottom (every
/// member known, the identity of a join: a value not yet seen); a missing map (null where one is expected) knows nothing.
internal sealed class MemberMap
{
    public const int MaxMembers = 32;

    public static readonly MemberMap All = new(ImmutableDictionary<ISymbol, TaintValue>.Empty.WithComparers(SymbolEqualityComparer.Default), true);

    private MemberMap(ImmutableDictionary<ISymbol, TaintValue> values, bool all)
    {
        Values = values;
        IsAll = all;
    }

    public ImmutableDictionary<ISymbol, TaintValue> Values { get; }

    public bool IsAll { get; }

    public static MemberMap? Of(ImmutableDictionary<ISymbol, TaintValue> values)
    {
        if (values.IsEmpty) return null;
        if (values.Values.Any(v => v.Members != null)) values = values.ToImmutableDictionary(kv => kv.Key, kv => Flat(kv.Value), SymbolEqualityComparer.Default);
        return new MemberMap(values.WithComparers(SymbolEqualityComparer.Default), false);
    }

    /// A member's value without what it knows of its own members: exactness is one level deep (fix round 1, C1).
    public static TaintValue Flat(TaintValue value) => value.Members == null ? value : value with { Members = null };

    public bool TryGet(ISymbol member, out TaintValue value) => Values.TryGetValue(member, out value!);

    /// The members both know, their values joined (null: none).
    public static MemberMap? Meet(MemberMap? a, MemberMap? b)
    {
        if (a == null || b == null) return null;
        if (ReferenceEquals(a, b) || b.IsAll) return a;
        if (a.IsAll) return b;
        var builder = ImmutableDictionary.CreateBuilder<ISymbol, TaintValue>(SymbolEqualityComparer.Default);
        var same = true;
        foreach (var (k, v) in a.Values)
        {
            if (!b.Values.TryGetValue(k, out var w))
            {
                same = false;
                continue;
            }
            var joined = v.Join(w);
            if (!ReferenceEquals(joined, v)) same = false;
            builder[k] = joined;
        }
        return same ? a : Of(builder.ToImmutable());
    }

    public bool SameFlow(MemberMap? other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other == null || other.IsAll != IsAll || other.Values.Count != Values.Count) return false;
        foreach (var (k, v) in Values)
            if (!other.Values.TryGetValue(k, out var w) || !v.SameFlow(w) || !v.SameIdentity(w)) return false;
        return true;
    }

    public MemberMap? Select(Func<TaintValue, TaintValue> map)
    {
        if (IsAll) return this;
        var builder = ImmutableDictionary.CreateBuilder<ISymbol, TaintValue>(SymbolEqualityComparer.Default);
        foreach (var (k, v) in Values) builder[k] = map(v);
        return Of(builder.ToImmutable());
    }
}

/// The kinds of abstract objects: an allocation site in source (`new`, an anonymous object, an array or collection
/// expression, a record `with` copy), the object the model binder makes for an action parameter (one per entry point:
/// per action body and parameter), and the object a body's parameter (or `this`, slot −1) stands for in its summary
/// (substituted at each call by the objects the call gives).
internal enum ObjKind { Site, Bound, Param }

/// The abstract objects of one run, numbered (Task 27): allocation sites by their syntax, bound parameters by body and
/// ordinal, parameter objects by body and slot. Also the member slots of summaries: a label of slot MemberSlot(k, M) is
/// "member M of the objects parameter k is given" (read in a body through a parameter or `this` whose objects are its
/// own parameter objects), substituted at a call site by what the call's argument holds in M.
internal sealed class ObjectTable
{
    /// The first number of a member slot (parameter slots are −1 and up).
    public const int FirstMemberSlot = 1 << 20;

    private readonly Dictionary<object, int> _ids = new();
    private readonly List<(ObjKind Kind, int Owner, int Slot)> _objects = new();
    private readonly Dictionary<(int Slot, ISymbol Member), int> _memberSlots = new(new SlotComparer());
    private readonly List<(int Slot, ISymbol Member)> _slots = new();

    private readonly record struct SiteKey(SyntaxTree Tree, Microsoft.CodeAnalysis.Text.TextSpan Span);

    public int Count => _objects.Count;

    private readonly List<ObjSet> _singles = new();
    private readonly Dictionary<(int Owner, int Slot), TaintValue> _slotLabels = new();

    /// The one-object set of an object, interned (fix round 1, M4).
    public ObjSet Single(int id)
    {
        while (_singles.Count <= id) _singles.Add(ObjSet.Of(_singles.Count));
        return _singles[id];
    }

    /// The label of member slot `slot` of body `owner`, interned (fix round 1, M4).
    public TaintValue SlotLabel(int owner, int slot)
    {
        if (!_slotLabels.TryGetValue((owner, slot), out var label)) _slotLabels[(owner, slot)] = label = TaintValue.Param(owner, slot);
        return label;
    }

    public int MemberSlotCount => _slots.Count;

    private readonly Dictionary<int, SiteKey> _sites = new();

    /// The allocation site of an expression.
    public int Site(SyntaxNode syntax)
    {
        var key = new SiteKey(syntax.SyntaxTree, syntax.Span);
        var id = Intern(key, ObjKind.Site, -1, 0);
        _sites.TryAdd(id, key);
        return id;
    }

    /// Whether an object is an allocation site inside `body`'s syntax (the method that allocates it; ruling R-E35).
    public bool AllocatedIn(int id, SyntaxNode body) =>
        _sites.TryGetValue(id, out var site) && site.Tree == body.SyntaxTree && body.Span.Contains(site.Span);

    /// The object the binder makes for parameter `ordinal` of the entry body `body`.
    public int Bound(int body, int ordinal) => Intern(("bound", body, ordinal), ObjKind.Bound, body, ordinal);

    /// The object parameter `slot` (−1: `this`) of body `owner` stands for.
    public int Param(int owner, int slot) => Intern(("param", owner, slot), ObjKind.Param, owner, slot);

    public (ObjKind Kind, int Owner, int Slot) Describe(int id) => _objects[id];

    public bool IsParam(int id) => _objects[id].Kind == ObjKind.Param;

    private int Intern(object key, ObjKind kind, int owner, int slot)
    {
        if (_ids.TryGetValue(key, out var id)) return id;
        id = _objects.Count;
        _objects.Add((kind, owner, slot));
        _ids[key] = id;
        return id;
    }

    /// The member slot of member `member` (a definition) of the objects of parameter `slot`.
    public int MemberSlot(int slot, ISymbol member)
    {
        var key = (slot, member);
        if (_memberSlots.TryGetValue(key, out var s)) return s;
        s = FirstMemberSlot + _slots.Count;
        _slots.Add(key);
        _memberSlots[key] = s;
        return s;
    }

    public static bool IsMemberSlot(int slot) => slot >= FirstMemberSlot;

    /// The parameter slot and member of a member slot.
    public (int Slot, ISymbol Member) OfMemberSlot(int slot) => _slots[slot - FirstMemberSlot];

    private sealed class SlotComparer : IEqualityComparer<(int Slot, ISymbol Member)>
    {
        public bool Equals((int Slot, ISymbol Member) x, (int Slot, ISymbol Member) y) => x.Slot == y.Slot && SymbolEqualityComparer.Default.Equals(x.Member, y.Member);

        public int GetHashCode((int Slot, ISymbol Member) obj) => HashCode.Combine(obj.Slot, SymbolEqualityComparer.Default.GetHashCode(obj.Member));
    }
}

/// A member of a known object as a heap location (Task 27): Object the object's number, Member the member's key
/// (Dispatch.Key of its definition; Symbol the member, not part of the identity). A member read through unknown objects
/// reads the member's own key (its field location: every write of it, on any object); a member read through known
/// objects reads their locations and TopLocation (the writes through unknown objects).
internal readonly struct ObjLocation : IEquatable<ObjLocation>
{
    public ObjLocation(int obj, object member, ISymbol? symbol = null)
    {
        Object = obj;
        Member = member;
        Symbol = symbol;
    }

    public int Object { get; }

    public object Member { get; }

    public ISymbol? Symbol { get; }

    public bool Equals(ObjLocation other) => Object == other.Object && Member.Equals(other.Member);

    public override bool Equals(object? obj) => obj is ObjLocation o && Equals(o);

    public override int GetHashCode() => HashCode.Combine(Object, Member);
}

/// The writes of a member through unknown objects (Task 27).
internal readonly record struct TopLocation(object Member);
