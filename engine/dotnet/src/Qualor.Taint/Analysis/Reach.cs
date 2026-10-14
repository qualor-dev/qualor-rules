namespace Qualor.Taint;

/// A set of entry points (bit i: entry i of EntryPoints): what reaches a strongly connected component of the call graph
/// or a Minimal API handler's body, and the entry points request data is valid for (TaintValue.Scope). Every non-empty
/// set is interned by its ReachTable, so equal sets are one object (reference equality is value equality within a run);
/// Equals still compares by value. None is the empty set, shared by every run.
internal sealed class Reach : IEquatable<Reach>
{
    public static readonly Reach None = new(Array.Empty<ulong>(), null, 0, 0);

    private readonly ReachTable? _table;
    private readonly int _hash;

    internal Reach(ulong[] bits, ReachTable? table, int id, int hash)
    {
        Bits = bits;
        _table = table;
        Id = id;
        _hash = hash;
        IsEmpty = Array.TrueForAll(bits, w => w == 0);
    }

    public ulong[] Bits { get; }

    /// The set's number in its table (0 for None).
    public int Id { get; }

    public bool IsEmpty { get; }

    public bool Has(int bit) => (bit >> 6) < Bits.Length && (Bits[bit >> 6] & (1UL << (bit & 63))) != 0;

    public bool Intersects(Reach other)
    {
        if (ReferenceEquals(this, other)) return !IsEmpty;
        var a = Bits;
        var b = other.Bits;
        var n = Math.Min(a.Length, b.Length);
        for (var i = 0; i < n; i++)
            if ((a[i] & b[i]) != 0) return true;
        return false;
    }

    /// The entry points in both (None when they share none).
    public Reach Intersect(Reach other)
    {
        if (ReferenceEquals(this, other) || IsEmpty) return this;
        if (other.IsEmpty) return None;
        return (_table ?? other._table)!.Intersect(this, other);
    }

    /// The entry points in either.
    public Reach Union(Reach other)
    {
        if (ReferenceEquals(this, other) || other.IsEmpty) return this;
        if (IsEmpty) return other;
        return (_table ?? other._table)!.Union(this, other);
    }

    public bool Equals(Reach? other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || _hash != other._hash) return false;
        var n = Math.Max(Bits.Length, other.Bits.Length);
        for (var i = 0; i < n; i++)
            if ((i < Bits.Length ? Bits[i] : 0) != (i < other.Bits.Length ? other.Bits[i] : 0)) return false;
        return true;
    }

    public override bool Equals(object? obj) => Equals(obj as Reach);

    public override int GetHashCode() => _hash;

    internal static int HashOf(ulong[] bits)
    {
        var hash = new HashCode();
        var last = bits.Length - 1;
        while (last >= 0 && bits[last] == 0) last--;
        for (var i = 0; i <= last; i++) hash.Add(bits[i]);
        return hash.ToHashCode();
    }
}

/// The Reach sets of one engine run: one value-keyed intern table, so every set exists once, and one global capped memo
/// of intersections and unions per pair of sets (keyed by their ids), so the heap's reads and the joins of scoped values
/// neither allocate nor recompute a set they have seen. Used from the run's one thread.
internal sealed class ReachTable
{
    private const int MaxMemo = 1 << 19;

    private readonly Dictionary<Reach, Reach> _intern = new();
    private readonly Dictionary<long, Reach> _intersections = new();
    private readonly Dictionary<long, Reach> _unions = new();
    private int _nextId = 1;

    /// The sets interned so far.
    public int Count => _intern.Count;

    /// The interned set of these bits (None when empty); the array is kept when it is new.
    public Reach Of(ulong[] bits)
    {
        if (Array.TrueForAll(bits, w => w == 0)) return Reach.None;
        var probe = new Reach(bits, this, 0, Reach.HashOf(bits));
        if (_intern.TryGetValue(probe, out var known)) return known;
        var reach = new Reach(bits, this, _nextId++, probe.GetHashCode());
        _intern[reach] = reach;
        return reach;
    }

    private static long Pair(Reach a, Reach b) => a.Id < b.Id ? ((long)a.Id << 32) | (uint)b.Id : ((long)b.Id << 32) | (uint)a.Id;

    public Reach Intersect(Reach a, Reach b)
    {
        var key = Pair(a, b);
        if (_intersections.TryGetValue(key, out var known)) return known;
        var n = Math.Min(a.Bits.Length, b.Bits.Length);
        var bits = new ulong[n];
        for (var i = 0; i < n; i++) bits[i] = a.Bits[i] & b.Bits[i];
        known = Of(bits);
        if (_intersections.Count < MaxMemo) _intersections[key] = known;
        return known;
    }

    public Reach Union(Reach a, Reach b)
    {
        var key = Pair(a, b);
        if (_unions.TryGetValue(key, out var known)) return known;
        var n = Math.Max(a.Bits.Length, b.Bits.Length);
        var bits = new ulong[n];
        for (var i = 0; i < n; i++) bits[i] = (i < a.Bits.Length ? a.Bits[i] : 0) | (i < b.Bits.Length ? b.Bits[i] : 0);
        known = Of(bits);
        if (_unions.Count < MaxMemo) _unions[key] = known;
        return known;
    }
}
