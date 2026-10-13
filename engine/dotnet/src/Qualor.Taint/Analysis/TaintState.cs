using System.Collections.Immutable;
using System.Numerics;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// The abstract value of an expression or a variable (spec §5): whether it carries request data (Request) and, if so,
/// the rules it has been cleaned for by a sanitizer (CleanFor: the value is dirty for every other rule). Path is one
/// witness from a source to here; Sources the source locations whose data it carries (at most MaxSources).
///
/// The lattice: a clean value (Request false) is the bottom; a request value is above it, and the smaller its CleanFor,
/// the higher. Join is the union of the request flags and the intersection of CleanFor (over the request values only:
/// a clean operand does not make a cleaned one dirty); Sources are united. Path does not take part in the order (it is
/// a witness, the shorter one is kept), so the fixed point ends when Request, CleanFor and Sources stop changing.
internal sealed record TaintValue(bool Request, ImmutableHashSet<string> CleanFor, ImmutableList<PathStep> Path)
{
    public const int MaxSources = 16;

    public static readonly TaintValue Clean = new(false, ImmutableHashSet<string>.Empty, ImmutableList<PathStep>.Empty);

    public ImmutableHashSet<Location> Sources { get; init; } = ImmutableHashSet<Location>.Empty;

    /// Request data that enters at `location` (a source).
    public static TaintValue Source(Location location, string message) =>
        new(true, ImmutableHashSet<string>.Empty, ImmutableList.Create(new PathStep(location, message)))
        {
            Sources = ImmutableHashSet.Create(location),
        };

    public bool TaintedFor(string rule) => Request && !CleanFor.Contains(rule);

    public TaintValue Join(TaintValue other)
    {
        if (!other.Request || ReferenceEquals(this, other)) return this;
        if (!Request) return other;
        var cleanFor = CleanFor.Count == 0 || other.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : CleanFor.Intersect(other.CleanFor);
        var sources = Sources;
        foreach (var s in other.Sources)
        {
            if (sources.Count >= MaxSources) break;
            sources = sources.Add(s);
        }
        var path = other.Path.Count < Path.Count ? other.Path : Path;
        if (cleanFor.Count == CleanFor.Count && ReferenceEquals(sources, Sources) && ReferenceEquals(path, Path)) return this;
        return new TaintValue(true, cleanFor, path) { Sources = sources };
    }

    /// Equal in the lattice (Path aside).
    public bool SameTaint(TaintValue other) =>
        ReferenceEquals(this, other)
        || (Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Sources.SetEquals(other.Sources))));

    /// The value cleaned for these rules (a sanitizer's result).
    public TaintValue CleanedFor(IReadOnlyCollection<string> rules) =>
        !Request || rules.Count == 0 || rules.All(CleanFor.Contains) ? this : this with { CleanFor = CleanFor.Union(rules) };

    /// The value with one more path step (a request value only; a step at the last step's location is not repeated).
    public TaintValue Step(Location location, string message)
    {
        if (!Request || (Path.Count > 0 && Path[^1].Location.Equals(location))) return this;
        return this with { Path = Path.Add(new PathStep(location, message)) };
    }
}

/// The abstract state at a program point: a map from what holds a value (a local, a parameter, a field by symbol, a
/// flow capture of the control-flow graph by its CaptureId) to its TaintValue; an absent key is clean.
///
/// The map is persistent (ruling R-E11): a hash array mapped trie whose nodes never change once built, so Clone is
/// O(1), an update copies one path, and a join walks only the subtrees the two states do not share (a block that
/// changes two variables of a thousand costs two paths, not a thousand entries).
internal sealed class TaintState
{
    private object? _root;

    public TaintState() { }

    private TaintState(object? root) => _root = root;

    public IEnumerable<KeyValuePair<object, TaintValue>> Entries =>
        TaintMap.Entries(_root).Select(e => new KeyValuePair<object, TaintValue>(e.Key, e.Value));

    public TaintValue Get(object key) => TaintMap.Get(_root, key, TaintMap.Hash(key), 0)?.Value ?? TaintValue.Clean;

    /// A strong update (an assignment).
    public void Set(object key, TaintValue value)
    {
        var hash = TaintMap.Hash(key);
        if (!value.Request)
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
        if (!value.Request) return;
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

    public TaintState Clone() => new(_root);

    /// Joins `other` into this state; true when this state changed (in the lattice).
    public bool JoinWith(TaintState other)
    {
        var changed = false;
        _root = TaintMap.Join(_root, other._root, 0, ref changed);
        return changed;
    }
}

/// The persistent hash array mapped trie of TaintState. A slot is an Entry, a Collision (the entries of one full hash)
/// or a Node (a branch on 5 bits of the hash per level, compressed by a bitmap). Only request values are stored.
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
