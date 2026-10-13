using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint.Tests.Intraprocedural;

/// The persistent state map (ruling R-E11) against a Dictionary oracle: sets, removals, weak adds and joins over keys
/// whose hashes collide in part (same low bits) and in full (same hash).
public sealed class TaintStateTests
{
    /// A key with a chosen hash code (TaintState compares non-symbol keys by Equals and GetHashCode).
    private sealed record Key(int Id, int Hash)
    {
        public override int GetHashCode() => Hash;
    }

    private static TaintValue Value(string source) =>
        TaintValue.Source(Location.Create("f.cs", new Microsoft.CodeAnalysis.Text.TextSpan(source.GetHashCode() & 0xFFF, 1),
            new Microsoft.CodeAnalysis.Text.LinePositionSpan()), source);

    private static Dictionary<Key, TaintValue> Oracle(TaintState state) =>
        state.Entries.ToDictionary(e => (Key)e.Key, e => e.Value);

    [Fact]
    public void Random_operations_match_a_dictionary()
    {
        var random = new Random(7);
        var keys = Enumerable.Range(0, 300).Select(i => new Key(i, i % 3 == 0 ? 42 : i % 3 == 1 ? (i << 5) : random.Next())).ToList();
        var mismatches = 0;
        for (var round = 0; round < 20; round++)
        {
            var a = new TaintState();
            var b = new TaintState();
            var oa = new Dictionary<Key, TaintValue>();
            var ob = new Dictionary<Key, TaintValue>();
            for (var op = 0; op < 400; op++)
            {
                var k = keys[random.Next(keys.Count)];
                var (s, o) = random.Next(2) == 0 ? (a, oa) : (b, ob);
                switch (random.Next(3))
                {
                    case 0:
                        var v = Value("s" + random.Next(5));
                        s.Set(k, v);
                        o[k] = v;
                        break;
                    case 1:
                        s.Set(k, TaintValue.Clean);
                        o.Remove(k);
                        break;
                    default:
                        var w = Value("w" + random.Next(5));
                        s.Add(k, w);
                        o[k] = o.TryGetValue(k, out var old) ? old.Join(w) : w;
                        break;
                }
                if (op % 50 == 0)
                {
                    var copy = a.Clone();
                    a.Set(keys[0], Value("after-clone"));
                    if (!Oracle(copy).Keys.ToHashSet().SetEquals(oa.Keys)) mismatches++;
                    oa[keys[0]] = Value("after-clone");
                }
            }
            var joined = a.Clone();
            var changed = joined.JoinWith(b);
            var expected = new Dictionary<Key, TaintValue>(oa);
            foreach (var (k, v) in ob) expected[k] = expected.TryGetValue(k, out var old) ? old.Join(v) : v;
            var actual = Oracle(joined);
            if (!actual.Keys.ToHashSet().SetEquals(expected.Keys) || actual.Any(e => !e.Value.SameTaint(expected[e.Key]))) mismatches++;
            if (changed != expected.Any(e => !oa.TryGetValue(e.Key, out var before) || !before.SameTaint(e.Value))) mismatches++;
            if (!Oracle(a).Keys.ToHashSet().SetEquals(oa.Keys)) mismatches++;
            if (joined.Clone().JoinWith(joined)) mismatches++;
        }
        Assert.Equal(0, mismatches);
    }
}
