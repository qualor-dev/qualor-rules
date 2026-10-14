using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint.Tests.Intraprocedural;

/// Task 20 fix round 2 (RR2): the two mechanisms behind scope-aware witness paths, each on its own. A value joined from
/// request data of entry point A (a short path) and of entry point B (a longer one) keeps both witnesses; narrowing to B
/// drops A's, and the witness for a sink only B reaches is B's.
public sealed class WitnessTests
{
    private static Location At(int start) => Location.Create("f.cs", new TextSpan(start, 1), new LinePositionSpan());

    private static (TaintValue Joined, Reach A, Reach B) Joined()
    {
        var table = new ReachTable();
        var a = table.Of(new ulong[] { 1 });
        var b = table.Of(new ulong[] { 2 });
        var fromA = TaintValue.Source(At(1), "a").ScopedTo(a);
        var fromB = TaintValue.Source(At(2), "b").Step(At(3), "b1").Step(At(4), "b2").ScopedTo(b);
        return (fromA.Join(fromB), a, b);
    }

    [Fact]
    public void A_join_of_two_scopes_keeps_both_witnesses_and_the_shorter_path()
    {
        var (joined, _, _) = Joined();

        Assert.Equal("a", joined.Path.ToList()[0].Message);
        Assert.Equal(2, joined.Witnesses.Length);
    }

    [Fact]
    public void Narrowed_drops_a_witness_outside_the_scope_and_makes_the_survivor_the_path()
    {
        var (joined, _, b) = Joined();

        var narrowed = joined.Narrowed(b);

        Assert.Same(b, narrowed.Scope);
        Assert.Equal("b", narrowed.Path.ToList()[0].Message);
        Assert.True(narrowed.Witnesses.IsDefaultOrEmpty);
    }

    [Fact]
    public void WitnessFor_picks_the_witness_inside_the_sinks_reach()
    {
        var (joined, a, b) = Joined();

        Assert.Equal("b", joined.WitnessFor(b).Path.ToList()[0].Message);
        Assert.Equal("a", joined.WitnessFor(a).Path.ToList()[0].Message);
    }

    // ---- Task 28 (R-9): a high witness is preferred to a medium one, whatever their lengths ----

    [Fact]
    public void A_trail_is_medium_when_a_step_is_and_stays_so_when_capped_or_concatenated()
    {
        var plain = Trail.Of(new PathStep(At(1), "s")).Add(new PathStep(At(2), "x"));
        var medium = plain.Add(new PathStep(At(3), "read from heap", StepKind.HeapRead));

        Assert.False(plain.Medium);
        Assert.True(medium.Medium);
        Assert.True(plain.Concat(medium).Medium);
        Assert.True(medium.Concat(plain).Medium);
        Assert.False(StepKind.KeyedEntry.IsMedium());
        Assert.False(StepKind.ViewModel.IsMedium());
        Assert.All(new[] { StepKind.HeapRead, StepKind.AnyKeyEntry, StepKind.KeyLookup, StepKind.ViewFallback, StepKind.DispatchFallback },
            k => Assert.True(k.IsMedium()));

        var full = Trail.Empty;
        for (var i = 0; i < Trail.MaxSteps; i++) full = full.Add(new PathStep(At(i + 10), "s"));
        Assert.Equal(Trail.MaxSteps, full.Count);
        Assert.True(full.Add(new PathStep(At(5), "late", StepKind.KeyLookup)).Medium);
    }

    [Fact]
    public void A_join_keeps_the_high_path_even_when_it_is_longer()
    {
        var medium = TaintValue.Source(At(1), "m").Step(At(2), "read from heap", StepKind.HeapRead);
        var high = TaintValue.Source(At(3), "h").Step(At(4), "h1").Step(At(5), "h2").Step(At(6), "h3");

        Assert.Equal("h", medium.Join(high).Path.ToList()[0].Message);
        Assert.Equal("h", high.Join(medium).Path.ToList()[0].Message);
        // A value whose path became high has risen in the lattice (each value at most once).
        Assert.False(medium.Join(high).SameFlow(medium));
        Assert.True(high.Join(medium).SameFlow(high));
    }

    [Fact]
    public void Scoped_witnesses_put_a_high_one_first_and_WitnessFor_prefers_it()
    {
        var table = new ReachTable();
        var a = table.Of(new ulong[] { 1 });
        var ab = table.Of(new ulong[] { 3 });
        var medium = TaintValue.Source(At(1), "m").Step(At(2), "read from heap", StepKind.HeapRead).ScopedTo(a);
        var high = TaintValue.Source(At(3), "h").Step(At(4), "h1").Step(At(5), "h2").ScopedTo(ab);

        var joined = medium.Join(high);

        Assert.Equal(2, joined.Witnesses.Length);
        Assert.False(joined.Path.Medium);
        Assert.Equal("h", joined.WitnessFor(a).Path.ToList()[0].Message);
    }

    [Fact]
    public void A_path_cleaned_for_a_rule_is_never_the_witness_of_that_rule()
    {
        // The encoded side is high and short but clean for xss: it is no witness of an xss finding (R-E32 revised: the
        // join keeps both, the finding chooses). A label keeps the path of the side that is request data for more rules.
        var encoded = TaintValue.Source(At(1), "encoded").CleanedFor(new[] { "csharp.xss" });
        var raw = TaintValue.Source(At(2), "raw").Step(At(3), "r1").Step(At(4), "read from heap", StepKind.HeapRead);
        var reach = new ReachTable().Of(new ulong[] { 1 });

        Assert.Equal("raw", encoded.Join(raw).WitnessFor(reach, "csharp.xss").Path.ToList()[0].Message);
        Assert.Equal("raw", raw.Join(encoded).WitnessFor(reach, "csharp.xss").Path.ToList()[0].Message);
        Assert.True(encoded.Join(raw).WitnessFor(reach, "csharp.xss").Path.Medium);
        Assert.Equal("encoded", encoded.Join(raw).Path.ToList()[0].Message);

        var x = TaintValue.Param(1, 0).CleanedFor(new[] { "csharp.xss" });
        var y = TaintValue.Param(1, 0).Step(At(5), "y1").Step(At(6), "y2");
        Assert.Equal(2, x.Join(y).Labels[0].Path.Count);
    }

    // ---- Task 28 fix round 1 (I1, R-E32 revised): the witness of a finding is chosen for its rule ----

    private static readonly string[] Xss = { "csharp.xss" };
    private static readonly string[] Sql = { "csharp.sql-injection" };

    [Fact]
    public void A_finding_gets_the_best_witness_that_is_not_cleaned_for_its_rule()
    {
        // Incomparable cleanliness: one side clean for xss (high), the other clean for sql (medium).
        var forSql = TaintValue.Source(At(1), "encoded").CleanedFor(Xss);
        var forXss = TaintValue.Source(At(2), "heap").Step(At(3), "read from heap", StepKind.HeapRead).CleanedFor(Sql);
        var reach = new ReachTable().Of(new ulong[] { 1 });

        var joined = forSql.Join(forXss);

        Assert.Equal("encoded", joined.WitnessFor(reach, "csharp.sql-injection").Path.ToList()[0].Message);
        Assert.False(joined.WitnessFor(reach, "csharp.sql-injection").Path.Medium);
        Assert.Equal("heap", joined.WitnessFor(reach, "csharp.xss").Path.ToList()[0].Message);
        Assert.Equal("heap", forXss.Join(forSql).WitnessFor(reach, "csharp.xss").Path.ToList()[0].Message);
    }

    [Fact]
    public void A_high_witness_cleaned_for_another_rule_beats_a_dirtier_medium_one()
    {
        // Probe P1's shape: the encoded side is a high witness for sql although the heap side is dirtier.
        var encoded = TaintValue.Source(At(1), "encoded").CleanedFor(Xss);
        var heap = TaintValue.Source(At(2), "raw").Step(At(3), "read from heap", StepKind.HeapRead);
        var reach = new ReachTable().Of(new ulong[] { 1 });

        var joined = heap.Join(encoded);

        Assert.Equal("encoded", joined.WitnessFor(reach, "csharp.sql-injection").Path.ToList()[0].Message);
        Assert.Equal("raw", joined.WitnessFor(reach, "csharp.xss").Path.ToList()[0].Message);
    }

    [Fact]
    public void Witnesses_of_both_sides_keep_their_scope_when_their_cleanliness_differs()
    {
        // Probe P2b's shape: A's data is encoded (clean for xss), B's raw; narrowed to A, the sql witness is A's.
        var table = new ReachTable();
        var a = table.Of(new ulong[] { 1 });
        var b = table.Of(new ulong[] { 2 });
        var fromA = TaintValue.Source(At(1), "a").Step(At(4), "a1").Step(At(5), "a2").CleanedFor(Xss).ScopedTo(a);
        var fromB = TaintValue.Source(At(2), "b").ScopedTo(b);

        var joined = fromA.Join(fromB);

        Assert.Equal("a", joined.WitnessFor(a, "csharp.sql-injection").Path.ToList()[0].Message);
        Assert.Equal("a", joined.Narrowed(a).WitnessFor(a, "csharp.sql-injection").Path.ToList()[0].Message);
        Assert.Equal("b", joined.WitnessFor(b, "csharp.sql-injection").Path.ToList()[0].Message);
    }

    [Fact]
    public void A_witness_that_became_high_for_some_rule_is_a_change_in_the_lattice()
    {
        // The value already has a high witness (clean for xss); a high witness for xss joins in: SameFlow must see it.
        var encoded = TaintValue.Source(At(1), "encoded").CleanedFor(Xss);
        var heap = TaintValue.Source(At(2), "raw").Step(At(3), "read from heap", StepKind.HeapRead);
        var direct = TaintValue.Source(At(6), "direct").Step(At(7), "d1").Step(At(8), "d2").Step(At(9), "d3");

        var before = heap.Join(encoded);
        var after = before.Join(direct);

        Assert.False(after.SameFlow(before));
        Assert.True(after.Join(direct).SameFlow(after));
    }

    [Fact]
    public void The_witness_list_stays_bounded_and_keeps_a_high_witness_for_every_rule_it_had()
    {
        var reach = new ReachTable().Of(new ulong[] { 1 });
        var value = TaintValue.Clean;
        var rules = new[] { "r1", "r2", "r3", "r4", "r5", "r6" };
        foreach (var r in rules)
            value = value.Join(TaintValue.Source(At(rules.Length + Array.IndexOf(rules, r)), r).CleanedFor(rules.Where(x => x != r).ToArray()));

        Assert.True(value.Witnesses.Length <= rules.Length);
        foreach (var r in rules)
            Assert.Equal(r, value.WitnessFor(reach, r).Path.ToList()[0].Message);
    }

    [Fact]
    public void A_call_edge_joined_with_a_dirtier_one_takes_its_path()
    {
        var cleaned = Trail.Of(new PathStep(At(1), "encoded"));
        var raw = Trail.Of(new PathStep(At(2), "raw")).Add(new PathStep(At(3), "read from heap", StepKind.HeapRead));
        var xss = ImmutableHashSet.Create("csharp.xss");
        var old = new CallEffect(0, null!, 0, xss, cleaned);

        var joined = CallEffect.Joined(old, ImmutableHashSet<string>.Empty, raw);

        Assert.NotNull(joined);
        Assert.Same(raw, joined!.Path);
        Assert.Empty(joined.CleanFor);
        // The dirtier edge first: a cleaner high edge does not replace its path.
        Assert.Null(CallEffect.Joined(new CallEffect(0, null!, 0, ImmutableHashSet<string>.Empty, raw), xss, cleaned));
    }

    [Fact]
    public void A_medium_step_at_the_last_steps_location_is_still_recorded()
    {
        var value = TaintValue.Source(At(1), "s").Step(At(2), "assigned to 'x'");

        var stepped = value.Step(At(2), "written to ViewData (a key built at run time)", StepKind.AnyKeyEntry);

        Assert.True(stepped.Path.Medium);
        Assert.False(value.Step(At(2), "again").Path.Count > value.Path.Count);
    }
}
