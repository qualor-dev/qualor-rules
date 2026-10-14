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
    public void A_join_keeps_the_path_of_the_side_that_is_request_data_for_more_rules()
    {
        // The encoded side is high and short but clean for xss: it is no witness of an xss finding.
        var encoded = TaintValue.Source(At(1), "encoded").CleanedFor(new[] { "csharp.xss" });
        var raw = TaintValue.Source(At(2), "raw").Step(At(3), "r1").Step(At(4), "read from heap", StepKind.HeapRead);

        Assert.Equal("raw", encoded.Join(raw).Path.ToList()[0].Message);
        Assert.Equal("raw", raw.Join(encoded).Path.ToList()[0].Message);
        Assert.True(encoded.Join(raw).Path.Medium);

        var x = TaintValue.Param(1, 0).CleanedFor(new[] { "csharp.xss" });
        var y = TaintValue.Param(1, 0).Step(At(5), "y1").Step(At(6), "y2");
        Assert.Equal(2, x.Join(y).Labels[0].Path.Count);
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
