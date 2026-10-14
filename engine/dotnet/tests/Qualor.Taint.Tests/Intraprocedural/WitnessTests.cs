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
}
