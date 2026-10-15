namespace Qualor.Taint.Tests.Intraprocedural;

/// Final review I4: the working set counts garbage the collector has not taken yet, so a sample over the memory limit is
/// confirmed after a full, blocking collection before the run stops.
public sealed class BudgetTests
{
    private static TaintEngineOptions Limit(long bytes) => new(TimeSpan.FromHours(1), bytes);

    [Fact]
    public void A_sample_over_the_limit_that_a_collection_brings_under_it_goes_on()
    {
        var samples = new Queue<long>(new long[] { 100, 5_000, 400 });
        var collections = 0;
        var budget = new Budget(Limit(1_000), CancellationToken.None, sample: () => samples.Dequeue(), collect: () => collections++);
        Assert.True(budget.Check());
        Assert.Null(budget.Exceeded);
        Assert.Equal(1, collections);
    }

    [Fact]
    public void A_sample_still_over_the_limit_after_a_collection_stops_the_run()
    {
        var samples = new Queue<long>(new long[] { 100, 5_000, 4_000 });
        var collections = 0;
        var budget = new Budget(Limit(1_000), CancellationToken.None, sample: () => samples.Dequeue(), collect: () => collections++);
        Assert.False(budget.Check());
        Assert.StartsWith("memory limit", budget.Exceeded);
        Assert.Equal(1, collections);
        Assert.Equal(5_000, budget.PeakMemoryBytes);
    }

    [Fact]
    public void A_sample_under_the_limit_collects_nothing()
    {
        var samples = new Queue<long>(new long[] { 100, 200 });
        var collections = 0;
        var budget = new Budget(Limit(1_000), CancellationToken.None, sample: () => samples.Dequeue(), collect: () => collections++);
        Assert.True(budget.Check());
        Assert.Equal(0, collections);
    }
}
