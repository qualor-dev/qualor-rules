namespace Qualor.Taint;

/// The run's time and memory budget (spec §5, §6): Check() is called between method bodies; the first limit passed (or a
/// cancellation) is the reason the run stops incomplete. The working set is sampled every SampleEvery checks (and on
/// demand), which also gives the peak the stats report. Time is read from a TimeProvider (the system's, or a test's
/// manual clock).
///
/// The working set holds garbage the collector has not taken yet (about 0.6 GiB of nopCommerce's peak; final review I4),
/// so a sample over the limit is taken again after a full, blocking, compacting collection, and only a second sample
/// over it stops the run. The peak keeps the first sample (what the process held).
internal sealed class Budget
{
    private const int SampleEvery = 32;

    private readonly TaintEngineOptions _options;
    private readonly CancellationToken _ct;
    private readonly TimeProvider _clock;
    private readonly Func<long> _sample;
    private readonly Action _collect;
    private readonly long _started;
    private int _checks;

    /// `sample` and `collect` stand in for the working set and the collector in tests.
    public Budget(TaintEngineOptions options, CancellationToken ct, TimeProvider? clock = null, Func<long>? sample = null, Action? collect = null)
    {
        _options = options;
        _ct = ct;
        _clock = clock ?? TimeProvider.System;
        _sample = sample ?? (() => Environment.WorkingSet);
        _collect = collect ?? FullCollection;
        _started = _clock.GetTimestamp();
        Sample();
    }

    public TimeSpan Elapsed => _clock.GetElapsedTime(_started);

    public long PeakMemoryBytes { get; private set; }

    /// Why the run must stop, or null to go on. Once a reason is given, it is given again.
    public string? Exceeded { get; private set; }

    public bool Check()
    {
        if (Exceeded != null) return false;
        if (_ct.IsCancellationRequested) Exceeded = "cancelled";
        else if (Elapsed >= _options.TimeLimit) Exceeded = $"time limit of {_options.TimeLimit} exceeded";
        else if (_checks++ % SampleEvery == 0 && OverMemoryLimit())
            Exceeded = $"memory limit of {_options.MemoryLimitBytes} bytes exceeded";
        return Exceeded == null;
    }

    public long Sample()
    {
        var now = _sample();
        if (now > PeakMemoryBytes) PeakMemoryBytes = now;
        return now;
    }

    /// A sample over the limit, confirmed after a full collection.
    private bool OverMemoryLimit()
    {
        if (Sample() <= _options.MemoryLimitBytes) return false;
        _collect();
        return _sample() > _options.MemoryLimitBytes;
    }

    private static void FullCollection()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
    }
}
