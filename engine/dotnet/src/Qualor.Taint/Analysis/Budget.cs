using System.Diagnostics;

namespace Qualor.Taint;

/// The run's time and memory budget (spec §5, §6): Check() is called between method bodies; the first limit passed (or a
/// cancellation) is the reason the run stops incomplete. The working set is sampled every SampleEvery checks (and on
/// demand), which also gives the peak the stats report.
internal sealed class Budget
{
    private const int SampleEvery = 32;

    private readonly TaintEngineOptions _options;
    private readonly CancellationToken _ct;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private int _checks;

    public Budget(TaintEngineOptions options, CancellationToken ct)
    {
        _options = options;
        _ct = ct;
        Sample();
    }

    public TimeSpan Elapsed => _clock.Elapsed;

    public long PeakMemoryBytes { get; private set; }

    /// Why the run must stop, or null to go on. Once a reason is given, it is given again.
    public string? Exceeded { get; private set; }

    public bool Check()
    {
        if (Exceeded != null) return false;
        if (_ct.IsCancellationRequested) Exceeded = "cancelled";
        else if (_clock.Elapsed >= _options.TimeLimit) Exceeded = $"time limit of {_options.TimeLimit} exceeded";
        else if (_checks++ % SampleEvery == 0 && Sample() > _options.MemoryLimitBytes)
            Exceeded = $"memory limit of {_options.MemoryLimitBytes} bytes exceeded";
        return Exceeded == null;
    }

    public long Sample()
    {
        var now = Environment.WorkingSet;
        if (now > PeakMemoryBytes) PeakMemoryBytes = now;
        return now;
    }
}
