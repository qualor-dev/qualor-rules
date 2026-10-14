using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// The engine's limits for one run (spec §5 "Budgets"): over TimeLimit or MemoryLimitBytes the run stops and its result
/// is marked incomplete; MaxIterationsPerScc caps the fixed point of one strongly connected component of the call graph
/// (its analyses, per unit of the component, in one heap round), the rounds of one unit with its lambdas and local
/// functions, the heap rounds of the run (Task 8), and, times a method's block count, the fixed point of one method.
public sealed record TaintEngineOptions(TimeSpan TimeLimit, long MemoryLimitBytes, int MaxIterationsPerScc = 50)
{
    /// The directory the misuse rules' test-code globs are matched from (the scanned repository); null: the nearest
    /// directory above each file that holds `.git` (else the file's full path).
    public string? SourceRoot { get; init; }
}

/// One step of a finding's path: "request data enters here", "assigned to 'sql'", "reaches the sink ...".
public sealed record PathStep(Location Location, string Message)
{
    /// Where to report the step: its mapped file and lines (see Finding.SinkSpan).
    public FileLinePositionSpan Span => Location.GetMappedLineSpan();
}

/// One result: a sink site of a rule (the location of the sink argument or of the assignment of a property sink), the
/// path from a source to it, and the other sources whose data reaches the same site.
public sealed record Finding(string RuleId, Location Sink, IReadOnlyList<PathStep> Path, IReadOnlyList<Location> OtherSources)
{
    /// Where to report the finding: the sink's mapped file and lines. In generated code with `#line` directives (a Razor
    /// view's `*_cshtml.g.cs` from the Razor source generator) that is the directive's file and line, the `.cshtml` the
    /// developer wrote, with the path as the generator wrote it (the build's absolute path, like the recorded sources);
    /// in a `#line hidden` region or a file without directives, the file's own path and line.
    public FileLinePositionSpan SinkSpan => Sink.GetMappedLineSpan();
}

/// What a run found. Complete is false when the run stopped early (a budget, cancellation, an iteration cap); its
/// findings are then partial and must not replace the OpenGrep rules (R-4).
public sealed record AnalysisResult(IReadOnlyList<Finding> Findings, bool Complete, string? IncompleteReason, AnalysisStats Stats);

/// Counters of a run: projects and method bodies (methods, accessors, lambdas, local functions, initializers)
/// analysed, strongly connected components (Task 8), distinct external call sites that got the `unmodelled-external`
/// default, the elapsed time and the peak working set seen. FailedMethods: bodies skipped because their analysis threw
/// (ruling R-E10: the run stays complete up to 1 % of the bodies), with the first FirstErrors (at most
/// MaxErrors, `<file>:<line>: <exception>: <message>`).
public sealed record AnalysisStats(int Projects, int Methods, int Sccs, int UnmodelledExternalCalls, TimeSpan Elapsed, long PeakMemoryBytes)
{
    public const int MaxErrors = 10;

    public int FailedMethods { get; init; }

    public IReadOnlyList<string> FirstErrors { get; init; } = Array.Empty<string>();

    /// The request entry points the heap is scoped to (spec §5 "Heap", decision R-6; EntryPoints): actions, Razor Pages
    /// handlers, Minimal API handlers, and bodies that read the request themselves but no entry point reaches.
    public int EntryPoints { get; init; }

    /// Views rendered by name (`View()`, `PartialView`, `Page()`, partials, view components) resolved to their
    /// generated classes; UnresolvedViews: those whose name could not be resolved, which reach every view of the
    /// caller's project instead.
    public int ViewEdges { get; init; }

    public int UnresolvedViews { get; init; }
}
