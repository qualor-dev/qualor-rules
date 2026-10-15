using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// Qualor's taint engine for C# (spec §5) over a rebuilt solution. Every executable body of every project (methods,
/// constructors, operators, accessors, expression-bodied properties, field and property initializers, top-level
/// statements, and the lambdas and local functions inside them) is analysed by a MethodAnalyzer:
/// - Task 7: intraprocedural, over the control-flow graph;
/// - Task 8: interprocedural. The call graph over every compilation (CallGraph: units, Dispatch narrowed to the types
///   the solution creates or registers, decision R-7)
///   gives the bottom-up order of its strongly connected components; SummaryComputer computes each body's summary in
///   its parameters' labels and applies it at the call sites, together with a heap scoped to the request entry point
///   (Heap, EntryPoints: Task 20, decision R-6) and kept per abstract object where a value's objects are known (Task 27,
///   decision R-8: ObjectTable, member slots, strong updates), to their joint fixed point; a lambda or local function is
///   analysed with its enclosing body (its captures).
/// Then the misuse rules' checks (MisuseChecks, Task 12) run over every tree. Findings are deduplicated by rule, file and
/// line (a file compiled in several projects or target frameworks reports once, with the first input's path). A body
/// whose analysis throws is skipped and counted (AnalysisStats.FailedMethods); above 1 % of the bodies the run is
/// incomplete (ruling R-E10).
public sealed class TaintEngine
{
    private readonly ModelSet _models;
    private readonly TaintEngineOptions _options;
    private SummaryComputer? _last;

    public TaintEngine(ModelSet models, TaintEngineOptions options)
    {
        _models = models;
        _options = options;
    }

    /// Test hook: called before each body is analysed (an exception thrown here is a failure of that body).
    internal Action<IMethodSymbol?>? BeforeBody { get; set; }

    /// Test hook: called before each seed (request data at a body's parameter) runs its global effects.
    internal Action? BeforeSeed { get; set; }

    /// Test hook: the clock the time budget reads (the system's by default; a test's manual clock makes the time limit
    /// pass exactly where the test says, whatever the host's load).
    internal TimeProvider Clock { get; set; } = TimeProvider.System;

    /// The summaries of the last run (the brief's view), by body symbol: for tests and diagnostics.
    internal IReadOnlyDictionary<IMethodSymbol, Summary> Summaries() =>
        _last?.Summaries() ?? new Dictionary<IMethodSymbol, Summary>(SymbolEqualityComparer.Default);

    /// The work of the last run: unit analyses (counting the repeats of the fixed point), heap symbols tainted, heap
    /// rounds, the time the index (dispatch and call graph: one binding of every body) took, and the most global
    /// effects (sinks, call edges, heap writes) one summary holds.
    internal (int Analyses, int HeapSymbols, int HeapRounds, TimeSpan Index, int MaxGlobalEffects) Work() =>
        _last == null ? (0, 0, 0, _index, 0) : (_last.Analyses, _last.Heap.Count, _last.HeapRounds, _index, _last.MaxGlobalEffects());

    private TimeSpan _index;

    public AnalysisResult Analyze(LoadedSolution solution, CancellationToken ct)
    {
        var budget = new Budget(_options, ct, Clock);
        var ctx = new AnalysisContext(_models, _options);
        var misuse = new MisuseChecks(_models.Rules);
        SummaryComputer? computer = null;
        CallGraph? graph = null;
        EntryPoints? entries = null;
        Dispatch? dispatch = null;
        if (budget.Check())
        {
            try
            {
                foreach (var project in solution.Projects)
                {
                    ctx.Sources.RegisterHandlers(project.Compilation, ct);
                    ctx.Validation.Scan(project.Compilation, ct);
                }
                var started = budget.Elapsed;
                dispatch = new Dispatch(solution.Projects.Select(p => (Compilation)p.Compilation), ct);
                entries = new EntryPoints(ctx.Sources);
                graph = CallGraph.Build(solution, dispatch, budget.Check, ct, entries);
                _index = budget.Elapsed - started;
                computer = new SummaryComputer(ctx, graph, dispatch, entries, budget, BeforeBody, BeforeSeed);
                if (budget.Check()) computer.Run(ct);
                if (budget.Check()) misuse.Run(solution, budget, ctx, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                budget.Check();
            }
        }
        _last = computer;
        budget.Sample();
        var reason = budget.Exceeded ?? computer?.Incomplete ?? computer?.FailureReason() ?? MisuseFailure(misuse) ?? LoadFailure(solution);
        var findings = Deduplicate(solution, ctx.Findings)
            .OrderBy(f => f.Sink.SourceTree?.FilePath, StringComparer.Ordinal).ThenBy(f => f.Sink.SourceSpan.Start).ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();
        var stats = new AnalysisStats(solution.Projects.Count, computer?.Methods ?? 0, graph?.Sccs.Count ?? 0, ctx.UnmodelledExternalCalls, budget.Elapsed, budget.PeakMemoryBytes)
        {
            FailedMethods = (computer?.Failed ?? 0) + misuse.Failed,
            ProjectsWithErrors = solution.Projects.Count(p => p.Errors.Count > 0 || p.SourcesMissing),
            ProjectsWithoutSources = solution.Projects.Count(p => p.SourcesMissing),
            UnresolvedReferences = solution.Projects.Sum(p => p.UnresolvedReferences),
            ProjectProblems = solution.Projects.Where(p => p.Errors.Count > 0 || p.SourcesMissing).Select(Problem).ToList(),
            FirstErrors = (computer?.Errors ?? Array.Empty<string>()).Concat(misuse.Errors).Take(AnalysisStats.MaxErrors).ToList(),
            EntryPoints = entries?.Count ?? 0,
            ViewEdges = entries?.ViewEdges ?? 0,
            UnresolvedViews = entries?.UnresolvedViews ?? 0,
            UncompiledViews = entries?.UncompiledViews ?? 0,
            CompiledByEngineViews = solution.Projects.SelectMany(p => p.EngineViews).Select(SolutionLoader.PathKey).Distinct().Count(),
            EngineViewErrors = solution.Projects.SelectMany(p => p.EngineViewErrors).Select(e => SolutionLoader.PathKey(e[..ViewOfError(e)])).Distinct().Count(),
            DispatchByRegistrations = dispatch?.ByRegistrations ?? 0,
            DispatchNarrowed = dispatch?.Narrowed ?? 0,
            DispatchByScanning = dispatch?.ByScanning ?? 0,
            DispatchByHierarchy = dispatch?.ByHierarchy ?? 0,
            OpenProjects = dispatch?.OpenProjects ?? 0,
            OpenTypes = dispatch?.OpenTypes ?? 0,
            HighFindings = findings.Count(f => f.Confidence == Confidence.High),
            MediumFindings = findings.Count(f => f.Confidence == Confidence.Medium),
        };
        return new AnalysisResult(findings, reason == null, reason, stats);
    }

    /// Ruling R-E42: a project whose sources did not all load (a recorded source or the generated-file directory not
    /// read, or no syntax tree at all) was analysed without part of its code, so the run is incomplete (R-4: the caller
    /// falls back to the OpenGrep rules); compile errors and unresolved references alone are warnings.
    private static string? LoadFailure(LoadedSolution solution)
    {
        var missing = solution.Projects.Where(p => p.SourcesMissing).ToList();
        return missing.Count == 0 ? null
            : $"the sources of {missing.Count} project(s) could not be loaded; first: {Problem(missing[0])}";
    }

    /// One line for a project with load or compile problems: its path and framework, what is missing, its error count
    /// and its first error.
    private static string Problem(ProjectCompilation p)
    {
        var parts = new List<string>();
        if (p.SourcesNotLoaded > 0) parts.Add($"{p.SourcesNotLoaded} source(s) not loaded");
        else if (!p.Compilation.SyntaxTrees.Any()) parts.Add("no source loaded");
        if (p.UnresolvedReferences > 0) parts.Add($"{p.UnresolvedReferences} reference(s) not resolved");
        parts.Add($"{p.Errors.Count} error(s) while loading or compiling");
        var first = p.Errors.Count > 0 ? "; first: " + SolutionLoader.Format(p.Errors[0]) : "";
        return $"{p.Input.ProjectPath} ({p.Input.TargetFramework}): {string.Join(", ", parts)}{first}";
    }

    /// The view path of an EngineViewErrors line (`<path>: <reason>`; a Windows path's drive colon is no separator).
    private static int ViewOfError(string line)
    {
        var at = line.IndexOf(".cshtml:", StringComparison.OrdinalIgnoreCase);
        return at < 0 ? line.Length : at + ".cshtml".Length;
    }

    /// Ruling R-E10 for the misuse checks: trees whose check threw are skipped; above 1 % of the trees checked the run is
    /// incomplete.
    private static string? MisuseFailure(MisuseChecks misuse)
    {
        var total = misuse.Checked + misuse.Failed;
        return misuse.Failed > 0 && misuse.Failed > 0.01 * total
            ? $"{misuse.Failed} of {total} files failed the misuse checks (more than 1 %); first: {misuse.Errors[0]}"
            : null;
    }

    /// One finding per rule, file and line (Review Focus 2: a project of several target frameworks is analysed once
    /// per framework; two sinks of a rule on one line are one finding), by the mapped location (`#line`, generated
    /// views), keeping a high finding over a medium one (R-9), then the finding of the first compilation input in the
    /// solution's order, then the first on the line.
    private static IEnumerable<Finding> Deduplicate(LoadedSolution solution, IEnumerable<Finding> findings)
    {
        var order = new Dictionary<SyntaxTree, int>();
        for (var i = 0; i < solution.Projects.Count; i++)
            foreach (var tree in solution.Projects[i].Compilation.SyntaxTrees) order.TryAdd(tree, i);
        return findings
            .GroupBy(f =>
            {
                var span = f.Sink.GetMappedLineSpan();
                return (f.RuleId, span.Path, span.StartLinePosition.Line);
            })
            .Select(g => g
                .OrderBy(f => f.Confidence)
                .ThenBy(f => f.Sink.SourceTree is { } t && order.TryGetValue(t, out var i) ? i : int.MaxValue)
                .ThenBy(f => f.Sink.SourceSpan.Start)
                .ThenBy(f => f.Sink.SourceSpan.Length)
                .First());
    }
}
