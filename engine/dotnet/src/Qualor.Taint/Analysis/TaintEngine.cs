using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// Qualor's taint engine for C# (spec §5) over a rebuilt solution. Every executable body of every project (methods,
/// constructors, operators, accessors, expression-bodied properties, field and property initializers, top-level
/// statements, and the lambdas and local functions inside them) is analysed by a MethodAnalyzer:
/// - Task 7: intraprocedural, over the control-flow graph;
/// - Task 8: interprocedural. The call graph over every compilation (CallGraph: units, Dispatch by class hierarchy)
///   gives the bottom-up order of its strongly connected components; SummaryComputer computes each body's summary in
///   its parameters' labels and applies it at the call sites, together with a field-based heap scoped to the request
///   entry point (Heap, EntryPoints: Task 20, decision R-6), to their joint fixed point; a lambda or local function is
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
        var budget = new Budget(_options, ct);
        var ctx = new AnalysisContext(_models, _options);
        var misuse = new MisuseChecks(_models.Rules);
        SummaryComputer? computer = null;
        CallGraph? graph = null;
        EntryPoints? entries = null;
        if (budget.Check())
        {
            try
            {
                foreach (var project in solution.Projects) ctx.Sources.RegisterHandlers(project.Compilation, ct);
                var started = budget.Elapsed;
                var dispatch = new Dispatch(solution.Projects.Select(p => (Compilation)p.Compilation), ct);
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
        var reason = budget.Exceeded ?? computer?.Incomplete ?? computer?.FailureReason() ?? MisuseFailure(misuse);
        var findings = Deduplicate(solution, ctx.Findings)
            .OrderBy(f => f.Sink.SourceTree?.FilePath, StringComparer.Ordinal).ThenBy(f => f.Sink.SourceSpan.Start).ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();
        var stats = new AnalysisStats(solution.Projects.Count, computer?.Methods ?? 0, graph?.Sccs.Count ?? 0, ctx.UnmodelledExternalCalls, budget.Elapsed, budget.PeakMemoryBytes)
        {
            FailedMethods = (computer?.Failed ?? 0) + misuse.Failed,
            FirstErrors = (computer?.Errors ?? Array.Empty<string>()).Concat(misuse.Errors).Take(AnalysisStats.MaxErrors).ToList(),
            EntryPoints = entries?.Count ?? 0,
            ViewEdges = entries?.ViewEdges ?? 0,
            UnresolvedViews = entries?.UnresolvedViews ?? 0,
            UncompiledViews = entries?.UncompiledViews ?? 0,
        };
        return new AnalysisResult(findings, reason == null, reason, stats);
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
    /// views), keeping the finding of the first compilation input in the solution's order, then the first on the line.
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
                .OrderBy(f => f.Sink.SourceTree is { } t && order.TryGetValue(t, out var i) ? i : int.MaxValue)
                .ThenBy(f => f.Sink.SourceSpan.Start)
                .First());
    }
}
