using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// Qualor's taint engine for C# (spec §5) over a rebuilt solution. Every executable body of every project (methods,
/// constructors, operators, accessors, expression-bodied properties, field and property initializers, top-level
/// statements, and the lambdas and local functions inside them) is analysed by a MethodAnalyzer:
/// - Task 7: intraprocedural, over the control-flow graph;
/// - Task 8: interprocedural. The call graph over every compilation (CallGraph: units, Dispatch by class hierarchy)
///   gives the bottom-up order of its strongly connected components; SummaryComputer computes each body's summary in
///   its parameters' labels and applies it at the call sites, together with a field-based heap (Heap), to their joint
///   fixed point; a lambda or local function is analysed with its enclosing body (its captures).
/// Findings are deduplicated by rule and sink site (a file compiled in several projects or target frameworks reports
/// once). A body whose analysis throws is skipped and counted (AnalysisStats.FailedMethods); above 1 % of the bodies
/// the run is incomplete (ruling R-E10).
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
        SummaryComputer? computer = null;
        CallGraph? graph = null;
        if (budget.Check())
        {
            try
            {
                foreach (var project in solution.Projects) ctx.Sources.RegisterHandlers(project.Compilation, ct);
                var started = budget.Elapsed;
                var dispatch = new Dispatch(solution.Projects.Select(p => (Compilation)p.Compilation), ct);
                graph = CallGraph.Build(solution, dispatch, budget.Check, ct);
                _index = budget.Elapsed - started;
                computer = new SummaryComputer(ctx, graph, dispatch, budget, BeforeBody);
                if (budget.Check()) computer.Run(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                budget.Check();
            }
        }
        _last = computer;
        budget.Sample();
        var reason = budget.Exceeded ?? computer?.Incomplete ?? computer?.FailureReason();
        var findings = ctx.Findings
            .OrderBy(f => f.Sink.SourceTree?.FilePath, StringComparer.Ordinal).ThenBy(f => f.Sink.SourceSpan.Start).ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();
        var stats = new AnalysisStats(solution.Projects.Count, computer?.Methods ?? 0, graph?.Sccs.Count ?? 0, ctx.UnmodelledExternalCalls, budget.Elapsed, budget.PeakMemoryBytes)
        {
            FailedMethods = computer?.Failed ?? 0,
            FirstErrors = computer?.Errors ?? Array.Empty<string>(),
        };
        return new AnalysisResult(findings, reason == null, reason, stats);
    }
}
