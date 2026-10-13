using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// Qualor's taint engine for C# (spec §5) over a rebuilt solution. Task 7: intraprocedural. Every executable body of
/// every project (methods, constructors, operators, accessors, expression-bodied properties, field and property
/// initializers, top-level statements, and the lambdas and local functions inside them through the CFG's nested graphs)
/// is analysed by a MethodAnalyzer; a lambda or local function starts from the join of its enclosing body's states
/// (the values it may capture) plus its own source parameters. Findings are deduplicated by rule and sink site (a file
/// compiled in several projects or target frameworks reports once). A body whose analysis throws is skipped and
/// counted (AnalysisStats.FailedMethods); above 1 % of the bodies the run is incomplete (ruling R-E10).
public sealed class TaintEngine
{
    private readonly ModelSet _models;
    private readonly TaintEngineOptions _options;

    public TaintEngine(ModelSet models, TaintEngineOptions options)
    {
        _models = models;
        _options = options;
    }

    /// Test hook: called before each body is analysed (an exception thrown here is a failure of that body).
    internal Action<IMethodSymbol?>? BeforeBody { get; set; }

    public AnalysisResult Analyze(LoadedSolution solution, CancellationToken ct)
    {
        var budget = new Budget(_options, ct);
        var ctx = new AnalysisContext(_models, _options);
        var run = new Run(ctx, budget, BeforeBody);
        if (budget.Check())
        {
            try
            {
                foreach (var project in solution.Projects) ctx.Sources.RegisterHandlers(project.Compilation, ct);
                foreach (var project in solution.Projects)
                {
                    if (!run.AnalyzeProject(project.Compilation, ct)) break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                budget.Check();
            }
        }
        budget.Sample();
        var reason = budget.Exceeded ?? run.Incomplete ?? run.FailureReason();
        var findings = ctx.Findings
            .OrderBy(f => f.Sink.SourceTree?.FilePath, StringComparer.Ordinal).ThenBy(f => f.Sink.SourceSpan.Start).ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();
        var stats = new AnalysisStats(solution.Projects.Count, run.Methods, 0, ctx.UnmodelledExternalCalls, budget.Elapsed, budget.PeakMemoryBytes)
        {
            FailedMethods = run.Failed,
            FirstErrors = run.Errors,
        };
        return new AnalysisResult(findings, reason == null, reason, stats);
    }

    private sealed class Run
    {
        /// Ruling R-E10: failed bodies are skipped; above this share of all bodies the run is incomplete.
        private const double MaxFailedShare = 0.01;

        private readonly AnalysisContext _ctx;
        private readonly Budget _budget;
        private readonly Action<IMethodSymbol?>? _beforeBody;
        private readonly List<string> _errors = new();

        public Run(AnalysisContext ctx, Budget budget, Action<IMethodSymbol?>? beforeBody)
        {
            _ctx = ctx;
            _budget = budget;
            _beforeBody = beforeBody;
        }

        public int Methods { get; private set; }

        public int Failed { get; private set; }

        public IReadOnlyList<string> Errors => _errors;

        /// The first reason the result is partial that is not a budget or failures: an iteration cap.
        public string? Incomplete { get; private set; }

        /// Why the failures make the run incomplete (more than 1 % of the bodies analysed or failed), or null.
        public string? FailureReason()
        {
            var total = Methods + Failed;
            return Failed > 0 && Failed > MaxFailedShare * total
                ? $"{Failed} of {total} bodies failed (more than 1 %); first: {_errors[0]}"
                : null;
        }

        /// False when the budget stopped the run.
        public bool AnalyzeProject(Compilation compilation, CancellationToken ct)
        {
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var root in Roots(tree.GetRoot(ct)))
                {
                    if (!_budget.Check()) return false;
                    ControlFlowGraph? cfg;
                    IMethodSymbol? symbol;
                    try
                    {
                        cfg = Graph(model.GetOperation(root, ct), ct);
                        symbol = Symbol(root, model, ct);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        Fail(root, e);
                        continue;
                    }
                    if (cfg != null) Analyze(cfg, symbol, null, TaintValue.Clean, ct);
                }
            }
            return true;
        }

        /// An exception in one body (a Roslyn or engine bug): the body is skipped and counted (ruling R-E10).
        private void Fail(SyntaxNode node, Exception e)
        {
            Failed++;
            if (_errors.Count >= AnalysisStats.MaxErrors) return;
            var line = node.GetLocation().GetLineSpan();
            _errors.Add($"{line.Path}:{line.StartLinePosition.Line + 1}: {e.GetType().Name}: {e.Message}");
        }

        /// Analyses one graph, then the lambdas and local functions declared in it, each on its own (a failure skips
        /// that body only). A lambda given to an external method (`names.ForEach(n => ...)`, `ids.Select(id => ...)`)
        /// gets the taint of that call's receiver and other arguments in its parameters (`higherOrder`).
        private void Analyze(ControlFlowGraph cfg, IMethodSymbol? method, TaintState? enclosing, TaintValue higherOrder, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            TaintState? all;
            IReadOnlyList<IFlowAnonymousFunctionOperation> lambdas;
            try
            {
                _beforeBody?.Invoke(method);
                lambdas = AnonymousFunctions(cfg).ToList();
                var entry = new TaintState();
                if (enclosing != null)
                    foreach (var (key, value) in enclosing.Entries)
                        if (key is ISymbol) entry.Set(key, value);
                if (method != null)
                {
                    foreach (var p in method.Parameters)
                    {
                        if (_ctx.Sources.IsSourceParameter(p))
                        {
                            var location = p.Locations.FirstOrDefault(l => l.IsInSource) ?? Location.None;
                            entry.Set(p, TaintValue.Source(location, $"request data enters here: parameter '{p.Name}' of {_ctx.Name(method)}"));
                        }
                        else if (higherOrder.Request && !_ctx.Sources.IsScalar(p.Type))
                        {
                            entry.Add(p, higherOrder);
                        }
                    }
                }

                var analyzer = new MethodAnalyzer(_ctx, cfg);
                all = analyzer.Run(entry, collectAll: lambdas.Count > 0 || cfg.LocalFunctions.Length > 0);
                Methods++;
                if (!analyzer.Complete) Incomplete ??= $"iteration cap in {(method == null ? "a body" : _ctx.Name(method))}";
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Fail(cfg.OriginalOperation.Syntax, e);
                return;
            }

            foreach (var local in cfg.LocalFunctions)
                Nested(() => cfg.GetLocalFunctionControlFlowGraph(local, ct), local, all, TaintValue.Clean, cfg, ct);
            foreach (var lambda in lambdas)
                Nested(() => cfg.GetAnonymousFunctionControlFlowGraph(lambda, ct), lambda.Symbol, all, HigherOrder(lambda, all), cfg, ct);
        }

        private void Nested(Func<ControlFlowGraph> graph, IMethodSymbol method, TaintState? all, TaintValue higherOrder, ControlFlowGraph parent, CancellationToken ct)
        {
            ControlFlowGraph nested;
            try
            {
                nested = graph();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Fail(method.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(ct) ?? parent.OriginalOperation.Syntax, e);
                return;
            }
            Analyze(nested, method, all, higherOrder, ct);
        }

        /// The taint a lambda's parameters get when the lambda is an argument of an external call: the join of the
        /// call's receiver and other arguments that are variables (their value anywhere in the enclosing body).
        private static TaintValue HigherOrder(IFlowAnonymousFunctionOperation lambda, TaintState? enclosing)
        {
            if (enclosing == null) return TaintValue.Clean;
            var operation = lambda.Parent;
            while (operation is IDelegateCreationOperation or IConversionOperation) operation = operation.Parent;
            if (operation is not IArgumentOperation { Parent: IInvocationOperation call } argument) return TaintValue.Clean;
            if (MemberTable<object>.Definition(call.TargetMethod).DeclaringSyntaxReferences.Length > 0) return TaintValue.Clean;
            var value = TaintValue.Clean;
            if (call.Instance != null && MethodAnalyzer.Holder(call.Instance) is { } receiver) value = value.Join(enclosing.Get(receiver));
            foreach (var a in call.Arguments)
                if (!ReferenceEquals(a, argument) && MethodAnalyzer.Holder(a.Value) is { } holder) value = value.Join(enclosing.Get(holder));
            return value;
        }

        private static IEnumerable<IFlowAnonymousFunctionOperation> AnonymousFunctions(ControlFlowGraph cfg)
        {
            foreach (var block in cfg.Blocks)
            {
                foreach (var operation in block.Operations)
                    foreach (var f in operation.DescendantsAndSelf().OfType<IFlowAnonymousFunctionOperation>()) yield return f;
                if (block.BranchValue != null)
                    foreach (var f in block.BranchValue.DescendantsAndSelf().OfType<IFlowAnonymousFunctionOperation>()) yield return f;
            }
        }

        private static ControlFlowGraph? Graph(IOperation? operation, CancellationToken ct) => operation switch
        {
            IMethodBodyOperation body => ControlFlowGraph.Create(body, ct),
            IConstructorBodyOperation body => ControlFlowGraph.Create(body, ct),
            IBlockOperation { Parent: null } block => ControlFlowGraph.Create(block, ct),
            IFieldInitializerOperation field => ControlFlowGraph.Create(field, ct),
            IPropertyInitializerOperation property => ControlFlowGraph.Create(property, ct),
            _ => null,
        };

        private static IMethodSymbol? Symbol(SyntaxNode root, SemanticModel model, CancellationToken ct) => root switch
        {
            BaseMethodDeclarationSyntax or AccessorDeclarationSyntax => model.GetDeclaredSymbol(root, ct) as IMethodSymbol,
            ArrowExpressionClauseSyntax { Parent: BasePropertyDeclarationSyntax property } =>
                (model.GetDeclaredSymbol(property, ct) as IPropertySymbol)?.GetMethod,
            _ => null,
        };

        /// The roots of executable code in a tree; lambdas and local functions are reached through their enclosing
        /// graph. Method bodies and expressions are not descended into (they declare no members).
        private static IEnumerable<SyntaxNode> Roots(SyntaxNode root)
        {
            foreach (var node in root.DescendantNodesAndSelf(n => n is not (BlockSyntax or ArrowExpressionClauseSyntax
                         or EqualsValueClauseSyntax or GlobalStatementSyntax or ExpressionSyntax or ParameterListSyntax
                         or AttributeListSyntax)))
            {
                switch (node)
                {
                    case CompilationUnitSyntax unit when unit.Members.Any(m => m is GlobalStatementSyntax):
                        yield return unit;
                        break;
                    case BaseMethodDeclarationSyntax method when method.Body != null || method.ExpressionBody != null:
                        yield return method;
                        break;
                    case AccessorDeclarationSyntax accessor when accessor.Body != null || accessor.ExpressionBody != null:
                        yield return accessor;
                        break;
                    case ArrowExpressionClauseSyntax { Parent: PropertyDeclarationSyntax or IndexerDeclarationSyntax } arrow:
                        yield return arrow;
                        break;
                    case EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax { Parent.Parent: FieldDeclarationSyntax } } field:
                        yield return field;
                        break;
                    case EqualsValueClauseSyntax { Parent: PropertyDeclarationSyntax } property:
                        yield return property;
                        break;
                }
            }
        }
    }
}
