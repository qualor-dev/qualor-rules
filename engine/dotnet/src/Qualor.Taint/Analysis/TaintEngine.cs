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
/// compiled in several projects or target frameworks reports once).
public sealed class TaintEngine
{
    private readonly ModelSet _models;
    private readonly TaintEngineOptions _options;

    public TaintEngine(ModelSet models, TaintEngineOptions options)
    {
        _models = models;
        _options = options;
    }

    public AnalysisResult Analyze(LoadedSolution solution, CancellationToken ct)
    {
        var budget = new Budget(_options, ct);
        var ctx = new AnalysisContext(_models, _options);
        var run = new Run(ctx, budget);
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
        var reason = budget.Exceeded ?? run.Incomplete;
        var findings = ctx.Findings
            .OrderBy(f => f.Sink.SourceTree?.FilePath, StringComparer.Ordinal).ThenBy(f => f.Sink.SourceSpan.Start).ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ToList();
        var stats = new AnalysisStats(solution.Projects.Count, run.Methods, 0, ctx.UnmodelledExternalCalls, budget.Elapsed, budget.PeakMemoryBytes);
        return new AnalysisResult(findings, reason == null, reason, stats);
    }

    private sealed class Run
    {
        private readonly AnalysisContext _ctx;
        private readonly Budget _budget;

        public Run(AnalysisContext ctx, Budget budget)
        {
            _ctx = ctx;
            _budget = budget;
        }

        public int Methods { get; private set; }

        /// The first reason the result is partial that is not a budget: an iteration cap, an internal error.
        public string? Incomplete { get; private set; }

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
                    try
                    {
                        cfg = Graph(model.GetOperation(root, ct), ct);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        Fail(root, e);
                        continue;
                    }
                    if (cfg == null) continue;
                    try
                    {
                        Analyze(cfg, Symbol(root, model, ct), null, ct);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        Fail(root, e);
                    }
                }
            }
            return true;
        }

        /// An exception in one body (a Roslyn or engine bug): the body is skipped, the result marked incomplete.
        private void Fail(SyntaxNode root, Exception e)
        {
            var line = root.GetLocation().GetLineSpan();
            Incomplete ??= $"internal error in {line.Path}:{line.StartLinePosition.Line + 1}: {e.GetType().Name}: {e.Message}";
        }

        private void Analyze(ControlFlowGraph cfg, IMethodSymbol? method, TaintState? enclosing, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var entry = new TaintState();
            if (enclosing != null)
                foreach (var (key, value) in enclosing.Entries)
                    if (key is ISymbol) entry.Set(key, value);
            if (method != null)
            {
                foreach (var p in method.Parameters)
                {
                    if (!_ctx.Sources.IsSourceParameter(p)) continue;
                    var location = p.Locations.FirstOrDefault(l => l.IsInSource) ?? Location.None;
                    entry.Set(p, TaintValue.Source(location, $"request data enters here: parameter '{p.Name}' of {_ctx.Name(method)}"));
                }
            }

            var analyzer = new MethodAnalyzer(_ctx, cfg);
            var all = analyzer.Run(entry);
            Methods++;
            if (!analyzer.Complete) Incomplete ??= $"iteration cap in {(method == null ? "a body" : _ctx.Name(method))}";

            foreach (var local in cfg.LocalFunctions)
                Analyze(cfg.GetLocalFunctionControlFlowGraph(local, ct), local, all, ct);
            foreach (var lambda in AnonymousFunctions(cfg))
                Analyze(cfg.GetAnonymousFunctionControlFlowGraph(lambda, ct), lambda.Symbol, all, ct);
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
