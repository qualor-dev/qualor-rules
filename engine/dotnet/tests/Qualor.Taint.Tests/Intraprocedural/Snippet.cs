using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Qualor.Taint.Tests.Fixtures;

namespace Qualor.Taint.Tests.Intraprocedural;

/// A small C# snippet compiled against FixtureReferences.All (with the web SDK's implicit usings and the namespaces the
/// SQL snippets use) and analysed by the TaintEngine with the models of models/csharp. A line the snippet expects a
/// finding on is marked with `/*sink*/`.
internal static class Snippet
{
    private const string Usings = """
        global using Microsoft.AspNetCore.Mvc;
        global using Microsoft.AspNetCore.Mvc.RazorPages;
        global using Microsoft.Data.SqlClient;
        global using Dapper;
        """;

    private static readonly Lazy<ModelSet> ModelsLazy = new(() => ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")));

    public static ModelSet Models => ModelsLazy.Value;

    public static readonly TaintEngineOptions Options = new(TimeSpan.FromMinutes(1), 4L << 30);

    /// The 1-based lines of the snippet marked with `/*sink*/`.
    public static IReadOnlyList<int> Marked(string code) =>
        code.Split('\n').Select((l, i) => (l, i)).Where(x => x.l.Contains("/*sink*/", StringComparison.Ordinal)).Select(x => x.i + 1).ToList();

    /// The 1-based lines of the snippet the engine reports `rule` on, in order.
    public static IReadOnlyList<int> Findings(string code, string rule = "csharp.sql-injection") =>
        Analyze(code).Findings.Where(f => f.RuleId == rule && Path.GetFileName(f.Sink.SourceTree!.FilePath) == "Snippet.cs")
            .Select(f => f.Sink.GetLineSpan().StartLinePosition.Line + 1).OrderBy(l => l).ToList();

    public static AnalysisResult Analyze(string code, TaintEngineOptions? options = null) =>
        new TaintEngine(Models, options ?? Options).Analyze(Compile(code), CancellationToken.None);

    /// Compiles the snippet as one project; a snippet with compile errors throws (the test is wrong, not the engine).
    public static LoadedSolution Compile(string code)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new[]
        {
            CSharpSyntaxTree.ParseText(code, parse, "Snippet.cs"),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "GlobalUsings.g.cs"),
            CSharpSyntaxTree.ParseText(Usings, parse, "SnippetUsings.g.cs"),
        };
        var kind = trees[0].GetRoot().DescendantNodes().OfType<GlobalStatementSyntax>().Any()
            ? OutputKind.ConsoleApplication : OutputKind.DynamicallyLinkedLibrary;
        var options = new CSharpCompilationOptions(kind, nullableContextOptions: NullableContextOptions.Enable);
        var compilation = CSharpCompilation.Create("Snippet", trees, FixtureReferences.All, options);
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        if (errors.Count > 0) throw new InvalidOperationException("snippet does not compile:\n" + string.Join("\n", errors));
        var input = new CompilationInput(
            "Snippet.csproj", "net8.0", "Snippet", kind, LanguageVersion.CSharp12, NullableContextOptions.Enable,
            Array.Empty<string>(), true, null, new[] { "Snippet.cs" }, Array.Empty<string>(), Array.Empty<string>(), "Snippet.csproj");
        return new LoadedSolution(new[] { new ProjectCompilation(input, compilation, errors) });
    }
}
