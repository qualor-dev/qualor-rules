using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Misuse;

/// A snippet compiled at a given path (the misuse rules skip test code by path) and analysed with the shipped models.
internal static class MisuseSnippet
{
    public const string Deserialization = "csharp.unsafe-deserialization";
    public const string Xxe = "csharp.xxe";
    public const string Tls = "csharp.tls-verification-disabled";

    /// The 1-based lines of the file at `path` the engine reports `rule` on, in order.
    public static IReadOnlyList<int> Lines(string code, string rule, string path = "Snippet.cs", TaintEngineOptions? options = null) =>
        Analyze(code, path, options).Findings.Where(f => f.RuleId == rule && f.Sink.SourceTree!.FilePath == path)
            .Select(f => f.Sink.GetLineSpan().StartLinePosition.Line + 1).OrderBy(l => l).ToList();

    public static AnalysisResult Analyze(string code, string path = "Snippet.cs", TaintEngineOptions? options = null)
    {
        var result = new TaintEngine(Snippet.Models, options ?? Snippet.Options).Analyze(Compile(code, path), CancellationToken.None);
        if (result.Stats.FailedMethods > 0) throw new InvalidOperationException("failed bodies: " + string.Join("; ", result.Stats.FirstErrors));
        return result;
    }

    /// One project of the snippet at `path`; a snippet with compile errors throws (the test is wrong, not the engine).
    public static LoadedSolution Compile(string code, string path)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new[]
        {
            CSharpSyntaxTree.ParseText(code, parse, path),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "GlobalUsings.g.cs"),
            CSharpSyntaxTree.ParseText("global using Microsoft.AspNetCore.Mvc;\nglobal using Microsoft.Data.SqlClient;\n", parse, "SnippetUsings.g.cs"),
        };
        var kind = trees[0].GetRoot().DescendantNodes().OfType<GlobalStatementSyntax>().Any() ? OutputKind.ConsoleApplication : OutputKind.DynamicallyLinkedLibrary;
        var compilation = CSharpCompilation.Create("Snippet", trees, FixtureReferences.All, new CSharpCompilationOptions(kind, nullableContextOptions: NullableContextOptions.Enable));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        if (errors.Count > 0) throw new InvalidOperationException("snippet does not compile:\n" + string.Join("\n", errors));
        var input = new CompilationInput(
            "Snippet.csproj", "net8.0", "Snippet", kind, LanguageVersion.CSharp12, NullableContextOptions.Enable,
            Array.Empty<string>(), true, null, new[] { path }, Array.Empty<string>(), Array.Empty<string>(), "Snippet.csproj");
        return new LoadedSolution(new[] { new ProjectCompilation(input, compilation, errors) });
    }
}
