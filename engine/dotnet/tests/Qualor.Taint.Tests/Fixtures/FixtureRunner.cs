using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Qualor.Taint.Tests.Fixtures;

/// What the engine did with one fixture, compared with its annotations. Missing: ruleid lines without a finding;
/// Unexpected: ok lines with one; TodoFound: todoruleid lines with one. TodoOkReported (todook lines with a finding)
/// and Unannotated (findings of the fixture's rule on lines with no annotation) are informational.
public sealed record FixtureResult(
    IReadOnlyList<Annotation> Missing, IReadOnlyList<Annotation> Unexpected, IReadOnlyList<Annotation> TodoFound,
    IReadOnlyList<Diagnostic> CompileErrors)
{
    public IReadOnlyList<Annotation> TodoOkReported { get; init; } = Array.Empty<Annotation>();

    public IReadOnlyList<Annotation> Unannotated { get; init; } = Array.Empty<Annotation>();
}

/// A fixture compiled as one project: its files (the fixture, its companions `<name>.*.cs` and its shim), the
/// annotations of the fixture and its companions, and the compilation errors (uncompilable lines left out).
public sealed record CompiledFixture(string Name, string FixturePath, LoadedSolution Solution, IReadOnlyList<Annotation> Annotations, IReadOnlyList<Diagnostic> CompileErrors);

public static class FixtureRunner
{
    /// The implicit global usings of a Microsoft.NET.Sdk.Web project (`<ImplicitUsings>enable`), which the SDK generates
    /// into obj/ and Qualor's build hook records among the sources: the OpenGrep fixtures are written for such a project
    /// (they use Task, List and Uri without a using).
    internal const string ImplicitUsings = """
        global using global::System;
        global using global::System.Collections.Generic;
        global using global::System.IO;
        global using global::System.Linq;
        global using global::System.Net.Http;
        global using global::System.Threading;
        global using global::System.Threading.Tasks;
        global using global::System.Net.Http.Json;
        global using global::Microsoft.AspNetCore.Builder;
        global using global::Microsoft.AspNetCore.Hosting;
        global using global::Microsoft.AspNetCore.Http;
        global using global::Microsoft.AspNetCore.Routing;
        global using global::Microsoft.Extensions.Configuration;
        global using global::Microsoft.Extensions.DependencyInjection;
        global using global::Microsoft.Extensions.Hosting;
        global using global::Microsoft.Extensions.Logging;
        """;

    /// Every fixture of rules/csharp (`<dir>/<name>.cs`; companions such as `open-redirect.global.cs` belong to the
    /// fixture named `open-redirect`), in path order.
    public static IReadOnlyList<string> AllFixturePaths() =>
        Directory.GetFiles(Path.Combine(Repo.Root, "rules", "csharp"), "*.cs", SearchOption.AllDirectories)
            .Where(f => Path.GetFileName(f).Count(c => c == '.') == 1)
            .OrderBy(f => f, StringComparer.Ordinal).ToList();

    /// The files compiled together for a fixture: the fixture, its companions in its directory, its shim.
    public static IReadOnlyList<string> FilesOf(string fixturePath)
    {
        var name = Path.GetFileNameWithoutExtension(fixturePath);
        var dir = Path.GetDirectoryName(fixturePath)!;
        var files = new List<string> { fixturePath };
        files.AddRange(Directory.GetFiles(dir, name + ".*.cs").OrderBy(f => f, StringComparer.Ordinal));
        var shim = Path.Combine(Repo.EngineDir, "fixtures", "shims", name + ".shim.cs");
        if (File.Exists(shim)) files.Add(shim);
        return files;
    }

    /// Compiles a fixture (+ companions + shim) against FixtureReferences.All as one project. Compile errors on lines
    /// listed under `uncompilable:` are not reported.
    public static CompiledFixture Compile(string fixturePath, Expectations? expectations = null)
    {
        expectations ??= Expectations.None;
        var name = Path.GetFileNameWithoutExtension(fixturePath);
        var files = FilesOf(fixturePath);
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = files.Select(f => CSharpSyntaxTree.ParseText(File.ReadAllText(f), parse, f)).ToList();
        trees.Add(CSharpSyntaxTree.ParseText(ImplicitUsings, parse, "Fixture.GlobalUsings.g.cs"));
        // Top-level statements need an executable; a library otherwise.
        var kind = trees.Any(t => t.GetRoot().DescendantNodes().OfType<GlobalStatementSyntax>().Any())
            ? OutputKind.ConsoleApplication : OutputKind.DynamicallyLinkedLibrary;
        var options = new CSharpCompilationOptions(kind, nullableContextOptions: NullableContextOptions.Disable, allowUnsafe: true);
        var compilation = CSharpCompilation.Create("Fixture." + name, trees, FixtureReferences.All, options);

        var skip = expectations.Uncompilable.Select(u => (u.File, u.Line)).ToHashSet();
        var noCompare = expectations.Excluded.Select(u => (u.File, u.Line)).Concat(skip).ToHashSet();
        var errors = compilation.GetDiagnostics()
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .Where(d => !(d.Location.IsInSource && skip.Contains((Path.GetFileName(d.Location.SourceTree!.FilePath), d.Location.GetLineSpan().StartLinePosition.Line + 1))))
            .ToList();

        var annotations = files.Where(f => !f.EndsWith(".shim.cs", StringComparison.Ordinal))
            .SelectMany(f => Annotation.Parse(Path.GetFileName(f), File.ReadAllText(f)))
            .Where(a => !noCompare.Contains((a.File, a.Line)))
            .ToList();

        var input = new CompilationInput(
            fixturePath, "net8.0", compilation.AssemblyName!, kind, LanguageVersion.CSharp12, NullableContextOptions.Disable,
            Array.Empty<string>(), true, null, files, FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!).ToList(),
            Array.Empty<string>(), fixturePath);
        var solution = new LoadedSolution(new[] { new ProjectCompilation(input, compilation, errors) });
        return new CompiledFixture(name, fixturePath, solution, annotations, errors);
    }

    /// The engine's findings as the comparison takes them: (rule id, file path, 1-based line of the sink location).
    public static IReadOnlyList<(string RuleId, string File, int Line)> Lines(AnalysisResult result) =>
        result.Findings.Select(f => (f.RuleId, f.Sink.SourceTree?.FilePath ?? "", f.Sink.GetLineSpan().StartLinePosition.Line + 1)).ToList();

    /// Runs the real TaintEngine (default options: 10 minutes, 4 GB) on the fixture; an incomplete run or a failed body
    /// (ruling R-E10 would hide it in a complete run) fails.
    public static FixtureResult Run(string fixturePath, ModelSet models, TaintEngineOptions? options = null, Expectations? expectations = null)
    {
        options ??= new TaintEngineOptions(TimeSpan.FromMinutes(10), 4L << 30);
        return Run(fixturePath, solution =>
        {
            var result = new TaintEngine(models, options).Analyze(solution, CancellationToken.None);
            if (!result.Complete) throw new InvalidOperationException("incomplete engine run: " + result.IncompleteReason);
            if (result.Stats.FailedMethods > 0) throw new InvalidOperationException("failed bodies: " + string.Join("; ", result.Stats.FirstErrors));
            return Lines(result);
        }, expectations);
    }

    /// Compiles the fixture and compares what `analyze` reports (rule id, file name or path, line) for the fixture's
    /// rule(s) with the annotations: ruleid not reported → Missing; ok reported → Unexpected; todoruleid reported →
    /// TodoFound.
    public static FixtureResult Run(
        string fixturePath, Func<LoadedSolution, IReadOnlyList<(string RuleId, string File, int Line)>> analyze, Expectations? expectations = null)
    {
        var compiled = Compile(fixturePath, expectations);
        var rules = compiled.Annotations.Select(a => a.RuleId).ToHashSet();
        var reported = analyze(compiled.Solution)
            .Where(f => rules.Contains(f.RuleId))
            .Select(f => (f.RuleId, File: Path.GetFileName(f.File), f.Line))
            .ToHashSet();

        bool Hit(Annotation a) => reported.Contains((a.RuleId, a.File, a.Line));
        List<Annotation> Of(string kind, bool hit) => compiled.Annotations.Where(a => a.Kind == kind && Hit(a) == hit).ToList();

        var annotated = compiled.Annotations.Select(a => (a.RuleId, a.File, a.Line)).ToHashSet();
        var unannotated = reported.Where(f => !annotated.Contains(f)).OrderBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Line)
            .Select(f => new Annotation(f.File, f.Line, "finding", f.RuleId)).ToList();
        return new FixtureResult(Of("ruleid", false), Of("ok", true), Of("todoruleid", true), compiled.CompileErrors)
        {
            TodoOkReported = Of("todook", true),
            Unannotated = unannotated,
        };
    }
}
