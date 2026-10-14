using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using YamlDotNet.RepresentationModel;

namespace Qualor.Taint.Tests;

/// The engine's own multi-project fixtures (engine/dotnet/fixtures/solutions/&lt;name&gt;): small ASP.NET Core
/// solutions written from learn.microsoft.com patterns. `inputs.yml` names the projects, their source folders and project
/// references; the test turns it into CompilationInputs (no MSBuild), loads them with SolutionLoader, runs the TaintEngine
/// and compares its findings with the `// ruleid:` / `// ok:` / `// todoruleid:` annotations of every file.
public sealed class SolutionFixtureTests : TempDirs
{
    private static string SolutionsDir => Path.Combine(Repo.EngineDir, "fixtures", "solutions");

    private static readonly Lazy<ModelSet> Models = new(() => ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")));

    public static IEnumerable<object[]> Fixtures() =>
        Directory.GetDirectories(SolutionsDir).OrderBy(d => d, StringComparer.Ordinal).Select(d => new object[] { Path.GetFileName(d) });

    [Fact]
    public void There_are_six_solution_fixtures() => Assert.Equal(6, Fixtures().Count());

    private sealed record Loaded(LoadedSolution Solution, IReadOnlyList<Annotation> Annotations, int Projects);

    private Loaded Load(string name)
    {
        var dir = Path.Combine(SolutionsDir, name);
        var yaml = new YamlStream();
        using (var reader = new StreamReader(Path.Combine(dir, "inputs.yml"))) yaml.Load(reader);
        var projects = (YamlSequenceNode)((YamlMappingNode)yaml.Documents[0].RootNode).Children[new YamlScalarNode("projects")];

        var work = TempDir();
        var usings = Path.Combine(work, "GlobalUsings.g.cs");
        File.WriteAllText(usings, FixtureRunner.ImplicitUsings);
        var references = FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!).ToList();

        var inputs = new List<CompilationInput>();
        var annotations = new List<Annotation>();
        foreach (var node in projects.Children.Cast<YamlMappingNode>())
        {
            string Get(string key) => ((YamlScalarNode)node.Children[new YamlScalarNode(key)]).Value!;
            var project = Get("name");
            var folder = Path.Combine(dir, Get("folder"));
            var refs = node.Children.TryGetValue(new YamlScalarNode("references"), out var r)
                ? ((YamlSequenceNode)r).Children.Cast<YamlScalarNode>().Select(x => x.Value!).ToList() : new List<string>();
            var sources = Directory.GetFiles(folder, "*.cs", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal).ToList();
            foreach (var file in sources) annotations.AddRange(Annotation.Parse(Path.GetFileName(file), File.ReadAllText(file)));
            sources.Add(usings);
            inputs.Add(new CompilationInput(
                Path.Combine(dir, project + ".csproj"), "net8.0", project, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Disable, Array.Empty<string>(), true, null, sources, references,
                refs.Select(x => Path.Combine(dir, x + ".csproj")).ToList(), Path.Combine(work, project + ".txt")));
        }
        var solution = SolutionLoader.Load(inputs, CancellationToken.None);
        return new Loaded(solution, annotations, inputs.Count);
    }

    private static List<(string File, int Line)> Reported(AnalysisResult result) =>
        result.Findings.Where(f => f.RuleId == "csharp.sql-injection")
            .Select(f => (Path.GetFileName(f.Sink.SourceTree!.FilePath), f.Sink.GetLineSpan().StartLinePosition.Line + 1)).Distinct().ToList();

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Fixture_projects_compile_without_errors(string name)
    {
        var loaded = Load(name);
        Assert.True(loaded.Projects >= 2, name + " has fewer than two projects");
        var errors = loaded.Solution.Projects.SelectMany(p => p.Errors).ToList();
        Assert.True(errors.Count == 0, name + ": " + string.Join(Environment.NewLine, errors.Take(20)));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Every_ruleid_is_found_and_no_ok_is_reported(string name)
    {
        var loaded = Load(name);
        var result = new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(2), 4L << 30)).Analyze(loaded.Solution, CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.True(result.Stats.FailedMethods == 0, "failed bodies: " + string.Join("; ", result.Stats.FirstErrors));

        var reported = Reported(result).ToHashSet();
        var annotated = loaded.Annotations.Where(a => a.RuleId == "csharp.sql-injection").ToList();
        Assert.Contains(annotated, a => a.Kind == "ruleid");
        Assert.Contains(annotated, a => a.Kind == "ok");

        var missing = annotated.Where(a => a.Kind == "ruleid" && !reported.Contains((a.File, a.Line))).Select(a => a.File + ":" + a.Line).ToList();
        var unexpected = annotated.Where(a => a.Kind == "ok" && reported.Contains((a.File, a.Line))).Select(a => a.File + ":" + a.Line).ToList();
        var unannotated = reported.Where(f => !annotated.Any(a => a.File == f.File && a.Line == f.Line)).Select(f => f.File + ":" + f.Line).ToList();
        // A todoruleid line is a known limit (expectations.yml): it must stay missed; one that starts passing is promoted to ruleid.
        var todoFound = annotated.Where(a => a.Kind == "todoruleid" && reported.Contains((a.File, a.Line))).Select(a => a.File + ":" + a.Line).ToList();

        Assert.True(missing.Count == 0, name + " missing: " + string.Join(", ", missing));
        Assert.True(unexpected.Count == 0, name + " unexpected: " + string.Join(", ", unexpected));
        Assert.True(unannotated.Count == 0, name + " unannotated findings: " + string.Join(", ", unannotated));
        Assert.True(todoFound.Count == 0, name + " todoruleid lines now found (make them ruleid, drop the known limit): " + string.Join(", ", todoFound));
    }

    [Fact]
    public void A_ruleid_sits_across_a_project_boundary_in_every_fixture()
    {
        foreach (var name in Fixtures().Select(f => (string)f[0]))
        {
            var loaded = Load(name);
            var result = new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(2), 4L << 30)).Analyze(loaded.Solution, CancellationToken.None);
            // the request data enters in one project and the sink is in another
            var crossing = result.Findings.Any(f =>
            {
                var sinkProject = ProjectOf(loaded.Solution, f.Sink.SourceTree);
                return f.Path.Any(s => ProjectOf(loaded.Solution, s.Location.SourceTree) != sinkProject);
            });
            Assert.True(crossing, name + ": no finding whose path crosses a project boundary");
        }
    }

    private static string? ProjectOf(LoadedSolution solution, SyntaxTree? tree) =>
        solution.Projects.FirstOrDefault(p => tree != null && p.Compilation.ContainsSyntaxTree(tree))?.Input.AssemblyName;
}
