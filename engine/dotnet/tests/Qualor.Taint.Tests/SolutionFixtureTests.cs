using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using YamlDotNet.RepresentationModel;

namespace Qualor.Taint.Tests;

/// The engine's own multi-project fixtures (engine/dotnet/fixtures/solutions/&lt;name&gt;): small ASP.NET Core
/// solutions written from learn.microsoft.com patterns. `inputs.yml` names the projects, their source folders and project
/// references, and `rule:` the rule the fixture is about (default csharp.sql-injection); the test turns it into
/// CompilationInputs (no MSBuild), loads them with SolutionLoader, runs the TaintEngine and compares its findings of that
/// rule with the `// ruleid:` / `// ok:` / `// todoruleid:` annotations of every file. A project's sources are its folder's
/// `*.cs` files, so a Razor fixture commits the views' generated C# (`*_cshtml.g.cs`, with `#line` directives into the
/// `.cshtml` files next to it, annotated with Razor comments); findings are compared at their mapped location (`#line`).
public sealed class SolutionFixtureTests : TempDirs
{
    private static string SolutionsDir => Path.Combine(Repo.EngineDir, "fixtures", "solutions");

    private static readonly Lazy<ModelSet> Models = new(() => ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")));

    public static IEnumerable<object[]> Fixtures() =>
        Directory.GetDirectories(SolutionsDir).OrderBy(d => d, StringComparer.Ordinal).Select(d => new object[] { Path.GetFileName(d) });

    [Fact]
    public void There_are_fourteen_solution_fixtures() => Assert.Equal(14, Fixtures().Count());

    private sealed record Loaded(LoadedSolution Solution, IReadOnlyList<Annotation> Annotations, int Projects, string Rule);

    private Loaded Load(string name)
    {
        var dir = Path.Combine(SolutionsDir, name);
        var yaml = new YamlStream();
        using (var reader = new StreamReader(Path.Combine(dir, "inputs.yml"))) yaml.Load(reader);
        var root = (YamlMappingNode)yaml.Documents[0].RootNode;
        var projects = (YamlSequenceNode)root.Children[new YamlScalarNode("projects")];
        var rule = root.Children.TryGetValue(new YamlScalarNode("rule"), out var ruleNode) ? ((YamlScalarNode)ruleNode).Value! : "csharp.sql-injection";

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
            var views = Directory.GetFiles(folder, "*.cshtml", SearchOption.AllDirectories);
            foreach (var file in sources.Concat(views)) annotations.AddRange(Annotation.Parse(Path.GetFileName(file), File.ReadAllText(file)));
            sources.Add(usings);
            inputs.Add(new CompilationInput(
                Path.Combine(dir, project + ".csproj"), "net8.0", project, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Disable, Array.Empty<string>(), true, null, sources, references,
                refs.Select(x => Path.Combine(dir, x + ".csproj")).ToList(), Path.Combine(work, project + ".txt")));
        }
        var solution = SolutionLoader.Load(inputs, CancellationToken.None);
        return new Loaded(solution, annotations, inputs.Count, rule);
    }

    /// The findings of the rule at their mapped locations (a view's `.cshtml` line, through `#line`), by file name.
    private static List<(string File, int Line)> Reported(AnalysisResult result, string rule) =>
        result.Findings.Where(f => f.RuleId == rule)
            .Select(f => (Path.GetFileName(f.SinkSpan.Path), f.SinkSpan.StartLinePosition.Line + 1)).Distinct().ToList();

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

        var reported = Reported(result, loaded.Rule).ToHashSet();
        var annotated = loaded.Annotations.Where(a => a.RuleId == loaded.Rule).ToList();
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

    /// Task 13: the Razor source generator's C# for a view carries `#line` directives into the .cshtml; a sink in a view
    /// (`@Html.Raw(Model.Bio)`) is reported at the .cshtml file and line, as the generator wrote the path, never at the
    /// generated file. `@Model.Bio` (Write, HTML-encoded) is not a sink.
    [Fact]
    public void A_Razor_view_sink_is_reported_at_its_cshtml_line()
    {
        var loaded = Load("razor-xss");
        var result = new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(2), 4L << 30)).Analyze(loaded.Solution, CancellationToken.None);
        var views = result.Findings.Where(f => f.RuleId == "csharp.xss" && f.Sink.SourceTree!.FilePath.EndsWith("_cshtml.g.cs", StringComparison.Ordinal)).ToList();

        Assert.Equal(
            new[] { "/src/razor-xss/Web/Pages/Comment.cshtml:5", "/src/razor-xss/Web/Views/Profile/Show.cshtml:8", "/src/razor-xss/Web/Views/Profile/Show.cshtml:23" },
            views.OrderBy(f => f.SinkSpan.Path, StringComparer.Ordinal).ThenBy(f => f.SinkSpan.StartLinePosition.Line)
                .Select(f => f.SinkSpan.Path + ":" + (f.SinkSpan.StartLinePosition.Line + 1)));
        Assert.All(views, f => Assert.True(f.SinkSpan.HasMappedPath));
        // The request data enters in the controller (Show's q) or at the page's bound property read in the view.
        var bio = views.Single(f => f.SinkSpan.StartLinePosition.Line + 1 == 8);
        Assert.EndsWith("ProfileController.cs", bio.Path[0].Span.Path, StringComparison.Ordinal);
        Assert.EndsWith("Show.cshtml", bio.Path[^1].Span.Path, StringComparison.Ordinal);
    }

    private static string? ProjectOf(LoadedSolution solution, SyntaxTree? tree) =>
        solution.Projects.FirstOrDefault(p => tree != null && p.Compilation.ContainsSyntaxTree(tree))?.Input.AssemblyName;
}
