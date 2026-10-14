using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Cli.Output;
using Qualor.Taint.Tests.Fixtures;
using YamlDotNet.RepresentationModel;

namespace Qualor.Taint.Tests.Razor;

/// Task 30 (decision R-11): views no build compiled, compiled by the engine. The fixtures under
/// engine/dotnet/fixtures/views/&lt;name&gt; are written like the solution fixtures (`inputs.yml`, annotated sources), but
/// commit no generated view code: every `.cshtml` of a project is recorded as its `razor-view=`, as the hook does.
/// - runtime-compiled: an app whose views ASP.NET Core 2.x would compile at run time (an action's `View(model)`, a
///   layout and `_ViewStart`, an area with its own `_ViewImports`, a view that does not compile and one Razor cannot
///   parse);
/// - plugin: a plugin project whose views are Content the application compiles at run time, named by the path the
///   application copies them to (`~/Plugins/<name>/Views/…`), with `@inherits` a base page of another project.
public sealed class RuntimeViewTests : TempDirs
{
    private static string ViewsDir => Path.Combine(Repo.EngineDir, "fixtures", "views");

    private static readonly Lazy<ModelSet> Models = new(() => ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")));

    private sealed record Loaded(LoadedSolution Solution, IReadOnlyList<Annotation> Annotations, string Rule);

    /// The fixture's projects as compilation inputs; `views` false leaves the razor-view lines out (an older hook).
    private Loaded Load(string dir, bool views = true)
    {
        var yaml = new YamlStream();
        using (var reader = new StreamReader(Path.Combine(dir, "inputs.yml"))) yaml.Load(reader);
        var root = (YamlMappingNode)yaml.Documents[0].RootNode;
        var projects = (YamlSequenceNode)root.Children[new YamlScalarNode("projects")];
        var rule = ((YamlScalarNode)root.Children[new YamlScalarNode("rule")]).Value!;

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
            var cshtml = Directory.GetFiles(folder, "*.cshtml", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal).ToList();
            foreach (var file in sources.Concat(cshtml)) annotations.AddRange(Annotation.Parse(Path.GetFileName(file), File.ReadAllText(file)));
            sources.Add(usings);
            inputs.Add(new CompilationInput(
                Path.Combine(folder, project + ".csproj"), "net8.0", project, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Disable, Array.Empty<string>(), true, null, sources, references,
                refs.Select(x => Path.Combine(dir, x, x + ".csproj")).ToList(), Path.Combine(work, project + ".txt"))
            {
                RazorViews = views ? cshtml : Array.Empty<string>(),
            });
        }
        return new Loaded(SolutionLoader.Load(inputs, CancellationToken.None), annotations, rule);
    }

    private static AnalysisResult Analyze(Loaded loaded) =>
        new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(2), 4L << 30)).Analyze(loaded.Solution, CancellationToken.None);

    private static HashSet<(string File, int Line)> Reported(AnalysisResult result, string rule) =>
        result.Findings.Where(f => f.RuleId == rule)
            .Select(f => (Path.GetFileName(f.SinkSpan.Path), f.SinkSpan.StartLinePosition.Line + 1)).ToHashSet();

    /// Every ruleid of the fixture's files is reported at its .cshtml line, no ok line is.
    private static void AssertAnnotations(Loaded loaded, AnalysisResult result)
    {
        var reported = Reported(result, loaded.Rule);
        var annotated = loaded.Annotations.Where(a => a.RuleId == loaded.Rule).ToList();
        Assert.Contains(annotated, a => a.Kind == "ruleid");
        var missing = annotated.Where(a => a.Kind == "ruleid" && !reported.Contains((a.File, a.Line))).Select(a => a.File + ":" + a.Line).ToList();
        var unexpected = annotated.Where(a => a.Kind == "ok" && reported.Contains((a.File, a.Line))).Select(a => a.File + ":" + a.Line).ToList();
        Assert.True(missing.Count == 0, "missing: " + string.Join(", ", missing) + "; reported: " + string.Join(", ", reported));
        Assert.True(unexpected.Count == 0, "unexpected: " + string.Join(", ", unexpected));
    }

    private static string Rel(string dir, string path) => Path.GetRelativePath(dir, path).Replace('\\', '/');

    [Fact]
    public void Views_no_build_compiled_are_compiled_and_an_action_reaches_its_view()
    {
        var dir = Path.Combine(ViewsDir, "runtime-compiled");
        var loaded = Load(dir);
        var web = Assert.Single(loaded.Solution.Projects);
        // Every view but the imports files; _ViewStart and the layout are views of their own.
        Assert.Equal(
            new[] { "Web/Areas/Admin/Views/Notes/Edit.cshtml", "Web/Views/Home/Broken.cshtml", "Web/Views/Home/Show.cshtml",
                "Web/Views/Home/Unclosed.cshtml", "Web/Views/Shared/_Layout.cshtml", "Web/Views/_ViewStart.cshtml" },
            web.EngineViews.Select(v => Rel(dir, v)).OrderBy(v => v, StringComparer.Ordinal));
        Assert.Empty(web.Errors);   // the views' errors are theirs, not the build's

        var result = Analyze(loaded);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.Equal(0, result.Stats.FailedMethods);
        AssertAnnotations(loaded, result);
        // `@Html.Raw(Model.Bio)` reached from Show(q) through View(model), reported at the .cshtml with the action's path.
        var show = result.Findings.Single(f => Path.GetFileName(f.SinkSpan.Path) == "Show.cshtml");
        Assert.True(show.SinkSpan.HasMappedPath);
        Assert.Equal(Path.Combine(dir, "Web", "Views", "Home", "Show.cshtml"), show.SinkSpan.Path.Replace('/', Path.DirectorySeparatorChar));
        Assert.EndsWith("HomeController.cs", show.Path[0].Span.Path, StringComparison.Ordinal);
        Assert.Equal(6, result.Stats.CompiledByEngineViews);
        Assert.Equal(0, result.Stats.UncompiledViews);
    }

    [Fact]
    public void Without_the_recorded_views_nothing_is_compiled_and_nothing_found()
    {
        var loaded = Load(Path.Combine(ViewsDir, "runtime-compiled"), views: false);
        Assert.Empty(Assert.Single(loaded.Solution.Projects).EngineViews);
        var result = Analyze(loaded);
        Assert.Empty(Reported(result, loaded.Rule));
        Assert.Equal(0, result.Stats.CompiledByEngineViews);
    }

    [Fact]
    public void A_plugin_view_named_by_its_runtime_path_is_compiled_and_reached()
    {
        var dir = Path.Combine(ViewsDir, "plugin");
        var loaded = Load(dir);
        var plugin = loaded.Solution.Projects.Single(p => p.Input.AssemblyName == "Plugin");
        Assert.Equal(new[] { "Plugin/Views/Configure.cshtml" }, plugin.EngineViews.Select(v => Rel(dir, v)));
        Assert.Empty(loaded.Solution.Projects.Single(p => p.Input.AssemblyName == "Framework").EngineViews);

        var result = Analyze(loaded);
        Assert.True(result.Complete, result.IncompleteReason);
        AssertAnnotations(loaded, result);
        var finding = result.Findings.Single(f => f.RuleId == "csharp.xss");
        Assert.EndsWith("DemoPaymentController.cs", finding.Path[0].Span.Path, StringComparison.Ordinal);
        Assert.Equal(0, result.Stats.UncompiledViews);   // the `~/Plugins/Payments.Demo/Views/Configure.cshtml` name resolves
        Assert.Equal(1, result.Stats.ViewEdges);
    }

    [Fact]
    public void ViewImports_usings_and_inherits_are_honoured()
    {
        // The model types' namespaces are imported only by the _ViewImports.cshtml files (the area's own one for its
        // view), the plugin's views inherit the framework's base page: the views compile without an error.
        var runtime = Load(Path.Combine(ViewsDir, "runtime-compiled"));
        var errors = Assert.Single(runtime.Solution.Projects).EngineViewErrors;
        Assert.DoesNotContain(errors, e => e.Contains("Show.cshtml", StringComparison.Ordinal) || e.Contains("Edit.cshtml", StringComparison.Ordinal)
            || e.Contains("_Layout.cshtml", StringComparison.Ordinal) || e.Contains("_ViewStart.cshtml", StringComparison.Ordinal));

        var plugin = Load(Path.Combine(ViewsDir, "plugin"));
        var project = plugin.Solution.Projects.Single(p => p.Input.AssemblyName == "Plugin");
        Assert.Empty(project.EngineViewErrors);
        var view = project.Compilation.SyntaxTrees.Single(t => t.FilePath.EndsWith("Configure.cshtml.g.cs", StringComparison.Ordinal));
        var model = project.Compilation.GetSemanticModel(view);
        var type = view.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.ClassDeclarationSyntax>()
            .Select(c => model.GetDeclaredSymbol(c)!).Single(t => t.BaseType?.Name == "ShopRazorPage");
        Assert.Equal("Shop.Plugin.Payments.Demo.Models.ConfigureModel", type.BaseType!.TypeArguments[0].ToDisplayString());
        // The tag helpers of `@addTagHelper` are in the generated code (`asp-for`: InputTagHelper).
        Assert.Contains("InputTagHelper", view.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_view_that_fails_to_compile_is_counted_and_the_run_goes_on()
    {
        var loaded = Load(Path.Combine(ViewsDir, "runtime-compiled"));
        var web = Assert.Single(loaded.Solution.Projects);
        Assert.Equal(2, web.EngineViewErrors.Count);
        Assert.Contains(web.EngineViewErrors, e => e.Contains("Broken.cshtml", StringComparison.Ordinal) && e.Contains("CS1061", StringComparison.Ordinal));
        Assert.Contains(web.EngineViewErrors, e => e.Contains("Unclosed.cshtml", StringComparison.Ordinal));

        var result = Analyze(loaded);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.Equal(2, result.Stats.EngineViewErrors);
        Assert.Contains(Reported(result, loaded.Rule), f => f.File == "Show.cshtml");

        // The SARIF carries both counts.
        using var stream = new MemoryStream();
        SarifWriter.Write(stream, Models.Value, result, "t", null, Array.Empty<string>());
        using var doc = JsonDocument.Parse(stream.ToArray());
        var stats = doc.RootElement.GetProperty("runs")[0].GetProperty("properties").GetProperty("analysisStats");
        Assert.Equal(6, stats.GetProperty("compiledByEngineViews").GetInt32());
        Assert.Equal(2, stats.GetProperty("engineViewErrors").GetInt32());
    }

    [Fact]
    public void Views_the_build_compiled_are_not_compiled_again()
    {
        // razor-xss commits the source generator's code for its views, with `#line` paths of the machine that generated
        // it: the RazorCompiledItem identifiers still tell the views apart.
        var dir = Path.Combine(Repo.EngineDir, "fixtures", "solutions", "razor-xss");
        var with = Load(dir);
        Assert.All(with.Solution.Projects, p => Assert.Empty(p.EngineViews));
        Assert.All(with.Solution.Projects, p => Assert.Empty(p.EngineViewErrors));
        var without = Load(dir, views: false);
        Assert.Equal(Reported(Analyze(without), "csharp.xss"), Reported(Analyze(with), "csharp.xss"));
    }
}
