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
            new[] { "Web/Areas/Admin/Views/Notes/Edit.cshtml", "Web/Views/Home/Broken.cshtml", "Web/Views/Home/Search.cshtml",
                "Web/Views/Home/Show.cshtml", "Web/Views/Home/Unclosed.cshtml", "Web/Views/Shared/_Layout.cshtml", "Web/Views/_ViewStart.cshtml" },
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
        Assert.Equal(7, result.Stats.CompiledByEngineViews);
        Assert.Equal(0, result.Stats.UncompiledViews);
    }

    [Fact]
    public void A_ViewData_entry_the_action_writes_reaches_an_engine_compiled_view()
    {
        // Review I1(a): Search(term) writes ViewData["term"] and renders a view no build compiled; the entry's raw output
        // there is found (Task 22's keyed request stores through Task 30's compiled view), its encoded output stays quiet.
        // Without the recorded views nothing is found (below).
        var loaded = Load(Path.Combine(ViewsDir, "runtime-compiled"));
        var result = Analyze(loaded);
        Assert.True(result.Complete, result.IncompleteReason);
        var reported = Reported(result, "csharp.xss");
        var annotated = loaded.Annotations.Where(a => a.File == "Search.cshtml" && a.RuleId == "csharp.xss").ToList();
        Assert.Contains(annotated, a => a.Kind == "ruleid");
        Assert.Contains(annotated, a => a.Kind == "ok");
        foreach (var a in annotated) Assert.Equal(a.Kind == "ruleid", reported.Contains((a.File, a.Line)));
        var finding = result.Findings.Single(f => Path.GetFileName(f.SinkSpan.Path) == "Search.cshtml");
        Assert.EndsWith("HomeController.cs", finding.Path[0].Span.Path, StringComparison.Ordinal);
        Assert.Contains(finding.Path, s => s.Message.Contains("ViewData", StringComparison.Ordinal));
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
        Assert.Equal(7, stats.GetProperty("compiledByEngineViews").GetInt32());
        Assert.Equal(2, stats.GetProperty("engineViewErrors").GetInt32());
    }

    [Fact]
    public void Against_references_without_Razor_Hosting_the_attributes_they_lack_are_left_out()
    {
        // ASP.NET Core 2.0 has no Microsoft.AspNetCore.Razor.Hosting (RazorCompiledItem and the like came with 2.1): the
        // view's code leaves those attributes out instead of failing on them; the action still reaches the view, known by
        // its `#line` file.
        var dir = TempDir();
        Directory.CreateDirectory(Path.Combine(dir, "Views", "Home"));
        File.WriteAllText(Path.Combine(dir, "HomeController.cs"), """
            using Microsoft.AspNetCore.Mvc;
            namespace Old.Web;
            public class HomeController : Controller
            {
                public IActionResult Index(string q) => View(new Box { Text = q });
            }
            public class Box { public string Text { get; set; } }
            """);
        File.WriteAllText(Path.Combine(dir, "Views", "_ViewImports.cshtml"), "@using Old.Web\n");
        File.WriteAllText(Path.Combine(dir, "Views", "Home", "Index.cshtml"), "@model Box\n<p>@Html.Raw(Model.Text)</p>\n");
        var usings = Path.Combine(dir, "GlobalUsings.g.cs");
        File.WriteAllText(usings, FixtureRunner.ImplicitUsings);
        var references = FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!)
            .Where(p => Path.GetFileName(p) != "Microsoft.AspNetCore.Razor.Runtime.dll").ToList();
        var input = new CompilationInput(Path.Combine(dir, "Old.Web.csproj"), "net8.0", "Old.Web", OutputKind.DynamicallyLinkedLibrary,
            LanguageVersion.CSharp12, NullableContextOptions.Disable, Array.Empty<string>(), false, null,
            new[] { Path.Combine(dir, "HomeController.cs"), usings }, references, Array.Empty<string>(), Path.Combine(dir, "in.txt"))
        {
            RazorViews = new[] { Path.Combine(dir, "Views", "_ViewImports.cshtml"), Path.Combine(dir, "Views", "Home", "Index.cshtml") },
        };
        var solution = SolutionLoader.Load(new[] { input }, CancellationToken.None);
        var project = Assert.Single(solution.Projects);
        Assert.Single(project.EngineViews);
        Assert.True(project.EngineViewErrors.Count == 0, string.Join("; ", project.EngineViewErrors));
        Assert.DoesNotContain("Razor.Hosting", project.Compilation.SyntaxTrees.Single(t => t.FilePath.EndsWith(".cshtml.g.cs", StringComparison.Ordinal)).ToString(), StringComparison.Ordinal);
        var result = new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(2), 4L << 30)).Analyze(solution, CancellationToken.None);
        Assert.Contains(("Index.cshtml", 2), Reported(result, "csharp.xss"));
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
