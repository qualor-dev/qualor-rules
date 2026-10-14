using Microsoft.AspNetCore.Razor.Language;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;

namespace Qualor.Taint.Tests.Razor;

/// Task 30 review minors (M1–M6): which recorded views count as already compiled, what is reported for views outside the
/// project directory and for projects without MVC, the Razor language version per ASP.NET Core, and tag helper discovery
/// failures.
public sealed class RazorViewDetectionTests : TempDirs
{
    /// A project in `<root>/Web` with Views/Home/Index.cshtml, and Linked.cshtml and Other.cshtml in `<root>/shared` (outside
    /// the project directory, as a `<Content Include="..\shared\X.cshtml" Link="…">` item is). `generated` lists the views a
    /// build-generated tree maps `#line` directives to, without any Razor attribute.
    private (CompilationInput Input, string Root) Project(string assembly, IEnumerable<string> generated, bool mvc = true)
    {
        var root = TempDir();
        var web = Path.Combine(root, "Web");
        Directory.CreateDirectory(Path.Combine(web, "Views", "Home"));
        Directory.CreateDirectory(Path.Combine(root, "shared"));
        var index = Path.Combine(web, "Views", "Home", "Index.cshtml");
        var linked = Path.Combine(root, "shared", "Linked.cshtml");
        var other = Path.Combine(root, "shared", "Other.cshtml");
        foreach (var view in new[] { index, linked, other }) File.WriteAllText(view, "<p>@Html.Raw(\"x\")</p>\n");
        var views = new Dictionary<string, string> { ["Index"] = index, ["Linked"] = linked, ["Other"] = other };

        var sources = new List<string>();
        var usings = Path.Combine(root, "GlobalUsings.g.cs");
        File.WriteAllText(usings, FixtureRunner.ImplicitUsings);
        sources.Add(usings);
        var n = 0;
        foreach (var name in generated)
        {
            // What a build's generator writes for a view, reduced to the `#line` into it and no Razor attribute.
            var file = Path.Combine(web, "obj", $"View{n}.g.cs");
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, $$"""
                namespace Generated
                {
                    public class View{{n}} : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
                    {
                        public override async global::System.Threading.Tasks.Task ExecuteAsync()
                        {
                #line 1 "{{views[name]}}"
                            WriteLiteral("<p></p>");
                #line default
                            await global::System.Threading.Tasks.Task.CompletedTask;
                        }
                    }
                }
                """);
            sources.Add(file);
            n++;
        }
        var references = FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!)
            .Where(p => mvc || !Path.GetFileName(p).StartsWith("Microsoft.AspNetCore.Mvc", StringComparison.Ordinal)).ToList();
        var input = new CompilationInput(Path.Combine(web, "Web.csproj"), "net8.0", assembly, OutputKind.DynamicallyLinkedLibrary,
            LanguageVersion.CSharp12, NullableContextOptions.Disable, Array.Empty<string>(), false, null, sources, references,
            Array.Empty<string>(), Path.Combine(root, "in.txt"))
        {
            RazorViews = new[] { index, linked, other },
        };
        return (input, root);
    }

    private static ProjectCompilation Load(CompilationInput input) =>
        Assert.Single(SolutionLoader.Load(new[] { input }, CancellationToken.None).Projects);

    [Fact]
    public void A_view_a_generated_tree_maps_line_directives_to_is_not_compiled_again()
    {
        // M2: no Razor attribute names the view, only the `#line` path does.
        var project = Load(Project("Detect.Line", new[] { "Index" }).Input);
        Assert.DoesNotContain(project.EngineViews, v => v.EndsWith("Index.cshtml", StringComparison.Ordinal));
    }

    [Fact]
    public void A_view_outside_the_project_directory_counts_only_when_no_build_compiled_it()
    {
        // M1: Linked.cshtml (outside, compiled by the build) is no error; Other.cshtml (outside, not compiled) is.
        var project = Load(Project("Detect.Outside", new[] { "Index", "Linked" }).Input);
        Assert.Empty(project.EngineViews);
        var error = Assert.Single(project.EngineViewErrors);
        Assert.Contains("Other.cshtml", error, StringComparison.Ordinal);
        Assert.Contains("outside the project directory", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_project_without_MVC_reports_no_view()
    {
        // M3: a .cshtml of a project that references no MVC Razor views is no view: nothing compiled, nothing reported,
        // not even the files outside its directory.
        var project = Load(Project("Detect.NoMvc", Array.Empty<string>(), mvc: false).Input);
        Assert.Empty(project.EngineViews);
        Assert.Empty(project.EngineViewErrors);
    }

    [Fact]
    public void A_RazorPage_type_two_references_define_still_makes_a_view_project()
    {
        // M4: with a second reference defining Microsoft.AspNetCore.Mvc.Razor.RazorPage, GetTypeByMetadataName finds none;
        // the views are still compiled.
        var (input, root) = Project("Detect.Duplicate", Array.Empty<string>());
        var duplicate = Path.Combine(root, "Duplicate.dll");
        var emitted = CSharpCompilation.Create("Duplicate",
                new[] { CSharpSyntaxTree.ParseText("namespace Microsoft.AspNetCore.Mvc.Razor { public abstract class RazorPage { } }") },
                FixtureReferences.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
            .Emit(duplicate);
        Assert.True(emitted.Success);
        input = input with { RazorViews = new[] { input.RazorViews[0] }, References = input.References.Append(duplicate).ToList() };
        var project = Load(input);
        Assert.Single(project.EngineViews);
    }

    public static IEnumerable<object?[]> Versions() => new[]
    {
        new object?[] { null, "Latest" },
        new object?[] { "1.0.0.0", "1.1" },
        new object?[] { "1.1.2.0", "1.1" },
        new object?[] { "2.0.0.0", "2.0" },
        new object?[] { "2.1.0.0", "2.1" },
        new object?[] { "2.2.0.0", "2.1" },
        new object?[] { "3.1.0.0", "3.0" },
        new object?[] { "5.0.0.0", "5.0" },
        new object?[] { "6.0.0.0", "Latest" },
        new object?[] { "8.0.0.0", "Latest" },
    };

    [Theory]
    [MemberData(nameof(Versions))]
    public void The_Razor_language_version_follows_the_referenced_ASP_NET_Core(string? mvcRazor, string expected)
    {
        // M5: the version of Microsoft.AspNetCore.Mvc.Razor the project references.
        var version = RazorViews.LanguageVersionOf(mvcRazor == null ? null : Version.Parse(mvcRazor));
        Assert.Equal(expected == "Latest" ? RazorLanguageVersion.Latest : RazorLanguageVersion.Parse(expected), version);
    }

    [Fact]
    public void A_failed_tag_helper_discovery_is_reported_and_the_views_still_compile()
    {
        // M6: the views compile with tag helpers as markup; one line for the project says why.
        var (input, _) = Project("Detect.TagHelpers", Array.Empty<string>());
        input = input with { RazorViews = new[] { input.RazorViews[0] } };
        RazorViews.FailTagHelperDiscovery = c => c.AssemblyName == "Detect.TagHelpers";
        try
        {
            var project = Load(input);
            Assert.Single(project.EngineViews);
            var error = Assert.Single(project.EngineViewErrors);
            Assert.StartsWith(input.ProjectPath + ": tag helper discovery failed: ", error, StringComparison.Ordinal);
        }
        finally
        {
            RazorViews.FailTagHelperDiscovery = null;
        }
    }
}
