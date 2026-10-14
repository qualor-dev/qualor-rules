using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 13: Razor views analysed as their generated C#, reported at the .cshtml line. The razor-xss solution fixture holds
/// SDK 8.0.425's output (`#line (l,c)-(l,c) "file"` around the expression); SDK 10's generator puts `Write(` inside the
/// mapped span with a character offset (`#line (l,c)-(l,c) 6 "file"`). This view is written in that later shape (as
/// SDK 10.0.401 emits it for the fixture), with a code block and code outside any directive.
public sealed class RazorViewTests
{
    private const string View = "/src/App/obj/generated/Views_Profile_Show_cshtml.g.cs";
    private const string Cshtml = "/src/App/Views/Profile/Show.cshtml";

    private const string Code = """
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Mvc.Rendering;

        public class ProfileModel { public string Bio { get; set; } public string Name { get; set; } }

        public class ProfileController : Controller
        {
            public IActionResult Show([FromQuery] string q)
            {
                var model = new ProfileModel { Name = "Ada" };
                model.Bio = q;
                return View(model);
            }
        }

        internal sealed class Views_Profile_Show : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<ProfileModel>
        {
            public async override global::System.Threading.Tasks.Task ExecuteAsync()
            {
                WriteLiteral("<p>");
        #nullable restore
        #line (3,2)-(3,21) 6 "/src/App/Views/Profile/Show.cshtml"
        Write(Html.Raw(Model.Bio)

        #line default
        #line hidden
        #nullable disable
                );
        #nullable restore
        #line (5,3)-(5,26) "/src/App/Views/Profile/Show.cshtml"
        WriteLiteral(Model.Bio);

        #line default
        #line hidden
        #nullable disable
        #nullable restore
        #line (7,2)-(7,11) 6 "/src/App/Views/Profile/Show.cshtml"
        Write(Model.Bio

        #line default
        #line hidden
        #nullable disable
                );
        #nullable restore
        #line (9,2)-(9,22) 6 "/src/App/Views/Profile/Show.cshtml"
        Write(Html.Raw(Model.Name)

        #line default
        #line hidden
        #nullable disable
                );
                WriteLiteral(Model.Bio);
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<ProfileModel> Html { get; private set; } = default!;
        }
        """;

    private static AnalysisResult Analyze()
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new[]
        {
            CSharpSyntaxTree.ParseText(Code, parse, View),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "/src/App/obj/GlobalUsings.g.cs"),
        };
        var compilation = CSharpCompilation.Create("App", trees, FixtureReferences.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.Empty(errors);
        var input = new CompilationInput(
            "/src/App/App.csproj", "net10.0", "App", OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12, NullableContextOptions.Disable,
            Array.Empty<string>(), false, null, new[] { View }, Array.Empty<string>(), Array.Empty<string>(), "/inputs/App.txt");
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(new LoadedSolution(new[] { new ProjectCompilation(input, compilation, errors) }), CancellationToken.None);
        Assert.True(result.Stats.FailedMethods == 0, string.Join("; ", result.Stats.FirstErrors));
        return result;
    }

    [Fact]
    public void Raw_output_is_reported_at_the_cshtml_line_and_encoded_output_is_not()
    {
        var reported = Analyze().Findings.Where(f => f.RuleId == "csharp.xss")
            .Select(f => f.SinkSpan.Path + ":" + (f.SinkSpan.StartLinePosition.Line + 1)).OrderBy(x => x, StringComparer.Ordinal).ToList();

        // Html.Raw(Model.Bio) at 3, WriteLiteral(Model.Bio) in a code block at 5; Write(Model.Bio) at 7 (encoded) and
        // Html.Raw(Model.Name) at 9 (no request data) are quiet. The WriteLiteral after the last `#line hidden` has no
        // .cshtml line: it is reported in the generated file, at its own line (52).
        Assert.Equal(new[] { Cshtml + ":3", Cshtml + ":5", View + ":52" }, reported);
    }

    [Fact]
    public void Findings_and_path_steps_carry_the_mapped_path_and_the_generated_location_stays_available()
    {
        var finding = Analyze().Findings.Single(f => f.RuleId == "csharp.xss" && f.SinkSpan.StartLinePosition.Line + 1 == 3);

        Assert.True(finding.SinkSpan.HasMappedPath);
        Assert.Equal(Cshtml, finding.SinkSpan.Path);
        Assert.Equal(View, finding.Sink.SourceTree!.FilePath);
        Assert.Equal(View, finding.Sink.GetLineSpan().Path);
        Assert.Equal(Cshtml, finding.Path[^1].Span.Path);
        Assert.Equal(View, finding.Path[0].Span.Path);
    }
}
