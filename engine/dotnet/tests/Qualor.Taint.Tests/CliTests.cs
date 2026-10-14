using System.Text;
using System.Text.Json;
using Basic.Reference.Assemblies;
using Microsoft.CodeAnalysis;
using Qualor.Taint.Tests.Fixtures;

namespace Qualor.Taint.Tests;

public sealed class CliTests : TempDirs
{
    [Fact]
    public void Rebuild_writes_one_entry_per_project_with_its_first_errors()
    {
        var dir = TempDir();
        var refs = Path.Combine(dir, "refs");
        Directory.CreateDirectory(refs);
        var corlib = Net80.ReferenceInfos.All.Single(r => r.FileName == "System.Runtime.dll");
        File.WriteAllBytes(Path.Combine(refs, corlib.FileName), corlib.ImageBytes);
        var source = Path.Combine(dir, "Ünï cödé.cs");
        File.WriteAllText(source, "class C { Missing m; }", new UTF8Encoding(false));
        var inputs = Path.Combine(dir, "compilations");
        Directory.CreateDirectory(inputs);
        File.WriteAllText(Path.Combine(inputs, "x.txt"), string.Join("\n", "qualor-compilation=1",
            "project=" + Path.Combine(dir, "X.csproj"), "tfm=net8.0", "assembly=X", "output-kind=Library",
            "source=" + source, "reference=" + Path.Combine(refs, corlib.FileName)) + "\n", new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(inputs, "broken.txt"), "project=y.csproj\n");
        var json = Path.Combine(dir, "out dir", "rebuild.json");

        var code = Qualor.Taint.Cli.Program.Run(new[] { "rebuild", "--inputs", inputs, "--json", json }, TextWriter.Null);

        Assert.Equal(0, code);
        using var doc = JsonDocument.Parse(File.ReadAllText(json, Encoding.UTF8));
        var project = Assert.Single(doc.RootElement.GetProperty("projects").EnumerateArray());
        Assert.Equal(Path.Combine(dir, "X.csproj"), project.GetProperty("project").GetString());
        Assert.Equal("net8.0", project.GetProperty("tfm").GetString());
        Assert.Equal(1, project.GetProperty("sources").GetInt32());
        Assert.Equal(1, project.GetProperty("errors").GetInt32());
        var first = Assert.Single(project.GetProperty("firstErrors").EnumerateArray()).GetString()!;
        Assert.StartsWith("CS0246 ", first);
        Assert.Contains("Ünï cödé.cs", first);
        Assert.Contains("broken.txt", Assert.Single(doc.RootElement.GetProperty("inputErrors").EnumerateArray()).GetString());
    }

    [Fact]
    public void Rebuild_reports_the_project_references_served_by_their_recorded_assembly()   // ruling R-E6
    {
        var dir = TempDir();
        var corlib = Net80.ReferenceInfos.All.Single(r => r.FileName == "System.Runtime.dll");
        var corlibPath = Path.Combine(dir, corlib.FileName);
        File.WriteAllBytes(corlibPath, corlib.ImageBytes);
        var libDll = Path.Combine(dir, "Lib Ü.dll");
        File.WriteAllBytes(libDll, corlib.ImageBytes);   // any readable assembly serves as the fallback
        var source = Path.Combine(dir, "A.cs");
        File.WriteAllText(source, "class A { }", new UTF8Encoding(false));
        var inputs = Path.Combine(dir, "compilations");
        Directory.CreateDirectory(inputs);
        File.WriteAllText(Path.Combine(inputs, "a.txt"), string.Join("\n", "qualor-compilation=1",
            "project=" + Path.Combine(dir, "A.csproj"), "tfm=net8.0", "assembly=A", "source=" + source, "reference=" + corlibPath,
            "project-reference=" + Path.Combine(dir, "Lib", "Lib.vbproj"), "project-reference-assembly=" + libDll) + "\n", new UTF8Encoding(false));
        var json = Path.Combine(dir, "rebuild.json");

        Assert.Equal(0, Qualor.Taint.Cli.Program.Run(new[] { "rebuild", "--inputs", inputs, "--json", json }, TextWriter.Null));

        using var doc = JsonDocument.Parse(File.ReadAllText(json, Encoding.UTF8));
        var project = Assert.Single(doc.RootElement.GetProperty("projects").EnumerateArray());
        Assert.Equal(1, project.GetProperty("fallbacks").GetInt32());
        Assert.Equal(libDll, Assert.Single(project.GetProperty("fallbackAssemblies").EnumerateArray()).GetString());
    }

    [Theory]
    [InlineData()]
    [InlineData("rebuild")]
    [InlineData("rebuild", "--inputs", "x")]
    [InlineData("rebuild", "--json", "x")]
    [InlineData("analyze", "--inputs", "x", "--json", "y")]
    [InlineData("analyze", "--inputs", "x", "--models", "y")]
    [InlineData("rebuild", "--inputs", "x", "--json", "y", "--extra")]
    public void Invalid_arguments_exit_2(params string[] args)
    {
        Assert.Equal(2, Qualor.Taint.Cli.Program.Run(args, TextWriter.Null));
    }

    [Fact]
    public void A_missing_inputs_directory_exits_2()
    {
        var dir = TempDir();
        Assert.Equal(2, Qualor.Taint.Cli.Program.Run(
            new[] { "rebuild", "--inputs", Path.Combine(dir, "absent"), "--json", Path.Combine(dir, "o.json") }, TextWriter.Null));
    }

    // ---- analyze (Task 14) ----

    private const string AppCode = """
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Mvc.Rendering;

        public class ProfileModel { public string Bio { get; set; } }

        public class ProfileController : Controller
        {
            public IActionResult Show([FromQuery] string q)
            {
                var model = new ProfileModel();
                model.Bio = q;
                return View(model);
            }
        }

        internal sealed class Views_Profile_Show : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<ProfileModel>
        {
            public async override global::System.Threading.Tasks.Task ExecuteAsync()
            {
        #nullable restore
        #line (3,2)-(3,21) 6 "@CSHTML@"
        Write(Html.Raw(Model.Bio)

        #line default
        #line hidden
        #nullable disable
                );
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<ProfileModel> Html { get; private set; } = default!;
        }
        """;

    /// A one-project inputs directory whose view sits at `<root>\Views\Profile\Show.cshtml` (the path form the build
    /// recorded, with this OS's separators), the Razor view written as its generated C#.
    private (string Inputs, string Root) AppInputs(string? extra = null)
    {
        var root = TempDir();
        var cshtml = Path.Combine(root, "Views", "Profile", "Show.cshtml");
        var src = Path.Combine(root, "obj", "Views_Profile_Show_cshtml.g.cs");
        Directory.CreateDirectory(Path.GetDirectoryName(src)!);
        File.WriteAllText(src, AppCode.Replace("@CSHTML@", cshtml), new UTF8Encoding(false));
        var extraPath = Path.Combine(root, "Tls.cs");
        if (extra != null) File.WriteAllText(extraPath, extra, new UTF8Encoding(false));
        var usings = Path.Combine(root, "obj", "GlobalUsings.g.cs");
        File.WriteAllText(usings, FixtureRunner.ImplicitUsings, new UTF8Encoding(false));
        var inputs = Path.Combine(root, "compilations");
        Directory.CreateDirectory(inputs);
        var lines = new List<string> { "qualor-compilation=1", "project=" + Path.Combine(root, "App.csproj"), "tfm=net8.0", "assembly=App",
            "output-kind=Library", "source=" + src, "source=" + usings };
        if (extra != null) lines.Add("source=" + extraPath);
        lines.AddRange(FixtureReferences.All.Select(r => "reference=" + ((PortableExecutableReference)r).FilePath));
        File.WriteAllText(Path.Combine(inputs, "app.txt"), string.Join("\n", lines) + "\n", new UTF8Encoding(false));
        return (inputs, root);
    }

    private static string Models => Path.Combine(Repo.Root, "models", "csharp");

    private static JsonDocument ReadSarif(string path) => JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));

    [Fact]
    public void Analyze_writes_sarif_with_codeflows_and_the_mapped_cshtml_location()
    {
        var (inputs, root) = AppInputs();
        var sarif = Path.Combine(root, "out dir", "r.sarif");

        var code = Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", sarif, "--root", root, "--version", "2026.10.9" }, TextWriter.Null);

        Assert.Equal(0, code);
        using var doc = ReadSarif(sarif);
        Assert.Equal("2.1.0", doc.RootElement.GetProperty("version").GetString());
        var run = Assert.Single(doc.RootElement.GetProperty("runs").EnumerateArray());
        var driver = run.GetProperty("tool").GetProperty("driver");
        Assert.Equal("qualor-taint", driver.GetProperty("name").GetString());
        Assert.Equal("2026.10.9", driver.GetProperty("semanticVersion").GetString());
        var ruleIds = driver.GetProperty("rules").EnumerateArray().Select(r => r.GetProperty("id").GetString()).ToList();
        Assert.Contains("csharp.xss", ruleIds);
        Assert.Equal(ruleIds.Count, ruleIds.Distinct().Count());
        Assert.All(ruleIds, id => Assert.StartsWith("csharp.", id));

        var result = run.GetProperty("results").EnumerateArray().First(r => r.GetProperty("ruleId").GetString() == "csharp.xss");
        Assert.False(result.TryGetProperty("partialFingerprints", out _));
        Assert.Contains("csharp.xss", result.GetProperty("message").GetProperty("text").GetString());
        var location = result.GetProperty("locations")[0].GetProperty("physicalLocation");
        Assert.Equal("Views/Profile/Show.cshtml", location.GetProperty("artifactLocation").GetProperty("uri").GetString());
        Assert.Equal("%SRCROOT%", location.GetProperty("artifactLocation").GetProperty("uriBaseId").GetString());
        Assert.Equal(3, location.GetProperty("region").GetProperty("startLine").GetInt32());
        var flow = result.GetProperty("codeFlows")[0].GetProperty("threadFlows")[0].GetProperty("locations").EnumerateArray().ToList();
        Assert.True(flow.Count >= 2);
        // SARIF 2.1.0: a threadFlowLocation holds its location (physicalLocation, message) under "location".
        Assert.All(flow, l =>
        {
            Assert.Equal(new[] { "location" }, l.EnumerateObject().Select(p => p.Name).ToArray());
            Assert.Equal(new[] { "message", "physicalLocation" }, l.GetProperty("location").EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray());
            Assert.False(string.IsNullOrEmpty(l.GetProperty("location").GetProperty("message").GetProperty("text").GetString()));
        });
        Assert.Equal("obj/Views_Profile_Show_cshtml.g.cs", flow[0].GetProperty("location").GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
        Assert.Equal("Views/Profile/Show.cshtml", flow[^1].GetProperty("location").GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());

        var invocation = run.GetProperty("invocations")[0];
        Assert.True(invocation.GetProperty("executionSuccessful").GetBoolean());
        var stats = run.GetProperty("properties").GetProperty("analysisStats");
        Assert.Equal(1, stats.GetProperty("projects").GetInt32());
        Assert.True(stats.GetProperty("methods").GetInt32() > 0);
        Assert.Equal(0, stats.GetProperty("failedMethods").GetInt32());
        foreach (var name in new[] { "firstErrors", "sccs", "unmodelledExternalCalls", "elapsedSeconds", "peakMemoryBytes" })
            Assert.True(stats.TryGetProperty(name, out _), name);
    }

    [Fact]
    public void A_path_outside_the_root_is_written_absolute_with_a_note()
    {
        var (inputs, _) = AppInputs();
        var elsewhere = TempDir();
        var sarif = Path.Combine(elsewhere, "r.sarif");

        Assert.Equal(0, Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", sarif, "--root", elsewhere }, TextWriter.Null));

        using var doc = ReadSarif(sarif);
        var run = doc.RootElement.GetProperty("runs")[0];
        var result = run.GetProperty("results").EnumerateArray().First(r => r.GetProperty("ruleId").GetString() == "csharp.xss");
        var artifact = result.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation");
        Assert.StartsWith("file:///", artifact.GetProperty("uri").GetString());
        Assert.EndsWith("/Views/Profile/Show.cshtml", Uri.UnescapeDataString(artifact.GetProperty("uri").GetString()!));
        Assert.False(artifact.TryGetProperty("uriBaseId", out _));
        var notes = run.GetProperty("invocations")[0].GetProperty("toolExecutionNotifications").EnumerateArray().Select(n => n.GetProperty("message").GetProperty("text").GetString());
        Assert.Contains(notes, n => n!.Contains("outside --root"));
    }

    [Fact]
    public void A_misuse_finding_says_insecure_configuration_not_request_data()
    {
        var (inputs, root) = AppInputs("""
            public class Tls
            {
                public void M()
                {
                    var h = new System.Net.Http.HttpClientHandler();
                    h.ServerCertificateCustomValidationCallback = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }
            }
            """);
        var sarif = Path.Combine(root, "r.sarif");

        Assert.Equal(0, Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", sarif, "--root", root }, TextWriter.Null));

        using var doc = ReadSarif(sarif);
        var result = doc.RootElement.GetProperty("runs")[0].GetProperty("results").EnumerateArray()
            .Single(r => r.GetProperty("ruleId").GetString() == "csharp.tls-verification-disabled");
        var text = result.GetProperty("message").GetProperty("text").GetString()!;
        Assert.Equal("csharp.tls-verification-disabled: insecure configuration (tls-verification-disabled)", text);
        Assert.DoesNotContain("request data", text);
        Assert.Equal("Tls.cs", result.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
    }

    [Fact]
    public void A_crash_exits_1_with_the_exception_on_stderr()
    {
        var (inputs, root) = AppInputs();
        var log = new StringWriter();
        Qualor.Taint.Cli.Program.BeforeCommand = () => throw new InvalidOperationException("boom from the hook");
        try
        {
            Assert.Equal(1, Qualor.Taint.Cli.Program.Run(
                new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", Path.Combine(root, "r.sarif") }, log));
        }
        finally { Qualor.Taint.Cli.Program.BeforeCommand = null; }
        Assert.Contains("crash:", log.ToString());
        Assert.Contains("boom from the hook", log.ToString());
    }

    [Theory]
    [InlineData("/work/repo", @"C:\repo\x.cs", "file:///C:/repo/x.cs", false)]               // Windows-recorded path, posix root
    [InlineData(@"C:\repo", "/work/repo/a.cs", "file:///work/repo/a.cs", false)]              // posix-recorded path, Windows root
    [InlineData(@"C:\repo", @"c:\REPO\Views\a b.cshtml", "Views/a%20b.cshtml", true)]       // drive root: case-insensitive
    [InlineData("/work/repo", "/work/repo/Views/a.cshtml", "Views/a.cshtml", true)]
    [InlineData("/work/repo", "/work/Repo/a.cs", "file:///work/Repo/a.cs", false)]             // posix root: case-sensitive
    [InlineData("/work/repo", "/work/repository/a.cs", "file:///work/repository/a.cs", false)] // a sibling with the root as prefix
    public void Paths_are_relative_under_the_root_and_absolute_file_uris_with_a_note_otherwise(string root, string path, string uri, bool relative)
    {
        var mapper = new Qualor.Taint.Cli.Output.SarifWriter.PathMapper(root);

        var (actual, isRelative) = mapper.Map(path);

        Assert.Equal(uri, actual);
        Assert.Equal(relative, isRelative);
        Assert.Equal(relative ? 0 : 1, mapper.Outside.Count);
    }

    [Fact]
    public void A_time_limit_of_zero_exits_3_with_the_sarif_marked_unsuccessful()
    {
        var (inputs, root) = AppInputs();
        var sarif = Path.Combine(root, "r.sarif");

        var code = Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", sarif, "--root", root, "--time-limit", "0" }, TextWriter.Null);

        Assert.Equal(3, code);
        using var doc = ReadSarif(sarif);
        var invocation = doc.RootElement.GetProperty("runs")[0].GetProperty("invocations")[0];
        Assert.False(invocation.GetProperty("executionSuccessful").GetBoolean());
        var note = Assert.Single(invocation.GetProperty("toolExecutionNotifications").EnumerateArray(), n => n.GetProperty("level").GetString() == "error");
        Assert.Contains("time limit", note.GetProperty("message").GetProperty("text").GetString());
    }

    [Fact]
    public void A_memory_limit_below_the_working_set_exits_3_naming_the_memory_limit()
    {
        var (inputs, root) = AppInputs();
        var sarif = Path.Combine(root, "r.sarif");

        var code = Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", sarif, "--memory-limit", "1" }, TextWriter.Null);

        Assert.Equal(3, code);
        using var doc = ReadSarif(sarif);
        var invocation = doc.RootElement.GetProperty("runs")[0].GetProperty("invocations")[0];
        Assert.False(invocation.GetProperty("executionSuccessful").GetBoolean());
        Assert.Contains("memory limit", invocation.GetProperty("toolExecutionNotifications")[0].GetProperty("message").GetProperty("text").GetString());
    }

    [Fact]
    public void A_broken_model_directory_exits_2_with_the_model_error_on_stderr()
    {
        var (inputs, root) = AppInputs();
        var models = Path.Combine(root, "models");
        Directory.CreateDirectory(models);
        foreach (var file in Directory.GetFiles(Models)) File.Copy(file, Path.Combine(models, Path.GetFileName(file)));
        File.WriteAllText(Path.Combine(models, "sources.yml"), "format: [oops\n");
        var log = new StringWriter();
        var sarif = Path.Combine(root, "r.sarif");

        Assert.Equal(2, Qualor.Taint.Cli.Program.Run(new[] { "analyze", "--inputs", inputs, "--models", models, "--sarif", sarif }, log));

        Assert.Contains("sources.yml", log.ToString());
        Assert.False(File.Exists(sarif));
    }

    [Fact]
    public void An_unwritable_sarif_path_exits_2_with_a_message()
    {
        var (inputs, root) = AppInputs();
        var blocker = Path.Combine(root, "blocker");
        File.WriteAllText(blocker, "a file where the output directory should be");
        var log = new StringWriter();

        var code = Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", Path.Combine(blocker, "r.sarif") }, log);

        Assert.Equal(2, code);
        Assert.Contains("cannot write the SARIF file", log.ToString());
    }

    [Theory]
    [InlineData("--time-limit", "soon")]
    [InlineData("--time-limit", "-1")]
    [InlineData("--memory-limit", "lots")]
    [InlineData("--root", "does-not-exist")]
    public void Invalid_analyze_values_exit_2(string option, string value)
    {
        var (inputs, root) = AppInputs();
        Assert.Equal(2, Qualor.Taint.Cli.Program.Run(
            new[] { "analyze", "--inputs", inputs, "--models", Models, "--sarif", Path.Combine(root, "r.sarif"), option, value }, TextWriter.Null));
    }
}
