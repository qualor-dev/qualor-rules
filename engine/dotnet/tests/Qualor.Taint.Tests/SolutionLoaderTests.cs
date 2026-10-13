using System.Text;
using Basic.Reference.Assemblies;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint.Tests;

public sealed class SolutionLoaderTests : TempDirs
{
    [Fact]
    public void Project_references_become_source_compilations()
    {
        // Lib: public class Svc { public string Get(string s) => s; }  App: references Lib, calls new Svc().Get("x")
        var solution = SolutionLoader.Load(WriteTwoProjects(), default);
        var app = solution.Projects.Single(p => p.Input.AssemblyName == "App");
        Assert.Empty(app.Errors);
        Assert.Contains(app.Compilation.References, r => r is CompilationReference);
    }

    [Fact]
    public void A_project_with_errors_is_loaded_and_its_errors_reported()   // Review Focus 1
    {
        var inputs = WriteTwoProjects(appSource: "class C { Missing m; }");
        var solution = SolutionLoader.Load(inputs, default);
        var app = solution.Projects.Single(p => p.Input.AssemblyName == "App");
        Assert.Contains(app.Errors, d => d.Id == "CS0246");
        Assert.Empty(solution.Projects.Single(p => p.Input.AssemblyName == "Lib").Errors);
    }

    [Fact]
    public void Generated_sources_are_added()
    {
        var inputs = WriteTwoProjects(generated: ("Gen/Views/Index.g.cs", "public class GeneratedView { }"));
        var app = SolutionLoader.Load(inputs, default).Projects.Single(p => p.Input.AssemblyName == "App");
        Assert.NotNull(app.Compilation.GetTypeByMetadataName("GeneratedView"));
    }

    [Fact]
    public void A_file_recorded_as_source_and_found_under_the_generated_dir_is_added_once()
    {
        var src = TempDir();
        var generatedDir = Path.Combine(src, "generated", "1");
        var file = Write(generatedDir, Path.Combine("Gen", "G.g.cs"), "public class G { }");
        var recorded = OperatingSystem.IsWindows() ? file.Replace('\\', '/') : file;   // the same file, other separators
        var input = Input(src, "Dup", "net8.0", new[] { recorded, recorded }, generatedDir: generatedDir);
        var p = Assert.Single(SolutionLoader.Load(new[] { input }, default).Projects);
        Assert.Empty(p.Errors);
        Assert.Single(p.Compilation.SyntaxTrees);
    }

    [Fact]
    public void Projects_come_in_dependency_order_and_the_reference_is_the_lib_compilation()
    {
        var solution = SolutionLoader.Load(WriteTwoProjects(), default);
        Assert.Equal(new[] { "Lib", "App" }, solution.Projects.Select(p => p.Input.AssemblyName));
        var lib = solution.Projects[0].Compilation;
        var app = solution.Projects[1].Compilation;
        Assert.Contains(app.References, r => r is CompilationReference c && ReferenceEquals(c.Compilation, lib));
        Assert.Equal("Lib", lib.AssemblyName);
        Assert.Equal(OutputKind.ConsoleApplication, app.Options.OutputKind);
    }

    [Fact]
    public void Compiler_options_follow_the_input()
    {
        var src = TempDir();
        var file = Write(src, "Ünï cödé.cs", "#if A\nunsafe class U { int* p; string? s; }\n#endif\n");
        var input = Input(src, "Opt", "net8.0", new[] { file }, defines: new[] { "A" }, allowUnsafe: true,
            nullable: NullableContextOptions.Enable, lang: LanguageVersion.CSharp12);
        var p = Assert.Single(SolutionLoader.Load(new[] { input }, default).Projects);
        Assert.Empty(p.Errors);
        Assert.True(p.Compilation.Options.AllowUnsafe);
        Assert.Equal(NullableContextOptions.Enable, p.Compilation.Options.NullableContextOptions);
        var tree = Assert.Single(p.Compilation.SyntaxTrees);
        Assert.Equal(file, tree.FilePath);
        var options = (CSharpParseOptions)tree.Options;
        Assert.Equal(LanguageVersion.CSharp12, options.LanguageVersion);
        Assert.Contains("A", options.PreprocessorSymbolNames);
        Assert.NotNull(p.Compilation.GetTypeByMetadataName("U"));
    }

    [Fact]
    public void A_missing_referenced_input_is_an_error_and_the_rest_still_loads()   // Review Focus 1
    {
        var inputs = WriteTwoProjects().Where(i => i.AssemblyName == "App").ToList();
        var app = Assert.Single(SolutionLoader.Load(inputs, default).Projects);
        Assert.Contains(app.Errors, d => d.Id == SolutionLoader.MissingProjectReferenceId && d.GetMessage().Contains("Lib.csproj"));
        Assert.Contains(app.Errors, d => d.Id == "CS0246");
        Assert.DoesNotContain(app.Compilation.References, r => r is CompilationReference);
    }

    [Fact]
    public void A_cycle_is_broken_with_an_error_and_both_projects_load()
    {
        var src = TempDir();
        var a = Input(src, "A", "net8.0", new[] { Write(src, "A.cs", "public class A { }") }, projectRefs: new[] { Path.Combine(src, "B.csproj") });
        var b = Input(src, "B", "net8.0", new[] { Write(src, "B.cs", "public class B { }") }, projectRefs: new[] { Path.Combine(src, "A.csproj") });
        var solution = SolutionLoader.Load(new[] { a, b }, default);
        Assert.Equal(2, solution.Projects.Count);
        Assert.Contains(solution.Projects.SelectMany(p => p.Errors), d => d.Id == SolutionLoader.ReferenceCycleId);
    }

    [Fact]
    public void A_referenced_project_without_input_falls_back_to_its_recorded_assembly()   // ruling R-E4
    {
        var src = TempDir();
        var libDll = Emit(src, Path.Combine("lib out", "Lib Ü.dll"), "Lib", "public class Svc { public string Get(string s) => s; }");
        var app = Input(src, "App", "net8.0", new[] { Write(src, "App.cs", "class P { string M() => new Svc().Get(\"x\"); }") },
            projectRefs: new[] { Path.Combine(src, "Lib", "Lib.csproj") }) with { ProjectReferenceAssemblies = new[] { libDll } };
        var p = Assert.Single(SolutionLoader.Load(new[] { app }, default).Projects);
        Assert.Empty(p.Errors);
        Assert.Contains(p.Compilation.References, r => r is PortableExecutableReference pe && pe.FilePath == libDll);
        Assert.Equal(new[] { libDll }, p.FallbackAssemblies);
    }

    [Theory]   // ruling R-E6: the SDK's InterceptorsNamespaces (configuration binder, RDG) reach the parse options
    [InlineData("interceptors-namespaces=Other.Ns;Gen.Interceptors", false)]
    [InlineData("features=InterceptorsNamespaces=Gen.Interceptors", false)]
    [InlineData("features=qualor-unrelated", true)]
    [InlineData("", true)]
    public void Recorded_interceptors_namespaces_enable_generated_interceptors(string line, bool expectCs9137)
    {
        var src = TempDir();
        const string target = "namespace App { public static class C { public static int M() => 1; public static int Use() => M(); } }";
        var targetFile = Write(src, "Program.cs", target);
        var interceptor = Write(src, Path.Combine("generated", "Interceptor.g.cs"), InterceptorFor(targetFile, target));
        var inputs = Path.Combine(src, "compilations");
        Directory.CreateDirectory(inputs);
        File.WriteAllText(Path.Combine(inputs, "i.txt"), string.Join("\n", new[] { "qualor-compilation=1",
            "project=" + Path.Combine(src, "App.csproj"), "tfm=net8.0", "assembly=App", "output-kind=Library", line,
            "source=" + targetFile, "source=" + interceptor }.Concat(RefPaths.Value.Select(r => "reference=" + r))) + "\n", new UTF8Encoding(false));
        var read = InputReader.Read(inputs, out var errors);
        Assert.Empty(errors);

        var p = Assert.Single(SolutionLoader.Load(read, default).Projects);

        if (expectCs9137) Assert.Contains(p.Errors, d => d.Id == "CS9137");
        else Assert.Empty(p.Errors);
    }

    [Fact]
    public void Features_reach_the_parse_options_with_true_for_a_bare_key()
    {
        var src = TempDir();
        var input = Input(src, "F", "net8.0", new[] { Write(src, "F.cs", "class F { }") }) with
        {
            Features = new[] { "qualor-flag", "qualor-key=v=1" },
            InterceptorsNamespaces = new[] { "A.B", "C" },
        };
        var options = (CSharpParseOptions)Assert.Single(Assert.Single(SolutionLoader.Load(new[] { input }, default).Projects).Compilation.SyntaxTrees).Options;
        Assert.Equal("true", options.Features["qualor-flag"]);
        Assert.Equal("v=1", options.Features["qualor-key"]);
        Assert.Equal("A.B;C", options.Features["InterceptorsNamespaces"]);
        Assert.Equal("A.B;C", options.Features["InterceptorsPreviewNamespaces"]);
    }

    [Fact]
    public void A_referenced_project_whose_recorded_assembly_is_missing_is_an_error()
    {
        var src = TempDir();
        var app = Input(src, "App", "net8.0", new[] { Write(src, "App.cs", "class P { Svc s; }") },
            projectRefs: new[] { Path.Combine(src, "Lib.csproj") }) with { ProjectReferenceAssemblies = new[] { Path.Combine(src, "absent", "Lib.dll") } };
        var p = Assert.Single(SolutionLoader.Load(new[] { app }, default).Projects);
        Assert.Contains(p.Errors, d => d.Id == SolutionLoader.MissingProjectReferenceId && d.GetMessage().Contains(Path.Combine("absent", "Lib.dll")));
        Assert.Contains(p.Errors, d => d.Id == "CS0246");
    }

    [Fact]
    public void A_cycle_falls_back_to_the_recorded_assembly_of_the_dropped_reference()
    {
        var src = TempDir();
        var bDll = Emit(src, Path.Combine("b", "B.dll"), "B", "public class B { }");
        var a = Input(src, "A", "net8.0", new[] { Write(src, "A.cs", "public class A { public B? Other; }") },
            projectRefs: new[] { Path.Combine(src, "B.csproj") }) with { ProjectReferenceAssemblies = new[] { bDll } };
        var b = Input(src, "B", "net8.0", new[] { Write(src, "B.cs", "public class B { }") },
            projectRefs: new[] { Path.Combine(src, "A.csproj") }) with { ProjectReferenceAssemblies = new[] { Path.Combine(src, "a", "A.dll") } };
        var solution = SolutionLoader.Load(new[] { a, b }, default);
        Assert.Equal(2, solution.Projects.Count);
        var loadedA = solution.Projects.Single(p => p.Input.AssemblyName == "A");
        Assert.DoesNotContain(loadedA.Errors, d => d.Id is SolutionLoader.ReferenceCycleId or "CS0246");
        Assert.Contains(loadedA.Compilation.References, r => r is PortableExecutableReference pe && pe.FilePath == bDll);
    }

    [Fact]
    public void Malformed_paths_and_an_unlistable_generated_dir_are_errors_of_that_project_only()   // Review Focus 1
    {
        var inputs = WriteTwoProjects();
        var src = Path.GetDirectoryName(Path.GetDirectoryName(inputs[0].InputFile))!;
        var broken = inputs.Select(i => i.AssemblyName != "App" ? i : i with
        {
            Sources = i.Sources.Append(Path.Combine(src, "bad\0name.cs")).ToList(),
            References = i.References.Append(Path.Combine(src, "bad\0ref.dll")).ToList(),
            GeneratedDir = Path.Combine(src, "gen\0dir"),
        }).ToList();
        var solution = SolutionLoader.Load(broken, default);
        Assert.Empty(solution.Projects.Single(p => p.Input.AssemblyName == "Lib").Errors);
        var app = solution.Projects.Single(p => p.Input.AssemblyName == "App");
        Assert.Contains(app.Errors, d => d.Id == SolutionLoader.MissingFileId && d.GetMessage().Contains("bad\0name.cs"));
        Assert.Contains(app.Errors, d => d.Id == SolutionLoader.MissingFileId && d.GetMessage().Contains("bad\0ref.dll"));
        Assert.Contains(app.Errors, d => d.Id == SolutionLoader.MissingFileId && d.GetMessage().Contains("gen\0dir"));
        Assert.DoesNotContain(app.Errors, d => d.Id == "CS0246");   // App's own source still binds Lib's Svc
    }

    [Fact]
    public void A_generated_dir_that_is_a_file_is_an_error_not_an_exception()
    {
        var src = TempDir();
        var notADir = Write(src, "generated.txt", "not a directory");
        var input = Input(src, "G", "net8.0", new[] { Write(src, "G.cs", "class G { }") }, generatedDir: notADir);
        var p = Assert.Single(SolutionLoader.Load(new[] { input }, default).Projects);
        Assert.NotNull(p.Compilation.GetTypeByMetadataName("G"));
        Assert.All(p.Errors, d => Assert.Equal(SolutionLoader.MissingFileId, d.Id));
    }

    [Fact]
    public void A_missing_source_or_reference_file_is_an_error_not_an_exception()
    {
        var src = TempDir();
        var input = Input(src, "M", "net8.0", new[] { Write(src, "M.cs", "class M { }"), Path.Combine(src, "gone.cs") },
            extraRefs: new[] { Path.Combine(src, "gone.dll") });
        var p = Assert.Single(SolutionLoader.Load(new[] { input }, default).Projects);
        Assert.Contains(p.Errors, d => d.Id == SolutionLoader.MissingFileId && d.GetMessage().Contains("gone.cs"));
        Assert.Contains(p.Errors, d => d.Id == SolutionLoader.MissingFileId && d.GetMessage().Contains("gone.dll"));
        Assert.NotNull(p.Compilation.GetTypeByMetadataName("M"));
    }

    [Theory]
    [InlineData("net8.0", "Lib80")]          // same TFM
    [InlineData("net9.0", "Lib80")]          // highest compatible
    [InlineData("net7.0", "Lib60")]
    [InlineData("netstandard2.1", "LibStd")]
    [InlineData("netfoo", "Lib60")]          // nothing compatible: the first recorded input
    public void A_multi_targeting_reference_picks_the_matching_framework(string appTfm, string expectedType)
    {
        var src = TempDir();
        var libPath = Path.Combine(src, "Lib.csproj");
        var libs = new[] { ("net6.0", "Lib60"), ("net8.0", "Lib80"), ("netstandard2.0", "LibStd") }
            .Select(t => Input(src, "Lib", t.Item1, new[] { Write(src, t.Item2 + ".cs", $"public class {t.Item2} {{ }}") }, project: libPath));
        var app = Input(src, "App", appTfm, new[] { Write(src, "App.cs", $"class P {{ {expectedType} x; }}") }, projectRefs: new[] { libPath });
        var loaded = SolutionLoader.Load(libs.Append(app).ToList(), default).Projects.Single(p => p.Input.AssemblyName == "App");
        Assert.DoesNotContain(loaded.Errors, d => d.Id == "CS0246");
    }

    // ----- helpers -----

    private static readonly Lazy<IReadOnlyList<string>> RefPaths = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "qualor-taint-tests", "ref net80 " + typeof(Net80).Assembly.GetName().Version);
        Directory.CreateDirectory(dir);
        var paths = new List<string>();
        foreach (var info in Net80.ReferenceInfos.All)
        {
            var path = Path.Combine(dir, info.FileName);
            if (!File.Exists(path)) File.WriteAllBytes(path, info.ImageBytes);
            paths.Add(path);
        }
        return paths;
    });

    private static string Write(string dir, string relative, string text)
    {
        var path = Path.Combine(dir, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, new UTF8Encoding(false));
        return path;
    }

    /// A generated interceptor of the call `M()` in the target file, in namespace Gen.Interceptors, the way a source
    /// generator writes one: InterceptsLocation(version, data) from Roslyn's GetInterceptableLocation.
    private static string InterceptorFor(string targetPath, string targetText)
    {
        var tree = CSharpSyntaxTree.ParseText(targetText, path: targetPath, encoding: Encoding.UTF8);
        var compilation = CSharpCompilation.Create("probe", new[] { tree }, RefPaths.Value.Select(r => MetadataReference.CreateFromFile(r)));
        var call = tree.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.InvocationExpressionSyntax>().Single();
#pragma warning disable RSEXPERIMENTAL002   // the interceptors API is marked experimental
        var location = compilation.GetSemanticModel(tree).GetInterceptableLocation(call)!;
#pragma warning restore RSEXPERIMENTAL002
        return "namespace System.Runtime.CompilerServices { [System.AttributeUsage(System.AttributeTargets.Method, AllowMultiple = true)] " +
            "file sealed class InterceptsLocationAttribute : System.Attribute { public InterceptsLocationAttribute(int version, string data) { } } }\n" +
            "namespace Gen.Interceptors { static file class I { " +
            $"[System.Runtime.CompilerServices.InterceptsLocation({location.Version}, \"{location.Data}\")] public static int Intercepted() => 2; }} }}\n";
    }

    /// A library assembly compiled from text and written to dir/relative, standing in for a project's build output.
    private static string Emit(string dir, string relative, string assemblyName, string text)
    {
        var path = Path.Combine(dir, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var compilation = CSharpCompilation.Create(assemblyName, new[] { CSharpSyntaxTree.ParseText(text) },
            RefPaths.Value.Select(r => MetadataReference.CreateFromFile(r)), new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        using (var stream = File.Create(path))
        {
            var emitted = compilation.Emit(stream);
            Assert.True(emitted.Success, string.Join("\n", emitted.Diagnostics));
        }
        return path;
    }

    private static CompilationInput Input(string dir, string name, string tfm, IReadOnlyList<string> sources,
        IReadOnlyList<string>? projectRefs = null, IReadOnlyList<string>? extraRefs = null, string? project = null,
        IReadOnlyList<string>? defines = null, bool allowUnsafe = false, string? generatedDir = null,
        NullableContextOptions nullable = NullableContextOptions.Disable, LanguageVersion lang = LanguageVersion.Default,
        OutputKind kind = OutputKind.DynamicallyLinkedLibrary) =>
        new(project ?? Path.Combine(dir, name + ".csproj"), tfm, name, kind, lang, nullable, defines ?? Array.Empty<string>(),
            allowUnsafe, generatedDir, sources, RefPaths.Value.Concat(extraRefs ?? Array.Empty<string>()).ToList(),
            projectRefs ?? Array.Empty<string>(), Path.Combine(dir, name + "-" + tfm + ".txt"));

    /// Lib and App (App references Lib) as compilation input files, read back with InputReader.
    private IReadOnlyList<CompilationInput> WriteTwoProjects(string? appSource = null, (string Path, string Text)? generated = null)
    {
        var src = TempDir();
        var inputsDir = Path.Combine(src, "compilations");
        Directory.CreateDirectory(inputsDir);
        var lib = Path.Combine(src, "Lib", "Lib.csproj");
        var app = Path.Combine(src, "App", "App.csproj");
        var libSource = Write(src, Path.Combine("Lib", "Svc.cs"), "public class Svc { public string Get(string s) => s; }");
        var appFile = Write(src, Path.Combine("App", "Ünï cödé.cs"), appSource ?? "class P { static void Main() => new Svc().Get(\"x\"); }");
        var generatedDir = Path.Combine(src, ".qualor", "dotnet", "generated", "app1");
        if (generated is { } g) Write(generatedDir, g.Path, g.Text);

        void WriteInput(string file, IEnumerable<string> lines) =>
            File.WriteAllText(Path.Combine(inputsDir, file), string.Join("\n", lines) + "\n", new UTF8Encoding(false));
        var refs = RefPaths.Value.Select(r => "reference=" + r);
        WriteInput("lib.txt", new[] { "qualor-compilation=1", "project=" + lib, "tfm=net8.0", "assembly=Lib", "output-kind=Library",
            "lang-version=12.0", "nullable=enable", "defines=DEBUG;NET8_0", "allow-unsafe=false", "generated-dir=" + Path.Combine(src, "nothing"),
            "source=" + libSource }.Concat(refs));
        WriteInput("app.txt", new[] { "qualor-compilation=1", "project=" + app, "tfm=net8.0", "assembly=App", "output-kind=Exe",
            "lang-version=12.0", "nullable=enable", "defines=DEBUG;NET8_0", "allow-unsafe=false", "generated-dir=" + generatedDir,
            "source=" + appFile }.Concat(refs).Append("project-reference=" + lib));

        var inputs = InputReader.Read(inputsDir, out var errors);
        Assert.Empty(errors);
        return inputs;
    }
}
