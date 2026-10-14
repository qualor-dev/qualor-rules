using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint.Tests;

public sealed class InputReaderTests : TempDirs
{
    [Fact]
    public void Reads_v1_files_with_spaces_unicode_and_windows_separators()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "a.txt"), string.Join("\n",
            "qualor-compilation=1", @"project=C:\work\My App\Api\Api.csproj", "tfm=net8.0", "assembly=Api",
            "output-kind=Exe", "lang-version=12.0", "nullable=enable", "defines=DEBUG;NET8_0;A",
            "allow-unsafe=false", @"generated-dir=C:\work\My App\.qualor\dotnet\generated\1",
            @"source=C:\work\My App\Api\Ünï cödé.cs", @"reference=C:\nuget\x.dll",
            @"project-reference=C:\work\My App\Lib\Lib.csproj"), new UTF8Encoding(false));
        var inputs = InputReader.Read(dir, out var errors);
        Assert.Empty(errors);
        var i = Assert.Single(inputs);
        Assert.Equal(@"C:\work\My App\Api\Ünï cödé.cs", Assert.Single(i.Sources));
        Assert.Equal(new[] { "DEBUG", "NET8_0", "A" }, i.Defines);
        Assert.Equal(LanguageVersion.CSharp12, i.LanguageVersion);
        Assert.Equal(NullableContextOptions.Enable, i.Nullable);
        Assert.Equal(OutputKind.ConsoleApplication, i.OutputKind);
        Assert.Equal(@"C:\work\My App\Lib\Lib.csproj", Assert.Single(i.ProjectReferences));
    }

    [Fact]
    public void Returns_malformed_files_as_errors()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "no-header.txt"), "project=a.csproj\n");
        File.WriteAllText(Path.Combine(dir, "bad-kind.txt"), "qualor-compilation=1\nproject=b.csproj\ntfm=net8.0\noutput-kind=Module\n");
        var inputs = InputReader.Read(dir, out var errors);
        Assert.Empty(inputs);
        Assert.Equal(2, errors.Count);
        Assert.Contains(errors, e => e.Contains("no-header.txt") && e.Contains("qualor-compilation=1"));
        Assert.Contains(errors, e => e.Contains("bad-kind.txt") && e.Contains("output-kind"));
    }

    [Fact]
    public void Reads_every_scalar_and_list_key_exactly()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "b.txt"), string.Join("\n",
            "qualor-compilation=1", "project=/src/My App/Web/Web.csproj", "tfm=net9.0", "assembly=My.Web",
            "output-kind=WinExe", "lang-version=", "nullable=", "defines=", "allow-unsafe=true",
            "generated-dir=", "unknown-key=whatever",
            "source=/src/My App/Web/A.cs", "source=/src/My App/Web/b=c.cs",
            "reference=/r/one.dll", "reference=/r/two.dll",
            "project-reference=/src/My App/Lib/Lib.csproj", "project-reference=/src/My App/Core/Core.csproj", ""),
            new UTF8Encoding(false));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Equal("/src/My App/Web/Web.csproj", i.ProjectPath);
        Assert.Equal("net9.0", i.TargetFramework);
        Assert.Equal("My.Web", i.AssemblyName);
        Assert.Equal(OutputKind.WindowsApplication, i.OutputKind);
        Assert.Equal(LanguageVersion.Default, i.LanguageVersion);
        Assert.Equal(NullableContextOptions.Disable, i.Nullable);
        Assert.Empty(i.Defines);
        Assert.True(i.AllowUnsafe);
        Assert.Null(i.GeneratedDir);
        Assert.Equal(new[] { "/src/My App/Web/A.cs", "/src/My App/Web/b=c.cs" }, i.Sources);
        Assert.Equal(new[] { "/r/one.dll", "/r/two.dll" }, i.References);
        Assert.Equal(new[] { "/src/My App/Lib/Lib.csproj", "/src/My App/Core/Core.csproj" }, i.ProjectReferences);
        Assert.Equal(Path.Combine(dir, "b.txt"), i.InputFile);
    }

    [Fact]
    public void Accepts_a_byte_order_mark_and_crlf_line_ends_and_a_library_without_assembly()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "c.txt"),
            "qualor-compilation=1\r\nproject=C:\\x\\Lib Ü.csproj\r\ntfm=net8.0\r\noutput-kind=Library\r\nnullable=Warnings\r\nsource=C:\\x\\Ä.cs\r\n",
            new UTF8Encoding(true));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Equal(@"C:\x\Lib Ü.csproj", i.ProjectPath);
        Assert.Equal("Lib Ü", i.AssemblyName);
        Assert.Equal(OutputKind.DynamicallyLinkedLibrary, i.OutputKind);
        Assert.Equal(NullableContextOptions.Warnings, i.Nullable);
        Assert.Equal(@"C:\x\Ä.cs", Assert.Single(i.Sources));
    }

    [Fact]
    public void Ignores_other_files_and_reports_unsupported_values()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "notes.json"), "{}");
        File.WriteAllText(Path.Combine(dir, "v2.txt"), "qualor-compilation=2\nproject=a.csproj\n");
        File.WriteAllText(Path.Combine(dir, "no-project.txt"), "qualor-compilation=1\ntfm=net8.0\n");
        File.WriteAllText(Path.Combine(dir, "bad-lang.txt"), "qualor-compilation=1\nproject=a.csproj\nlang-version=99.9\n");
        File.WriteAllText(Path.Combine(dir, "bad-nullable.txt"), "qualor-compilation=1\nproject=a.csproj\nnullable=sometimes\n");
        File.WriteAllText(Path.Combine(dir, "bad-unsafe.txt"), "qualor-compilation=1\nproject=a.csproj\nallow-unsafe=maybe\n");
        File.WriteAllText(Path.Combine(dir, "bad-line.txt"), "qualor-compilation=1\nproject=a.csproj\nno equals sign\n");
        File.WriteAllBytes(Path.Combine(dir, "bad-utf8.txt"), new byte[] { 0x71, 0x3D, 0xFF, 0xFE, 0x0A });
        Assert.Empty(InputReader.Read(dir, out var errors));
        Assert.Equal(7, errors.Count);
        Assert.Contains(errors, e => e.Contains("v2.txt") && e.Contains("qualor-compilation=1"));
        Assert.Contains(errors, e => e.Contains("no-project.txt") && e.Contains("project"));
        Assert.Contains(errors, e => e.Contains("bad-lang.txt") && e.Contains("lang-version"));
        Assert.Contains(errors, e => e.Contains("bad-nullable.txt") && e.Contains("nullable"));
        Assert.Contains(errors, e => e.Contains("bad-unsafe.txt") && e.Contains("allow-unsafe"));
        Assert.Contains(errors, e => e.Contains("bad-line.txt") && e.Contains("line 3"));
        Assert.Contains(errors, e => e.Contains("bad-utf8.txt") && e.Contains("UTF-8"));
    }

    [Fact]
    public void A_missing_directory_is_an_error_not_an_exception()
    {
        var missing = Path.Combine(TempDir(), "absent");
        Assert.Empty(InputReader.Read(missing, out var errors));
        Assert.Contains("absent", Assert.Single(errors));
    }

    [Fact]
    public void Reads_each_project_reference_with_its_paired_assembly()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "p.txt"), string.Join("\n",
            "qualor-compilation=1", @"project=C:\w\App\App.csproj", "tfm=net8.0",
            @"project-reference=C:\w\Lib\Lib.csproj", @"project-reference-assembly=C:\w\Lib\obj\Debug\net8.0\ref\Lib Ü.dll",
            "project-reference=/w/Vb/Vb.vbproj", "project-reference-assembly=/w/Vb/bin/Vb.dll"), new UTF8Encoding(false));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Equal(new[] { @"C:\w\Lib\Lib.csproj", "/w/Vb/Vb.vbproj" }, i.ProjectReferences);
        Assert.Equal(new[] { @"C:\w\Lib\obj\Debug\net8.0\ref\Lib Ü.dll", "/w/Vb/bin/Vb.dll" }, i.ProjectReferenceAssemblies);
    }

    [Fact]
    public void Reads_features_and_interceptors_namespaces()   // ruling R-E6
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "f.txt"), string.Join("\n",
            "qualor-compilation=1", "project=/w/App/App.csproj", "tfm=net10.0",
            "features=strict; peverify-compat=false;;InterceptorsNamespaces=A.B",
            "interceptors-namespaces=Microsoft.Extensions.Configuration.Binder.SourceGeneration;Gen.X"), new UTF8Encoding(false));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Equal(new[] { "strict", "peverify-compat=false", "InterceptorsNamespaces=A.B" }, i.Features);
        Assert.Equal(new[] { "Microsoft.Extensions.Configuration.Binder.SourceGeneration", "Gen.X" }, i.InterceptorsNamespaces);
    }

    [Fact]
    public void Reads_the_startup_object_and_leaves_it_null_when_empty()   // Task 23
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "s.txt"), "qualor-compilation=1\nproject=/w/B.csproj\noutput-kind=Exe\nstartup-object=Bench.Program\n", new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(dir, "t.txt"), "qualor-compilation=1\nproject=/w/C.csproj\nstartup-object=\n", new UTF8Encoding(false));
        var read = InputReader.Read(dir, out var errors);
        Assert.Empty(errors);
        Assert.Equal("Bench.Program", read[0].StartupObject);
        Assert.Null(read[1].StartupObject);
    }

    [Fact]
    public void Features_and_interceptors_namespaces_are_empty_when_not_recorded()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "e.txt"), "qualor-compilation=1\nproject=/w/A.csproj\nfeatures=\ninterceptors-namespaces=\n");
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Empty(i.Features);
        Assert.Empty(i.InterceptorsNamespaces);
    }

    [Fact]
    public void A_project_reference_assembly_count_mismatch_is_an_error_and_the_input_is_kept()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "m.txt"), string.Join("\n",
            "qualor-compilation=1", "project=/w/App/App.csproj", "tfm=net8.0",
            "project-reference=/w/Lib/Lib.csproj", "project-reference=/w/Core/Core.csproj",
            "project-reference-assembly=/w/Lib/Lib.dll"), new UTF8Encoding(false));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Contains("m.txt", Assert.Single(errors));
        Assert.Contains("project-reference-assembly", errors[0]);
        Assert.Equal(2, i.ProjectReferences.Count);
        Assert.Empty(i.ProjectReferenceAssemblies);
    }
}
