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
}
