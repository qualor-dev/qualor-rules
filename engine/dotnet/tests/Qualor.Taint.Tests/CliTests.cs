using System.Text;
using System.Text.Json;
using Basic.Reference.Assemblies;

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

    [Theory]
    [InlineData()]
    [InlineData("rebuild")]
    [InlineData("rebuild", "--inputs", "x")]
    [InlineData("rebuild", "--json", "x")]
    [InlineData("analyze", "--inputs", "x", "--json", "y")]
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
}
