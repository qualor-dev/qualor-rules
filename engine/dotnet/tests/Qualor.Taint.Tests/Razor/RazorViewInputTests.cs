using System.Text;

namespace Qualor.Taint.Tests.Razor;

/// Task 30 (R-11): the hook records the project's Razor views as `razor-view=<absolute path>` lines. The format stays
/// v1: a reader that does not know the key ignores it, this one keeps the paths exactly as recorded, in order.
public sealed class RazorViewInputTests : TempDirs
{
    [Fact]
    public void Razor_view_lines_are_read_exactly_and_in_order()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "a.txt"), string.Join("\n",
            "qualor-compilation=1", @"project=C:\work\My App\Web\Web.csproj", "tfm=net8.0",
            @"source=C:\work\My App\Web\Program.cs",
            @"razor-view=C:\work\My App\Web\Views\Home\Ïndex.cshtml",
            "razor-view=",
            @"razor-view=C:\work\My App\Web\Views\_ViewImports.cshtml", ""), new UTF8Encoding(false));
        var i = Assert.Single(InputReader.Read(dir, out var errors));
        Assert.Empty(errors);
        Assert.Equal(new[] { @"C:\work\My App\Web\Views\Home\Ïndex.cshtml", @"C:\work\My App\Web\Views\_ViewImports.cshtml" }, i.RazorViews);
        Assert.Equal(new[] { @"C:\work\My App\Web\Program.cs" }, i.Sources);
    }

    [Fact]
    public void A_record_without_razor_view_lines_has_no_views()
    {
        var dir = TempDir();
        File.WriteAllText(Path.Combine(dir, "a.txt"), "qualor-compilation=1\nproject=/src/Web/Web.csproj\ntfm=net8.0\n", new UTF8Encoding(false));
        Assert.Empty(Assert.Single(InputReader.Read(dir, out _)).RazorViews);
    }
}
