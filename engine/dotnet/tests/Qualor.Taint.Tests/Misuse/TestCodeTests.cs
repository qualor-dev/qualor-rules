using Qualor.Taint.Tests.Fixtures;
using static Qualor.Taint.Tests.Misuse.MisuseSnippet;

namespace Qualor.Taint.Tests.Misuse;

/// The misuse rules skip test code by file path (`test-code:`, the rules' `paths: exclude`, COVERAGE.md "Test code"):
/// a glob ending in '/' names a directory at any depth, any other glob a file or directory name at any depth; the path
/// is taken relative to the source root (TaintEngineOptions.SourceRoot, else the nearest directory above the project
/// holding `.git`).
public sealed class TestCodeTests : TempDirs
{
    private static readonly string[] CSharpGlobs = { "test/", "tests/", "*.Tests/", "*.UnitTests/", "*.IntegrationTests/", "*.Test/", "*.Specs/", "*Tests.cs", "*Test.cs" };

    /// A misuse model's `test-code` is its OpenGrep rule's `paths: exclude`, in the same order (one list, two copies).
    [Fact]
    public void The_misuse_models_skip_what_their_OpenGrep_rules_skip()
    {
        var misuse = Intraprocedural.Snippet.Models.Rules.Where(r => r.Kind == RuleKind.Misuse).ToList();
        Assert.Equal(3, misuse.Count);
        foreach (var rule in misuse)
        {
            var name = rule.RuleId["csharp.".Length..];
            var file = Directory.GetFiles(Path.Combine(Repo.Root, "rules", "csharp"), name + ".yml", SearchOption.AllDirectories).Single();
            var yaml = new YamlDotNet.RepresentationModel.YamlStream();
            using (var reader = new StreamReader(file)) yaml.Load(reader);
            var opengrep = ((YamlDotNet.RepresentationModel.YamlSequenceNode)yaml.Documents[0].RootNode["rules"])[0]["paths"]["exclude"];
            var globs = ((YamlDotNet.RepresentationModel.YamlSequenceNode)opengrep).Children.Select(n => ((YamlDotNet.RepresentationModel.YamlScalarNode)n).Value!).ToList();
            Assert.Equal(globs, rule.Misuse!.TestCode);
            Assert.Equal(CSharpGlobs, rule.Misuse.TestCode);
        }
    }

    [Theory]
    [InlineData("tests/Api/Client.cs", true)]
    [InlineData("test/Client.cs", true)]
    [InlineData("src/Api.Tests/Client.cs", true)]
    [InlineData("src/Api.UnitTests/Deep/Client.cs", true)]
    [InlineData("src/Api.IntegrationTests/Client.cs", true)]
    [InlineData("src/Api.Test/Client.cs", true)]
    [InlineData("src/Api.Specs/Client.cs", true)]
    [InlineData("src/Api/ClientTests.cs", true)]
    [InlineData("src/Api/ClientTest.cs", true)]
    [InlineData(@"src\Api.Tests\Client.cs", true)]
    [InlineData("src/Api/Client.cs", false)]
    [InlineData("src/Testing/Client.cs", false)]
    [InlineData("src/Api/Contest.cs", false)]
    [InlineData("src/LatestTests/Client.cs", false)]
    [InlineData("src/Api/tests.cs", false)]
    [InlineData("src/Tests/Client.cs", false)]
    public void Test_code_is_matched_by_the_rule_globs(string path, bool excluded) =>
        Assert.Equal(excluded, TestCode.Matches(path, CSharpGlobs));

    private const string Code = """
        using System.Runtime.Serialization.Formatters.Binary;
        #pragma warning disable SYSLIB0011
        public class Formatters
        {
            public object Read(Stream s) => new BinaryFormatter().Deserialize(s);
            public int Count(string q) => new SqlCommand("SELECT * FROM t WHERE a = '" + q + "'").ExecuteNonQuery();
        }
        public class FormattersController : ControllerBase
        {
            public IActionResult Find(string q) { new Formatters().Count(q); return Ok(); }
        }
        """;

    [Theory]
    [InlineData("src/App/Formatters.cs", 1)]
    [InlineData("tests/App/Formatters.cs", 0)]
    [InlineData("src/App.Tests/Formatters.cs", 0)]
    [InlineData("src/App/FormattersTests.cs", 0)]
    public void A_misuse_rule_skips_test_code_and_a_taint_rule_does_not(string path, int misuse)
    {
        var findings = Analyze(Code, path).Findings;

        Assert.Equal(misuse, findings.Count(f => f.RuleId == Deserialization));
        Assert.Single(findings, f => f.RuleId == "csharp.sql-injection");
    }

    [Fact]
    public void Directories_above_the_source_root_do_not_count()
    {
        var root = Path.Combine(TempDir(), "test", "repo");
        var file = Path.Combine(root, "src", "Formatters.cs");

        Assert.Single(Analyze(Code, file, Intraprocedural.Snippet.Options with { SourceRoot = root }).Findings, f => f.RuleId == Deserialization);
        Assert.DoesNotContain(Analyze(Code, file, Intraprocedural.Snippet.Options).Findings, f => f.RuleId == Deserialization);
    }

    [Fact]
    public void Without_a_source_root_the_repository_above_the_file_is_the_root()
    {
        var repo = Path.Combine(TempDir(), "tests", "repo");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        var inRepo = Path.Combine(repo, "src", "Formatters.cs");
        var inTests = Path.Combine(repo, "tests", "Formatters.cs");

        Assert.Equal(Path.Combine("src", "Formatters.cs"), TestCode.Relative(inRepo, null));
        Assert.Single(Analyze(Code, inRepo).Findings, f => f.RuleId == Deserialization);
        Assert.DoesNotContain(Analyze(Code, inTests).Findings, f => f.RuleId == Deserialization);
    }
}
