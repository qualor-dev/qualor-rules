using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Review Focus 2: a project that targets several frameworks is recorded once per target framework, so its files are
/// analysed once per framework; each finding is reported once per (rule, file, line), with the path of the first
/// compilation input that reports it.
public sealed class MultiTargetTests
{
    private const string File = "/src/Api/OrdersController.cs";

    private const string Code = """
        using System.Runtime.Serialization.Formatters.Binary;
        #pragma warning disable SYSLIB0011
        public class OrdersController : ControllerBase
        {
            public IActionResult Find([FromQuery] string a, [FromQuery] string b)
            {
        #if NET9_0
                var q = b;
        #else
                var q = a;
        #endif
                new SqlCommand("SELECT * FROM o WHERE n = '" + q + "'").ExecuteNonQuery();
                return Ok();
            }
            public object Read(Stream s) => new BinaryFormatter().Deserialize(s);
        }
        """;

    private static ProjectCompilation Project(string tfm, string define)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12, preprocessorSymbols: new[] { define });
        var trees = new[]
        {
            CSharpSyntaxTree.ParseText(Code, parse, File),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings + "\nglobal using Microsoft.AspNetCore.Mvc;\nglobal using Microsoft.Data.SqlClient;\n", parse, "/src/Api/obj/" + tfm + "/GlobalUsings.g.cs"),
        };
        var compilation = CSharpCompilation.Create("Api", trees, FixtureReferences.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.Empty(errors);
        var input = new CompilationInput(
            "/src/Api/Api.csproj", tfm, "Api", OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12, NullableContextOptions.Disable,
            new[] { define }, false, null, new[] { File }, Array.Empty<string>(), Array.Empty<string>(), "/inputs/" + tfm + ".txt");
        return new ProjectCompilation(input, compilation, errors);
    }

    private static IReadOnlyList<Finding> Analyze(params ProjectCompilation[] projects) =>
        new TaintEngine(Snippet.Models, Snippet.Options).Analyze(new LoadedSolution(projects), CancellationToken.None).Findings;

    private static int Line(Location l) => l.GetLineSpan().StartLinePosition.Line + 1;

    [Fact]
    public void A_file_of_two_target_frameworks_reports_each_finding_once()
    {
        var findings = Analyze(Project("net8.0", "NET8_0"), Project("net9.0", "NET9_0"));

        Assert.Equal(12, Line(Assert.Single(findings, f => f.RuleId == "csharp.sql-injection").Sink));
        Assert.Equal(15, Line(Assert.Single(findings, f => f.RuleId == "csharp.unsafe-deserialization").Sink));
    }

    [Theory]
    [InlineData("net8.0", "NET8_0", "net9.0", "NET9_0", 10)]
    [InlineData("net9.0", "NET9_0", "net8.0", "NET8_0", 8)]
    public void The_path_of_the_first_input_is_kept(string tfm1, string define1, string tfm2, string define2, int assignedAt)
    {
        var sql = Assert.Single(Analyze(Project(tfm1, define1), Project(tfm2, define2)), f => f.RuleId == "csharp.sql-injection");

        Assert.Contains(sql.Path, s => Line(s.Location) == assignedAt);
        Assert.DoesNotContain(sql.Path, s => Line(s.Location) == 18 - assignedAt);
    }

    [Fact]
    public void Two_sinks_of_a_rule_on_one_line_are_one_finding()
    {
        var findings = Snippet.Analyze("""
            public class OrdersController : ControllerBase
            {
                public IActionResult Find(string q)
                {
                    new SqlCommand("SELECT a FROM t WHERE n = '" + q + "'").ExecuteNonQuery(); new SqlCommand("SELECT b FROM t WHERE n = '" + q + "'").ExecuteNonQuery();
                    return Ok();
                }
            }
            """).Findings;

        Assert.Single(findings, f => f.RuleId == "csharp.sql-injection");
    }
}
