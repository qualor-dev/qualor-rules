using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 8 across projects: a solution of three projects written to disk and loaded by SolutionLoader (project
/// references become CompilationReferences): Contracts (an interface and DTOs), Services (the implementation; it
/// references Contracts) and Web (a controller; it references Contracts only, the DI registration being elsewhere).
public sealed class MultiProjectTests : TempDirs
{
    private const string Usings = """
        global using global::System;
        global using global::System.Collections.Generic;
        global using global::System.Linq;
        global using global::System.Threading.Tasks;
        global using global::Microsoft.AspNetCore.Http;
        global using global::Microsoft.AspNetCore.Mvc;
        global using global::Microsoft.Data.SqlClient;
        """;

    private const string Contracts = """
        namespace Contracts;
        public interface IOrderService
        {
            int Find(string text);
            int Count(string text);
        }
        public class OrderDto
        {
            public string Name { get; set; } = "";
            public int Quantity { get; set; }
        }
        public class Order
        {
            public string Customer { get; set; } = "";
        }
        """;

    private const string Services = """
        using Contracts;
        namespace Services;
        public class OrderService : IOrderService
        {
            private readonly SqlConnection _conn = new();
            public int Find(string text)
            {
                var sql = "SELECT * FROM orders WHERE name = '" + text + "'";
                return new SqlCommand(sql, _conn).ExecuteNonQuery(); /*sink*/
            }
            public int Count(string text) => new SqlCommand("SELECT COUNT(*) FROM orders", _conn).ExecuteNonQuery();
        }
        public class ReportJob
        {
            private readonly SqlConnection _conn = new();
            public int Run(Order order) => new SqlCommand("SELECT * FROM o WHERE c = '" + order.Customer + "'", _conn).ExecuteNonQuery(); /*sink*/
        }
        """;

    private const string Web = """
        using Contracts;
        namespace Web;
        [ApiController]
        public class OrdersController : ControllerBase
        {
            private readonly IOrderService _orders;
            public OrdersController(IOrderService orders) => _orders = orders;
            [HttpGet("find")]
            public IActionResult Find(string q)
            {
                _orders.Find(q);
                _orders.Count(q);
                return Ok();
            }
            [HttpPost("orders")]
            public IActionResult Post([FromBody] OrderDto dto)
            {
                var order = new Order();
                order.Customer = dto.Name;
                return Ok(order);
            }
        }
        """;

    private (LoadedSolution Solution, string Services, string Web) Load()
    {
        var dir = TempDir();
        var references = FixtureReferences.All.Select(r => ((PortableExecutableReference)r).FilePath!).ToList();
        var usings = Path.Combine(dir, "GlobalUsings.g.cs");
        File.WriteAllText(usings, Usings);
        CompilationInput Project(string name, string code, params string[] refs)
        {
            var projectDir = Path.Combine(dir, name);
            Directory.CreateDirectory(projectDir);
            var source = Path.Combine(projectDir, name + ".cs");
            File.WriteAllText(source, code);
            return new CompilationInput(
                Path.Combine(projectDir, name + ".csproj"), "net8.0", name, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Enable, Array.Empty<string>(), false, null, new[] { source, usings }, references,
                refs.Select(r => Path.Combine(dir, r, r + ".csproj")).ToList(), Path.Combine(dir, name + ".txt"));
        }
        var inputs = new[]
        {
            Project("Web", Web, "Contracts"),
            Project("Services", Services, "Contracts"),
            Project("Contracts", Contracts),
        };
        var solution = SolutionLoader.Load(inputs, CancellationToken.None);
        Assert.All(solution.Projects, p => Assert.Empty(p.Errors));
        return (solution, Path.Combine(dir, "Services", "Services.cs"), Path.Combine(dir, "Web", "Web.cs"));
    }

    private static List<(string File, int Line)> Lines(AnalysisResult result) =>
        result.Findings.Select(f => (Path.GetFileName(f.Sink.SourceTree!.FilePath), f.Sink.GetLineSpan().StartLinePosition.Line + 1)).OrderBy(x => x).ToList();

    [Fact]
    public void A_project_reference_resolves_to_the_referenced_compilations_own_symbols()
    {
        var (solution, _, _) = Load();
        var contracts = solution.Projects.Single(p => p.Input.AssemblyName == "Contracts").Compilation;
        var web = solution.Projects.Single(p => p.Input.AssemblyName == "Web").Compilation;
        var own = contracts.GetTypeByMetadataName("Contracts.IOrderService");
        var seen = web.GetTypeByMetadataName("Contracts.IOrderService");
        Assert.NotNull(own);
        Assert.True(SymbolEqualityComparer.Default.Equals(own, seen));
        Assert.Equal(own!.DeclaringSyntaxReferences.Single().SyntaxTree, seen!.DeclaringSyntaxReferences.Single().SyntaxTree);
    }

    [Fact]
    public void A_controller_calling_an_interface_reaches_the_implementation_in_another_project_with_the_path()
    {
        var (solution, services, web) = Load();
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(solution, CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.Equal(0, result.Stats.FailedMethods);
        var finding = Assert.Single(result.Findings, f => f.Sink.SourceTree!.FilePath == services && f.Sink.GetLineSpan().StartLinePosition.Line + 1 == 9);
        var path = finding.Path;
        Assert.Equal(web, path[0].Location.SourceTree!.FilePath);
        Assert.Contains("parameter 'q' of OrdersController.Find", path[0].Message);
        Assert.Contains(path, s => s.Location.SourceTree!.FilePath == web && s.Message.Contains("OrderService.Find(string)"));
        Assert.Equal(services, path[^1].Location.SourceTree!.FilePath);
        Assert.Contains("SqlCommand", path[^1].Message);
        Assert.True(result.Stats.Sccs > 0);
    }

    [Fact]
    public void A_DTO_property_written_from_the_request_body_is_request_data_in_another_projects_service()
    {
        var (solution, _, _) = Load();
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(solution, CancellationToken.None);
        var code = Services.Split('\n');
        var marked = code.Select((l, i) => (l, i)).Where(x => x.l.Contains("/*sink*/", StringComparison.Ordinal)).Select(x => ("Services.cs", x.i + 1)).ToList();
        Assert.Equal(marked, Lines(result));
    }
}
