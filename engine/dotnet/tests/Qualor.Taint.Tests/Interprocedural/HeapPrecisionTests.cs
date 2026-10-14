using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Fix round 1 of Task 8 (review I1, M5): the heap is fields and properties by symbol (spec §5). Request data written to
/// a member taints that member's symbol, never the object holding it, the field holding that object, or a caller's
/// receiver; a collection write taints the collection member. The four FP probes of the review stay quiet; the members
/// actually written stay request data. Also ruling R-E12: the budget is checked while seeds run.
public sealed class HeapPrecisionTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void Another_field_of_an_entity_built_with_request_data_is_clean() => Expect("""
        public class Order { public string Customer { get; set; } = ""; public string Status { get; set; } = "open"; }
        public class OrderRepo
        {
            private readonly SqlConnection _c = new();
            public void Save(Order o)
            {
                _c.Execute("UPDATE t SET s = '" + o.Status + "'");
                _c.Execute("UPDATE t SET c = '" + o.Customer + "'"); /*sink*/
            }
        }
        public class OrdersController : ControllerBase
        {
            private readonly OrderRepo _repo = new();
            public IActionResult Post(string name)
            {
                var o = new Order { Customer = name, Status = "new" };
                _repo.Save(o);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_member_write_does_not_taint_the_local_holding_the_object() => Expect("""
        public class Order { public string Customer { get; set; } = ""; public string Status { get; set; } = "open"; }
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Post(string name)
            {
                var o = new Order();
                o.Customer = name;
                _c.Execute("UPDATE t SET s = '" + o.Status + "'");
                _c.Execute("UPDATE t SET c = '" + o.Customer + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_class_typed_service_keeps_its_fixed_sql_after_another_field_got_request_data() => Expect("""
        public class ReportService
        {
            private readonly SqlConnection _conn = new();
            private readonly string _sql = "SELECT COUNT(*) FROM orders";
            private string _tenant = "";
            public void SetTenant(string t) => _tenant = t;
            public int Count() => new SqlCommand(_sql, _conn).ExecuteNonQuery();
            public int CountConn() => new SqlCommand("SELECT 1 FROM " + _conn.Database, _conn).ExecuteNonQuery();
            public int ForTenant() => new SqlCommand("SELECT * FROM " + _tenant, _conn).ExecuteNonQuery(); /*sink*/
        }
        public class ReportsController : ControllerBase
        {
            private readonly ReportService _reports;
            public ReportsController(ReportService reports) => _reports = reports;
            public IActionResult A(string tenant) { _reports.SetTenant(tenant); _reports.Count(); _reports.CountConn(); _reports.ForTenant(); return Ok(); }
        }
        """);

    [Fact]
    public void A_DbSet_add_of_a_request_entity_taints_the_set_not_the_context() => Expect("""
        using Microsoft.EntityFrameworkCore;
        public class Order { public int Id { get; set; } public string Name { get; set; } = ""; }
        public class AppDb : DbContext
        {
            public DbSet<Order> Orders { get; set; } = null!;
            public string Schema { get; set; } = "dbo";
        }
        public class OrderService
        {
            private readonly AppDb _db;
            public OrderService(AppDb db) => _db = db;
            public void Add(Order o) { _db.Orders.Add(o); _db.SaveChanges(); }
            public int Purge() => _db.Database.ExecuteSqlRaw("DELETE FROM " + _db.Schema + ".orders WHERE old = 1");
            public int Purge2() => _db.Database.ExecuteSqlRaw("DELETE FROM " + _db.Schema + ".x");
            public int Last() => _db.Database.ExecuteSqlRaw("DELETE FROM t WHERE n IN (" + string.Join(",", _db.Orders.Select(x => x.Name)) + ")"); /*sink*/
        }
        public class OrdersController : ControllerBase
        {
            private readonly OrderService _svc;
            public OrdersController(OrderService svc) => _svc = svc;
            public IActionResult Post([FromBody] Order o) { _svc.Add(o); _svc.Purge(); _svc.Last(); return Ok(); }
            public IActionResult Del() { _svc.Purge(); return Ok(); }
        }
        """);

    [Fact]
    public void A_fixed_field_of_an_object_built_from_request_data_is_clean_while_the_written_field_is_not() => Expect("""
        public class Filter
        {
            private readonly string _text;
            private readonly string _table = "orders";
            public Filter(string text) => _text = text;
            public string Text() => _text;
            public string Table() => _table;
        }
        public class C : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var a = new Filter(q);
                var b = new Filter("fixed");
                _c.Execute("SELECT * FROM t WHERE n = '" + a.Text() + "'"); /*sink*/
                _c.Execute("SELECT * FROM " + a.Table());
                _c.Execute("SELECT * FROM " + b.Table());
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_entitys_other_field_read_in_another_project_is_clean()
    {
        const string contracts = """
            namespace Contracts;
            public class Order { public string Customer { get; set; } = ""; public string Status { get; set; } = "open"; }
            public interface IOrderRepo { void Save(Order o); }
            """;
        const string services = """
            using Contracts;
            namespace Services;
            public class OrderRepo : IOrderRepo
            {
                private readonly SqlConnection _c = new();
                public void Save(Order o)
                {
                    new SqlCommand("UPDATE t SET s = '" + o.Status + "'", _c).ExecuteNonQuery();
                    new SqlCommand("UPDATE t SET c = '" + o.Customer + "'", _c).ExecuteNonQuery();
                }
            }
            """;
        const string web = """
            using Contracts;
            public class OrdersController : ControllerBase
            {
                private readonly IOrderRepo _repo;
                public OrdersController(IOrderRepo repo) => _repo = repo;
                public IActionResult Post(string name)
                {
                    var o = new Order { Customer = name, Status = "new" };
                    _repo.Save(o);
                    return Ok();
                }
            }
            """;
        var c = Project("Contracts", contracts);
        var s = Project("Services", services, c);
        var w = Project("Web", web, c);
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(new LoadedSolution(new[] { c, s, w }), CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        var lines = result.Findings.Select(f => (Path.GetFileName(f.Sink.SourceTree!.FilePath), f.Sink.GetLineSpan().StartLinePosition.Line + 1)).ToList();
        Assert.Equal(new[] { ("Services.cs", 9) }, lines);
    }

    [Fact]
    public void The_budget_is_checked_while_seeds_run()
    {
        // A chain of 300 calls: the controller's one seed drains through 300 call edges in one Drain. The hook lets the
        // time limit pass at the first seed; the run stops there (R-E12) instead of draining all 300.
        const int length = 300;
        var code = new System.Text.StringBuilder("public class Chain\n{\n    private readonly SqlConnection _c = new();\n");
        for (var i = 0; i < length; i++)
        {
            var next = i + 1 < length ? $"return M{i + 1}(x);" : "return x;";
            code.Append($"    public string M{i}(string s) {{ var x = s + \"{i}\"; _c.Execute(\"DELETE FROM t WHERE n = '\" + x + \"'\"); {next} }}\n");
        }
        code.Append("}\npublic class ItemsController : ControllerBase\n{\n    private readonly Chain _chain = new();\n");
        code.Append("    public IActionResult M(string q) { _chain.M0(q); return Ok(); }\n}\n");
        var solution = Snippet.Compile(code.ToString());
        var limit = TimeSpan.FromSeconds(3);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var seeds = 0;
        var engine = new TaintEngine(Snippet.Models, new TaintEngineOptions(limit, 4L << 30))
        {
            BeforeSeed = () =>
            {
                if (seeds++ == 0 && clock.Elapsed < limit + TimeSpan.FromMilliseconds(200))
                    Thread.Sleep(limit + TimeSpan.FromMilliseconds(200) - clock.Elapsed);
            },
        };
        var result = engine.Analyze(solution, CancellationToken.None);
        Assert.False(result.Complete);
        Assert.StartsWith("time limit of", result.IncompleteReason);
        Assert.Equal(1, seeds);
        Assert.True(result.Findings.Count < length);
    }

    private const string Usings = """
        global using global::System;
        global using global::System.Collections.Generic;
        global using global::System.Linq;
        global using global::Microsoft.AspNetCore.Mvc;
        global using global::Microsoft.Data.SqlClient;
        """;

    private static ProjectCompilation Project(string name, string code, params ProjectCompilation[] references)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new[] { CSharpSyntaxTree.ParseText(code, parse, name + ".cs"), CSharpSyntaxTree.ParseText(Usings, parse, name + ".Usings.g.cs") };
        var refs = FixtureReferences.All.Concat(references.Select(r => (MetadataReference)r.Compilation.ToMetadataReference()));
        var compilation = CSharpCompilation.Create(name, trees, refs, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, string.Join("\n", errors));
        var input = new CompilationInput(name + ".csproj", "net8.0", name, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
            NullableContextOptions.Disable, Array.Empty<string>(), false, null, new[] { name + ".cs" }, Array.Empty<string>(), Array.Empty<string>(), name + ".csproj");
        return new ProjectCompilation(input, compilation, errors);
    }
}
