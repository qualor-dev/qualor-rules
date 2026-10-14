using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 8: method summaries in one project — helpers, getters, base classes and overrides, recursion, constructors,
/// out parameters, the heap across methods, and the iteration cap.
public sealed class SummaryTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void A_helper_returning_its_argument_is_reported_at_the_sink_after_it() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private static string Wrap(string s)
            {
                var r = "[" + s + "]";
                return r;
            }
            public IActionResult M(string q)
            {
                var w = Wrap(q);
                _c.Execute("DELETE FROM t WHERE n = '" + w + "'"); /*sink*/
                _c.Execute("DELETE FROM t WHERE n = '" + Wrap("fixed") + "'");
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_awaited_helper_returning_a_Task_of_its_argument_is_reported() => Expect("""
        public class C
        {
            private static Task<string> Echo(string s) => Task.FromResult(s.Trim());
            public async Task M([FromQuery] string q, SqlConnection c)
            {
                var t = await Echo(q);
                await c.ExecuteAsync("DELETE FROM t WHERE n = '" + t + "'"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_helper_that_ignores_its_argument_is_not_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private static string Column(string requested) => "name";
            public IActionResult M(string q)
            {
                _c.Execute("SELECT * FROM t ORDER BY " + Column(q));
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_expression_bodied_pass_through_helper_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string B(string s) => "x" + s;
            public IActionResult M(string q)
            {
                _c.Execute("DELETE FROM t WHERE n = '" + B(q) + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_helper_that_reads_the_request_itself_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private static string TermOf(HttpRequest request) => request.Query["term"].ToString();
            public IActionResult M()
            {
                _c.Execute("DELETE FROM t WHERE n = '" + TermOf(Request) + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_property_getter_returning_a_tainted_field_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string _term = "";
            private string Term => _term;
            public IActionResult M(string q)
            {
                _term = q;
                _c.Execute("DELETE FROM t WHERE n = '" + Term + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_field_written_in_a_request_is_request_data_through_a_getter_that_request_runs() => Expect("""
        public class ItemsController : ControllerBase
        {
            private static string _last = "";
            private readonly SqlConnection _c = new();
            private string Last { get { return _last; } }
            public IActionResult Remember(string q)
            {
                _last = q;
                Replay();
                return Ok();
            }
            private void Replay()
            {
                _c.Execute("DELETE FROM t WHERE n = '" + Last + "'"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_base_controller_method_with_the_sink_is_reported_when_a_derived_controller_passes_the_request_value() => Expect("""
        public abstract class ApiBase : ControllerBase
        {
            protected readonly SqlConnection Conn = new();
            protected abstract string Table { get; }
            protected int Delete(string name) => Conn.Execute("DELETE FROM " + Table + " WHERE n = '" + name + "'"); /*sink*/
        }
        public class ItemsController : ApiBase
        {
            protected override string Table => "items";
            public IActionResult M(string q)
            {
                Delete(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_base_action_calling_an_abstract_method_reaches_the_override_in_a_derived_controller() => Expect("""
        public abstract class ApiBase : ControllerBase
        {
            public IActionResult Find(string q)
            {
                Run(q);
                return Ok();
            }
            protected abstract void Run(string s);
        }
        public class ItemsController : ApiBase
        {
            private readonly SqlConnection _c = new();
            protected override void Run(string s) => _c.Execute("DELETE FROM t WHERE n = '" + s + "'"); /*sink*/
        }
        public class TagsController : ApiBase
        {
            private readonly SqlConnection _c = new();
            protected override void Run(string s) => _c.Execute("DELETE FROM tags WHERE n = 'fixed'");
        }
        """);

    [Fact]
    public void Mutually_recursive_helpers_passing_the_value_terminate_and_report() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string A(string s, int n) => n <= 0 ? s : B(s + "a", n - 1);
            private string B(string s, int n) => n <= 0 ? "b" : A(s + "b", n - 1);
            public IActionResult M(string q)
            {
                _c.Execute("DELETE FROM t WHERE n = '" + B(q, 3) + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void Mutual_recursion_with_the_sink_inside_reports_at_the_sink() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private void Even(string s, int n)
            {
                if (n == 0) _c.Execute("DELETE FROM t WHERE n = '" + s + "'"); /*sink*/
                else Odd(s, n - 1);
            }
            private void Odd(string s, int n) => Even(s.Trim(), n - 1);
            public IActionResult M(string q)
            {
                Odd(q, 5);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_service_method_whose_sink_argument_is_a_constant_is_not_reported() => Expect("""
        public class Purger
        {
            private readonly SqlConnection _c = new();
            public string Run(string table)
            {
                _c.Execute("DELETE FROM t WHERE expired = 1");
                return "done";
            }
        }
        public class ItemsController : ControllerBase
        {
            private readonly Purger _purger = new();
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var status = _purger.Run(q);
                _c.Execute("INSERT INTO log VALUES ('" + status + "')");
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_out_parameter_of_a_helper_carries_its_argument() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private static bool TrySplit(string s, out string head)
            {
                head = s.Split(',')[0];
                return head.Length > 0;
            }
            public IActionResult M(string q)
            {
                if (TrySplit(q, out var head)) _c.Execute("DELETE FROM t WHERE n = '" + head + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_constructor_storing_its_argument_taints_the_object_it_makes() => Expect("""
        public class Filter
        {
            private readonly string _text;
            public Filter(string text) { _text = text; }
            public string Sql() => "WHERE n = '" + _text + "'";
        }
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var f = new Filter(q);
                _c.Execute("DELETE FROM t " + f.Sql()); /*sink*/
                // Decision R-8 (Task 27): Filter._text is per allocation site; the other instance's is the constant.
                _c.Execute("DELETE FROM t " + new Filter("fixed").Sql());
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_positional_record_built_from_request_data_carries_it() => Expect("""
        public record Term(string Text, int Page);
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var t = new Term(q, 1);
                _c.Execute("DELETE FROM t WHERE n = '" + t.Text + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_setter_with_a_body_writes_its_field_for_a_later_getter() => Expect("""
        public class Query
        {
            private string _where = "";
            public string Where { get => _where; set => _where = "WHERE " + value; }
        }
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var query = new Query();
                query.Where = "n = '" + q + "'";
                _c.Execute("DELETE FROM t " + query.Where); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_getter_of_a_request_bound_object_reads_its_fields() => Expect("""
        public class OrderDto
        {
            public string Name { get; set; } = "";
            public string Label => "n=" + Name;
        }
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Post([FromBody] OrderDto dto)
            {
                _c.Execute("DELETE FROM t WHERE " + dto.Label); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_injected_service_of_a_request_bound_object_is_not_request_data() => Expect("""
        public interface IClock { string Now(); }
        public class OrderDto
        {
            private readonly IClock _clock;
            public OrderDto(IClock clock) { _clock = clock; }
            public string Name { get; set; } = "";
            public string Stamp() => _clock.Now();
            public string Filter() => "name = '" + Name + "'";
        }
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Post([FromBody] OrderDto dto)
            {
                _c.Execute("DELETE FROM t WHERE at = '" + dto.Stamp() + "'");
                _c.Execute("DELETE FROM t WHERE " + dto.Filter()); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_generic_repository_interface_dispatches_to_its_implementation() => Expect("""
        public interface IRepository<T> { IEnumerable<T> Where(string filter); }
        public class Repository<T> : IRepository<T>
        {
            private readonly SqlConnection _c = new();
            public IEnumerable<T> Where(string filter) => _c.Query<T>("SELECT * FROM t WHERE " + filter); /*sink*/
        }
        public class Order { }
        public class OrdersController : ControllerBase
        {
            private readonly IRepository<Order> _orders = new Repository<Order>();
            public IActionResult Find(string q) => Ok(_orders.Where("name = '" + q + "'"));
        }
        """);

    /// Task 22: an interface member implemented by a virtual (or abstract) method of a base class runs the derived class's
    /// override (the interface map names the base's method; the override replaces it in the derived type).
    [Fact]
    public void An_interface_call_reaches_the_overrides_of_a_base_classes_virtual_implementation() => Expect("""
        public interface IStep { string Run(string input); }
        public abstract class StepBase : IStep
        {
            public virtual string Run(string input) => "none";
        }
        public abstract class Abstract : IStep
        {
            public abstract string Run(string input);
        }
        public class DeleteStep : StepBase
        {
            private readonly SqlConnection _c = new();
            public override string Run(string input) { _c.Execute("DELETE FROM t WHERE n = '" + input + "'"); /*sink*/ return "done"; }
        }
        public class InsertStep : Abstract
        {
            private readonly SqlConnection _c = new();
            public override string Run(string input) { _c.Execute("INSERT INTO t VALUES ('" + input + "')"); /*sink*/ return "done"; }
        }
        public class SealedStep : StepBase
        {
        }
        public class StepsController : ControllerBase
        {
            private readonly List<IStep> _steps = new();
            public IActionResult Go(string q)
            {
                foreach (var s in _steps) s.Run(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_explicit_interface_implementation_and_an_extension_method_in_source_are_followed() => Expect("""
        public interface IStore { int Delete(string name); }
        public class Store : IStore
        {
            private readonly SqlConnection _c = new();
            int IStore.Delete(string name) => _c.Execute("DELETE FROM t WHERE n = " + name.Quoted()); /*sink*/
        }
        public static class Text
        {
            public static string Quoted(this string s) => "'" + s + "'";
        }
        public class ItemsController : ControllerBase
        {
            private readonly IStore _store = new Store();
            public IActionResult M(string q)
            {
                _store.Delete(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void The_summary_of_a_pass_through_helper_names_its_parameter_and_a_constant_sink_none()
    {
        const string code = """
            public class Helpers
            {
                private readonly SqlConnection _c = new();
                public static string Wrap(string s) => "[" + s + "]";
                public int Purge(string table) => _c.Execute("DELETE FROM t WHERE expired = 1");
                public int Drop(string table) => _c.Execute("DROP TABLE " + table);
            }
            """;
        var engine = new TaintEngine(Snippet.Models, Snippet.Options);
        engine.Analyze(Snippet.Compile(code), CancellationToken.None);
        var summaries = engine.Summaries().ToDictionary(kv => kv.Key.Name, kv => kv.Value);
        Assert.True(summaries["Wrap"].Params[0].ToReturn);
        Assert.False(summaries["Wrap"].ReturnsRequest);
        Assert.True(!summaries.TryGetValue("Purge", out var purge) || purge.Params.Values.All(p => p.ToSinks.Count == 0));
        Assert.Equal("csharp.sql-injection", Assert.Single(summaries["Drop"].Params[0].ToSinks).RuleId);
    }

    [Fact]
    public void A_long_call_chain_with_a_sink_in_every_method_keeps_each_summary_small()
    {
        // Ruling R-E11: a callee's sinks are not copied into its callers' summaries (a chain of N calls would hold N²
        // sinks); request data flows on along call edges instead.
        const int length = 300;
        var code = new System.Text.StringBuilder("public class Chain\n{\n    private readonly SqlConnection _c = new();\n");
        for (var i = 0; i < length; i++)
        {
            var next = i + 1 < length ? $"return M{i + 1}(x);" : "return x;";
            code.Append($"    public string M{i}(string s) {{ var x = s + \"{i}\"; _c.Execute(\"DELETE FROM t WHERE n = '\" + x + \"'\"); {next} }}\n");
        }
        code.Append("}\npublic class ItemsController : ControllerBase\n{\n    private readonly Chain _chain = new();\n");
        code.Append("    public IActionResult M(string q) { _chain.M0(q); return Ok(); }\n}\n");
        var engine = new TaintEngine(Snippet.Models, Snippet.Options);
        var result = engine.Analyze(Snippet.Compile(code.ToString()), CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.Equal(length, result.Findings.Count);
        Assert.InRange(engine.Work().MaxGlobalEffects, 1, 3);
    }

    [Fact]
    public void A_component_over_its_iteration_cap_makes_the_run_incomplete()
    {
        const string code = """
            public class ItemsController : ControllerBase
            {
                private readonly SqlConnection _c = new();
                private string A(string s, int n) => n <= 0 ? s : B(s, n - 1);
                private string B(string s, int n) => n <= 0 ? s : A(s, n - 1);
                public IActionResult M(string q) { _c.Execute(A(q, 2)); return Ok(); }
            }
            """;
        var result = Snippet.Analyze(code, new TaintEngineOptions(TimeSpan.FromMinutes(1), 4L << 30, MaxIterationsPerScc: 1));
        Assert.False(result.Complete);
        Assert.StartsWith("iteration cap in ItemsController.", result.IncompleteReason);
        Assert.True(Snippet.Analyze(code).Complete);
    }
}
