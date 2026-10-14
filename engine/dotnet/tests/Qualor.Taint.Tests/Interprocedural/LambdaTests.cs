using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 8, open items of Task 7: lambdas and local functions (captured writes, higher-order methods in source and
/// external, method groups, a lambda's return value), collection writes, and a failed body's nested lambdas.
public sealed class LambdaTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void A_lambda_writing_a_captured_variable_writes_it_back() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M([FromQuery] List<string> names)
            {
                var acc = "";
                names.ForEach(n => acc += n + ",");
                _c.Execute("DELETE FROM t WHERE n IN (" + acc + ")"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_local_function_writing_a_captured_variable_writes_it_back() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var sql = "SELECT 1";
                void Build() { sql = "DELETE FROM t WHERE n = '" + q + "'"; }
                Build();
                _c.Execute(sql); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_lambda_given_to_a_higher_order_method_in_source_gets_its_arguments() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private static void Each(List<string> items, Action<string> act)
            {
                foreach (var i in items) act(i);
            }
            public IActionResult M([FromQuery] List<string> names)
            {
                Each(names, n => _c.Execute("DELETE FROM t WHERE n = '" + n + "'")); /*sink*/
                Each(new List<string> { "a" }, n => _c.Execute("DELETE FROM t WHERE n = '" + n + "'"));
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_method_group_given_to_ForEach_reaches_its_sink() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private void Delete(string n) => _c.Execute("DELETE FROM t WHERE n = '" + n + "'"); /*sink*/
            public IActionResult M([FromQuery] List<string> names)
            {
                names.ForEach(Delete);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_lambda_returning_a_captured_request_value_taints_the_Select_result() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                var parts = new List<string> { "a", "b" }.Select(p => p + q);
                _c.Execute("DELETE FROM t WHERE n IN (" + string.Join(",", parts) + ")"); /*sink*/
                var fixedParts = new List<string> { "a", "b" }.Select(p => p + "x");
                _c.Execute("DELETE FROM t WHERE n IN (" + string.Join(",", fixedParts) + ")");
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_local_function_has_a_summary_of_its_own_parameters() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q)
            {
                string Quote(string s) => "'" + s + "'";
                _c.Execute("DELETE FROM t WHERE n = " + Quote(q)); /*sink*/
                _c.Execute("DELETE FROM t WHERE n = " + Quote("fixed"));
                return Ok();
            }
        }
        """);

    [Fact]
    public void Collection_writes_taint_the_collection_for_a_later_element_read() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M(string q, [FromQuery] string[] more)
            {
                var a = new List<string>();
                a.Insert(0, q);
                _c.Execute("DELETE FROM t WHERE n = '" + a[0] + "'"); /*sink*/
                var b = new Dictionary<string, string>();
                b["k"] = q;
                _c.Execute("DELETE FROM t WHERE n = '" + b["k"] + "'"); /*sink*/
                var c = new List<string>();
                c.AddRange(more);
                _c.Execute("DELETE FROM t WHERE n = '" + c.First() + "'"); /*sink*/
                var d = new List<string>();
                d.Add("fixed");
                _c.Execute("DELETE FROM t WHERE n = '" + d[0] + "'");
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_collection_field_written_in_a_request_is_request_data_where_that_request_reads_it() => Expect("""
        public class ItemsController : ControllerBase
        {
            private static readonly List<string> Recent = new();
            private readonly SqlConnection _c = new();
            public IActionResult Add(string q)
            {
                Recent.Add(q);
                Replay();
                return Ok();
            }
            private void Replay()
            {
                foreach (var r in Recent) _c.Execute("DELETE FROM t WHERE n = '" + r + "'"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_failed_body_still_has_its_lambdas_analysed()
    {
        const string code = """
            public static class Routes
            {
                public static void Map(WebApplication app)
                {
                    app.MapGet("/t", (string q, SqlConnection c) => c.Execute("DELETE FROM t WHERE n = '" + q + "'")); /*sink*/
                }
            }
            """;
        var engine = new TaintEngine(Snippet.Models, Snippet.Options)
        {
            BeforeBody = m => { if (m?.Name == "Map") throw new InvalidOperationException("injected"); },
        };
        var result = engine.Analyze(Snippet.Compile(code), CancellationToken.None);
        Assert.Equal(1, result.Stats.FailedMethods);
        Assert.Equal(Snippet.Marked(code), result.Findings.Where(f => f.Sink.SourceTree!.FilePath == "Snippet.cs").Select(f => f.Sink.GetLineSpan().StartLinePosition.Line + 1).ToList());
    }
}
