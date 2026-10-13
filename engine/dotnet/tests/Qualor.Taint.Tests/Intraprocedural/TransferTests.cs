namespace Qualor.Taint.Tests.Intraprocedural;

/// The transfer functions of the intraprocedural core: assignments and compound assignments (a property's get and set
/// patterns by the access), out arguments, receivers written by fluent builders and collection writes, loops,
/// exception regions, lambdas, and the temporary in-source call rule (replaced by summaries in Task 8).
public sealed class TransferTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void A_compound_assignment_to_CommandText_is_a_write_of_the_joined_value() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var cmd = c.CreateCommand();
                cmd.CommandText = "SELECT * FROM t WHERE n = ";
                cmd.CommandText += q; /*sink*/
            }
        }
        """);

    [Fact]
    public void An_object_initializer_CommandText_is_a_sink() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                using var cmd = new SqlCommand { CommandText = "SELECT * FROM t WHERE n = '" + q + "'", Connection = c }; /*sink*/
            }
        }
        """);

    [Fact]
    public void A_value_reassigned_to_a_constant_is_clean() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                q = "fixed";
                c.Execute("DELETE FROM t WHERE n = '" + q + "'");
            }
        }
        """);

    [Fact]
    public void A_sink_argument_on_its_own_line_is_reported_there() => Expect("""
        public class C
        {
            public int M([FromQuery] string q, SqlConnection c) => c.Execute(
                "DELETE FROM t WHERE n = '" + q + "'"); /*sink*/
        }
        """);

    [Fact]
    public void Scalar_parsing_sanitizes_and_scalar_out_values_are_clean() => Expect("""
        public enum E { A, B }
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                c.Execute("DELETE FROM t WHERE id = " + int.Parse(q));
                c.Execute("SELECT * FROM t ORDER BY " + Enum.Parse(typeof(E), q));
                if (long.TryParse(q, out var n)) c.Execute("DELETE FROM t WHERE id = " + n);
            }
        }
        """);

    [Fact]
    public void A_StringBuilder_append_chain_taints_the_builder() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var sb = new System.Text.StringBuilder("SELECT * FROM t WHERE 1 = 1");
                sb.Append(" AND n = '").Append(q).Append("'");
                c.Query<int>(sb.ToString()); /*sink*/
            }
        }
        """);

    [Fact]
    public void An_interpolated_string_given_to_a_StringBuilder_handler_taints_the_builder() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var sb = new System.Text.StringBuilder();
                sb.Append($"SELECT * FROM t WHERE n = '{q}'");
                c.Query<int>(sb.ToString()); /*sink*/
            }
        }
        """);

    [Fact]
    public void TryGetValue_on_the_request_query_taints_its_out_value() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M()
            {
                if (Request.Query.TryGetValue("owner", out var owner))
                    _c.Execute("DELETE FROM t WHERE owner = '" + owner + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_element_of_a_tainted_array_in_a_foreach_is_tainted() => Expect("""
        public class C
        {
            public void M([FromQuery] string[] names, SqlConnection c)
            {
                foreach (var n in names)
                    c.Execute("DELETE FROM t WHERE n = '" + n + "'"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_lookup_by_a_request_key_is_request_data_until_allow_lists_exist() => Expect("""
        public class C
        {
            private static readonly Dictionary<string, string> Columns = new() { ["price"] = "unit_price" };
            public void M([FromQuery] string q, SqlConnection c)
            {
                c.Execute("SELECT * FROM t ORDER BY " + Columns.GetValueOrDefault(q, "name")); /*sink*/
                c.Execute("SELECT * FROM t ORDER BY " + Columns.GetValueOrDefault("price", q)); /*sink*/
                c.Execute("SELECT * FROM t ORDER BY " + Columns[q]); /*sink*/
                if (Columns.TryGetValue(q, out var column)) c.Execute("SELECT * FROM t ORDER BY " + column); /*sink*/
                c.Execute("SELECT * FROM t ORDER BY " + Columns.GetValueOrDefault("price", "name"));
            }
        }
        """);

    [Fact]
    public void A_foreach_over_the_request_query_gives_tainted_keys_and_values() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M()
            {
                foreach (var pair in Request.Query)
                    _c.Execute("DELETE FROM t WHERE " + pair.Key + " = '" + pair.Value + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_list_a_request_value_is_added_to_is_tainted() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var list = new List<string> { "a" };
                list.Add(q);
                c.Execute("DELETE FROM t WHERE n IN ('" + string.Join("','", list) + "')"); /*sink*/
            }
        }
        """);

    [Fact]
    public void Concatenation_in_a_loop_reaches_a_fixed_point() => Expect("""
        public class C
        {
            public void M([FromQuery] string[] parts, SqlConnection c)
            {
                var sql = "SELECT 1";
                for (var i = 0; i < parts.Length; i++) sql += " UNION SELECT " + parts[i];
                c.Execute(sql); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_sink_in_a_catch_block_sees_the_try_block_state() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var v = "";
                try { v = q.Trim(); c.Open(); }
                catch (Exception) { c.Execute("INSERT INTO errors VALUES ('" + v + "')"); /*sink*/ }
            }
        }
        """);

    [Fact]
    public void An_awaited_ReadFromJsonAsync_result_is_request_data() => Expect("""
        public record Dto(string Name);
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public async Task<IActionResult> M()
            {
                var dto = await Request.ReadFromJsonAsync<Dto>();
                return Ok(await _c.ExecuteAsync("DELETE FROM t WHERE n = '" + dto!.Name + "'")); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_lambda_sees_a_captured_request_value() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                Action run = () => c.Execute("DELETE FROM t WHERE n = '" + q + "'"); /*sink*/
                run();
            }
        }
        """);

    [Fact]
    public void A_call_to_a_source_method_returns_its_arguments_taint_until_summaries_exist() => Expect("""
        public class C
        {
            private static string Wrap(string s) => "[" + s + "]";
            public void M([FromQuery] string q, SqlConnection c)
            {
                c.Execute("DELETE FROM t WHERE n = '" + Wrap(q) + "'"); /*sink*/
                c.Execute("DELETE FROM t WHERE n = '" + Wrap("fixed") + "'");
            }
        }
        """);

    [Fact]
    public void NonAction_static_and_private_controller_methods_have_no_source_parameters() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            [NonAction] public int Purge(string t) => _c.Execute("DELETE FROM " + t);
            public static int Count(string t, SqlConnection c) => c.Execute("SELECT COUNT(*) FROM " + t);
            private int Drop(string t) => _c.Execute("DROP TABLE " + t);
            public int Find(string code) => _c.Execute("SELECT * FROM t WHERE c = '" + code + "'"); /*sink*/
        }
        """);

    [Fact]
    public void The_path_starts_at_the_source_and_ends_at_the_sink()
    {
        const string code = """
            public class C
            {
                public void M([FromQuery] string q, SqlConnection c)
                {
                    var sql = "DELETE FROM t WHERE n = '" + q + "'";
                    c.Execute(sql);
                }
            }
            """;
        var path = Snippet.Analyze(code).Findings.Single().Path;
        Assert.Equal((3, 6), (path[0].Location.GetLineSpan().StartLinePosition.Line + 1, path[^1].Location.GetLineSpan().StartLinePosition.Line + 1));
    }

    [Fact]
    public void A_run_over_its_time_limit_is_incomplete()
    {
        var result = Snippet.Analyze("public class C { public void M() { } }", new TaintEngineOptions(TimeSpan.Zero, 4L << 30));
        Assert.Equal((false, "time limit of 00:00:00 exceeded"), (result.Complete, result.IncompleteReason));
    }
}
