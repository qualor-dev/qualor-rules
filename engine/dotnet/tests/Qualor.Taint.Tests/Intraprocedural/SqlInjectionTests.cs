namespace Qualor.Taint.Tests.Intraprocedural;

/// The intraprocedural core on csharp.sql-injection: the shared ASP.NET Core sources, the SQL sinks and sanitizers, and
/// the control flow the CFG lowers (throw expressions, conditionals, switch expressions, conditional access).
public sealed class SqlInjectionTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void A_FromQuery_string_concatenated_into_a_SqlCommand_is_reported_at_the_constructor() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var cmd = new SqlCommand("SELECT * FROM t WHERE n = '" + q + "'", c); /*sink*/
                cmd.ExecuteReader();
            }
        }
        """);

    [Fact]
    public void SqlParameter_and_AddWithValue_are_not_reported() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var cmd = new SqlCommand("SELECT * FROM t WHERE n = @n AND m = @m", c);
                cmd.Parameters.AddWithValue("@n", q);
                cmd.Parameters.Add(new SqlParameter("@m", q));
                cmd.ExecuteReader();
            }
        }
        """);

    [Fact]
    public void An_int_a_Guid_and_a_nullable_long_interpolated_are_not_reported() => Expect("""
        public class ProductsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Get(int id, Guid tenant, long? page)
            {
                var cmd = new SqlCommand($"SELECT * FROM p WHERE id = {id} AND t = '{tenant}' OFFSET {page}", _c);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_throw_expression_null_check_before_the_sink_does_not_hide_it() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var v = q ?? throw new ArgumentNullException(nameof(q));
                c.Execute("DELETE FROM t WHERE n = '" + v + "'"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_conditional_with_a_request_branch_is_reported() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, [FromQuery] bool cond, SqlConnection c)
            {
                var x = cond ? q : "a";
                c.Execute("SELECT * FROM t ORDER BY " + x); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_switch_expression_to_constants_is_not_reported() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var col = q switch { "price" => "unit_price", "date" => "created", _ => "name" };
                c.Execute("SELECT * FROM t ORDER BY " + col);
            }
        }
        """);

    [Fact]
    public void Request_Query_indexed_and_ToString_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Sorted()
            {
                var sort = Request.Query["sort"].ToString();
                return Ok(_c.Query<int>("SELECT 1 FROM t ORDER BY " + sort)); /*sink*/
            }
        }
        """);

    [Fact]
    public void HttpContext_Request_Query_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Delete()
            {
                var cmd = _c.CreateCommand();
                cmd.CommandText = "DELETE FROM t WHERE n = '" + HttpContext.Request.Query["n"] + "'"; /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void HttpContext_conditional_access_Request_Query_is_reported() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Delete()
            {
                var n = HttpContext?.Request.Query["n"].ToString();
                return Ok(_c.Execute("DELETE FROM t WHERE n = '" + n + "'")); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_plain_service_method_parameter_is_not_a_source() => Expect("""
        public class ReportService
        {
            private readonly SqlConnection _c = new();
            public void Run(string s)
            {
                _c.Execute("INSERT INTO runs VALUES ('" + s + "')");
            }
        }
        """);

    [Fact]
    public void A_Minimal_API_lambda_string_parameter_is_reported() => Expect("""
        var app = WebApplication.Create(args);
        app.MapGet("/u", (string name, SqlConnection c) => c.Query<User>($"SELECT * FROM u WHERE n = '{name}'")); /*sink*/
        app.Run();
        public record User(string Name);
        """);

    [Fact]
    public void A_Minimal_API_DI_service_parameter_is_not_a_source() => Expect("""
        var app = WebApplication.Create(args);
        app.MapGet("/r", (AppDb db, SqlConnection c) => c.Query<User>("SELECT * FROM " + db.Schema + ".users"));
        app.Run();
        public record User(string Name);
        public class AppDb { public string Schema { get; set; } = ""; }
        """);

    [Fact]
    public void A_BindProperty_read_in_OnPost_is_reported() => Expect("""
        public class SearchModel : PageModel
        {
            private readonly SqlConnection _c = new();
            [BindProperty]
            public string Term { get; set; } = "";
            public void OnPost()
            {
                _c.Execute("UPDATE stats SET last = '" + Term + "'"); /*sink*/
            }
        }
        """);
}
