namespace Qualor.Taint.Tests.Intraprocedural;

/// The Task 7 review's probes (fix round 1): assignments through the CFG's lvalue flow captures (C1), fields of another
/// instance (I3), exception regions (M1, M2), lambdas given to external methods (M3), inherited [NonAction] (M6).
public sealed class ReviewProbeTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void An_existing_local_reassigned_from_a_conditional_is_tainted() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, [FromQuery] string mode, SqlConnection c)
            {
                var a = "x";
                a = mode == "raw" ? q : "name";
                c.Execute("SELECT * FROM t ORDER BY " + a); /*sink*/
            }
        }
        """);

    [Fact]
    public void An_existing_local_reassigned_from_a_coalesce_is_tainted() => Expect("""
        public class C
        {
            public void M([FromQuery] string? r, SqlConnection c)
            {
                var b = "y";
                b = r ?? "name";
                c.Execute("SELECT * FROM t ORDER BY " + b); /*sink*/
            }
        }
        """);

    [Fact]
    public void An_existing_local_reassigned_from_a_switch_expression_is_tainted() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, [FromQuery] string mode, SqlConnection c)
            {
                var d = "z";
                d = mode switch { "raw" => q, _ => "name" };
                c.Execute("SELECT * FROM t ORDER BY " + d); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_coalescing_assignment_of_a_conditional_access_is_tainted() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M()
            {
                string? s = null;
                s ??= Request?.Query["x"].ToString();
                return Ok(_c.Execute("SELECT " + s)); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_field_assigned_from_a_conditional_is_tainted() => Expect("""
        public class C
        {
            private string _f = "";
            public void M([FromQuery] string q, [FromQuery] string mode, SqlConnection c)
            {
                _f = mode == "raw" ? q : "name";
                c.Execute("SELECT * FROM t ORDER BY " + _f); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_property_sink_assigned_from_a_conditional_is_reported() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, [FromQuery] bool raw, SqlConnection c)
            {
                var cmd = c.CreateCommand();
                cmd.CommandText = raw ? q : "SELECT 1"; /*sink*/
            }
        }
        """);

    [Fact]
    public void A_request_value_overwritten_by_a_conditional_of_constants_is_clean() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M()
            {
                string sort = Request.Query["sort"].ToString();
                sort = sort == "asc" ? "ASC" : "DESC";
                return Ok(_c.Execute("SELECT * FROM t ORDER BY n " + sort));
            }
        }
        """);

    [Fact]
    public void A_tuple_element_of_a_local_carries_its_value() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var t = (Name: q, Id: 1);
                c.Execute("DELETE FROM t WHERE n = '" + t.Name + "'"); /*sink*/
                c.Execute("DELETE FROM t WHERE id = " + t.Id);
            }
        }
        """);

    [Fact]
    public void A_tuple_element_write_taints_that_tuple_only() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var a = ("x", 1);
                var b = ("y", 2);
                a.Item1 = q;
                c.Execute("DELETE FROM t WHERE n = '" + a.Item1 + "'"); /*sink*/
                c.Execute("DELETE FROM t WHERE n = '" + b.Item1 + "'");
            }
        }
        """);

    [Fact]
    public void A_catch_sees_a_value_overwritten_later_in_the_try_block() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var v = "";
                try { v = q; c.Open(); v = "safe"; }
                catch (Exception) { c.Execute("INSERT INTO errors VALUES ('" + v + "')"); /*sink*/ }
            }
        }
        """);

    [Fact]
    public void A_value_written_in_a_finally_reaches_the_code_after_it() => Expect("""
        public class C
        {
            public void M([FromQuery] string q, SqlConnection c)
            {
                var s = "a";
                try { c.Open(); }
                finally { s = q; }
                c.Execute("SELECT " + s); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_lambda_given_to_an_external_method_gets_its_receivers_taint() => Expect("""
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult M([FromQuery] List<string> names)
            {
                names.ForEach(n => _c.Execute("DELETE FROM t WHERE n = '" + n + "'")); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_override_of_a_NonAction_method_is_no_action() => Expect("""
        public class BaseApi : ControllerBase
        {
            [NonAction] public virtual int Run(string t) => 0;
        }
        public class ItemsController : BaseApi
        {
            private readonly SqlConnection _c = new();
            public override int Run(string t) => _c.Execute("DELETE FROM " + t);
        }
        """);
}
