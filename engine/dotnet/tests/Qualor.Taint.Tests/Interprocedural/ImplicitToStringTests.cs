using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 8 review N1: an object used where a string is built is its ToString() result.
public sealed class ImplicitToStringTests
{
    private const string Types = """
        public class Ticket
        {
            public Ticket(string reference) => Reference = reference;
            public string Reference { get; }
            public override string ToString() => Reference;
        }
        public class Plain
        {
            public Plain(string reference) => Reference = reference;
            public string Reference { get; }
        }
        public struct Tag
        {
            public string Text;
            public override string ToString() => Text;
        }
        """;

    private static string Code(string body) => Types + """
        [ApiController]
        public class C : ControllerBase
        {
            private readonly SqlConnection _conn = new();
            [HttpGet("a")]
            public IActionResult A(string q)
            {
        """ + body + """

                return Ok();
            }
        }
        """;

    [Fact]
    public void An_interpolated_object_with_a_tainted_ToString_reaches_the_sink()
    {
        var code = Code("""
                var t = new Ticket(q);
                new SqlCommand($"SELECT * FROM T WHERE R = '{t}'", _conn).ExecuteNonQuery(); /*sink*/
        """);
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));
    }

    [Fact]
    public void A_concatenated_object_with_a_tainted_ToString_reaches_the_sink()
    {
        var code = Code("""
                var t = new Ticket(q);
                new SqlCommand("SELECT * FROM T WHERE R = '" + t + "'", _conn).ExecuteNonQuery(); /*sink*/
        """);
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));
    }

    [Fact]
    public void A_struct_with_a_tainted_ToString_reaches_the_sink()
    {
        var code = Code("""
                var t = new Tag { Text = q };
                new SqlCommand($"SELECT * FROM T WHERE R = '{t}'", _conn).ExecuteNonQuery(); /*sink*/
        """);
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));
    }

    [Fact]
    public void An_object_without_a_ToString_override_or_with_a_clean_one_stays_quiet()
    {
        var code = Code("""
                var p = new Plain(q);
                new SqlCommand($"SELECT * FROM T WHERE R = '{p}'", _conn).ExecuteNonQuery();
                var t = new Ticket("fixed");
                new SqlCommand($"SELECT * FROM T WHERE R = '{t}'", _conn).ExecuteNonQuery();
                new SqlCommand("SELECT * FROM T WHERE R = '" + t + "'", _conn).ExecuteNonQuery();
        """);
        Assert.Empty(Snippet.Findings(code));
    }
}
