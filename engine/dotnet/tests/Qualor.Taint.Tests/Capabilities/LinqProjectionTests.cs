namespace Qualor.Taint.Tests.Capabilities;

/// Task 23: a LINQ projection's result is what its selector returns (Select, SelectMany, the value selectors of
/// ToDictionary and ToLookup), so an encoder inside the selector cleans the result; the operators that keep the source's
/// elements (Where, OrderBy, Take, Distinct, ...) still pass the source sequence on.
public sealed class LinqProjectionTests : ProbeModels
{
    private ModelSet EncodedModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Content
            args: [0]
        sanitizers:
          - method: System.Net.WebUtility.HtmlEncode
        """);

    [Fact]
    public void A_selector_that_encodes_each_element_cleans_the_projection() => Expect(EncodedModels(), """
        using System.Net;
        public class NotesController : ControllerBase
        {
            public IActionResult Show([FromQuery] List<string> notes, [FromQuery] string tail)
            {
                Content(string.Join("<br>", notes.Select(n => WebUtility.HtmlEncode(n))));
                Content(string.Join("<br>", notes.Select((n, i) => i + ". " + WebUtility.HtmlEncode(n))));
                Content(string.Join("<br>", notes.Select(n => WebUtility.HtmlEncode(n)).Distinct().Take(5)));
                Content(string.Join("<br>", notes.Select(n => n.Trim()))); /*sink*/
                Content(string.Join("<br>", notes.Select(n => WebUtility.HtmlEncode(n) + tail))); /*sink*/
                Content(string.Join("<br>", notes.Select(n => new { Text = WebUtility.HtmlEncode(n) }).Select(x => x.Text)));
                Content(string.Join("<br>", notes.Select(n => new { Text = n }).Select(x => x.Text))); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void The_operators_that_keep_the_elements_still_pass_the_sequence() => Expect(EncodedModels(), """
        public class NotesController : ControllerBase
        {
            public IActionResult Show([FromQuery] List<string> notes)
            {
                Content(string.Join(",", notes.Where(n => n.Length > 2))); /*sink*/
                Content(string.Join(",", notes.OrderBy(n => n.Length).Take(3))); /*sink*/
                Content(string.Join(",", notes.Distinct().Skip(1))); /*sink*/
                Content(notes.FirstOrDefault(n => n.StartsWith("a")) ?? ""); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void SelectMany_and_the_dictionary_value_selectors_follow_their_selectors() => Expect(EncodedModels(), """
        using System.Net;
        public class NotesController : ControllerBase
        {
            public IActionResult Show([FromQuery] List<string> notes)
            {
                Content(string.Join(",", notes.SelectMany(n => n.Split(';')))); /*sink*/
                Content(string.Join(",", notes.SelectMany(n => n.Split(';'), (n, part) => WebUtility.HtmlEncode(part))));
                Content(string.Join(",", notes.SelectMany(n => n.Split(';'), (n, part) => part))); /*sink*/
                Content(string.Join(",", notes.ToDictionary(n => n.Length, n => WebUtility.HtmlEncode(n)).Values));
                Content(string.Join(",", notes.ToDictionary(n => n, n => WebUtility.HtmlEncode(n)).Keys)); /*sink*/
                Content(string.Join(",", notes.ToDictionary(n => n.GetHashCode()).Values)); /*sink*/
                Content(string.Join(",", notes.ToLookup(n => n.Length, n => WebUtility.HtmlEncode(n)).SelectMany(g => g)));
                Content(string.Join(",", notes.ToLookup(n => n.Length).SelectMany(g => g))); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_method_group_selector_is_its_method_applied_to_the_elements() => Expect(EncodedModels(), """
        using System.Net;
        public class NotesController : ControllerBase
        {
            private static string Escape(string s) => WebUtility.HtmlEncode(s);
            private static string Keep(string s) => s;
            private string Header() => Request.Headers["X-Title"].ToString();
            private string Titled(string s) => Header() + WebUtility.HtmlEncode(s);
            public IActionResult Show([FromQuery] List<string> notes)
            {
                Content(string.Join(",", notes.Select(Escape)));
                Content(string.Join(",", notes.Select(WebUtility.HtmlEncode)));
                Content(string.Join(",", notes.Select(Keep))); /*sink*/
                Content(string.Join(",", new List<string> { "a" }.Select(Titled))); /*sink*/
                return Ok();
            }
        }
        """);

    // Ruling R-E23 (fix round 1): a selector that is a delegate parameter, a field or a local is no known selector, so
    // the sequence passes through as before Task 23. A caller's lambda was seeded with the caller's own arguments, not
    // with what the helper applies it to, and a delegate held in a field or a local was seeded by nobody. The cost is
    // the first line: an encoder given to a helper's Select is reported (FP).
    [Fact]
    public void A_selector_held_in_a_variable_or_given_by_a_caller_keeps_the_sequence() => Expect(EncodedModels(), """
        using System.Net;
        public class NotesController : ControllerBase
        {
            private static readonly Func<string, string> Same = s => s;
            private static IEnumerable<string> Map(IEnumerable<string> items, Func<string, string> f) => items.Select(f);
            private IEnumerable<string> FromHeader(Func<string, string> f) => Request.Headers["X-Notes"].ToArray().Select(f!);
            public IActionResult Show([FromQuery] List<string> notes, Func<string, string>? injected)
            {
                Content(string.Join(",", Map(notes, n => WebUtility.HtmlEncode(n)))); /*sink*/
                Content(string.Join(",", Map(notes, n => n))); /*sink*/
                Content(string.Join(",", notes.Select(injected ?? (n => n)))); /*sink*/
                Func<string, string> same = s => s;
                Content(string.Join(",", Map(notes, Same))); /*sink*/
                Content(string.Join(",", Map(notes, same))); /*sink*/
                Content(string.Join(",", notes.Select(Same))); /*sink*/
                Content(string.Join(",", FromHeader(h => h))); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_result_selector_sees_the_elements_of_the_collection_selector() => Expect(EncodedModels(), """
        using System.Net;
        public class NotesController : ControllerBase
        {
            private static string Keep(string outer, string inner) => inner;
            public IActionResult Show([FromQuery] List<string> notes)
            {
                var fixedList = new List<string> { "a", "b" };
                Content(string.Join(",", fixedList.SelectMany(f => notes, (f, n) => n))); /*sink*/
                Content(string.Join(",", from f in fixedList from n in notes select n)); /*sink*/
                Content(string.Join(",", from f in fixedList from h in Request.Headers["X-Tags"].ToArray() select f + h)); /*sink*/
                Content(string.Join(",", fixedList.SelectMany(f => notes, Keep))); /*sink*/
                Content(string.Join(",", fixedList.SelectMany(f => notes, (f, n) => WebUtility.HtmlEncode(n))));
                // A lambda's parameters are seeded alike, so the outer element takes the inner elements' data too (FP).
                Content(string.Join(",", from f in fixedList from n in notes select f)); /*sink*/
                return Ok();
            }
        }
        """);
}
