namespace Qualor.Taint.Tests.Intraprocedural;

/// The shipped csharp.xss model on shapes the OpenGrep fixture does not hold (Task 10 review, fix round 1).
public sealed class XssModelTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.xss"));

    [Fact]
    public void AppendHtml_of_a_tag_helper_content_is_a_sink_as_is_the_builder_interface() => Expect("""
        using Microsoft.AspNetCore.Html;
        using Microsoft.AspNetCore.Razor.TagHelpers;
        public class PagesController : ControllerBase
        {
            public IActionResult Show(string q)
            {
                TagHelperContent content = new DefaultTagHelperContent();
                content.AppendHtml(q); /*sink*/
                var concrete = new DefaultTagHelperContent();
                concrete.AppendHtml("<b>" + q + "</b>"); /*sink*/
                IHtmlContentBuilder builder = new HtmlContentBuilder();
                builder.AppendHtml(q); /*sink*/
                content.Append(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_PathString_turned_into_text_is_URI_escaped_wherever_it_flows() => Expect("""
        public class PagesController : ControllerBase
        {
            public IActionResult Show()
            {
                Content(Request.Path, "text/html");
                Content("<p>" + Request.Path.ToString() + "</p>", "text/html");
                Content("<p>" + Request.PathBase.ToUriComponent() + "</p>", "text/html");
                string p = Request.Path;
                Content("<p>" + p + "</p>", "text/html");
                Content($"<a href=\"{Request.Path}\">x</a>", "text/html");
                Content("<a href=\"" + Request.PathBase + "/home\">x</a>", "text/html");
                Content("<p>" + Request.Path.Value + "</p>", "text/html"); /*sink*/
                var held = Request.Path;
                Content("<p>" + held.Value + "</p>", "text/html"); /*sink*/
                Content("<p>" + Request.Query["q"] + "</p>", "text/html"); /*sink*/
                return Ok();
            }
        }
        """);
}
