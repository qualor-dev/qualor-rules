using System.Net;
using System.Net.Mime;
using System.Text.Encodings.Web;
using System.Text.Unicode;
// No `using Microsoft.AspNetCore.Html;`: the qualified and the short HtmlString are tested apart.
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Primitives;

var app = WebApplication.Create(args);

// Minimal APIs: request data written into an HTML response.
app.MapGet("/hello", (string name) =>
    // ruleid: csharp.xss
    Results.Content("<h1>Hello " + name + "</h1>", "text/html"));

app.MapGet("/greet", (string name) =>
{
    // ruleid: csharp.xss
    return Results.Text($"<p>Hi {name}</p>", "text/html; charset=utf-8");
});

app.MapGet("/typed", (string name) =>
{
    // ruleid: csharp.xss
    return TypedResults.Content("<p>" + name + "</p>", MediaTypeNames.Text.Html);
});

// Plain text, JSON and encoded values are not HTML.
app.MapGet("/plain", (string name) =>
{
    // ok: csharp.xss
    var a = Results.Text("Hello " + name);
    // ok: csharp.xss
    var b = Results.Content("Hello " + name, "text/plain");
    // ok: csharp.xss
    var c = Results.Json(new { name });
    // ok: csharp.xss
    var d = Results.Ok(name);
    // ok: csharp.xss
    return Results.Content("<h1>Hello " + HtmlEncoder.Default.Encode(name) + "</h1>", "text/html");
});

// The response written directly after an HTML content type.
app.MapGet("/raw", async (HttpContext context) =>
{
    var q = context.Request.Query["q"].ToString();
    context.Response.ContentType = "text/html";
    // ruleid: csharp.xss
    await context.Response.WriteAsync("<p>You searched for " + q + "</p>");
    // ok: csharp.xss
    await context.Response.WriteAsync("<p>" + WebUtility.HtmlEncode(q) + "</p>");
});

app.MapGet("/raw-text", async (HttpContext context) =>
{
    var q = context.Request.Query["q"].ToString();
    context.Response.ContentType = "text/plain";
    // ok: csharp.xss
    await context.Response.WriteAsync("You searched for " + q);
});

// A lambda given to another API is not a request handler.
Retry.Run("render", (string html) =>
{
    // ok: csharp.xss
    return new HtmlString(html);
});

app.Run();

public record Comment(string Author, string Body);
public record Link(string Path);
public enum Theme { Light, Dark }

[ApiController]
[Route("api/[controller]")]
public class PagesController : ControllerBase
{
    private static readonly HashSet<string> Sections = new() { "news", "sports" };

    private readonly HtmlEncoder _encoder;
    private readonly UrlEncoder _urlEncoder;

    public PagesController(HtmlEncoder encoder, UrlEncoder urlEncoder)
    {
        _encoder = encoder;
        _urlEncoder = urlEncoder;
    }

    // URL-encoded values: quotes, angle brackets and ampersands are percent-encoded.
    [HttpGet("links")]
    public IActionResult Links(string q)
    {
        // ok: csharp.xss
        var a = Content("<a href=\"/search?q=" + UrlEncoder.Default.Encode(q) + "\">Search</a>", "text/html");
        // ok: csharp.xss
        var b = Content("<a href=\"/search?q=" + UrlEncoder.Create(UnicodeRanges.BasicLatin).Encode(q) + "\">Search</a>", "text/html");
        // ok: csharp.xss
        var c = Content("<a href=\"/search?q=" + _urlEncoder.Encode(q) + "\">Search</a>", "text/html");
        // ok: csharp.xss
        var d = Content("<a href='/search?q=" + Uri.EscapeDataString(q) + "'>Search</a>", "text/html");
        // ok: csharp.xss
        var e = Content("<a href=\"/search?q=" + WebUtility.UrlEncode(q) + "\">Search</a>", "text/html");
        // ruleid: csharp.xss
        return Content("<a href=\"/search?q=" + q + "\">Search</a>", "text/html");
    }

    // Content with an HTML content type, in every form.
    [HttpGet("search")]
    public IActionResult Search(string q)
    {
        // ruleid: csharp.xss
        var a = Content("<p>Results for " + q + "</p>", "text/html");
        // ruleid: csharp.xss
        var b = this.Content($"<p>Results for {q}</p>", "text/html; charset=utf-8");
        // ruleid: csharp.xss
        var c = Content(string.Format("<p>{0}</p>", q), MediaTypeNames.Text.Html);
        // ruleid: csharp.xss
        var d = Content("<p>" + q + "</p>", "application/xhtml+xml");
        // ok: csharp.xss
        var e = Content("Results for " + q);
        // ok: csharp.xss
        var f = Content("{\"q\": 1}", "application/json");
        // ok: csharp.xss
        var g = Content("<p>Results for " + _encoder.Encode(q) + "</p>", "text/html");
        // ok: csharp.xss
        var h = Content("<p>Results for " + HttpUtility.HtmlEncode(q) + "</p>", "text/html");
        // ok: csharp.xss
        var i = Content("<p>Page " + int.Parse(q) + "</p>", "text/html");
        // ok: csharp.xss
        return Ok(new { q });
    }

    [HttpPost("comment")]
    public IActionResult Post([FromBody] Comment comment)
    {
        // ruleid: csharp.xss
        var html = new HtmlString("<blockquote>" + comment.Body + "</blockquote>");
        // ruleid: csharp.xss
        var qualified = new Microsoft.AspNetCore.Html.HtmlString("<cite>" + comment.Author + "</cite>");
        var result = new ContentResult
        {
            ContentType = "text/html",
            // ruleid: csharp.xss
            Content = "<p>" + comment.Author + "</p>",
            StatusCode = 200,
        };
        var reversed = new ContentResult
        {
            // ruleid: csharp.xss
            Content = "<p>" + comment.Author + "</p>",
            ContentType = MediaTypeNames.Text.Html,
        };
        var assigned = new ContentResult();
        assigned.ContentType = "text/html";
        // ruleid: csharp.xss
        assigned.Content = "<p>" + comment.Body + "</p>";
        var plain = new ContentResult
        {
            ContentType = "text/plain",
            // ok: csharp.xss
            Content = comment.Body,
        };
        return result;
    }

    // The request object, and HTML built with a builder.
    [HttpGet("profile")]
    public IActionResult Profile()
    {
        var name = Request.Query["name"].ToString();
        // ruleid: csharp.xss
        var a = Content("<h2>" + name + "</h2>", "text/html");
        // ruleid: csharp.xss
        var b = Content("<p>" + Request.Headers["Referer"] + "</p>", "text/html");
        if (Request.Cookies.TryGetValue("theme", out var theme))
        {
            // ruleid: csharp.xss
            return Content("<body class=\"" + theme + "\"></body>", "text/html");
        }
        // The path as a PathString is escaped for a URI; its Value is not.
        // ok: csharp.xss
        var c = Content("<a href=\"" + Request.PathBase + "/home\">Home</a>", "text/html");
        // ok: csharp.xss
        var d = Content($"<a href=\"{HttpContext.Request.Path}?page=2\">Next</a>", "text/html");
        // ruleid: csharp.xss
        var e = Content("<p>Not found: " + Request.Path.Value + "</p>", "text/html");
        // ruleid: csharp.xss
        var f = Content("<p>Base: " + HttpContext.Request.PathBase.Value + "</p>", "text/html");
        // A PathString held in a variable before its Value is read is not followed (Known limit).
        var held = Request.Path;
        // todoruleid: csharp.xss
        var g = Content("<p>Not found: " + held.Value + "</p>", "text/html");
        // PathString escapes for a URI, not for HTML: a quote (') passes, so a single-quoted
        // attribute or a script string is missed (Known limit).
        // todoruleid: csharp.xss
        var h = Content("<a href='" + Request.Path + "'>Reload</a>", "text/html");
        // todoruleid: csharp.xss
        var i = Content("<script>var page = '" + Request.PathBase + "';</script>", "text/html");
        var builder = new HtmlContentBuilder();
        // ruleid: csharp.xss
        builder.AppendHtml("<b>" + name + "</b>");
        // ok: csharp.xss
        builder.Append(name);
        return Ok();
    }

    // An allow-list guard: an error page that echoes the rejected value is still reported.
    [HttpGet("section")]
    public IActionResult Section(string section, Theme theme)
    {
        if (!Sections.Contains(section))
        {
            // ruleid: csharp.xss
            return Content("<p>Unknown section: " + section + "</p>", "text/html");
        }
        // ok: csharp.xss
        var page = Content("<h1>" + section + "</h1>", "text/html");
        // ok: csharp.xss
        return Content("<body class=\"" + theme + "\"></body>", "text/html");
    }

    [HttpGet("section2")]
    public IActionResult Section2(string section)
    {
        // ruleid: csharp.xss
        if (!Sections.Contains(section)) return Content("<p>Unknown " + section + "</p>", "text/html");
        // ok: csharp.xss
        return Content("<h1>" + section + "</h1>", "text/html");
    }

    // Look-alikes: a property named Content, a model's Text, a logger.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string text)
    {
        var message = new ChatMessage();
        // ok: csharp.xss
        message.Content = text;
        // ok: csharp.xss
        _logger.LogInformation("Rendered {Text}", text);
        // ok: csharp.xss
        var note = _notes.Text(text, "text/html");
        // ok: csharp.xss
        var card = _notes.Content(text, "text/html");
        return Ok();
    }

    // Every form once more: MediaTypeNames, ContentResult orders, calls over several lines.
    [HttpPost("forms")]
    public async Task<IActionResult> Forms([FromBody] Link link, string text)
    {
        // ruleid: csharp.xss
        var a = Results.Text("<p>" + text + "</p>", MediaTypeNames.Text.Html);
        // ruleid: csharp.xss
        var b = this.Content("<p>" + text + "</p>", MediaTypeNames.Text.Html);
        // ruleid: csharp.xss
        var c = Content("<a href=\"" + link.Path + "\">link</a>", "text/html");
        var d = new ContentResult
        {
            // ruleid: csharp.xss
            Content = "<p>" + text + "</p>",
            ContentType = "text/html; charset=utf-8",
        };
        var e = new ContentResult
        {
            ContentType = MediaTypeNames.Text.Html,
            // ruleid: csharp.xss
            Content = "<p>" + text + "</p>",
        };
        var f = new ContentResult();
        f.ContentType = MediaTypeNames.Text.Html;
        // ruleid: csharp.xss
        f.Content = "<p>" + text + "</p>";
        var g = new ContentResult();
        // ruleid: csharp.xss
        g.Content = "<p>" + text + "</p>";
        g.ContentType = "text/html";
        var h = new ContentResult();
        // ok: csharp.xss
        h.Content = text;
        var builder = new HtmlContentBuilder();
        // ruleid: csharp.xss
        builder.AppendHtmlLine("<li>" + text + "</li>");
        // ok: csharp.xss
        builder.AppendHtml("<li>" + HtmlEncoder.Create(UnicodeRanges.All).Encode(text) + "</li>");
        var i = Results.Content(
            // ruleid: csharp.xss
            "<p>" + text + "</p>",
            "text/html");
        var j = Content(
            // ruleid: csharp.xss
            "<p>" + text + "</p>",
            "text/html");
        builder.AppendHtml(
            // ruleid: csharp.xss
            "<li>" + text + "</li>");
        Response.ContentType = MediaTypeNames.Text.Html;
        await Response.WriteAsync(
            // ruleid: csharp.xss
            "<p>" + text + "</p>");
        return Ok();
    }

    // Known limits.
    [HttpGet("limits")]
    public async Task<IActionResult> Limits(string text, string other)
    {
        // A response written without a content type is not checked.
        // todoruleid: csharp.xss
        await Response.WriteAsync("<p>" + text + "</p>");
        // A content type held in a variable chosen at run time is not followed.
        var type = other == "html" ? "text/html" : "text/plain";
        // todoruleid: csharp.xss
        return Content("<p>" + text + "</p>", type);
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried(string other)
    {
        // todoruleid: csharp.xss
        var a = Content("<p>" + TextOf(Request) + "</p>", "text/html");
        // todoruleid: csharp.xss
        var b = Content("<p>" + Referrer + "</p>", "text/html");
        // todoruleid: csharp.xss
        var c = Content("<p>" + Channel + "</p>", "text/html");
        if (!Sections.Contains(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.xss
        return Content("<p>" + other + "</p>", "text/html");
    }

    [HttpGet("prio")]
    public IActionResult Prio(Level level, string section, string other)
    {
        // todook: csharp.xss
        var a = Content("<p>" + level + "</p>", "text/html");
        if (section != "news" && section != "sports")
        {
            return BadRequest();
        }
        // todook: csharp.xss
        var b = Content("<p>" + section + "</p>", "text/html");
        var chosen = Enumerable.Contains(Sections, other) ? other : "news";
        // todook: csharp.xss
        return Content("<p>" + chosen + "</p>", "text/html");
    }

    [NonAction]
    public IActionResult Render(string html)
    {
        // ok: csharp.xss
        return Content(html, "text/html");
    }

    private static string TextOf(HttpRequest request) => request.Query["text"].ToString();

    private string Referrer => Request.Headers["Referer"].ToString();

    private string Channel
    {
        get { return Request.Query["channel"].ToString(); }
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class CommentEndpoints
{
    public static IEndpointRouteBuilder MapCommentEndpoints(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/comments/preview", (Comment comment) =>
            // todoruleid: csharp.xss
            Results.Content("<p>" + comment.Body + "</p>", "text/html"));
        routes.MapGet("/comments/echo", Echo);
        routes.MapGet("/comments/other", OtherHandlers.Echo);
        return routes;
    }

    public static IResult Echo(string text)
    {
        // ruleid: csharp.xss
        return Results.Content("<p>" + text + "</p>", "text/html");
    }
}

public static class OtherHandlers
{
    public static IResult Echo(string text)
    {
        // todoruleid: csharp.xss
        return Results.Content("<p>" + text + "</p>", "text/html");
    }
}

public abstract class AppBase : ControllerBase
{
}

public class BannerController : AppBase
{
    public IActionResult Show(string message)
    {
        // todoruleid: csharp.xss
        return Content("<div>" + message + "</div>", "text/html");
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class GuestbookModel : PageModel
{
    [BindProperty]
    public string Message { get; set; } = "";

    public IHtmlContent? Preview { get; private set; }

    public void OnPost()
    {
        // ruleid: csharp.xss
        Preview = new HtmlString("<p>" + Message + "</p>");
        // ok: csharp.xss
        Preview = new HtmlString("<p>" + HtmlEncoder.Default.Encode(Message) + "</p>");
    }

    public IActionResult OnGetEcho(string text)
    {
        // ruleid: csharp.xss
        return Content("<p>" + text + "</p>", "text/html");
    }
}

// A tag helper writes HTML content with SetHtmlContent; its attributes are not request data.
[HtmlTargetElement("note")]
public class NoteTagHelper : TagHelper
{
    public string Text { get; set; } = "";

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        // ok: csharp.xss
        output.Content.SetHtmlContent("<em>" + Text + "</em>");
    }
}

// A view component given request data by a controller.
[Route("widgets")]
public class WidgetsController : Controller
{
    [HttpGet("{title}")]
    public IActionResult Widget(string title)
    {
        var tag = new TagBuilder("h3");
        // ruleid: csharp.xss
        tag.InnerHtml.SetHtmlContent(title);
        // ok: csharp.xss
        tag.InnerHtml.SetContent(title);
        return View(tag);
    }
}

// A plain service: its parameters are not request data.
public class Mailer
{
    public HtmlString Body(string text)
    {
        // ok: csharp.xss
        return new HtmlString("<p>" + text + "</p>");
    }
}

public enum Level { Low, High }
