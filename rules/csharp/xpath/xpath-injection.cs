using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Xml.Xsl;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

var app = WebApplication.Create(args);
var catalog = new XmlDocument();
catalog.Load("catalog.xml");

// Minimal APIs: a title from the query string in an XPath expression.
app.MapGet("/books", (string title) =>
{
    // ruleid: csharp.xpath-injection
    var nodes = catalog.SelectNodes("//book[title='" + title + "']");
    return Results.Ok(nodes?.Count);
});

app.MapGet("/books/{id}", (string id, int edition) =>
{
    // ruleid: csharp.xpath-injection
    var node = catalog.DocumentElement!.SelectSingleNode($"//book[@id='{id}']");
    // A number cannot leave the predicate.
    // ok: csharp.xpath-injection
    var byEdition = catalog.SelectNodes("//book[@edition=" + edition + "]");
    return Results.Ok(node?.InnerText);
});

app.MapPost("/books/search", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var author = form["author"].ToString();
    var document = new XPathDocument("catalog.xml");
    var navigator = document.CreateNavigator();
    // ruleid: csharp.xpath-injection
    var books = navigator.Select("//book[author='" + author + "']");
    // ruleid: csharp.xpath-injection
    var count = navigator.Evaluate("count(//book[author='" + author + "'])");
    return Results.Ok(count);
});

// A lambda given to another API is not a request handler.
Retry.Run("warmup", (string title) =>
{
    // ok: csharp.xpath-injection
    catalog.SelectNodes("//book[title='" + title + "']");
});

app.Run();

public record BookQuery(string Title, string Author);
public enum Genre { Novel, Poetry }

[ApiController]
[Route("api/[controller]")]
public class CatalogController : ControllerBase
{
    private static readonly Dictionary<string, string> Fields = new() { ["title"] = "title", ["author"] = "author/last-name" };

    private readonly XmlDocument _catalog;
    private readonly IRepository _repository;

    public CatalogController(XmlDocument catalog, IRepository repository)
    {
        _catalog = catalog;
        _repository = repository;
    }

    // XmlNode.SelectNodes and SelectSingleNode, with and without a namespace manager.
    [HttpGet("by-author")]
    public IActionResult ByAuthor(string lastName)
    {
        var nsmgr = new XmlNamespaceManager(_catalog.NameTable);
        nsmgr.AddNamespace("bk", "urn:samples");
        // ruleid: csharp.xpath-injection
        var books = _catalog.SelectNodes("//bk:book[bk:author/bk:last-name='" + lastName + "']", nsmgr);
        XmlNode root = _catalog.DocumentElement!;
        // ruleid: csharp.xpath-injection
        var first = root.SelectSingleNode(string.Format("//book[author/last-name='{0}']", lastName));
        var query = "//book[author/last-name='" + lastName + "']";
        // ruleid: csharp.xpath-injection
        var again = _catalog.SelectNodes(query);
        return Ok(books?.Count);
    }

    [HttpPost("query")]
    public IActionResult Query([FromBody] BookQuery body)
    {
        // ruleid: csharp.xpath-injection
        var nodes = _catalog.SelectNodes("//book[title='" + body.Title + "']");
        return Ok(nodes?.Count);
    }

    // The request object, a StringBuilder and a compiled expression.
    [HttpGet("raw")]
    public IActionResult Raw()
    {
        var title = Request.Query["title"].ToString();
        var sb = new StringBuilder("//book[title='");
        sb.Append(title).Append("']");
        // ruleid: csharp.xpath-injection
        var nodes = _catalog.SelectNodes(sb.ToString());
        // ruleid: csharp.xpath-injection
        var expression = XPathExpression.Compile("//book[@genre='" + Request.Headers["X-Genre"] + "']");
        XPathNavigator navigator = _catalog.CreateNavigator()!;
        // Selecting with the compiled expression is not reported again.
        // ok: csharp.xpath-injection
        var selected = navigator.Select(expression);
        // ruleid: csharp.xpath-injection
        XPathExpression compiled = navigator.Compile("//book[@isbn='" + Request.Cookies["isbn"] + "']");
        // ok: csharp.xpath-injection
        var price = navigator.Evaluate(compiled);
        // ruleid: csharp.xpath-injection
        var matches = navigator.Matches("book[@genre='" + title + "']");
        // ruleid: csharp.xpath-injection
        var single = _catalog.CreateNavigator()!.SelectSingleNode("//book[title='" + title + "']");
        // ruleid: csharp.xpath-injection
        var plain = new XPathDocument("catalog.xml").CreateNavigator().Select("//book[title='" + title + "']");
        // ruleid: csharp.xpath-injection
        var other = _catalog.CreateNavigator()!.Evaluate("//book[title='" + title + "']");
        return Ok(nodes?.Count);
    }

    // LINQ to XML's XPath extension methods.
    [HttpGet("linq")]
    public IActionResult Linq(string title)
    {
        var document = XDocument.Load("catalog.xml");
        // ruleid: csharp.xpath-injection
        var elements = document.XPathSelectElements("//book[title='" + title + "']");
        // ruleid: csharp.xpath-injection
        var element = document.Root!.XPathSelectElement($"book[title='{title}']");
        // ruleid: csharp.xpath-injection
        var value = document.XPathEvaluate("string(//book[title='" + title + "']/price)");
        // ok: csharp.xpath-injection
        var all = document.XPathSelectElements("//book");
        return Ok(value);
    }

    // Safe forms: numbers, an allow-list, a constant, an XPath variable from an XsltContext.
    [HttpGet("safe")]
    public IActionResult Safe(string id, string field, string title, Genre genre)
    {
        // ok: csharp.xpath-injection
        _catalog.SelectNodes("//book[@id=" + int.Parse(id) + "]");
        // ok: csharp.xpath-injection
        _catalog.SelectNodes("//book/" + Fields[field]);
        // ok: csharp.xpath-injection
        _catalog.SelectNodes("//book[@genre='" + genre + "']");
        // ok: csharp.xpath-injection
        _catalog.SelectNodes("//book[title='Emma']");
        var expression = XPathExpression.Compile("//book[title=$title]");
        expression.SetContext(new TitleContext(title));
        XPathNavigator navigator = _catalog.CreateNavigator()!;
        // ok: csharp.xpath-injection
        var books = navigator.Select(expression);
        return Ok();
    }

    // Look-alikes: a repository's Select and Evaluate, a node's name lookups.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string name)
    {
        // ok: csharp.xpath-injection
        var rows = _repository.Select(name);
        // ok: csharp.xpath-injection
        var score = _repository.Evaluate(name);
        // ok: csharp.xpath-injection
        var element = _catalog.GetElementsByTagName(name);
        XPathNavigator navigator = _catalog.CreateNavigator()!;
        // ok: csharp.xpath-injection
        var children = navigator.SelectChildren(name, "");
        // The value read from the selected node is no expression.
        // ok: csharp.xpath-injection
        var node = _catalog.SelectSingleNode("//book[1]")?.Attributes?[name];
        return Ok();
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried(string other)
    {
        // todoruleid: csharp.xpath-injection
        _catalog.SelectNodes(TitleOf(Request));
        // todoruleid: csharp.xpath-injection
        _catalog.SelectNodes("//book[title='" + Title + "']");
        // todoruleid: csharp.xpath-injection
        _catalog.SelectNodes("//book[title='" + Author + "']");
        if (!Fields.ContainsKey(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.xpath-injection
        _catalog.SelectNodes("//book/" + other);
        return Ok();
    }

    [HttpGet("prio")]
    public IActionResult Prio(Level level, string region, string other)
    {
        // todook: csharp.xpath-injection
        _catalog.SelectNodes("//book[@level='" + level + "']");
        if (region != "eu" && region != "us")
        {
            return BadRequest();
        }
        // todook: csharp.xpath-injection
        _catalog.SelectNodes("//book[@region='" + region + "']");
        var chosen = Enumerable.Contains(Fields.Keys, other) ? other : "title";
        // todook: csharp.xpath-injection
        _catalog.SelectNodes("//book/" + chosen);
        return Ok();
    }

    [NonAction]
    public XmlNodeList? Find(string xpath)
    {
        // ok: csharp.xpath-injection
        return _catalog.SelectNodes(xpath);
    }

    private static string TitleOf(HttpRequest request) => "//book[title='" + request.Query["t"] + "']";

    private string Title => Request.Query["title"].ToString();

    private string Author
    {
        get { return Request.Headers["X-Author"].ToString(); }
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class BookEndpoints
{
    public static IEndpointRouteBuilder MapBooks(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/books/find", (BookQuery query, XmlDocument catalog) =>
        {
            // todoruleid: csharp.xpath-injection
            return Results.Ok(catalog.SelectNodes("//book[title='" + query.Title + "']")?.Count);
        });
        routes.MapGet("/books/by-title", ByTitle);
        routes.MapGet("/books/other", OtherHandlers.ByTitle);
        return routes;
    }

    public static IResult ByTitle(string title, XmlDocument catalog)
    {
        // ruleid: csharp.xpath-injection
        return Results.Ok(catalog.SelectNodes("//book[title='" + title + "']")?.Count);
    }
}

public static class OtherHandlers
{
    public static IResult ByTitle(string title, XmlDocument catalog)
    {
        // todoruleid: csharp.xpath-injection
        return Results.Ok(catalog.SelectNodes("//book[title='" + title + "']")?.Count);
    }
}

public abstract class AppBase : ControllerBase
{
}

public class ShelfController : AppBase
{
    private readonly XmlDocument _shelf = new();

    public IActionResult Find(string title)
    {
        // todoruleid: csharp.xpath-injection
        return Ok(_shelf.SelectNodes("//book[title='" + title + "']"));
    }
}

// Razor Pages: a [BindProperty] property and a handler parameter.
public class SearchModel : PageModel
{
    private readonly XmlDocument _catalog;

    public SearchModel(XmlDocument catalog) => _catalog = catalog;

    [BindProperty]
    public string Title { get; set; } = "";

    public void OnPost()
    {
        // ruleid: csharp.xpath-injection
        _catalog.SelectNodes("//book[title='" + Title + "']");
    }

    public void OnGetAuthor(string author)
    {
        // ruleid: csharp.xpath-injection
        _catalog.SelectSingleNode("//book[author='" + author + "']");
    }
}

// An XsltContext that supplies the value of $title as an XPath variable.
public class TitleContext : XsltContext
{
    private readonly string _title;

    public TitleContext(string title) => _title = title;

    public override IXsltContextVariable ResolveVariable(string prefix, string name) => new TitleVariable(_title);

    public override IXsltContextFunction ResolveFunction(string prefix, string name, XPathResultType[] argTypes) => throw new NotSupportedException();

    public override bool PreserveWhitespace(XPathNavigator node) => false;

    public override int CompareDocument(string baseUri, string nextbaseUri) => 0;

    public override bool Whitespace => false;
}

// A plain service: its parameters are not request data.
public class CatalogReader
{
    private readonly XmlDocument _catalog = new();

    public XmlNodeList? Find(string xpath)
    {
        // ok: csharp.xpath-injection
        return _catalog.SelectNodes(xpath);
    }
}

public interface IRepository
{
    object Select(string name);
    object Evaluate(string name);
}

public enum Level { Low, High }
