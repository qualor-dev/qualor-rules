// System.DirectoryServices comes from a global using in another file (GlobalUsings.cs); a few
// lines below write its names out in full.
using System.DirectoryServices.Protocols;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

var app = WebApplication.Create(args);

// Minimal APIs: DirectorySearcher's Filter property and its constructors.
app.MapGet("/directory/users", (string name) =>
{
    using var searcher = new DirectorySearcher();
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + name + "))";
    return Results.Ok(searcher.FindOne()?.Path);
});

app.MapGet("/directory/find", (string name, string mail, DirectoryEntry root) =>
{
    // ruleid: csharp.ldap-injection
    using var a = new DirectorySearcher("(cn=" + name + ")");
    // ruleid: csharp.ldap-injection
    using var b = new DirectorySearcher($"(mail={mail})", new[] { "cn", "mail" });
    // ruleid: csharp.ldap-injection
    using var c = new DirectorySearcher(string.Format("(cn={0})", name), new string[] { "cn" }, System.DirectoryServices.SearchScope.Subtree);
    // ruleid: csharp.ldap-injection
    using var d = new DirectorySearcher(root, "(cn=" + name + ")");
    // ruleid: csharp.ldap-injection
    using var e = new DirectorySearcher(root, "(cn=" + name + ")", new[] { "cn" });
    // ruleid: csharp.ldap-injection
    using var f = new DirectorySearcher(root, "(cn=" + name + ")", new[] { "cn" }, System.DirectoryServices.SearchScope.OneLevel);
    // ruleid: csharp.ldap-injection
    using var g = new DirectorySearcher(root) { Filter = "(uid=" + name + ")", SizeLimit = 10 };
    // ruleid: csharp.ldap-injection
    using var h = new System.DirectoryServices.DirectorySearcher("(cn=" + name + ")");
    var i = new DirectorySearcher(
        root,
        // ruleid: csharp.ldap-injection
        "(sn=" + name + ")");
    // ruleid: csharp.ldap-injection
    using var j = new DirectorySearcher(name);
    // ruleid: csharp.ldap-injection
    using var k = new System.DirectoryServices.DirectorySearcher(root, "(cn=" + name + ")", new[] { "cn" });
    System.DirectoryServices.DirectorySearcher legacy = new System.DirectoryServices.DirectorySearcher();
    // ruleid: csharp.ldap-injection
    legacy.Filter = "(cn=" + name + ")";
    // ruleid: csharp.ldap-injection
    using var l = new System.DirectoryServices.DirectorySearcher { Filter = "(cn=" + name + ")" };
    return Results.Ok();
});

// System.DirectoryServices.Protocols: SearchRequest's ldapFilter and Filter.
app.MapPost("/ldap/search", ([FromForm] string uid, LdapConnection connection) =>
{
    // ruleid: csharp.ldap-injection
    var request = new SearchRequest("ou=people,dc=example,dc=com", "(uid=" + uid + ")", System.DirectoryServices.Protocols.SearchScope.Subtree, "cn", "mail");
    var response = (SearchResponse)connection.SendRequest(request);
    var other = new SearchRequest();
    other.DistinguishedName = "ou=people,dc=example,dc=com";
    // ruleid: csharp.ldap-injection
    other.Filter = $"(uid={uid})";
    var third = new SearchRequest
    {
        DistinguishedName = "ou=people,dc=example,dc=com",
        // ruleid: csharp.ldap-injection
        Filter = "(|(uid=" + uid + ")(mail=" + uid + "))",
    };
    // ruleid: csharp.ldap-injection
    var fourth = new System.DirectoryServices.Protocols.SearchRequest("dc=example,dc=com", "(cn=" + uid + ")", System.DirectoryServices.Protocols.SearchScope.Base);
    return Results.Ok(response.Entries.Count);
});

// The request object itself.
app.MapGet("/directory/lookup", (HttpRequest request) =>
{
    using var searcher = new DirectorySearcher();
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(cn=" + request.Query["cn"] + ")";
    return Results.Ok();
});

app.MapGet("/directory/me", (HttpContext context) =>
{
    using var searcher = new DirectorySearcher();
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(userPrincipalName=" + context.Request.Headers["X-User"] + ")";
    return Results.Ok();
});

// Safe forms in a Minimal API: a constant filter, a number, the LDAP filter encoder the OWASP LDAP
// Injection Prevention Cheat Sheet names (Encoder.LdapFilterEncode, AntiXSS).
app.MapGet("/directory/safe", (string name, string id) =>
{
    using var searcher = new DirectorySearcher();
    // ok: csharp.ldap-injection
    searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
    // ok: csharp.ldap-injection
    searcher.Filter = "(employeeID=" + int.Parse(id) + ")";
    // ok: csharp.ldap-injection
    searcher.Filter = "(cn=" + Encoder.LdapFilterEncode(name) + ")";
    // ok: csharp.ldap-injection
    searcher.Filter = $"(sn={Encoder.LdapFilterEncode(name)})";
    var encoded = Encoder.LdapFilterEncode(name);
    // ok: csharp.ldap-injection
    using var other = new DirectorySearcher("(cn=" + encoded + ")");
    // The attributes to load and the search scope are no filter.
    // ok: csharp.ldap-injection
    searcher.PropertiesToLoad.Add(name);
    // ok: csharp.ldap-injection
    using var props = new DirectorySearcher("(objectClass=user)", new[] { name });
    var attributes = new string[] { name, "cn" };
    // ok: csharp.ldap-injection
    using var held = new DirectorySearcher("(objectClass=user)", attributes, System.DirectoryServices.SearchScope.Subtree);
    // ok: csharp.ldap-injection
    using var listedInPlace = new DirectorySearcher("(objectClass=user)", new string[] { name });
    // An attribute list from a helper is taken for a filter after a filter (Known limit).
    // todook: csharp.ldap-injection
    using var listed = new DirectorySearcher("(objectClass=user)", AttributesFor(name));
    return Results.Ok();
});

// An encoder sanitizes only the value it returns: a discarded result, or the raw value next to
// the encoded one, is still request data.
app.MapGet("/directory/half", (string name) =>
{
    using var searcher = new DirectorySearcher();
    Encoder.LdapFilterEncode(name);
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(cn=" + name + ")";
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(|(cn=" + Encoder.LdapFilterEncode(name) + ")(sn=" + name + "))";
    // Distinguished-name encoding (RFC 4514) leaves '*', '(' and ')' as they are.
    // ruleid: csharp.ldap-injection
    searcher.Filter = "(cn=" + Encoder.LdapDistinguishedNameEncode(name) + ")";
    // A sink inside the encoder's argument is still checked: only the encoder's value is clean.
    // ruleid: csharp.ldap-injection
    var label = Encoder.LdapFilterEncode(Describe(new DirectorySearcher("(cn=" + name + ")")));
    return Results.Ok();
});

// A lambda given to another API is not a request handler.
Retry.Run("sync", (string name) =>
{
    using var searcher = new DirectorySearcher();
    // ok: csharp.ldap-injection
    searcher.Filter = "(cn=" + name + ")";
});

// A complex type bound implicitly from the JSON body cannot be told from a DI service without
// types: not a source (Known limit).
app.MapPost("/directory/query", (UserQuery query) =>
{
    using var searcher = new DirectorySearcher();
    // todoruleid: csharp.ldap-injection
    searcher.Filter = "(cn=" + query.Name + ")";
    return Results.Ok();
});

app.MapGet("/directory/other", DirectoryHandlers.Find);

app.Run();

static string[] AttributesFor(string extra)
{
    return new[] { "cn", extra };
}

static string Describe(DirectorySearcher searcher)
{
    return searcher.Filter;
}

public record UserQuery(string Name, string Department);

public enum Status { Active, Disabled }

// A handler declared in another class is not followed (Known limit).
public static class DirectoryHandlers
{
    public static IResult Find(string name)
    {
        using var searcher = new DirectorySearcher();
        // todoruleid: csharp.ldap-injection
        searcher.Filter = "(cn=" + name + ")";
        return Results.Ok();
    }
}

[ApiController]
[Route("api/[controller]")]
public class DirectoryController : ControllerBase
{
    private static readonly Dictionary<string, string> Departments = new() { ["sales"] = "Sales", ["it"] = "IT" };
    private static readonly HashSet<string> Classes = new() { "user", "group", "contact" };

    private readonly DirectorySearcher _searcher;
    private readonly LdapConnection _connection;
    private readonly IDirectoryCache _cache;

    public DirectoryController(LdapConnection connection, IDirectoryCache cache)
    {
        _searcher = new DirectorySearcher();
        _connection = connection;
        _cache = cache;
    }

    // Action parameters, a body DTO, headers and cookies.
    [HttpGet("users/{account}")]
    public IActionResult FindUser(string account, [FromQuery] string department, [FromHeader(Name = "X-Mail")] string mail)
    {
        // ruleid: csharp.ldap-injection
        _searcher.Filter = "(sAMAccountName=" + account + ")";
        // ruleid: csharp.ldap-injection
        this._searcher.Filter = $"(&(objectClass=user)(department={department}))";
        var filter = "(mail=" + mail + ")";
        // ruleid: csharp.ldap-injection
        _searcher.Filter = filter;
        return Ok(_searcher.FindAll().Count);
    }

    [HttpPost("query")]
    public IActionResult Query([FromBody] UserQuery query)
    {
        // ruleid: csharp.ldap-injection
        var request = new SearchRequest("dc=example,dc=com", "(&(cn=" + query.Name + ")(department=" + query.Department + "))", System.DirectoryServices.Protocols.SearchScope.Subtree);
        return Ok(_connection.SendRequest(request));
    }

    [HttpGet("cookie")]
    public IActionResult Cookie()
    {
        var builder = new StringBuilder("(&(objectClass=user)(cn=");
        builder.Append(Request.Cookies["user"]);
        builder.Append("))");
        // ruleid: csharp.ldap-injection
        _searcher.Filter = builder.ToString();
        if (Request.Query.TryGetValue("group", out var group))
        {
            // ruleid: csharp.ldap-injection
            _searcher.Filter = "(memberOf=" + group + ")";
        }
        var form = Request.Form["name"].ToString();
        // ruleid: csharp.ldap-injection
        _searcher.Filter = string.Concat("(cn=", form, ")");
        return Ok();
    }

    // Safe forms: numbers, GUIDs, enums of this file, allow-lists, the encoder.
    [HttpGet("safe")]
    public IActionResult Safe(int employee, Guid id, Status status, string department, string kind, string name)
    {
        // ok: csharp.ldap-injection
        _searcher.Filter = "(employeeNumber=" + employee + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(objectGUID=" + id + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(accountStatus=" + status + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(department=" + Departments[department] + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(department=" + Departments.GetValueOrDefault(department, "Sales") + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(objectClass=" + (Classes.Contains(kind) ? kind : "user") + ")";
        // ok: csharp.ldap-injection
        _searcher.Filter = "(cn=" + Encoder.LdapFilterEncode(name) + ")";
        return Ok();
    }

    [HttpGet("guarded")]
    public IActionResult Guarded(string kind)
    {
        if (!Classes.Contains(kind))
        {
            return BadRequest();
        }
        // ok: csharp.ldap-injection
        _searcher.Filter = "(objectClass=" + kind + ")";
        return Ok();
    }

    // Look-alikes: a Filter property of other objects, and a cache with a Filter method.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string term)
    {
        var grid = new GridQuery();
        // ok: csharp.ldap-injection
        grid.Filter = "(cn=" + term + ")";
        // ok: csharp.ldap-injection
        var options = new GridQuery { Filter = term };
        // ok: csharp.ldap-injection
        _cache.Filter("(cn=" + term + ")");
        return Ok(grid);
    }

    // Only the search filter is a sink (Known limit): a distinguished name built from request
    // data (the search root, the base of a SearchRequest) is not reported.
    [HttpGet("tree")]
    public IActionResult Tree(string ou)
    {
        // todoruleid: csharp.ldap-injection
        var root = new DirectoryEntry("LDAP://OU=" + ou + ",DC=example,DC=com");
        // ok: csharp.ldap-injection
        using var searcher = new DirectorySearcher(root);
        // ok: csharp.ldap-injection
        using var scoped = new DirectorySearcher(new DirectoryEntry("LDAP://OU=" + ou + ",DC=example,DC=com"), "(objectClass=user)");
        // ok: csharp.ldap-injection
        using var qualified = new DirectorySearcher(new System.DirectoryServices.DirectoryEntry("LDAP://OU=" + ou + ",DC=example,DC=com"));
        // todoruleid: csharp.ldap-injection
        var request = new SearchRequest("OU=" + ou + ",DC=example,DC=com", "(objectClass=user)", System.DirectoryServices.Protocols.SearchScope.OneLevel);
        // A search root from a helper is taken for a filter in the one-argument constructor
        // (Known limit).
        // todook: csharp.ldap-injection
        using var helped = new DirectorySearcher(RootFor(ou));
        return Ok();
    }

    // A hand-written escaper is not recognised (Known limit): its result is still reported.
    [HttpGet("escaped")]
    public IActionResult Escaped(string name)
    {
        // todook: csharp.ldap-injection
        _searcher.Filter = "(cn=" + EscapeFilterValue(name) + ")";
        // So is LdapFilterEncode reached through another qualified class name: only the name
        // Encoder.LdapFilterEncode counts.
        // todook: csharp.ldap-injection
        _searcher.Filter = "(cn=" + Acme.Text.Encoder.LdapFilterEncode(name) + ")";
        return Ok();
    }

    // The shared source block's limits: helpers and properties, enums declared later, other
    // checks.
    [HttpGet("limits")]
    public IActionResult Limits(Level level, string region, string kind)
    {
        // todoruleid: csharp.ldap-injection
        _searcher.Filter = "(cn=" + NameOf(Request) + ")";
        // todoruleid: csharp.ldap-injection
        _searcher.Filter = "(cn=" + Account + ")";
        // todoruleid: csharp.ldap-injection
        _searcher.Filter = "(cn=" + Office + ")";
        // todook: csharp.ldap-injection
        _searcher.Filter = "(level=" + level + ")";
        if (region != "eu" && region != "us")
        {
            return BadRequest();
        }
        // todook: csharp.ldap-injection
        _searcher.Filter = "(c=" + region + ")";
        var chosen = Enumerable.Contains(Classes, kind) ? kind : "user";
        // todook: csharp.ldap-injection
        _searcher.Filter = "(objectClass=" + chosen + ")";
        return Ok();
    }

    [HttpGet("again")]
    public IActionResult Again(string kind)
    {
        if (!Classes.Contains(kind)) return BadRequest();
        kind = Request.Query["again"].ToString();
        // todoruleid: csharp.ldap-injection
        _searcher.Filter = "(objectClass=" + kind + ")";
        return Ok();
    }

    [NonAction]
    public void Configure(string filter)
    {
        // ok: csharp.ldap-injection
        _searcher.Filter = filter;
    }

    private static DirectoryEntry RootFor(string ou)
    {
        return new DirectoryEntry("LDAP://OU=" + ou + ",DC=example,DC=com");
    }

    private static string EscapeFilterValue(string value)
    {
        return value.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
    }

    private static string NameOf(HttpRequest request) => request.Query["name"].ToString();

    private string Account => Request.Headers["X-Account"].ToString();

    private string Office
    {
        get { return Request.Query["office"].ToString(); }
    }
}

// A controller whose base class is named otherwise is not recognised (Known limit).
public abstract class AppBase : ControllerBase
{
}

public class PeopleController : AppBase
{
    public IActionResult Find(string name)
    {
        using var searcher = new DirectorySearcher();
        // todoruleid: csharp.ldap-injection
        searcher.Filter = "(cn=" + name + ")";
        return Ok();
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class PeopleSearchModel : PageModel
{
    private readonly LdapConnection _connection;

    public PeopleSearchModel(LdapConnection connection) => _connection = connection;

    [BindProperty]
    public string Surname { get; set; } = "";

    public void OnPost()
    {
        var request = new SearchRequest();
        // ruleid: csharp.ldap-injection
        request.Filter = "(sn=" + Surname + ")";
        _connection.SendRequest(request);
    }

    public void OnGetByMail(string mail)
    {
        using var searcher = new DirectorySearcher();
        // ruleid: csharp.ldap-injection
        searcher.Filter = "(mail=" + mail + ")";
    }
}

// A plain service: its parameters are not request data.
public class DirectoryService
{
    private readonly LdapConnection _connection;

    public DirectoryService(LdapConnection connection) => _connection = connection;

    public SearchResponse Find(string filter)
    {
        // ok: csharp.ldap-injection
        return (SearchResponse)_connection.SendRequest(new SearchRequest("dc=example,dc=com", filter, System.DirectoryServices.Protocols.SearchScope.Subtree));
    }
}

public class GridQuery
{
    public string Filter { get; set; } = "";
}

public interface IDirectoryCache
{
    void Filter(string expression);
}

public enum Level { Low, High }

// A project's own class named Encoder whose LdapFilterEncode does not escape is taken for the
// AntiXSS encoder, since the encoder is matched by its name (Known limit).
namespace Acme.Directory
{
    using Acme.Text;

    [ApiController]
    public class StaffController : ControllerBase
    {
        private readonly DirectorySearcher _searcher = new DirectorySearcher();

        [HttpGet("staff")]
        public IActionResult Find(string name)
        {
            // todoruleid: csharp.ldap-injection
            _searcher.Filter = "(cn=" + Encoder.LdapFilterEncode(name) + ")";
            return Ok();
        }
    }
}

// Another library's SearchRequest declared in a file that also imports
// System.DirectoryServices.Protocols: OpenGrep resolves the name through the using directive, so
// its Filter is reported in an object initializer (Known limit).
namespace Acme.Catalog
{
    public class SearchRequest
    {
        public string Filter { get; set; } = "";
    }

    [ApiController]
    public class CatalogController : ControllerBase
    {
        [HttpGet("catalog")]
        public IActionResult Search(string term)
        {
            // todook: csharp.ldap-injection
            var request = new SearchRequest { Filter = term };
            return Ok(request);
        }
    }
}
