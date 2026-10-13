using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;

var app = WebApplication.Create(args);

// Minimal APIs: a return URL from the query string.
app.MapGet("/signin-done", (string returnUrl) =>
{
    // ruleid: csharp.open-redirect
    return Results.Redirect(returnUrl);
});

app.MapGet("/go", (string target, bool permanent) =>
    // ruleid: csharp.open-redirect
    TypedResults.Redirect(target, permanent));

app.MapGet("/local", (string returnUrl) =>
{
    // LocalRedirect throws for a URL that is not local.
    // ok: csharp.open-redirect
    return Results.LocalRedirect(returnUrl);
});

// The HttpResponse given to a Minimal API handler.
app.MapGet("/raw", (HttpResponse response, string next) =>
{
    // ruleid: csharp.open-redirect
    response.Redirect(next);
    // ruleid: csharp.open-redirect
    response.Headers.Location = next;
    // ruleid: csharp.open-redirect
    response.Headers["Location"] = next;
    // ruleid: csharp.open-redirect
    response.Headers[HeaderNames.Location] = next;
    // ruleid: csharp.open-redirect
    response.Headers.Append("Location", next);
    // ruleid: csharp.open-redirect
    response.Headers.Append(HeaderNames.Location, next);
    // ok: csharp.open-redirect
    response.Headers.Append("Link", next);
});

app.MapGet("/checked", (string returnUrl) =>
{
    if (RedirectHttpResult.IsLocalUrl(returnUrl))
    {
        // ok: csharp.open-redirect
        return Results.Redirect(returnUrl);
    }
    // ruleid: csharp.open-redirect
    return Results.Redirect(returnUrl + "/");
});

// Middleware: the response redirected and the Location header set by hand.
app.Use(async (context, next) =>
{
    var next1 = context.Request.Query["next"].ToString();
    if (next1.Length > 0)
    {
        // ruleid: csharp.open-redirect
        context.Response.Redirect(next1);
        return;
    }
    // ruleid: csharp.open-redirect
    context.Response.Redirect(context.Request.Query["moved"], true);
    // ruleid: csharp.open-redirect
    context.Response.Headers.Location = context.Request.Query["to"].ToString();
    // ruleid: csharp.open-redirect
    context.Response.Headers["Location"] = context.Request.Headers["X-Back"].ToString();
    // ruleid: csharp.open-redirect
    context.Response.Headers.Append(HeaderNames.Location, context.Request.Form["to"].ToString());
    // ruleid: csharp.open-redirect
    context.Response.Headers.Add("location", context.Request.Cookies["last"]);
    // ruleid: csharp.open-redirect
    context.Response.Headers.Add(HeaderNames.Location, context.Request.Cookies["last"]);
    // ruleid: csharp.open-redirect
    context.Response.Headers.Append("Location", context.Request.Query["to"].ToString());
    // ruleid: csharp.open-redirect
    context.Response.Headers[HeaderNames.Location] = context.Request.Query["to"].ToString();
    // Another header is no redirect.
    // ok: csharp.open-redirect
    context.Response.Headers["X-Requested-Page"] = context.Request.Query["to"].ToString();
    // ok: csharp.open-redirect
    context.Response.Headers.Append("Content-Location", context.Request.Query["to"].ToString());
    await next(context);
});

// A lambda given to another API is not a request handler.
Retry.Run("warmup", (string url) =>
{
    // ok: csharp.open-redirect
    return Results.Redirect(url);
});

app.Run();

public record SignInForm(string UserName, string ReturnUrl);
public enum Section { Home, Orders }

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private static readonly Dictionary<string, string> Partners = new() { ["shop"] = "https://shop.example/", ["blog"] = "https://blog.example/" };

    private readonly INavigator _navigator;

    public AccountController(INavigator navigator)
    {
        _navigator = navigator;
    }

    // Controller helpers: Redirect and its permanent and method-preserving forms, RedirectResult.
    [HttpGet("login-done")]
    public IActionResult LoginDone(string returnUrl)
    {
        // ruleid: csharp.open-redirect
        return Redirect(returnUrl);
    }

    [HttpGet("moved")]
    public IActionResult Moved([FromQuery] string to, [FromQuery(Name = "m")] string mode)
    {
        if (mode == "p")
        {
            // ruleid: csharp.open-redirect
            return RedirectPermanent(to);
        }
        if (mode == "k")
        {
            // ruleid: csharp.open-redirect
            return this.RedirectPreserveMethod(to);
        }
        if (mode == "pk")
        {
            // ruleid: csharp.open-redirect
            return RedirectPermanentPreserveMethod(to);
        }
        // ruleid: csharp.open-redirect
        return new RedirectResult(to, false);
    }

    [HttpGet("moved2")]
    public IActionResult Moved2(string to)
    {
        // ruleid: csharp.open-redirect
        var a = this.Redirect(to);
        // ruleid: csharp.open-redirect
        var b = this.RedirectPermanent(to);
        // ruleid: csharp.open-redirect
        var c = RedirectPreserveMethod(to);
        // ruleid: csharp.open-redirect
        var d = this.RedirectPermanentPreserveMethod(to);
        // ruleid: csharp.open-redirect
        var e = new Microsoft.AspNetCore.Mvc.RedirectResult(to);
        // ruleid: csharp.open-redirect
        this.Response.Redirect(to);
        // ruleid: csharp.open-redirect
        HttpContext.Response.Redirect(to);
        return a;
    }

    [HttpPost("signin")]
    public IActionResult SignIn([FromBody] SignInForm form)
    {
        var target = form.ReturnUrl;
        // ruleid: csharp.open-redirect
        return Redirect(target);
    }

    // The request object.
    [HttpGet("back")]
    public IActionResult Back()
    {
        var back = Request.Query["back"].ToString();
        // ruleid: csharp.open-redirect
        Response.Redirect(back);
        if (Request.Query.TryGetValue("then", out var then))
        {
            // ruleid: csharp.open-redirect
            return Redirect(then.ToString());
        }
        // ruleid: csharp.open-redirect
        return Redirect(Request.Headers["Referer"].ToString());
    }

    // Strings built from request data: a host, a scheme, "/" or "~/" before it, a fallback.
    [HttpGet("built")]
    public IActionResult Built(string host, string path, string next)
    {
        // ruleid: csharp.open-redirect
        Response.Redirect("https://" + host + "/home");
        // ruleid: csharp.open-redirect
        Response.Redirect($"https://{host}.example/home");
        // ruleid: csharp.open-redirect
        Response.Redirect("https://partner.example" + path);
        // "/" + "/evil.example" is "//evil.example", another host.
        // ruleid: csharp.open-redirect
        Response.Redirect("/" + path);
        // ruleid: csharp.open-redirect
        Response.Redirect($"/{path}");
        // ruleid: csharp.open-redirect
        Response.Redirect("~/" + path);
        // ruleid: csharp.open-redirect
        Response.Redirect(string.Format("{0}/done", next));
        // ruleid: csharp.open-redirect
        return Redirect(next ?? "/");
    }

    // Safe forms: a fixed path or origin with request data after a separator or in the query.
    [HttpGet("fixed")]
    public IActionResult Fixed(string id, string q, string name)
    {
        // ok: csharp.open-redirect
        Response.Redirect("/orders/" + id);
        // ok: csharp.open-redirect
        Response.Redirect("/search?q=" + q);
        // ok: csharp.open-redirect
        Response.Redirect($"/orders/{id}/items");
        // ok: csharp.open-redirect
        Response.Redirect("~/orders/" + id);
        // ok: csharp.open-redirect
        Response.Redirect("https://help.example/articles/" + id);
        // ok: csharp.open-redirect
        Response.Redirect(string.Format("/orders/{0}", id));
        // ok: csharp.open-redirect
        Response.Redirect("orders/" + id);
        // ok: csharp.open-redirect
        Response.Redirect("?page=" + q);
        // ok: csharp.open-redirect
        Response.Redirect(QueryHelpers.AddQueryString("/login", "returnUrl", q));
        // ok: csharp.open-redirect
        Response.Redirect("/orders/" + int.Parse(id));
        // A percent-encoded value has no "/" or ":" left to name a host.
        // ok: csharp.open-redirect
        Response.Redirect(Uri.EscapeDataString(name));
        // ok: csharp.open-redirect
        Response.Redirect(WebUtility.UrlEncode(name) + "/details");
        // ok: csharp.open-redirect
        Response.Redirect(HttpUtility.UrlEncode(name));
        // ok: csharp.open-redirect
        Response.Redirect(UrlEncoder.Default.Encode(name));
        // A redirect written inside an encoder call is still checked.
        // ruleid: csharp.open-redirect
        var shown = Uri.EscapeDataString(new RedirectResult(name).Url);
        // An encoder's result counts, not the raw value next to it.
        Uri.EscapeDataString(name);
        // ruleid: csharp.open-redirect
        Response.Redirect(name);
        // ruleid: csharp.open-redirect
        Response.Redirect(Uri.EscapeDataString(name) + name);
        // ruleid: csharp.open-redirect
        return Redirect(QueryHelpers.AddQueryString(name, "x", "1"));
    }

    // LocalRedirect, generated local URLs and an allow-list.
    [HttpGet("safe")]
    public IActionResult Safe(string returnUrl, string partner, string action)
    {
        if (partner != null)
        {
            // ok: csharp.open-redirect
            return Redirect(Partners[partner]);
        }
        if (action == "x")
        {
            // ok: csharp.open-redirect
            return Redirect(Url.Action(action, "Home", new { returnUrl }));
        }
        if (action == "y")
        {
            // ok: csharp.open-redirect
            return Redirect(Url.Action(action));
        }
        if (action == "z")
        {
            // ok: csharp.open-redirect
            return Redirect(Url.Page(action, new { returnUrl }));
        }
        if (action == "h")
        {
            // A host given to Url.Action makes an absolute URL.
            // ruleid: csharp.open-redirect
            return Redirect(Url.Action("Index", "Home", null, "https", returnUrl));
        }
        // ok: csharp.open-redirect
        Response.Redirect(Url.Page("/Index", new { returnUrl }));
        // ok: csharp.open-redirect
        Response.Redirect(Url.RouteUrl("default", new { returnUrl }));
        // ok: csharp.open-redirect
        return LocalRedirect(returnUrl);
    }

    [HttpGet("safe2")]
    public IActionResult Safe2(string returnUrl)
    {
        // ok: csharp.open-redirect
        return LocalRedirectPermanent(returnUrl);
    }

    [HttpGet("route")]
    public IActionResult Route(string action, string controller)
    {
        // A route-generated redirect stays on this site.
        // ok: csharp.open-redirect
        return RedirectToAction(action, controller);
    }

    // Url.IsLocalUrl: the branch where it holds, a guard that leaves, a ternary, a fallback.
    [HttpGet("local1")]
    public IActionResult Local1(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            // ok: csharp.open-redirect
            return Redirect(returnUrl);
        }
        else
        {
            // ruleid: csharp.open-redirect
            Response.Redirect(returnUrl);
            return RedirectToAction("Index", "Home");
        }
    }

    [HttpGet("local2")]
    public IActionResult Local2(string returnUrl, string other)
    {
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            // ok: csharp.open-redirect
            return Redirect(returnUrl);
        }
        if (Url.IsLocalUrl(other))
        {
            // The checked value only.
            // ruleid: csharp.open-redirect
            return Redirect(returnUrl);
        }
        return Ok();
    }

    [HttpGet("local3")]
    public IActionResult Local3(string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            // ruleid: csharp.open-redirect
            Response.Redirect(returnUrl);
            return BadRequest();
        }
        // ok: csharp.open-redirect
        return Redirect(returnUrl);
    }

    [HttpGet("local4")]
    public IActionResult Local4(string returnUrl)
    {
        // ok: csharp.open-redirect
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction("Index");
    }

    [HttpGet("local5")]
    public IActionResult Local5(string returnUrl)
    {
        var target = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
        // ok: csharp.open-redirect
        return Redirect(target);
    }

    [HttpGet("local6")]
    public IActionResult Local6(string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            returnUrl = Url.Content("~/");
        }
        // ok: csharp.open-redirect
        return Redirect(returnUrl);
    }

    [HttpGet("local7")]
    public IActionResult Local7(string returnUrl)
    {
        // A check whose failing branch does not leave the method.
        if (!Url.IsLocalUrl(returnUrl))
        {
            Console.WriteLine("not local");
        }
        // ruleid: csharp.open-redirect
        return Redirect(returnUrl);
    }

    [HttpGet("local8")]
    public IActionResult Local8(string returnUrl, string next, string other)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return BadRequest();
        }
        else
        {
            // ok: csharp.open-redirect
            Response.Redirect(returnUrl);
        }
        // The failing guard itself.
        // ruleid: csharp.open-redirect
        if (!Url.IsLocalUrl(next)) return Redirect(next);
        if (next.Length > 100 || !this.Url.IsLocalUrl(other)) throw new ArgumentException("other");
        // ok: csharp.open-redirect
        return Redirect(other);
    }

    // A check stored in a variable first is not recognised.
    [HttpGet("local9")]
    public IActionResult Local9(string returnUrl)
    {
        var isLocal = Url.IsLocalUrl(returnUrl);
        if (isLocal)
        {
            // todook: csharp.open-redirect
            return Redirect(returnUrl);
        }
        return Ok();
    }

    [HttpGet("local10")]
    public IActionResult Local10(string returnUrl, string other)
    {
        if (Url.IsLocalUrl(returnUrl) && returnUrl.Length < 200)
        {
            // ok: csharp.open-redirect
            Response.Redirect(returnUrl);
        }
        if (string.IsNullOrEmpty(other) || !Url.IsLocalUrl(other))
        {
            return BadRequest();
        }
        else
        {
            // ok: csharp.open-redirect
            return Redirect(other);
        }
    }

    // Guards that always leave the method.
    [HttpGet("guards")]
    public IActionResult Guards(string a, string b, string c, string d, string e, string f)
    {
        if (!Url.IsLocalUrl(a)) return BadRequest();
        if (!Url.IsLocalUrl(b)) throw new ArgumentException("b");
        if (!Url.IsLocalUrl(c))
        {
            Console.WriteLine("c");
            Console.WriteLine("not local");
            return BadRequest();
        }
        if (a.Length == 0 || !Url.IsLocalUrl(d)) return BadRequest();
        if (a.Length == 0 || !Url.IsLocalUrl(e))
        {
            Console.WriteLine("e");
            return BadRequest();
        }
        if (a.Length == 0 || !Url.IsLocalUrl(f))
        {
            Console.WriteLine("f");
            Console.WriteLine("not local");
            return BadRequest();
        }
        // ok: csharp.open-redirect
        Response.Redirect(a);
        // ok: csharp.open-redirect
        Response.Redirect(b);
        // ok: csharp.open-redirect
        Response.Redirect(c);
        // ok: csharp.open-redirect
        Response.Redirect(d);
        // ok: csharp.open-redirect
        Response.Redirect(e);
        // ok: csharp.open-redirect
        return Redirect(f);
    }

    // Fallbacks after a failing check: a literal is fixed, a value built from the request is not.
    [HttpGet("fallbacks")]
    public IActionResult Fallbacks(string a, string b, string c)
    {
        if (!Url.IsLocalUrl(a)) a = "/";
        if (a.Length > 100 || !Url.IsLocalUrl(c)) c = "/";
        // ok: csharp.open-redirect
        Response.Redirect(c);
        // ok: csharp.open-redirect
        Response.Redirect(a);
        if (!Url.IsLocalUrl(b)) b = b + "/";
        // ruleid: csharp.open-redirect
        return Redirect(b);
    }

    // A failing check whose block resets the target to a generated local URL among other work.
    [HttpGet("wizard/finish")]
    public IActionResult FinishWizard(string continueTo, string step)
    {
        if (!Url.IsLocalUrl(continueTo))
        {
            Console.WriteLine("wizard target rejected");
            continueTo = Url.Action("Summary", "Wizard", new { step });
        }
        // ok: csharp.open-redirect
        Response.Redirect(continueTo);
        // ok: csharp.open-redirect
        return RedirectPreserveMethod(continueTo);
    }

    [HttpGet("wizard/cancel")]
    public IActionResult CancelWizard(string backTo, string reason)
    {
        if (reason == "timeout" || !Url.IsLocalUrl(backTo))
        {
            backTo = "/wizard";
            Console.WriteLine(reason);
        }
        // ok: csharp.open-redirect
        return Redirect(backTo);
    }

    // The application's path base is configured, not chosen by the client.
    [HttpGet("base")]
    public IActionResult Base()
    {
        // ok: csharp.open-redirect
        Response.Redirect(Request.PathBase + "/orders/recent");
        // ok: csharp.open-redirect
        Response.Redirect($"{HttpContext.Request.PathBase}/help#contact");
        var root = HttpContext.Request.PathBase;
        // ok: csharp.open-redirect
        return Redirect(root);
    }

    // Uri.MakeRelativeUri: a path relative to a URL taken from the request names no host.
    [HttpGet("relative")]
    public IActionResult Relative(string referrer)
    {
        var from = new Uri(referrer);
        var catalog = new Uri("https://www.contoso.com/catalog/");
        // ok: csharp.open-redirect
        Response.Redirect(from.MakeRelativeUri(catalog).ToString());
        // The argument is cleaned too, though it may be a URL of another host (Known limit).
        // todoruleid: csharp.open-redirect
        return Redirect(catalog.MakeRelativeUri(new Uri(referrer)).ToString());
    }

    // A redirect rebuilt on the request's own host keeps the client on this site: the host comes
    // before the path, and Path, PathBase and QueryString are escaped request parts.
    [HttpGet("canonical")]
    public IActionResult Canonical(string section)
    {
        // ok: csharp.open-redirect
        Response.Redirect("https://" + Request.Host + Request.Path);
        // ok: csharp.open-redirect
        Response.Redirect(Request.Scheme + "://" + Request.Host + Request.PathBase + Request.Path + Request.QueryString);
        // ok: csharp.open-redirect
        Response.Redirect($"https://{HttpContext.Request.Host}{HttpContext.Request.Path}");
        // ok: csharp.open-redirect
        Response.Redirect($"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}{Request.QueryString}");
        // ok: csharp.open-redirect
        Response.Redirect(UriHelper.BuildAbsolute("https", Request.Host, Request.PathBase, Request.Path, Request.QueryString));
        // Request data that is no escaped path right after the host can still change it ("@evil").
        // ruleid: csharp.open-redirect
        Response.Redirect("https://" + Request.Host + section);
        // ruleid: csharp.open-redirect
        Response.Redirect($"https://{Request.Host}{section}");
        // ruleid: csharp.open-redirect
        Response.Redirect(UriHelper.BuildAbsolute("https", new HostString(section), Request.PathBase));
        // A relative path can start with "//".
        // ruleid: csharp.open-redirect
        return Redirect(UriHelper.BuildRelative(Request.PathBase, Request.Path));
    }

    // Look-alikes: a navigator's Redirect, a Redirect of another object.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string page)
    {
        // ok: csharp.open-redirect
        _navigator.Redirect(page);
        // ok: csharp.open-redirect
        _navigator.Response.Redirect(page);
        return Ok();
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried(string other)
    {
        // todoruleid: csharp.open-redirect
        Response.Redirect(UrlOf(Request));
        // todoruleid: csharp.open-redirect
        Response.Redirect(Next);
        // todoruleid: csharp.open-redirect
        Response.Redirect(Back);
        if (!Partners.ContainsKey(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.open-redirect
        return Redirect(other);
    }

    [HttpGet("prio")]
    public IActionResult Prio(Level level, string region, string other)
    {
        // todook: csharp.open-redirect
        Response.Redirect("https://" + level + ".status.example/");
        if (region != "eu" && region != "us")
        {
            return BadRequest();
        }
        // todook: csharp.open-redirect
        Response.Redirect("https://" + region + ".status.example/");
        var chosen = Enumerable.Contains(Partners.Keys, other) ? other : "shop";
        // todook: csharp.open-redirect
        return Redirect("https://" + chosen + ".example/");
    }

    // A check of the URL's host is not recognised.
    private static readonly HashSet<string> AllowedHosts = new() { "shop.example" };

    [HttpGet("hostcheck")]
    public IActionResult HostCheck(string url)
    {
        var uri = new Uri(url);
        if (!AllowedHosts.Contains(uri.Host))
        {
            return BadRequest();
        }
        // todook: csharp.open-redirect
        return Redirect(url);
    }

    // The request's path is request data: a path "//evil.example" names another host.
    [HttpGet("{**rest}")]
    public IActionResult Path()
    {
        // ruleid: csharp.open-redirect
        Response.Redirect(Request.Path + "/");
        // ok: csharp.open-redirect
        return Redirect("/login?returnUrl=" + Request.Path);
    }

    [NonAction]
    public IActionResult Go(string url)
    {
        // ok: csharp.open-redirect
        return Redirect(url);
    }

    private static string UrlOf(HttpRequest request) => request.Query["url"].ToString();

    private string Next => Request.Query["next"].ToString();

    private string Back
    {
        get { return Request.Headers["Referer"].ToString(); }
    }
}

// A URL stored in a record that an awaited lookup on another object found by a request id is
// stored data; a lookup without await is still taken for request data.
public class ArchiveController : ControllerBase
{
    private readonly IArchive _archive;

    public ArchiveController(IArchive archive) => _archive = archive;

    public async Task<IActionResult> Open(string slug)
    {
        var document = await _archive.GetDocumentAsync(slug);
        // ok: csharp.open-redirect
        return Redirect(document.DownloadLink);
    }

    public async Task<IActionResult> Mirror(string slug)
    {
        var mirror = await _archive.LoadMirror(slug).ConfigureAwait(false);
        // ok: csharp.open-redirect
        return Redirect(mirror.DownloadLink);
    }

    public IActionResult Peek(string slug)
    {
        var document = _archive.FindDocument(slug);
        // todook: csharp.open-redirect
        return Redirect(document.DownloadLink);
    }

    public async Task<IActionResult> Canonical(string target)
    {
        // A lookup-named method that hands request data back is missed (Known limit).
        var canonical = await _archive.LoadCanonicalAsync(target);
        // todoruleid: csharp.open-redirect
        return Redirect(canonical);
    }

    // An awaited call that is no lookup keeps the request data.
    public async Task<IActionResult> Short(string target)
    {
        var shortened = await _archive.ShortenAsync(target);
        // ruleid: csharp.open-redirect
        return Redirect(shortened);
    }
}

// Duende IdentityServer: the interaction service tells whether a return URL belongs to a pending
// authorization request.
public class ExternalLoginController : Controller
{
    private readonly IIdentityServerInteractionService _interaction;

    public ExternalLoginController(IIdentityServerInteractionService interaction) => _interaction = interaction;

    [HttpPost]
    public async Task<IActionResult> Callback(string returnUrl, string fallback)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context != null)
        {
            // ok: csharp.open-redirect
            Response.Redirect(returnUrl);
        }
        else
        {
            // ruleid: csharp.open-redirect
            Response.Redirect(returnUrl);
        }
        if (_interaction.IsValidReturnUrl(fallback))
        {
            // ok: csharp.open-redirect
            return Redirect(fallback);
        }
        return Redirect("/account/login");
    }

    [HttpPost]
    public async Task<IActionResult> Resume(string returnUrl, string landing)
    {
        var pending = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (pending == null) return BadRequest();
        // ok: csharp.open-redirect
        Response.Redirect(returnUrl);
        // ruleid: csharp.open-redirect
        return Redirect(landing);
    }

    [HttpPost]
    public async Task<IActionResult> Done(string returnUrl, string afterwards)
    {
        var signIn = await _interaction.GetAuthorizationContextAsync(afterwards);
        if (signIn is null) return Redirect("/");
        // ok: csharp.open-redirect
        Response.Redirect(afterwards);
        var authentication = await _interaction.GetAuthenticationContextAsync(returnUrl);
        if (authentication is not null)
        {
            // ok: csharp.open-redirect
            return Redirect(returnUrl);
        }
        return Redirect("/");
    }

    // A helper that checks the context and hands the URL back next to the context's client name.
    [HttpPost]
    public async Task<IActionResult> Continue(string returnUrl)
    {
        var ticket = await PrepareAsync(returnUrl);
        // ok: csharp.open-redirect
        return Redirect(ticket.Destination);
    }

    private async Task<ResumeTicket> PrepareAsync(string returnUrl)
    {
        var ticket = new ResumeTicket();
        var pending = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (pending == null) return ticket;
        ticket.ClientName = pending.Client.ClientName;
        ticket.Destination = returnUrl;
        return ticket;
    }

    // An object a helper returns is tainted as a whole when any of its fields holds request data,
    // so its checked URL is reported too (Known limit).
    [HttpPost]
    public async Task<IActionResult> ContinueWithHint(string returnUrl, string hint)
    {
        var ticket = await PrepareWithHintAsync(returnUrl, hint);
        // todook: csharp.open-redirect
        return Redirect(ticket.Destination);
    }

    private async Task<ResumeTicket> PrepareWithHintAsync(string returnUrl, string hint)
    {
        var ticket = new ResumeTicket();
        var pending = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (pending == null) return ticket;
        ticket.Destination = returnUrl;
        ticket.Hint = hint;
        return ticket;
    }
}

public class ResumeTicket
{
    public string Destination { get; set; } = "/";
    public string ClientName { get; set; } = "";
    public string Hint { get; set; } = "";
}
// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class SignInEndpoints
{
    public static IEndpointRouteBuilder MapSignIn(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/signin", (SignInForm form) =>
        {
            // todoruleid: csharp.open-redirect
            return Results.Redirect(form.ReturnUrl);
        });
        routes.MapGet("/signin/next", Continue);
        routes.MapGet("/signin/other", OtherHandlers.Continue);
        return routes;
    }

    public static IResult Continue(string next)
    {
        // ruleid: csharp.open-redirect
        return Results.Redirect(next);
    }
}

public static class OtherHandlers
{
    public static IResult Continue(string next)
    {
        // todoruleid: csharp.open-redirect
        return Results.Redirect(next);
    }
}

public abstract class AppBase : ControllerBase
{
}

public class LinkController : AppBase
{
    public IActionResult Open(string link)
    {
        // todoruleid: csharp.open-redirect
        return Redirect(link);
    }
}

// Razor Pages: a [BindProperty] property and handler parameters.
public class LoginModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string ReturnUrl { get; set; } = "";

    public IActionResult OnPost()
    {
        // ruleid: csharp.open-redirect
        return Redirect(ReturnUrl);
    }

    public IActionResult OnGetExternal(string returnUrl)
    {
        // ruleid: csharp.open-redirect
        return RedirectPermanent(returnUrl);
    }

    public IActionResult OnGetLocal(string returnUrl)
    {
        returnUrl ??= Url.Content("~/");
        // ok: csharp.open-redirect
        return LocalRedirect(returnUrl);
    }
}

// A plain service: its parameters are not request data.
public class LinkService
{
    public void Send(HttpResponse response, string url)
    {
        // ok: csharp.open-redirect
        response.Redirect(url);
    }
}

public interface INavigator
{
    void Redirect(string page);
    Navigation Response { get; }
}

public enum Level { Low, High }
