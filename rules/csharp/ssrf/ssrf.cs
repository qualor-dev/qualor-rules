using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Primitives;

var app = WebApplication.Create(args);

// Minimal APIs: a URL from the query string fetched by the server.
app.MapGet("/preview", async (string url, IHttpClientFactory factory) =>
{
    var client = factory.CreateClient();
    // ruleid: csharp.ssrf
    var html = await client.GetStringAsync(url);
    return Results.Text(html);
});

app.MapGet("/proxy", async (string target) =>
{
    using var http = new HttpClient();
    // ruleid: csharp.ssrf
    var response = await http.GetAsync(target);
    // ruleid: csharp.ssrf
    var bytes = await http.GetByteArrayAsync(new Uri(target));
    // ruleid: csharp.ssrf
    var stream = await http.GetStreamAsync("https://" + target + "/feed");
    return Results.Ok();
});

// A host without a separator after it: "@evil.example" or ".evil.example" changes the host.
app.MapGet("/weather", async (string city, IHttpClientFactory factory) =>
{
    var client = factory.CreateClient("weather");
    // ruleid: csharp.ssrf
    var a = await client.GetStringAsync("https://api.weather.example" + city);
    // ruleid: csharp.ssrf
    var b = await client.GetStringAsync($"https://{city}.weather.example/today");
    // A fixed origin followed by a path: only the path is chosen by the request.
    // ok: csharp.ssrf
    var c = await client.GetStringAsync("https://api.weather.example/v1/cities/" + city);
    // ok: csharp.ssrf
    var d = await client.GetStringAsync($"https://api.weather.example/v1/cities/{city}/today");
    // ok: csharp.ssrf
    var e = await client.GetStringAsync(string.Format("https://api.weather.example/v1/cities/{0}", city));
    // ok: csharp.ssrf
    var f = await client.GetStringAsync("https://api.weather.example/v1/search?q=" + Uri.EscapeDataString(city));
    // A relative URI resolved against the client's BaseAddress.
    // ok: csharp.ssrf
    var g = await client.GetStringAsync($"v1/cities/{city}");
    // ok: csharp.ssrf
    var h = await client.GetStringAsync("/v1/cities/" + city);
    // An absolute URI replaces the BaseAddress, and "//host" is a host.
    // ruleid: csharp.ssrf
    var i = await client.GetStringAsync(city);
    // ruleid: csharp.ssrf
    var j = await client.GetStringAsync("/" + city);
    // ruleid: csharp.ssrf
    var k = await client.GetStringAsync(string.Format("https://{0}.weather.example/", city));
    // Percent-encoded data cannot form a scheme or a host.
    // ok: csharp.ssrf
    var l = await client.GetStringAsync(Uri.EscapeDataString(city) + "/today");
    // ok: csharp.ssrf
    var m = await client.GetStringAsync(WebUtility.UrlEncode(city) + "/today");
    // ok: csharp.ssrf
    var n = await client.GetStringAsync(HttpUtility.UrlEncode(city) + "/today");
    var o = await client.GetStringAsync(
        // ruleid: csharp.ssrf
        city);
    return Results.Ok();
});

// A lambda given to another API is not a request handler.
Retry.Run("warmup", async (string url) =>
{
    using var http = new HttpClient();
    // ok: csharp.ssrf
    await http.GetAsync(url);
});

app.Run();

public record Webhook(string Url, string Secret);
public enum Region { Eu, Us }

[ApiController]
[Route("api/[controller]")]
public class FetchController : ControllerBase
{
    private static readonly Dictionary<string, string> Mirrors = new() { ["eu"] = "https://eu.mirror.example/", ["us"] = "https://us.mirror.example/" };

    private readonly HttpClient _http;
    private readonly IHttpClientFactory _factory;
    private readonly IDistributedCache _cache;
    private readonly IMediator _mediator;
    private readonly IRepository _repository;

    public FetchController(HttpClient http, IHttpClientFactory factory, IDistributedCache cache, IMediator mediator, IRepository repository)
    {
        _http = http;
        _factory = factory;
        _cache = cache;
        _mediator = mediator;
        _repository = repository;
    }

    // HttpClient methods and HttpRequestMessage.
    [HttpPost("webhook")]
    public async Task<IActionResult> Ping([FromBody] Webhook hook)
    {
        // ruleid: csharp.ssrf
        await _http.PostAsync(hook.Url, new StringContent("ping"));
        // ruleid: csharp.ssrf
        await _http.PostAsJsonAsync(hook.Url, new { ok = true });
        // ruleid: csharp.ssrf
        await _http.PutAsync(hook.Url, null);
        // ruleid: csharp.ssrf
        await _http.DeleteAsync(hook.Url);
        // ruleid: csharp.ssrf
        var data = await _http.GetFromJsonAsync<Webhook>(hook.Url);
        // ruleid: csharp.ssrf
        var message = new HttpRequestMessage(HttpMethod.Post, hook.Url);
        await _http.SendAsync(message);
        var other = new HttpRequestMessage();
        // ruleid: csharp.ssrf
        other.RequestUri = new Uri(hook.Url);
        var third = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            // ruleid: csharp.ssrf
            RequestUri = new Uri(hook.Url),
        };
        return Ok();
    }

    // A client whose base address comes from the request, and the old WebRequest API.
    [HttpGet("mirror")]
    public async Task<IActionResult> Mirror(string mirror, string file)
    {
        var client = _factory.CreateClient("mirror");
        // ruleid: csharp.ssrf
        client.BaseAddress = new Uri(mirror);
        // ruleid: csharp.ssrf
        var configured = new HttpClient { BaseAddress = new Uri(mirror) };
        // ruleid: csharp.ssrf
        var request = WebRequest.Create(mirror + "/" + file);
        // ruleid: csharp.ssrf
        var http = WebRequest.CreateHttp(new Uri(new Uri("https://files.example/"), file));
        // ruleid: csharp.ssrf
        var legacy = HttpWebRequest.Create(mirror);
        // ruleid: csharp.ssrf
        using var r = await new HttpClient().GetAsync(mirror);
        // ruleid: csharp.ssrf
        using var s = await _factory.CreateClient().GetAsync(mirror);
        return Ok();
    }

    // The request object.
    [HttpGet("callback")]
    public async Task<IActionResult> Callback()
    {
        var url = Request.Query["callback"].ToString();
        // ruleid: csharp.ssrf
        await _http.GetAsync(url);
        // ruleid: csharp.ssrf
        await _http.GetAsync(Request.Headers["X-Callback"].ToString());
        if (Request.Form.TryGetValue("next", out var next))
        {
            // ruleid: csharp.ssrf
            await _http.GetAsync(next.ToString());
        }
        return Ok();
    }

    // Safe forms: a number, an allow-list, a fixed origin, an encoded path segment.
    [HttpGet("safe")]
    public async Task<IActionResult> Safe(string id, string region, string name)
    {
        // ok: csharp.ssrf
        await _http.GetAsync("https://catalog.example/items/" + int.Parse(id));
        // ok: csharp.ssrf
        await _http.GetAsync(Mirrors[region]);
        // ok: csharp.ssrf
        await _http.GetAsync(new Uri("https://catalog.example/search?q=" + name));
        // ok: csharp.ssrf
        await _http.GetAsync("https://catalog.example/items/" + Uri.EscapeDataString(name));
        // ok: csharp.ssrf
        await _http.GetAsync("https://catalog.example/health");
        return Ok();
    }

    // Look-alikes: a cache, a mediator and a repository with methods of the same names.
    [HttpGet("lookalikes")]
    public async Task<IActionResult> LookAlikes(string key)
    {
        // ok: csharp.ssrf
        var cached = await _cache.GetStringAsync(key);
        // ok: csharp.ssrf
        await _mediator.Send(key);
        // ok: csharp.ssrf
        var item = await _repository.GetAsync(key);
        // ok: csharp.ssrf
        await _repository.DeleteAsync(key);
        return Ok(cached);
    }

    // Known limits.
    private static readonly HashSet<string> AllowedHosts = new() { "api.partner.example" };

    [HttpGet("limits")]
    public async Task<IActionResult> Limits(string url, string host)
    {
        // A host allow-list check on a parsed Uri is not recognised.
        var uri = new Uri(url);
        if (!AllowedHosts.Contains(uri.Host))
        {
            return BadRequest();
        }
        // todook: csharp.ssrf
        await _http.GetAsync(uri);
        // A UriBuilder given the host.
        var builder = new UriBuilder("https", host);
        // ruleid: csharp.ssrf
        await _http.GetAsync(builder.Uri);
        return Ok();
    }

    // A record found by an id (an awaited lookup on another object) is stored data, also when the
    // id comes from the request; a lookup without await is still taken for request data.
    [HttpPost("instances/{id}/sync")]
    public async Task<IActionResult> Sync(string id)
    {
        var instance = await _repository.GetInstanceAsync(id);
        // ok: csharp.ssrf
        await _http.PostAsync(instance.Url, null);
        var found = await _repository.FindAsync<Webhook>(id);
        // ok: csharp.ssrf
        await _http.PostAsync(found.Url, null);
        // A value an awaited call that is no lookup made from request data.
        var built = await _repository.BuildUrlAsync(id);
        // ruleid: csharp.ssrf
        await _http.PostAsync(built, null);
        var cached = _repository.GetInstance(id);
        // todook: csharp.ssrf
        await _http.PostAsync(cached.Url, null);
        // A helper of this class called without a receiver is followed.
        var target = await GetTargetAsync(id);
        // ruleid: csharp.ssrf
        await _http.PostAsync(target, null);
        // Called on this, it counts as a lookup (Known limit).
        var other = await this.GetTargetAsync(id);
        // todoruleid: csharp.ssrf
        await _http.PostAsync(other, null);
        // So does a helper of another class or object that hands the value back (Known limit).
        var normalized = await UrlTools.LoadNormalizedAsync(id);
        // todoruleid: csharp.ssrf
        await _http.PostAsync(normalized, null);
        return Ok();
    }

    private async Task<string> GetTargetAsync(string value)
    {
        await Task.Yield();
        return value;
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public async Task<IActionResult> Tried(string other)
    {
        // todoruleid: csharp.ssrf
        await _http.GetAsync(UrlOf(Request));
        // todoruleid: csharp.ssrf
        await _http.GetAsync(Endpoint);
        // todoruleid: csharp.ssrf
        await _http.GetAsync(Channel);
        if (!Mirrors.ContainsKey(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.ssrf
        await _http.GetAsync(other);
        return Ok();
    }

    [HttpGet("prio")]
    public async Task<IActionResult> Prio(Level level, string region, string other)
    {
        // todook: csharp.ssrf
        await _http.GetAsync("https://" + level + ".status.example/");
        if (region != "eu" && region != "us")
        {
            return BadRequest();
        }
        // todook: csharp.ssrf
        await _http.GetAsync("https://" + region + ".status.example/");
        var chosen = Enumerable.Contains(Mirrors.Keys, other) ? other : "eu";
        // todook: csharp.ssrf
        await _http.GetAsync("https://" + chosen + ".status.example/");
        return Ok();
    }

    [NonAction]
    public Task<HttpResponseMessage> Fetch(string url)
    {
        // ok: csharp.ssrf
        return _http.GetAsync(url);
    }

    private static string UrlOf(HttpRequest request) => request.Query["url"].ToString();

    private string Endpoint => Request.Headers["X-Endpoint"].ToString();

    private string Channel
    {
        get { return Request.Query["channel"].ToString(); }
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class HookEndpoints
{
    public static IEndpointRouteBuilder MapHookEndpoints(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/hooks", async (Webhook hook, HttpClient http) =>
        {
            // todoruleid: csharp.ssrf
            await http.PostAsync(hook.Url, null);
            return Results.Ok();
        });
        routes.MapGet("/hooks/test", TestHook);
        routes.MapGet("/hooks/other", OtherHandlers.Test);
        return routes;
    }

    public static async Task<IResult> TestHook(string url, HttpClient http)
    {
        // ruleid: csharp.ssrf
        await http.GetAsync(url);
        return Results.Ok();
    }
}

public static class OtherHandlers
{
    public static async Task<IResult> Test(string url, HttpClient http)
    {
        // todoruleid: csharp.ssrf
        await http.GetAsync(url);
        return Results.Ok();
    }
}

public abstract class AppBase : ControllerBase
{
}

public class ImportController : AppBase
{
    private readonly HttpClient _http = new();

    public async Task<IActionResult> Run(string source)
    {
        // todoruleid: csharp.ssrf
        await _http.GetAsync(source);
        return Ok();
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class FeedModel : PageModel
{
    private readonly HttpClient _http;

    public FeedModel(HttpClient http) => _http = http;

    [BindProperty]
    public string FeedUrl { get; set; } = "";

    public async Task OnPostAsync()
    {
        // ruleid: csharp.ssrf
        await _http.GetStringAsync(FeedUrl);
    }

    public async Task OnGetPreviewAsync(string link)
    {
        // ruleid: csharp.ssrf
        await _http.GetStringAsync(link);
    }
}

// A plain service: its parameters are not request data.
public class FeedReader
{
    private readonly HttpClient _http;

    public FeedReader(HttpClient http) => _http = http;

    public Task<string> Read(string url)
    {
        // ok: csharp.ssrf
        return _http.GetStringAsync(url);
    }
}

public static class UrlTools
{
    public static async Task<string> LoadNormalizedAsync(string url)
    {
        await Task.Yield();
        return url.Trim();
    }
}

public enum Level { Low, High }
