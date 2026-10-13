using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

var app = WebApplication.Create(args);

// Minimal APIs: a search pattern from the query string.
app.MapGet("/search", (string q, string text) =>
{
    // ruleid: csharp.regex-injection
    var found = Regex.IsMatch(text, q);
    // The request value as the input, matched against a constant pattern, is fine.
    // ok: csharp.regex-injection
    var valid = Regex.IsMatch(q, "^[a-z0-9-]{1,40}$");
    return Results.Ok(found && valid);
});

app.MapPost("/filter", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var pattern = form["pattern"].ToString();
    // ruleid: csharp.regex-injection
    var regex = new Regex(pattern, RegexOptions.IgnoreCase);
    // Using the regex built above is not reported again.
    // ok: csharp.regex-injection
    var hit = regex.IsMatch(form["text"].ToString());
    // ruleid: csharp.regex-injection
    var count = Regex.Count(form["text"].ToString(), context.Request.Query["p"].ToString());
    return Results.Ok(count);
});

// A lambda given to another API is not a request handler.
Retry.Run("warmup", (string pattern) =>
{
    // ok: csharp.regex-injection
    return Regex.IsMatch("text", pattern);
});

app.Run();

public record Rule(string Pattern, string Replacement);
public enum Mode { Exact, Prefix }

[ApiController]
[Route("api/[controller]")]
public partial class TextController : ControllerBase
{
    private static readonly Dictionary<string, string> Patterns = new() { ["digits"] = "^[0-9]+$", ["word"] = "^\\w+$" };

    [GeneratedRegex("^[a-z]+$", RegexOptions.IgnoreCase)]
    private static partial Regex LettersRegex();

    private readonly ITextIndex _index;

    public TextController(ITextIndex index)
    {
        _index = index;
    }

    // The static methods: the pattern argument.
    [HttpGet("static")]
    public IActionResult Static(string pattern, string input)
    {
        // ruleid: csharp.regex-injection
        var m = Regex.Match(input, pattern);
        // ruleid: csharp.regex-injection
        var all = Regex.Matches(input, pattern, RegexOptions.Multiline);
        // ruleid: csharp.regex-injection
        var replaced = Regex.Replace(input, pattern, "*");
        // ruleid: csharp.regex-injection
        var parts = Regex.Split(input, pattern);
        // ruleid: csharp.regex-injection
        foreach (var match in Regex.EnumerateMatches(input, pattern))
        {
        }
        // ruleid: csharp.regex-injection
        var fromEvaluator = Regex.Replace(input, pattern, match => match.Value.ToUpperInvariant());
        // ruleid: csharp.regex-injection
        var qualified = System.Text.RegularExpressions.Regex.IsMatch(input, pattern);
        return Ok(m.Success);
    }

    [HttpPost("rules")]
    public IActionResult Rules([FromBody] Rule rule, [FromQuery] string text)
    {
        // ruleid: csharp.regex-injection
        var regex = new Regex(rule.Pattern);
        // ruleid: csharp.regex-injection
        Regex target = new("^" + rule.Pattern + "$");
        // The replacement string is no pattern.
        // ok: csharp.regex-injection
        var replaced = Regex.Replace(text, "[0-9]", rule.Replacement);
        // ok: csharp.regex-injection
        var changed = regex.Replace(text, rule.Replacement);
        return Ok(replaced);
    }

    // The request object and a pattern built from parts.
    [HttpGet("raw")]
    public IActionResult Raw()
    {
        var term = Request.Query["term"].ToString();
        // ruleid: csharp.regex-injection
        var contains = Regex.IsMatch("some text", ".*" + term + ".*");
        // ruleid: csharp.regex-injection
        var header = new Regex($"^{Request.Headers["X-Filter"]}$");
        // ruleid: csharp.regex-injection
        var cookie = Regex.IsMatch("some text", string.Format("^{0}", Request.Cookies["filter"]));
        return Ok(contains);
    }

    // A time-out or the non-backtracking engine does not make a pattern from the request safe:
    // Microsoft's docs say they are not a security boundary against malicious patterns.
    [HttpGet("limited")]
    public IActionResult Limited(string pattern, string input)
    {
        // ruleid: csharp.regex-injection
        var timed = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
        // ruleid: csharp.regex-injection
        var linear = Regex.IsMatch(input, pattern, RegexOptions.NonBacktracking);
        // ruleid: csharp.regex-injection
        var both = Regex.Match(input, pattern, RegexOptions.NonBacktracking, TimeSpan.FromSeconds(1));
        return Ok(timed.IsMatch(input) && linear && both.Success);
    }

    // Safe forms: Regex.Escape, an allow-list of patterns, constants, a number, a generated regex.
    [HttpGet("safe")]
    public IActionResult Safe(string term, string kind, string input, int length, Mode mode)
    {
        // ok: csharp.regex-injection
        var literal = Regex.IsMatch(input, Regex.Escape(term));
        // ok: csharp.regex-injection
        var prefix = new Regex("^" + Regex.Escape(term), RegexOptions.IgnoreCase);
        // ok: csharp.regex-injection
        var chosen = Regex.IsMatch(input, Patterns[kind]);
        // ok: csharp.regex-injection
        var sized = Regex.IsMatch(input, "^[a-z]{" + length + "}$");
        // ok: csharp.regex-injection
        var typed = Regex.IsMatch(input, "^" + mode + "$");
        // ok: csharp.regex-injection
        var letters = LettersRegex().IsMatch(term);
        // An escaped copy counts, not the raw value next to it.
        var escaped = Regex.Escape(term);
        // ruleid: csharp.regex-injection
        var raw = Regex.IsMatch(input, escaped + term);
        // A pattern call written inside Regex.Escape is still checked.
        // ruleid: csharp.regex-injection
        var nested = Regex.Escape(Regex.Replace(input, term, ""));
        return Ok(literal && prefix.IsMatch(input) && chosen && sized && typed && letters && raw);
    }

    // Look-alikes: an index's Match and Replace, string.Replace and Split.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string term, string input)
    {
        // ok: csharp.regex-injection
        var hits = _index.Match(input, term);
        // ok: csharp.regex-injection
        var replaced = input.Replace(term, "*");
        // ok: csharp.regex-injection
        var parts = input.Split(term);
        // ok: csharp.regex-injection
        var custom = TextPatterns.IsMatch(input, term);
        return Ok(hits);
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried(string other)
    {
        // todoruleid: csharp.regex-injection
        Regex.IsMatch("text", PatternOf(Request));
        // todoruleid: csharp.regex-injection
        Regex.IsMatch("text", Filter);
        // todoruleid: csharp.regex-injection
        Regex.IsMatch("text", Exclude);
        if (!Patterns.ContainsKey(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.regex-injection
        Regex.IsMatch("text", other);
        return Ok();
    }

    [HttpGet("prio")]
    public IActionResult Prio(Level level, string region, string other)
    {
        // todook: csharp.regex-injection
        Regex.IsMatch("text", "^" + level + "$");
        if (region != "eu" && region != "us")
        {
            return BadRequest();
        }
        // todook: csharp.regex-injection
        Regex.IsMatch("text", "^" + region + "$");
        var chosen = Enumerable.Contains(Patterns.Keys, other) ? other : "digits";
        // todook: csharp.regex-injection
        Regex.IsMatch("text", chosen);
        return Ok();
    }

    [NonAction]
    public bool Check(string pattern)
    {
        // ok: csharp.regex-injection
        return Regex.IsMatch("text", pattern);
    }

    private static string PatternOf(HttpRequest request) => request.Query["pattern"].ToString();

    private string Filter => Request.Query["filter"].ToString();

    private string Exclude
    {
        get { return Request.Headers["X-Exclude"].ToString(); }
    }
}

// Allow-lists of verbatim pattern literals (@"..."), the way regex patterns are usually written.
public class ShapesController : ControllerBase
{
    private static readonly Dictionary<string, string> Shapes = new()
    {
        { "zip", @"^\d{5}$" },
        { "code", @"^[A-Z]{2}-\d+$" },
    };

    private static readonly HashSet<string> Known = new() { @"^\w+$", @"^\d+$" };

    public IActionResult Check(string kind, string input, string chosen, string guarded, string thrown, string logged)
    {
        // ok: csharp.regex-injection
        var a = Regex.IsMatch(input, Shapes[kind]);
        // ok: csharp.regex-injection
        var b = Regex.IsMatch(input, Shapes.GetValueOrDefault(kind, @"^$"));
        // ok: csharp.regex-injection
        var c = Regex.IsMatch(input, Known.Contains(chosen) ? chosen : @"^\w+$");
        if (!Known.Contains(guarded)) return BadRequest();
        // ok: csharp.regex-injection
        var d = Regex.IsMatch(input, guarded);
        if (!Known.Contains(thrown)) throw new ArgumentException("pattern");
        // ok: csharp.regex-injection
        var e = Regex.IsMatch(input, thrown);
        if (!Known.Contains(logged))
        {
            Console.WriteLine("unknown pattern");
            return BadRequest();
        }
        // A guard with other statements before its return counts for "..." tables only (Known limit).
        // todook: csharp.regex-injection
        var f = Regex.IsMatch(input, logged);
        return Ok(a && b && c && d && e && f);
    }
}

// A verbatim table that a method changes is no allow-list.
public class EditableShapesController : ControllerBase
{
    private static readonly Dictionary<string, string> Shapes = new() { { "zip", @"^\d{5}$" } };

    public IActionResult Add(string kind, string pattern)
    {
        Shapes[kind] = pattern;
        return Ok();
    }

    public IActionResult Check(string kind, string input)
    {
        // ruleid: csharp.regex-injection
        return Ok(Regex.IsMatch(input, Shapes[kind]));
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class RuleEndpoints
{
    public static IEndpointRouteBuilder MapRules(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/rules/test", (Rule rule) =>
        {
            // todoruleid: csharp.regex-injection
            return Results.Ok(Regex.IsMatch("text", rule.Pattern));
        });
        routes.MapGet("/rules/check", Check);
        routes.MapGet("/rules/other", OtherHandlers.Check);
        return routes;
    }

    public static IResult Check(string pattern)
    {
        // ruleid: csharp.regex-injection
        return Results.Ok(Regex.IsMatch("text", pattern));
    }
}

public static class OtherHandlers
{
    public static IResult Check(string pattern)
    {
        // todoruleid: csharp.regex-injection
        return Results.Ok(Regex.IsMatch("text", pattern));
    }
}

public abstract class AppBase : ControllerBase
{
}

public class FilterController : AppBase
{
    public IActionResult Apply(string pattern)
    {
        // todoruleid: csharp.regex-injection
        return Ok(Regex.IsMatch("text", pattern));
    }
}

// Razor Pages: a [BindProperty] property and a handler parameter.
public class FindModel : PageModel
{
    [BindProperty]
    public string Pattern { get; set; } = "";

    public void OnPost()
    {
        // ruleid: csharp.regex-injection
        var regex = new Regex(Pattern);
    }

    public void OnGetSplit(string separator)
    {
        // ruleid: csharp.regex-injection
        var parts = Regex.Split("a,b;c", separator);
    }
}

// A plain service: its parameters are not request data.
public class PatternService
{
    public bool Test(string pattern, string input)
    {
        // ok: csharp.regex-injection
        return Regex.IsMatch(input, pattern);
    }
}

public static class TextPatterns
{
    public static bool IsMatch(string input, string term) => input.Contains(term);
}

public interface ITextIndex
{
    object Match(string input, string term);
}

public enum Level { Low, High }
