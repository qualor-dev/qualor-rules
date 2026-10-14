namespace Qualor.Taint.Tests.Capabilities;

/// Sanitizers by position in a string (`string-prefix:`, optionally for one `type:`) and by lookup name (`lookup:`).
public sealed class StringSanitizerTests : ProbeModels
{
    private ModelSet OriginModels() => Probe("""
        sinks:
          - method: System.Net.Http.HttpClient.GetStringAsync
            args: [0]
        sanitizers:
          - string-prefix: '^(https?://[^/?#"\s]+[/?#]|/[^/\\"\uFFFC]|[^/\\"\s:\uFFFC][^"\s:]*[/?#])'
        """);

    [Fact]
    public void A_value_after_a_fixed_origin_is_clean() => Expect(OriginModels(), """
        public class FetchController : ControllerBase
        {
            private const string Api = "https://api.contoso.test";
            public async Task Get(string q, string host, HttpClient http)
            {
                await http.GetStringAsync("https://api.contoso.test/v1/items/" + q);
                await http.GetStringAsync("https://" + q + "/feed"); /*sink*/
                await http.GetStringAsync("https://api.contoso.test" + q); /*sink*/
                await http.GetStringAsync($"https://api.contoso.test/v1/{q}/today");
                await http.GetStringAsync($"https://{q}.contoso.test/"); /*sink*/
                await http.GetStringAsync(string.Format("https://api.contoso.test/v1/{0}", q));
                await http.GetStringAsync(string.Format("https://{0}.contoso.test/", q)); /*sink*/
                await http.GetStringAsync("/v1/items/" + q);
                await http.GetStringAsync("/" + q); /*sink*/
                await http.GetStringAsync(q); /*sink*/
                await http.GetStringAsync(Api + "/v1/" + q);
                await http.GetStringAsync("https://" + host + "/v1/" + q); /*sink*/
                var url = "https://api.contoso.test/v1/" + q;
                await http.GetStringAsync(url);
            }
        }
        """);

    [Fact]
    public void A_later_value_after_an_earlier_one_is_not_taken_for_a_fixed_origin() => Expect(OriginModels(), """
        public class FetchController : ControllerBase
        {
            public async Task Get(string q, string host, HttpClient http)
            {
                await http.GetStringAsync(host + q); /*sink*/
                await http.GetStringAsync(host + "/" + q); /*sink*/
            }
        }
        """);

    private ModelSet PathStringModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Content
            args: [0]
        sanitizers:
          - string-prefix: '(?is)^(?!.*<(script|style)\b(?:(?!</(script|style)).)*$)(?:(?!.*<[^>]*$)|.*<[^>]*=\s*"[^"]*$)'
            type: Microsoft.AspNetCore.Http.PathString
        """);

    [Fact]
    public void A_typed_string_prefix_sanitizer_cleans_values_of_that_type_only() => Expect(PathStringModels(), """
        public class PagesController : ControllerBase
        {
            public IActionResult Get(string q)
            {
                Content("<a href=\"" + Request.PathBase + "/home\">Home</a>");
                Content($"<a href=\"{HttpContext.Request.Path}?page=2\">Next</a>");
                Content("<p>" + Request.Path + "</p>");
                Content("<a href='" + Request.Path + "'>x</a>"); /*sink*/
                Content("<scr" + "ipt>var p = '" + Request.PathBase + "';</scr" + "ipt>"); /*sink*/
                Content("<p>" + Request.Path.Value + "</p>"); /*sink*/
                Content("<a href=\"" + q + "\">x</a>"); /*sink*/
                var held = Request.Path;
                Content("<p>" + held.Value + "</p>"); /*sink*/
                return Ok();
            }
        }
        """);

    private ModelSet LookupModels() => Probe("""
        sinks:
          - method: System.Net.Http.HttpClient.GetStringAsync
            args: [0]
        sanitizers:
          - lookup: '^(Get|Find|Load)\w*Async$'
        """);

    [Fact]
    public void A_lookup_without_a_body_returns_stored_data_and_one_with_a_body_is_followed() => Expect(LookupModels(), """
        public interface IStore
        {
            Task<string> GetUrlAsync(string id);
            Task<string> BuildUrlAsync(string id);
        }
        public static class Tools
        {
            public static async Task<string> LoadNormalizedAsync(string url) { await Task.Yield(); return url.Trim(); }
        }
        public class FetchController : ControllerBase
        {
            private readonly IStore _store;
            private readonly HttpClient _http = new();
            public FetchController(IStore store) => _store = store;
            public async Task Get(string id)
            {
                await _http.GetStringAsync(await _store.GetUrlAsync(id));
                await _http.GetStringAsync(await _store.BuildUrlAsync(id)); /*sink*/
                await _http.GetStringAsync(await Tools.LoadNormalizedAsync(id)); /*sink*/
                await _http.GetStringAsync(await GetOwnAsync(id)); /*sink*/
            }
            private async Task<string> GetOwnAsync(string v) { await Task.Yield(); return v; }
        }
        """);

    [Fact]
    public void A_string_sanitizer_and_a_lookup_are_read()
    {
        var rule = PathStringModels().Rules.Single(r => r.RuleId == Rule);
        var s = Assert.Single(rule.StringSanitizers);
        Assert.Equal("Microsoft.AspNetCore.Http.PathString", s.Type);
        Assert.Single(LookupModels().Rules.Single(r => r.RuleId == Rule).LookupSanitizers);
        var e = Assert.Throws<ModelException>(() => Probe("sinks:\n  - method: A.B\n    args: [0]\nsanitizers:\n  - lookup: x\n    type: A.B\n"));
        Assert.Equal(8, e.Line);
    }
}
