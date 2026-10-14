namespace Qualor.Taint.Tests.Capabilities;

/// Task 23: the text a project member returns counts as written in place where a string is built from it, so a
/// `string-prefix:` sanitizer sees a fixed origin (or a format) that a helper returns: a property or method whose every
/// return starts with the same text (a literal, a constant, another such helper), a static readonly field initialised
/// with a literal. A return that may start otherwise (a parameter, an empty string, another host) gives no text.
public sealed class HelperTextTests : ProbeModels
{
    private ModelSet OriginModels() => Probe("""
        sinks:
          - method: System.Net.Http.HttpClient.GetStringAsync
            args: [0]
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
            args: [0]
        sanitizers:
          - string-prefix: '^(https?://[^/?#"\s]+[/?#]|/[^/\\"\uFFFC]|[^/\\"\s:\uFFFC][^"\s:]*[/?#])'
        """);

    private const string Endpoints = """
        public static class Endpoints
        {
            public const string Host = "https://api.contoso.test";
            public static string Base => Host + "/v2";
            public static string Items => Base + $"/{Segment}";
            public static string Segment => "items";
            public static string Search => "search?q={0}&page={1}";
            public static readonly string Feed = "https://feed.contoso.test/";
            public static string Bare => "https://api.contoso.test";
            public static string Versioned(bool two) => two ? "https://api.contoso.test/v2/" : "https://api.contoso.test/v1/";
            public static string Tenant(string t) => t.Length > 0 ? "https://" + t + ".contoso.test/" : "https://api.contoso.test/";
            public static string Maybe(bool on) => on ? "https://api.contoso.test/" : "";
            public static string Echo(string s) => s;
            public static string Report => "report?site={0}&v={1}&mail={2}&lang={3}";
        }
        public interface IOrigin { string Root { get; } }
        public sealed class Fixed : IOrigin { public string Root => "https://a.contoso.test/"; }
        public sealed class Configured : IOrigin { private readonly string _r; public Configured(string r) => _r = r; public string Root => _r; }
        """;

    [Fact]
    public void A_helper_returning_a_fixed_origin_cleans_what_follows_it() => Expect(OriginModels(), Endpoints + """
        public class FetchController : ControllerBase
        {
            public async Task Get(string q, HttpClient http)
            {
                await http.GetStringAsync(Endpoints.Base + "/" + q);
                await http.GetStringAsync($"{Endpoints.Items}/{q}");
                await http.GetStringAsync(string.Format(Endpoints.Search, q, 1));
                await http.GetStringAsync(Endpoints.Versioned(true) + q);
                await http.GetStringAsync(Endpoints.Feed + q);
                await http.GetStringAsync(Endpoints.Bare + q); /*sink*/
                await http.GetStringAsync(Endpoints.Tenant("x") + q); /*sink*/
                await http.GetStringAsync(Endpoints.Maybe(true) + q); /*sink*/
                await http.GetStringAsync(Endpoints.Echo("https://api.contoso.test/") + q); /*sink*/
                await http.GetStringAsync(Endpoints.Echo(q) + "/v1"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_format_with_more_than_three_values_cleans_each_by_its_place() => Expect(OriginModels(), Endpoints + """
        public class FetchController : ControllerBase
        {
            public async Task Get(string q, HttpClient http)
            {
                await http.GetStringAsync(string.Format(Endpoints.Report, q, "8.1", q, q));
                await http.GetStringAsync(string.Format("https://api.contoso.test/r?a={0}&b={1}&c={2}&d={3}", "a", "b", "c", q));
                await http.GetStringAsync(string.Format("{3}/r?a={0}&b={1}&c={2}", "a", "b", "c", q)); /*sink*/
                await http.GetStringAsync(string.Format("{0}{1}{2}{3}", "https://api.contoso.test/", "a", "b", q)); /*sink*/
                await http.GetStringAsync(string.Format(Endpoints.Echo(q), "a", "b", "c", "d")); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_member_with_several_implementations_gives_their_common_text() => Expect(OriginModels(), Endpoints + """
        public class FetchController : ControllerBase
        {
            private readonly IOrigin _origin;
            private readonly Fixed _fixed = new();
            public FetchController(IOrigin origin) => _origin = origin;
            public async Task Get(string q, HttpClient http)
            {
                await http.GetStringAsync(_fixed.Root + q);
                await http.GetStringAsync(_origin.Root + q); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_helper_text_holds_for_a_redirect_too() => Expect(OriginModels(), Endpoints + """
        public static class Links
        {
            public static string Docs => "https://docs.contoso.test/";
            public static string Page(string slug) => Docs + "pages/" + slug;
        }
        public class GoController : ControllerBase
        {
            public IActionResult Go(string slug, string to)
            {
                if (slug == "a") return Redirect(Links.Docs + slug);
                if (slug == "b") return Redirect(Links.Page(slug));
                if (slug == "c") return Redirect(Links.Page(slug) + to);
                return Redirect(to + Links.Docs); /*sink*/
            }
        }
        """);
}
