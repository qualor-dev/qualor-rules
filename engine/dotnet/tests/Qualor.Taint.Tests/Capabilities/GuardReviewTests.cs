using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// The Task 11 review's probes (fix round 1) with the shipped models: what the guards and allow-lists must not take for
/// a check, and the URL helpers' fragment.
public sealed class GuardReviewTests
{
    private static void Expect(string code, string rule) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, rule));

    [Fact]
    public void A_fragment_given_to_a_url_helper_reaches_the_url() => Expect("""
        public class S1Controller : Controller
        {
            public IActionResult A(string q) => Content("<a href='" + Url.Action("Index", "Home", null, null, null, q) + "'>x</a>", "text/html"); /*sink*/
            public IActionResult B(string q) => Content("<a href='" + Url.RouteUrl("r", null, null, null, q) + "'>x</a>", "text/html"); /*sink*/
            public IActionResult C(string q) => Content("<a href='" + Url.Page("/Index", null, null, null, null, q) + "'>x</a>", "text/html"); /*sink*/
            public IActionResult D(string q) => Content("<a href='" + Url.Action(q, "Home", new { q }) + "'>x</a>", "text/html");
        }
        """, "csharp.xss");

    [Fact]
    public void The_url_helpers_propagated_ordinals_are_protocol_host_and_fragment_in_every_overload()
    {
        var compilation = CSharpCompilation.Create("UrlHelpers", references: FixtureReferences.All);
        var type = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.UrlHelperExtensions")!;
        var models = ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp"));
        foreach (var name in new[] { "Action", "Page", "RouteUrl" })
        {
            var from = models.Propagators.Single(p => p.Member.TypeName == "Microsoft.AspNetCore.Mvc.UrlHelperExtensions" && p.Member.MemberName == name).From
                .Select(int.Parse).ToList();
            var overloads = type.GetMembers(name).OfType<IMethodSymbol>().ToList();
            Assert.NotEmpty(overloads);
            foreach (var m in overloads)
                foreach (var ordinal in from.Where(o => o < m.Parameters.Length))
                    Assert.Contains(m.Parameters[ordinal].Name, new[] { "protocol", "host", "fragment" });
            Assert.Contains(overloads, m => from.All(o => o < m.Parameters.Length));
        }
    }

    [Fact]
    public void A_table_used_in_any_way_but_a_known_read_or_of_a_projects_own_type_is_no_allow_list() => Expect("""
        using System.Collections.Concurrent;
        using System.Runtime.InteropServices;
        public class T1Controller : Controller
        {
            private static readonly List<string> Aliased = new() { "news" };
            private static readonly List<string> Helped = new() { "news" };
            private static readonly List<string> Casted = new() { "news" };
            private static readonly string[] Spanned = { "news" };
            private static readonly string[] Filled = { "news" };
            private static readonly string[] Copied = { "news" };
            private static readonly string[] SetVal = { "news" };
            private static readonly ConcurrentDictionary<string, string> Conc = new() { ["news"] = "<b>n</b>" };
            private static readonly Dictionary<string, string> ByRef = new() { ["news"] = "<b>n</b>" };
            private static readonly PatternSet Prefixes = new() { "news" };
            private static readonly HashSet<string> Weird = new(new AnyComparer()) { "news" };
            private static readonly HashSet<string> Kept = new(StringComparer.OrdinalIgnoreCase) { "news" };
            public static readonly HashSet<string> Exposed = new() { "news" };

            public void Grow(string q)
            {
                var a = Aliased; a.Add(q);
                AddTo(Helped, q);
                ((ICollection<string>)Casted).Add(q);
                Spanned.AsSpan()[0] = q;
                Array.Fill(Filled, q);
                Array.Copy(new[] { q }, Copied, 1);
                SetVal.SetValue(q, 0);
                Conc.TryUpdate("news", q, "<b>n</b>");
                CollectionsMarshal.GetValueRefOrAddDefault(ByRef, "news", out _) = q;
            }
            private static void AddTo(List<string> l, string v) => l.Add(v);

            public IActionResult A(string q) { if (!Aliased.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult B(string q) { if (!Helped.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult C(string q) { if (!Casted.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult D(string q) { if (!Spanned.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult E(string q) { if (!Filled.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult F(string q) { if (!Copied.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult G(string q) { if (!SetVal.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult H(string q) => Content("<p>" + Conc[q] + "</p>", "text/html"); /*sink*/
            public IActionResult I(string q) => Content("<p>" + ByRef[q] + "</p>", "text/html"); /*sink*/
            public IActionResult J(string q) { if (!Prefixes.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult K(string q) { if (!Weird.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult L(string q) { if (!Kept.Contains(q, new AnyComparer())) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult M(string q) { if (!Exposed.Contains(q)) return BadRequest(); return Content("<p>" + q + "</p>", "text/html"); /*sink*/ }
            public IActionResult N(string q)
            {
                if (!Kept.Contains(q) || Kept.Count == 0 || !Kept.Any() || string.Join(",", Kept).Length == 0) return BadRequest();
                foreach (var k in Kept) { }
                return Content("<p>" + q + "</p>", "text/html");
            }
        }
        public class PatternSet : List<string> { public new bool Contains(string s) => this.Any(p => s.StartsWith(p)); }
        public class AnyComparer : IEqualityComparer<string> { public bool Equals(string? a, string? b) => true; public int GetHashCode(string s) => 0; }
        """, "csharp.xss");

    [Fact]
    public void A_user_defined_equality_is_no_guard() => Expect("""
        public class E1Controller : Controller
        {
            public IActionResult F([FromQuery] Filter f)
            {
                if (!f.Equals("news")) return BadRequest();
                return Content("<p>" + f.Html + "</p>", "text/html"); /*sink*/
            }
            public IActionResult G([FromQuery] Filter f)
            {
                if (f != "news") return BadRequest();
                return Content("<p>" + f.Html + "</p>", "text/html"); /*sink*/
            }
            public IActionResult H(string q, Level l)
            {
                if (q != "a" || !"b".Equals(q) || !string.Equals(q, "a", StringComparison.Ordinal)) return BadRequest();
                return Content("<p>" + q + "</p>", "text/html");
            }
        }
        public enum Level { Low, High }
        public class Filter
        {
            public string Name { get; set; } = "";
            public string Html { get; set; } = "";
            public override bool Equals(object? o) => o is string s && s == Name;
            public override int GetHashCode() => 0;
            public static bool operator ==(Filter a, string b) => a?.Name == b;
            public static bool operator !=(Filter a, string b) => a?.Name != b;
        }
        """, "csharp.xss");

    [Fact]
    public void A_root_alone_is_no_containment_prefix() => Expect("""
        public class P1Controller : Controller
        {
            private readonly string _root = "/srv/files";
            public IActionResult C(string name)
            {
                var full = Path.GetFullPath(name);
                if (!full.StartsWith("/")) return NotFound();
                return PhysicalFile(full, "text/plain"); /*sink*/
            }
            public IActionResult H(string name)
            {
                var full = Path.GetFullPath(Path.Combine(_root, name));
                if (!full.StartsWith("C:\\")) return NotFound();
                return PhysicalFile(full, "text/plain"); /*sink*/
            }
            public IActionResult I(string name)
            {
                var full = Path.GetFullPath(Path.Combine(_root, name));
                if (!full.StartsWith("\\")) return NotFound();
                return PhysicalFile(full, "text/plain"); /*sink*/
            }
            public IActionResult J(string name)
            {
                var full = Path.GetFullPath(Path.Combine(_root, name));
                if (!full.StartsWith("D:/srv/")) return NotFound();
                return PhysicalFile(full, "text/plain");
            }
        }
        """, "csharp.path-traversal");

    [Fact]
    public void A_not_null_guard_does_not_clean_an_argument_assigned_after_the_call() => Expect("""
        namespace Duende.IdentityServer.Services
        {
            public interface IIdentityServerInteractionService { Task<AuthorizationRequest> GetAuthorizationContextAsync(string returnUrl); }
            public class AuthorizationRequest { }
        }
        namespace App
        {
            using Duende.IdentityServer.Services;
            public class N1Controller : Controller
            {
                private readonly IIdentityServerInteractionService _i;
                public N1Controller(IIdentityServerInteractionService i) { _i = i; }
                public async Task<IActionResult> A(string returnUrl, string other)
                {
                    var ctx = await _i.GetAuthorizationContextAsync(returnUrl);
                    returnUrl = other;
                    if (ctx != null) return Redirect(returnUrl); /*sink*/
                    return Ok();
                }
                public async Task<IActionResult> B(string returnUrl)
                {
                    var ctx = await _i.GetAuthorizationContextAsync(returnUrl);
                    if (ctx != null) return Redirect(returnUrl);
                    return Ok();
                }
            }
        }
        """, "csharp.open-redirect");
}
