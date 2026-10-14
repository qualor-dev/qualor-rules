using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 23, ruling R-E18 (narrows R-E9): a lookup by a request key gives request data only when what it finds can carry
/// an injection by itself (a string, char, number or bool, or a sequence or array of them); a settings or tenant object,
/// a cached entity, a content item found by its id does not take the key's taint, nor do its members. Cache APIs with a
/// value factory give the factory's result, not the key: IMemoryCache's GetOrCreate*, ConcurrentDictionary.GetOrAdd, and
/// a project method shaped like `T Get(key, Func<T> acquire)` (by its shape, whatever its name). A table the request
/// itself filled is still request data, and a literal allow-list table still cleans (Task 11).
public sealed class KeyedLookupTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void An_object_found_by_a_request_key_is_not_request_data() => Expect("""
        using System.Collections.Concurrent;
        public sealed class Tenant { public string Name { get; set; } = ""; public string Prefix = ""; }
        public class TenantsController : ControllerBase
        {
            private static readonly Dictionary<string, Tenant> Tenants = new();
            private static readonly ConcurrentDictionary<string, Tenant> Running = new();
            private static readonly Dictionary<string, object> Bag = new();
            private readonly SqlConnection _c = new();
            public IActionResult Show(string host)
            {
                if (Tenants.TryGetValue(host, out var t)) _c.Execute("SELECT * FROM " + t.Name);
                _c.Execute("SELECT * FROM " + Tenants[host].Prefix);
                _c.Execute("SELECT * FROM " + Tenants.GetValueOrDefault(host)?.Name);
                if (Running.TryGetValue(host, out var r)) _c.Execute("SELECT * FROM " + r.Name);
                _c.Execute("SELECT * FROM " + Bag[host]);
                return Ok();
            }
            public IActionResult Fallback(string host)
            {
                _c.Execute("SELECT * FROM " + Tenants.GetValueOrDefault(host, new Tenant { Name = host }).Name); /*sink*/
                return Ok();
            }
            public static void Register(string k, Tenant v, object o) { Tenants[k] = v; Running[k] = v; Bag[k] = o; }
        }
        """);

    [Fact]
    public void Text_and_sequences_of_text_found_by_a_request_key_are_request_data() => Expect("""
        public class LabelsController : ControllerBase
        {
            private static readonly Dictionary<string, string> Labels = new();
            private static readonly Dictionary<string, List<string>> Groups = new();
            private static readonly Dictionary<string, string[]> Parts = new();
            private readonly SqlConnection _c = new();
            public IActionResult Show(string k)
            {
                _c.Execute("SELECT * FROM " + Labels[k]); /*sink*/
                if (Labels.TryGetValue(k, out var l)) _c.Execute("SELECT * FROM " + l); /*sink*/
                _c.Execute("SELECT * FROM " + string.Join(",", Groups[k])); /*sink*/
                _c.Execute("SELECT * FROM " + Parts.GetValueOrDefault(k)?[0]); /*sink*/
                return Ok();
            }
            public static void Grow(string k, string v) { Labels[k] = v; Groups[k] = new() { v }; Parts[k] = new[] { v }; }
        }
        """);

    [Fact]
    public void A_table_the_request_filled_is_request_data_whatever_its_elements() => Expect("""
        public sealed class Item { public string Body { get; set; } = ""; }
        public class ItemsController : ControllerBase
        {
            private static readonly Dictionary<string, Item> ById = new();
            private readonly SqlConnection _c = new();
            public IActionResult Save(string id, string body)
            {
                ById[id] = new Item { Body = body };
                _c.Execute("SELECT * FROM " + ById["home"].Body); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_settings_object_picked_by_the_request_path_in_a_project_table_is_not_request_data() => Expect("""
        using System.Collections.Concurrent;
        public sealed class ShopSettings { public string Name { get; init; } = ""; public string RequestPrefix { get; init; } = ""; }
        public sealed class RunningShops
        {
            private readonly ConcurrentDictionary<string, ShopSettings> _byPrefix = new();
            public void Add(ShopSettings s) => _byPrefix[s.RequestPrefix] = s;
            public ShopSettings? Match(string host, string path)
            {
                var first = path.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                return _byPrefix.TryGetValue(host + "/" + first, out var s) ? s : null;
            }
        }
        public sealed class ShopMiddleware
        {
            private readonly RequestDelegate _next;
            private readonly RunningShops _shops;
            private readonly SqlConnection _c = new();
            public ShopMiddleware(RequestDelegate next, RunningShops shops) { _next = next; _shops = shops; }
            public async Task InvokeAsync(HttpContext context)
            {
                var shop = _shops.Match(context.Request.Host.Value ?? "", context.Request.Path.Value ?? "");
                if (shop != null) _c.Execute("SELECT * FROM shop_" + shop.Name);
                _c.Execute("SELECT * FROM t WHERE p = '" + context.Request.Path.Value + "'"); /*sink*/
                await _next(context);
            }
        }
        """);

    [Fact]
    public void A_project_cache_shaped_like_get_with_a_factory_gives_the_factory_result() => Expect("""
        public sealed class TextCache<T>
        {
            private readonly Dictionary<string, T> _items = new();
            public T Get(string key, Func<T> acquire)
            {
                if (_items.TryGetValue(key, out var hit)) return hit;
                var made = acquire();
                _items[key] = made;
                return made;
            }
            public async Task<T> GetAsync(Func<Task<T>> load, string key, params object[] parts) =>
                _items.TryGetValue(key + string.Join(".", parts), out var hit) ? hit : await load();
            public T? Find(string key) => _items.TryGetValue(key, out var hit) ? hit : default;
        }
        public class PagesController : ControllerBase
        {
            private static readonly TextCache<string> Titles = new();
            private readonly SqlConnection _c = new();
            public async Task<IActionResult> Show(string slug)
            {
                _c.Execute("SELECT * FROM " + Titles.Get(slug, () => "pages"));
                _c.Execute("SELECT * FROM " + await Titles.GetAsync(() => Task.FromResult("pages"), "k:" + slug, slug));
                _c.Execute("SELECT * FROM " + Titles.Find(slug)); /*sink*/
                return Ok();
            }
            public IActionResult Load(string slug)
            {
                _c.Execute("SELECT * FROM " + Titles.Get("pages", () => slug)); /*sink*/
                return Ok();
            }
            private static T Pick<T>(string key, T fallback, Func<T> make) where T : class => key.Length > 0 ? fallback : make();
            public IActionResult Choose(string slug)
            {
                _c.Execute("SELECT * FROM " + Pick("k", slug, () => "pages")); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void Library_caches_with_a_factory_give_the_factory_result() => Expect("""
        using System.Collections.Concurrent;
        using Microsoft.Extensions.Caching.Memory;
        public sealed class Page { public string Title { get; set; } = ""; }
        public class PagesController : ControllerBase
        {
            private static readonly ConcurrentDictionary<string, Page> Pages = new();
            private static readonly ConcurrentDictionary<string, string> Names = new();
            private readonly IMemoryCache _cache;
            private readonly SqlConnection _c = new();
            public PagesController(IMemoryCache cache) => _cache = cache;
            public async Task<IActionResult> Show(string slug)
            {
                _c.Execute("SELECT * FROM " + _cache.GetOrCreate(slug, e => "pages"));
                _c.Execute("SELECT * FROM " + await _cache.GetOrCreateAsync("p:" + slug, e => Task.FromResult("pages")));
                _c.Execute("SELECT * FROM " + Pages.GetOrAdd(slug, k => new Page { Title = "pages" }).Title);
                _c.Execute("SELECT * FROM " + Names.GetOrAdd(slug, "pages"));
                _c.Execute("SELECT * FROM " + _cache.Get<string>(slug)); /*sink*/
                return Ok();
            }
            public IActionResult Load(string slug)
            {
                _c.Execute("SELECT * FROM " + _cache.GetOrCreate("p", e => slug)); /*sink*/
                return Ok();
            }
            public IActionResult Name(string slug)
            {
                _c.Execute("SELECT * FROM " + Names.GetOrAdd("n", k => slug)); /*sink*/
                return Ok();
            }
        }
        """);
}
