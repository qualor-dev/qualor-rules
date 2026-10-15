using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 33: guards written the way project code writes them (models/README.md, "Guards in project code" and
/// "Membership"): a name equal to its own file-name part; a containment check held in a bool local, joined with `||` or
/// `&&`, or made on a full path built in a conditional; a project method returning bool whose true result proves a
/// check (a guard summary), or that throws unless it holds (an exit summary); membership in a collection that holds no
/// request data. Each with the controls that must stay found: a root the request chooses, a negated check, the failing
/// branch, a collection the request fills, a member path written after its check.
public sealed class ProjectGuardTests : ProbeModels
{
    private static void ExpectPath(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.path-traversal"));

    private static void ExpectRedirect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.open-redirect"));

    [Fact]
    public void A_name_equal_to_its_own_file_name_part_is_a_single_segment() => ExpectPath("""
        public class UploadController : ControllerBase
        {
            private const string Store = "/var/uploads";
            public void A(string name)
            {
                if (name != Path.GetFileName(name)) return;
                System.IO.File.Delete(Path.Combine(Store, name));
            }
            public void B(string name)
            {
                if (!string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal)) throw new ArgumentException(name);
                System.IO.File.Delete(Path.Combine(Store, name));
            }
            public void C(string name)
            {
                if (Path.GetFileName(name).Equals(name)) System.IO.File.Delete(Path.Combine(Store, name));
                System.IO.File.Delete(Path.Combine(Store, name)); /*sink*/
            }
            public void D(string name, string other)
            {
                // the file-name part of the name equals another value: the name itself may hold folders
                if (Path.GetFileName(name) != other) return;
                System.IO.File.Delete(Path.Combine(Store, name)); /*sink*/
            }
            public void E(string name)
            {
                // the failing branch
                if (name == Path.GetFileName(name)) return;
                System.IO.File.Delete(Path.Combine(Store, name)); /*sink*/
            }
            public void F(string name, string later)
            {
                if (name != Path.GetFileName(name)) return;
                name = later;
                System.IO.File.Delete(Path.Combine(Store, name)); /*sink*/
            }
            public void G(string name)
            {
                // the file-name part of another value equals the name: the name is that part, a single segment
                if (Path.GetFileName(Request.Query["p"].ToString()) != name) return;
                System.IO.File.Delete(Path.Combine(Store, name));
            }
        }
        """);

    [Fact]
    public void A_containment_check_held_in_a_bool_local_or_joined_with_or_is_a_guard() => ExpectPath("""
        public class StoreController : ControllerBase
        {
            private readonly string _root = Path.GetFullPath(Environment.GetEnvironmentVariable("STORE") ?? "/srv/store");
            public void A(string rel)
            {
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var inside = full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal);
                if (!inside) return;
                System.IO.File.ReadAllText(full);
            }
            public void B(string rel)
            {
                // the root itself, or a path below it; the full path is the root when nothing is asked for
                var full = string.IsNullOrEmpty(rel) ? _root : Path.GetFullPath(Path.Combine(_root, rel));
                var prefix = Path.EndsInDirectorySeparator(_root) ? _root : _root + Path.DirectorySeparatorChar;
                var allowed = full.Equals(_root, StringComparison.Ordinal) || full.StartsWith(prefix, StringComparison.Ordinal);
                if (!allowed) throw new InvalidOperationException(rel);
                System.IO.File.ReadAllText(full);
            }
            public void C(string rel, string chosen)
            {
                // the request chooses the root
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var inside = full.StartsWith(chosen + "/", StringComparison.Ordinal);
                if (!inside) return;
                System.IO.File.ReadAllText(full); /*sink*/
            }
            public void D(string rel)
            {
                // one side of the disjunction proves nothing
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var ok = full.StartsWith(_root + "/") || full.Length > 3;
                if (ok) System.IO.File.ReadAllText(full); /*sink*/
            }
            public void E(string rel)
            {
                // the bool says the path is outside
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var outside = !full.StartsWith(_root + "/");
                if (!outside) System.IO.File.ReadAllText(full);
                if (outside) System.IO.File.ReadAllText(full); /*sink*/
            }
            public void F(string rel)
            {
                // the path changes after the check is stored
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var inside = full.StartsWith(_root + "/");
                full = rel;
                if (inside) System.IO.File.ReadAllText(full); /*sink*/
            }
            public void G(string rel)
            {
                // one arm of the conditional is the request's own text
                var full = rel.Length == 0 ? rel : Path.GetFullPath(Path.Combine(_root, rel));
                if (!full.StartsWith(_root + "/")) return;
                System.IO.File.ReadAllText(full); /*sink*/
            }
            public void H(string rel)
            {
                // both sides of `&&` hold where the bool is true; `!(a && b)` false is both
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var both = full.Length > 1 && full.StartsWith(_root + "/");
                if (both) System.IO.File.ReadAllText(full);
                var neither = !(full.Length > 1 && full.StartsWith(_root + "/"));
                if (neither) return;
                System.IO.File.ReadAllText(full);
            }
            public void I(string rel)
            {
                // the prefix is the root alone, admitting every path
                var full = Path.GetFullPath(Path.Combine(_root, rel));
                var prefix = Path.EndsInDirectorySeparator(_root) ? _root : "/";
                if (!full.StartsWith(prefix)) return;
                System.IO.File.ReadAllText(full); /*sink*/
            }
        }
        """);

    /// A vault resolving names below its home folder (models/README.md, "Guards in project code": the home itself or a
    /// path below it, checked in a private helper): every operation through the helper is guarded.
    private const string Vault = """
        public sealed class Vault
        {
            private readonly string _home;
            public Vault(string home) => _home = Path.GetFullPath(home);
            public byte[] Load(string name) => System.IO.File.ReadAllBytes(Resolve(name)); /*sink*/
            public void Erase(string name) => System.IO.File.Delete(Resolve(name)); /*sink*/
            private string Resolve(string name)
            {
                if (name.Length == 0) return _home;
                string candidate = Path.GetFullPath(Path.Combine(_home, name));
                bool same = string.Equals(candidate, _home, StringComparison.OrdinalIgnoreCase);
                bool below = candidate.StartsWith($"{_home}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase);
                if (!(same || below)) throw new ArgumentOutOfRangeException(nameof(name));
                return candidate;
            }
        }
        """;

    [Fact]
    public void A_vault_with_a_home_the_server_chooses_is_quiet() => ExpectPath(Vault.Replace("/*sink*/", "") + """
        public class ArchiveController : ControllerBase
        {
            private readonly Vault _vault = new Vault("/srv/archive");
            public byte[] Get(string name) => _vault.Load(name);
            public void Delete(string name) => _vault.Erase(name);
        }
        """);

    [Fact]
    public void A_vault_whose_home_the_request_chooses_is_found() => ExpectPath(Vault + """
        public class ArchiveController : ControllerBase
        {
            public byte[] Get(string home, string name) => new Vault(home).Load(name);
            public void Delete(string home, string name) => new Vault(home).Erase(name);
        }
        """);

    [Fact]
    public void A_full_path_checked_in_place_cleans_the_path_it_was_made_of() => ExpectPath("""
        public class StoreController : ControllerBase
        {
            private const string Root = "/srv/store";
            public void A(string rel)
            {
                var path = Path.Combine(Root, rel);
                var full = Path.GetFullPath(path);
                if (!full.StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(path);
            }
            public void B(string rel)
            {
                var path = Path.Combine(Root, rel);
                if (!Path.GetFullPath(path).StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(path);
            }
            public void C(string rel, string other)
            {
                var path = Path.Combine(Root, rel);
                var full = Path.GetFullPath(path);
                path = other;
                if (!full.StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(path); /*sink*/
            }
        }
        """);

    private const string PathRules = """
        public static class PathRules
        {
            public static bool IsInside(string root, string candidate)
            {
                var full = Path.GetFullPath(candidate);
                return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            }
            public static bool IsOutside(string root, string candidate) => !IsInside(root, candidate);
            public static bool Loose(string root, string candidate) => candidate.Length > 0 || IsInside(root, candidate);
            public static bool IsSingleName(string name) => !string.IsNullOrEmpty(name) && name == Path.GetFileName(name);
        }
        """;

    [Fact]
    public void A_project_method_returning_bool_guards_its_argument_at_the_callers_branch() => ExpectPath(PathRules + """
        public class ReportController : ControllerBase
        {
            private const string Root = "/srv/reports";
            public void A(string p)
            {
                if (!PathRules.IsInside(Root, p)) return;
                System.IO.File.ReadAllText(p);
            }
            public void B(string p, string root)
            {
                // the request chooses the root the helper checks against
                if (!PathRules.IsInside(root, p)) return;
                System.IO.File.ReadAllText(p); /*sink*/
            }
            public void C(string p)
            {
                // the failing branch
                if (PathRules.IsInside(Root, p)) return;
                System.IO.File.ReadAllText(p); /*sink*/
            }
            public void D(string p)
            {
                if (PathRules.IsOutside(Root, p)) return;
                System.IO.File.ReadAllText(p);
            }
            public void G(string p)
            {
                // one side of the helper's disjunction proves nothing
                if (PathRules.Loose(Root, p)) System.IO.File.ReadAllText(p); /*sink*/
            }
            public void E(string name)
            {
                if (!PathRules.IsSingleName(name)) return;
                System.IO.File.Delete(Path.Combine(Root, name));
            }
            public void F(string name)
            {
                var ok = PathRules.IsSingleName(name);
                if (ok) System.IO.File.Delete(Path.Combine(Root, name));
                if (!ok) System.IO.File.Delete(Path.Combine(Root, name)); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_project_method_that_throws_unless_its_check_holds_cleans_its_argument_after_the_call() => ExpectPath(PathRules + """
        public class ReportController : ControllerBase
        {
            private const string Root = "/srv/reports";
            private static void EnsureInside(string p)
            {
                if (!PathRules.IsInside(Root, p)) throw new UnauthorizedAccessException(p);
            }
            private static void WarnOutside(string p)
            {
                if (!PathRules.IsInside(Root, p)) Console.WriteLine("outside: " + p);
            }
            private static void EnsureLater(string p)
            {
                if (!PathRules.IsInside(Root, p)) return;
                Console.WriteLine(p);
            }
            public void A(string p)
            {
                EnsureInside(p);
                System.IO.File.ReadAllText(p);
            }
            public void B(string p)
            {
                WarnOutside(p);
                System.IO.File.ReadAllText(p); /*sink*/
            }
            public void C(string p)
            {
                EnsureLater(p);
                System.IO.File.ReadAllText(p); /*sink*/
            }
        }
        """);

    /// RedirectHttpResult.IsLocalUrl is public from ASP.NET Core 10 (learn.microsoft.com); the fixture references are
    /// ASP.NET Core 8, so the snippet declares the type with the same name (a source type takes precedence).
    private const string LocalUrl = """
        namespace Microsoft.AspNetCore.Http.HttpResults
        {
            public sealed class RedirectHttpResult
            {
                public static bool IsLocalUrl(string? url) => url != null && url.Length > 0 && url[0] == '/';
            }
        }
        namespace Links
        {
            using Microsoft.AspNetCore.Http.HttpResults;
            public interface ILinkHelper { bool IsSafeTarget(string url); }
            public class LinkHelper : ILinkHelper
            {
                public virtual bool IsSafeTarget(string url)
                {
                    if (string.IsNullOrEmpty(url)) return false;
                    return RedirectHttpResult.IsLocalUrl(url);
                }
            }
        }
        """;

    [Fact]
    public void A_project_wrapper_of_IsLocalUrl_guards_the_redirect() => ExpectRedirect(LocalUrl + """
        namespace Links
        {
            using Microsoft.AspNetCore.Http.HttpResults;
            public class LoginController : ControllerBase
            {
                private readonly ILinkHelper _links;
                public LoginController(ILinkHelper links) => _links = links;
                public static ILinkHelper Make() => new LinkHelper();
                public IActionResult A(string returnUrl)
                {
                    if (!string.IsNullOrEmpty(returnUrl) && _links.IsSafeTarget(returnUrl)) return Redirect(returnUrl);
                    return Redirect(returnUrl); /*sink*/
                }
                public IActionResult B(string returnUrl)
                {
                    if (RedirectHttpResult.IsLocalUrl(returnUrl)) return Redirect(returnUrl);
                    return Redirect(returnUrl); /*sink*/
                }
            }
        }
        """);

    [Fact]
    public void A_wrapper_guards_only_when_every_target_of_the_call_is_one() => ExpectRedirect(LocalUrl + """
        namespace Links
        {
            public class TrustingLinkHelper : ILinkHelper
            {
                public bool IsSafeTarget(string url) => true;
            }
            public class LoginController : ControllerBase
            {
                private readonly ILinkHelper _links;
                public LoginController(ILinkHelper links) => _links = links;
                public static ILinkHelper Make(bool strict) => strict ? new LinkHelper() : new TrustingLinkHelper();
                public IActionResult A(string returnUrl)
                {
                    if (_links.IsSafeTarget(returnUrl)) return Redirect(returnUrl); /*sink*/
                    return Ok();
                }
            }
        }
        """);

    [Fact]
    public void A_wrapper_guards_a_member_path_until_it_is_written() => ExpectRedirect(LocalUrl + """
        namespace Links
        {
            public class SignIn { public string ReturnUrl { get; set; } = ""; public string Fallback { get; set; } = ""; }
            public class LoginController : ControllerBase
            {
                private readonly LinkHelper _links = new();
                public IActionResult A([FromBody] SignIn form)
                {
                    if (!_links.IsSafeTarget(form.ReturnUrl)) return BadRequest();
                    Redirect(form.ReturnUrl);
                    Redirect(form.Fallback); /*sink*/
                    form.ReturnUrl = form.Fallback;
                    return Redirect(form.ReturnUrl); /*sink*/
                }
                // the helper checks the URL it was given, then changes the member that URL was read from
                private static bool CheckThenSwap(string url, SignIn form)
                {
                    form.ReturnUrl = form.Fallback;
                    return Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult.IsLocalUrl(url);
                }
                public IActionResult B([FromBody] SignIn form)
                {
                    if (!CheckThenSwap(form.ReturnUrl, form)) return BadRequest();
                    return Redirect(form.ReturnUrl); /*sink*/
                }
            }
        }
        """);

    private const string Naming = """
        public sealed class Naming { public string[] Extensions { get; } = { ".srt", ".vtt" }; }
        public sealed class AnyEqual : IEqualityComparer<string>
        {
            public bool Equals(string? a, string? b) => true;
            public int GetHashCode(string s) => 0;
        }
        public static class Seq
        {
            public static bool Has(this IEnumerable<string> items, ReadOnlySpan<char> value, StringComparison comparison)
            {
                foreach (var item in items)
                    if (value.Equals(item, comparison)) return true;
                return false;
            }
        }
        public sealed class SaveForm { public string Format { get; set; } = ""; }
        """;

    [Fact]
    public void Membership_in_a_collection_that_holds_no_request_data_cleans_the_value() => ExpectPath(Naming + """
        public class SubtitleController : ControllerBase
        {
            private readonly HashSet<string> _formats;
            private readonly IReadOnlyDictionary<string, string> _folders;
            private readonly Dictionary<string, Type> _stores;
            private readonly string[] _named;
            public SubtitleController(Naming naming)
            {
                _named = naming.Extensions.Select(e => e.TrimStart('.')).ToArray();
                _formats = new HashSet<string>(naming.Extensions.Select(e => e.TrimStart('.')), StringComparer.OrdinalIgnoreCase);
                _folders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["movies"] = "/srv/movies", ["shows"] = "/srv/shows" };
                _stores = naming.Extensions.ToDictionary(e => e.TrimStart('.'), e => typeof(string), StringComparer.OrdinalIgnoreCase);
            }
            public void A(string format)
            {
                if (!_formats.Contains(format)) throw new ArgumentException(format);
                System.IO.File.Create("/srv/sub." + format);
            }
            public void B(string kind)
            {
                if (!_folders.ContainsKey(kind)) return;
                System.IO.Directory.CreateDirectory(Path.Combine("/srv", kind));
            }
            public void C(string kind)
            {
                if (!_stores.TryGetValue(kind, out var type)) throw new KeyNotFoundException(kind);
                System.IO.Directory.CreateDirectory(Path.Combine("/srv", kind));
            }
            public void D(string format)
            {
                // the failing branch
                if (_formats.Contains(format)) return;
                System.IO.File.Create("/srv/sub." + format); /*sink*/
            }
            public void E([FromBody] SaveForm form, string other)
            {
                if (!_formats.Contains(form.Format)) return;
                System.IO.File.Create("/srv/sub." + form.Format);
                form.Format = other;
                System.IO.File.Create("/srv/sub." + form.Format); /*sink*/
            }
            public void F(string format)
            {
                // a project method that compares with each element (passing the collection to it makes it no server
                // collection of its own: its summary says the value is one of the elements)
                if (!_named.Has(format, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException(format);
                System.IO.File.Create("/srv/sub." + format);
            }
            public void H(string format) => SaveAs(format.ToLowerInvariant());
            private void SaveAs(string extension)
            {
                // the same check in a helper the action calls (the field is the object's own state there)
                if (!_named.Has(extension, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException(extension);
                System.IO.File.Create("/srv/sub." + extension);
            }
            public void G(string format)
            {
                var known = new HashSet<string> { "srt", "vtt" };
                if (!known.Contains(format)) return;
                System.IO.File.Create("/srv/sub." + format);
            }
        }
        """);

    [Fact]
    public void Membership_in_a_collection_the_request_fills_is_no_guard() => ExpectPath(Naming + """
        public class TagController : ControllerBase
        {
            private static readonly List<string> Seen = new() { "a" };
            private readonly Dictionary<string, string> _byName = new();
            private readonly HashSet<string> _loose = new(new AnyEqual()) { "a" };
            public void Remember(string tag) => Seen.Add(tag);
            public void Name(string name) => _byName[name] = "x";
            public void A(string tag)
            {
                // another request writes the list
                if (!Seen.Contains(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void B(string tag, string other)
            {
                // this request writes it
                var known = new List<string> { "x" };
                known.Add(other);
                if (!known.Contains(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void C(string name)
            {
                // the keys are request data, the values are not
                if (!_byName.ContainsKey(name)) return;
                System.IO.File.Delete("/srv/tags/" + name); /*sink*/
            }
            public void D(string tag)
            {
                // a project comparer may call anything equal
                if (!_loose.Contains(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void E(string tag, string other)
            {
                var known = new List<string> { "x", other };
                if (!known.Has(tag, StringComparison.Ordinal)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void F(string other)
            {
                // a server value searched in a collection the request fills stays the server's on either branch
                var known = new List<string> { "x", other };
                var name = "fixed";
                if (!known.Has(name, StringComparison.Ordinal)) System.IO.File.Delete("/srv/tags/" + name);
                System.IO.File.Delete("/srv/tags/" + name);
            }
        }
        """);

    private const string Registry = """
        public sealed class Store { public string Key { get; set; } = ""; public Type Kind { get; set; } = typeof(object); }
        public sealed class Registry
        {
            private Store[] _stores = Array.Empty<Store>();
            public void Register(IEnumerable<string> keys) => _stores = keys.Select(k => new Store { Key = k }).ToArray();
            public void Register() => _stores = new[] { new Store { Key = "network" }, new Store { Key = "encoding" } };
            public Store Find(string key) => _stores.First(s => string.Equals(s.Key, key, StringComparison.OrdinalIgnoreCase));
            public Store? Lookup(string key) => Array.Find(_stores, s => s.Key == key);
            public bool Knows(string key) => _stores.Any(s => s.Key.Equals(key, StringComparison.Ordinal));
        }
        """;

    [Fact]
    public void A_search_of_registered_keys_that_fails_on_a_miss_cleans_the_key() => ExpectPath(Registry + """
        public class ConfigController : ControllerBase
        {
            private readonly Registry _registry;
            public ConfigController(Registry registry) => _registry = registry;
            private static string FileOf(string key) => Path.Combine("/etc/app", key.ToLowerInvariant() + ".xml");
            public void A(string key)
            {
                var store = _registry.Find(key);
                System.IO.File.WriteAllText(FileOf(key), store.Kind.Name);
            }
            public void B(string key)
            {
                if (_registry.Lookup(key) is null) return;
                System.IO.File.WriteAllText(FileOf(key), "x"); /*sink*/
            }
            public void C(string key)
            {
                if (!_registry.Knows(key)) return;
                System.IO.File.WriteAllText(FileOf(key), "x");
            }
            public void D(string key)
            {
                // the file is named before the search
                var file = FileOf(key);
                _registry.Find(key);
                System.IO.File.WriteAllText(file, "x"); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_search_of_keys_the_request_registers_is_no_guard() => ExpectPath(Registry + """
        public class ConfigController : ControllerBase
        {
            private readonly Registry _registry;
            public ConfigController(Registry registry) => _registry = registry;
            public void Add(string key) => _registry.Register(new[] { key });
            public void A(string key)
            {
                _registry.Find(key);
                System.IO.File.WriteAllText("/etc/app/" + key, "x"); /*sink*/
            }
        }
        """);

    // ---- Fix round 1 (review of Task 33; ruling R-E41) ----

    private const string Lines = """
        public sealed class Line { public string Code { get; set; } = ""; }
        public static class Lookup
        {
            public static Line ByCode(IEnumerable<Line> lines, string code) => lines.First(l => l.Code == code);
            public static bool HasCode(IEnumerable<Line> lines, string code) => lines.Any(l => l.Code == code);
        }
        public static class Defaults { public static Line Blank() => new Line { Code = "none" }; }
        """;

    [Fact]
    public void A_search_of_a_collection_the_request_posts_is_no_guard() => ExpectPath(Lines + """
        public class OrderController : ControllerBase
        {
            public void A([FromBody] List<Line> lines, string code)
            {
                // the posted lines hold the posted code: matching proves nothing
                if (lines.Any(l => l.Code == code)) System.IO.File.Delete("/srv/orders/" + code); /*sink*/
                if (lines.Exists(l => l.Code == code)) System.IO.File.Delete("/srv/orders/" + code); /*sink*/
                lines.First(l => l.Code.Equals(code));
                System.IO.File.Delete("/srv/orders/" + code); /*sink*/
            }
            public void B([FromBody] Line[] lines, string code)
            {
                if (Array.Exists(lines, l => l.Code == code)) System.IO.File.Delete("/srv/orders/" + code); /*sink*/
            }
            public void C([FromBody] Line line, string code)
            {
                var lines = new List<Line> { line };
                if (lines.Any(l => l.Code == code)) System.IO.File.Delete("/srv/orders/" + code); /*sink*/
            }
            public void D([FromBody] List<Line> lines, string code)
            {
                // a helper searching what its caller gives
                Lookup.ByCode(lines, code);
                System.IO.File.Delete("/srv/orders/" + code); /*sink*/
                if (Lookup.HasCode(lines, code)) System.IO.File.Delete("/srv/orders/" + code); /*sink*/
            }
        }
        """);

    private const string Checks = """
        public static class Checks
        {
            private const string Root = "/srv/reports";
            public static bool IsInside(string p) => Path.GetFullPath(p).StartsWith(Root + "/", StringComparison.Ordinal);
            public static async Task RequireAsync(string p)
            {
                await Task.Yield();
                if (!IsInside(p)) throw new UnauthorizedAccessException(p);
            }
            public static IEnumerable<string> RequireEach(string p)
            {
                if (!IsInside(p)) throw new UnauthorizedAccessException(p);
                yield return p;
            }
            // the returned condition is negated as a whole
            public static bool NotBoth(string p) => !(IsInside(p) && p.Length > 0);
        }
        """;

    [Fact]
    public void An_async_check_guards_only_where_it_is_awaited_and_an_iterator_never() => ExpectPath(Checks + """
        public class ReportController : ControllerBase
        {
            public async Task A(string p)
            {
                await Checks.RequireAsync(p);
                System.IO.File.ReadAllText(p);
            }
            public async Task B(string p)
            {
                await Checks.RequireAsync(p).ConfigureAwait(false);
                System.IO.File.ReadAllText(p);
            }
            public void C(string p)
            {
                // started, never awaited
                _ = Checks.RequireAsync(p);
                System.IO.File.ReadAllText(p); /*sink*/
            }
            public async Task D(string p)
            {
                // awaited only after the read
                var pending = Checks.RequireAsync(p);
                System.IO.File.ReadAllText(p); /*sink*/
                await pending;
            }
            public void E(string p)
            {
                // an iterator runs nothing until it is enumerated
                Checks.RequireEach(p);
                System.IO.File.ReadAllText(p); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_returned_condition_keeps_its_negation() => ExpectPath(Checks + """
        public class ReportController : ControllerBase
        {
            public void A(string p)
            {
                if (!Checks.NotBoth(p)) System.IO.File.ReadAllText(p);
                if (Checks.NotBoth(p)) System.IO.File.ReadAllText(p); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_full_path_resolved_against_another_base_does_not_clean_its_source() => ExpectPath("""
        public class ReportController : ControllerBase
        {
            private const string Root = "/srv/reports";
            public void A(string rel)
            {
                var full = Path.GetFullPath(rel, Root);
                if (!full.StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(full);
                System.IO.File.ReadAllText(rel); /*sink*/
            }
            public void B(string rel)
            {
                if (!Path.GetFullPath(rel, Root).StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(rel); /*sink*/
            }
        }
        """);

    [Fact]
    public void Only_comparers_that_tell_every_character_apart_count() => ExpectPath("""
        public class TagController : ControllerBase
        {
            private readonly HashSet<string> _loose;
            private readonly HashSet<string> _strict;
            public TagController()
            {
                _loose = new HashSet<string>(StringComparer.Create(System.Globalization.CultureInfo.InvariantCulture, System.Globalization.CompareOptions.IgnoreSymbols)) { "etcpasswd" };
                _strict = new HashSet<string>(StringComparer.FromComparison(StringComparison.OrdinalIgnoreCase)) { "readme" };
            }
            public void A(string tag)
            {
                if (_loose.Contains(tag)) System.IO.File.ReadAllText("/" + tag); /*sink*/
                if (_strict.Contains(tag)) System.IO.File.ReadAllText("/" + tag);
                var local = new HashSet<string>(System.Globalization.GlobalizationExtensions.GetStringComparer(System.Globalization.CultureInfo.InvariantCulture.CompareInfo, System.Globalization.CompareOptions.IgnoreSymbols)) { "etcpasswd" };
                if (local.Contains(tag)) System.IO.File.ReadAllText("/" + tag); /*sink*/
                var plain = new HashSet<string>(EqualityComparer<string>.Default) { "readme" };
                if (plain.Contains(tag)) System.IO.File.ReadAllText("/" + tag);
            }
        }
        """);

    private const string Stored = """
        public static class Seq2
        {
            public static bool Holds(this IEnumerable<string> items, string value)
            {
                foreach (var item in items)
                    if (string.Equals(item, value, StringComparison.Ordinal)) return true;
                return false;
            }
        }
        """;

    [Fact]
    public void Data_a_request_stored_never_vouches_for_fresh_input() => ExpectPath(Stored + """
        public class TagController : ControllerBase
        {
            private static readonly List<string> Recent = new() { "a" };
            private static string _previous = "x";
            private string[] _allowed = Array.Empty<string>();
            public void Remember(string tag) => Recent.Add(tag);
            public void Keep(string v) => _previous = v;
            public void Allow(string[] xs) => _allowed = xs.ToArray();
            public void A(string tag)
            {
                // through a project loop over the stored list
                if (!Recent.Holds(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void B(string tag)
            {
                // through a copy of it
                var snapshot = Recent.ToList();
                if (!snapshot.Contains(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void C(string tag)
            {
                // equal to a value another request stored
                if (tag == _previous) System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
                var copy = _previous;
                if (tag == copy) System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
            public void D(string tag)
            {
                // a collection another request assigns wholesale
                if (!_allowed.Contains(tag)) return;
                System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
        }
        """);

    [Fact]
    public void Data_set_at_startup_or_from_configuration_still_guards() => ExpectPath(Stored + """
        public static class Setup
        {
            public static string Root = "/srv/tags";
            public static readonly List<string> Known = new() { "a" };
            public static void Configure(Microsoft.Extensions.Configuration.IConfiguration config)
            {
                Root = config["TagRoot"] ?? "/srv/tags";
            }
        }
        public class TagController : ControllerBase
        {
            public void A(string folder)
            {
                if (folder == Setup.Root) System.IO.Directory.CreateDirectory(folder);
                if (Setup.Known.Holds(folder)) System.IO.Directory.CreateDirectory(folder);
            }
        }
        """);

    [Fact]
    public void An_or_cleans_only_what_both_sides_clean() => ExpectPath("""
        public class ReportController : ControllerBase
        {
            private const string Root = "/srv/reports";
            public void A(string rel, string name)
            {
                var full = Path.GetFullPath(Path.Combine(Root, rel));
                var ok = full.StartsWith(Root + "/") || name == "x";
                if (ok) System.IO.File.ReadAllText(full); /*sink*/
                if (ok) System.IO.File.ReadAllText(name); /*sink*/
                var both = full.StartsWith(Root + "/") || full == Root;
                if (both) System.IO.File.ReadAllText(full);
            }
        }
        """);

    // ---- R-E41 refined: a containment root stored earlier guards ----

    /// A media store whose home folder comes from a tenant name an admin request saved earlier (made a single folder name
    /// there): activating the tenant builds the store from the setting through its constructor; the store checks
    /// containment as "the home itself, or below it" (models/README.md, "Guards in project code").
    private const string Tenants = """
        public sealed class TenantSettings { public string Name { get; set; } = "default"; }
        public static class TenantHost
        {
            public static readonly TenantSettings Settings = new();
            public static MediaStore Store = new MediaStore("/srv/tenants/default");
            public static void Activate() => Store = new MediaStore(Path.Combine("/srv/tenants", Settings.Name));
        }
        public class TenantAdminController : ControllerBase
        {
            public void Rename(string name)
            {
                TenantHost.Settings.Name = Path.GetFileName(name);
                TenantHost.Activate();
            }
        }
        public sealed class MediaStore
        {
            private readonly string _home;
            public MediaStore(string home) => _home = Path.GetFullPath(home);
            public string Read(string rel)
            {
                var candidate = Path.GetFullPath(Path.Combine(_home, rel));
                var allowed = candidate.Equals(_home, StringComparison.Ordinal)
                    || candidate.StartsWith(_home + Path.DirectorySeparatorChar, StringComparison.Ordinal);
                if (!allowed) throw new UnauthorizedAccessException(rel);
                return System.IO.File.ReadAllText(candidate); /*sink*/
            }
        }
        """;

    [Fact]
    public void A_containment_root_stored_by_an_earlier_request_guards() => ExpectPath(Tenants.Replace("/*sink*/", "") + """
        public class MediaController : ControllerBase
        {
            public string Get(string rel) => TenantHost.Store.Read(rel);
        }
        """);

    [Fact]
    public void A_containment_root_taken_from_the_current_request_never_guards() => ExpectPath(Tenants + """
        public class MediaController : ControllerBase
        {
            public string Get(string home, string rel) => new MediaStore(home).Read(rel);
        }
        """);

    [Fact]
    public void An_allow_list_field_a_request_writes_still_does_not_guard() => ExpectPath("""
        public class TagController : ControllerBase
        {
            private static string _chosen = "a";
            public void Choose(string v) => _chosen = v;
            public void A(string tag)
            {
                // equality with the field is the allow-list: no containment around it
                if (tag.Equals(_chosen, StringComparison.Ordinal)) System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
                var ok = tag.Equals(_chosen, StringComparison.Ordinal) || tag.StartsWith("x", StringComparison.Ordinal);
                if (ok) System.IO.File.Delete("/srv/tags/" + tag); /*sink*/
            }
        }
        """);
}
