using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 27 (decision R-8): the heap is per abstract object inside the request scope. An object made by `new` (an object,
/// an anonymous object, a collection) is its allocation site; a model the binder makes for an action parameter is one
/// object per entry point. A member written through a known object is that object's member; a value whose objects are
/// unknown (or more than the bound) reads and writes the member's field location, which every read joins. A write that
/// replaces a member on every path (a strong update of an access path) is the member's whole value until something may
/// change it again; a summary carries what a body writes into and reads from the objects its parameters and `this` are,
/// and a call site puts its own objects in their place. Shapes written anew for this task.
public sealed class AllocationSiteHeapTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    // ---- Objects of one type ----

    [Fact]
    public void Two_objects_of_one_type_keep_their_members_apart() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Merge(string name, bool rename)
            {
                var kept = new Contact();
                var other = new Contact();
                if (rename) kept.Name = name;
                _c.Execute("SELECT id FROM contacts WHERE name = '" + other.Name + "'");
                _c.Execute("SELECT id FROM contacts WHERE name = '" + kept.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_helper_reads_the_member_of_the_object_each_call_gives_it() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Audit
        {
            private readonly SqlConnection _c = new();
            public void Created(Contact c) => _c.Execute("INSERT INTO log VALUES ('created " + c.Name + "')");
            public void Renamed(Contact c) => _c.Execute("INSERT INTO log VALUES ('renamed " + c.Name + "')"); /*sink*/
        }
        public class ContactsController : ControllerBase
        {
            private readonly Audit _audit = new();
            public IActionResult Rename(string name)
            {
                var fresh = new Contact();
                fresh.Name = "new contact";
                var renamed = new Contact();
                if (name.Length > 0) renamed.Name = name;
                _audit.Created(fresh);
                _audit.Renamed(renamed);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_helper_given_an_object_whose_member_was_overwritten_reads_the_new_value() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Audit
        {
            private readonly SqlConnection _c = new();
            public void Created(Contact c) => _c.Execute("INSERT INTO log VALUES ('created " + c.Name + "')");
            public void Renamed(Contact c) => _c.Execute("INSERT INTO log VALUES ('renamed " + c.Name + "')"); /*sink*/
        }
        public class ContactsController : ControllerBase
        {
            private readonly Audit _audit = new();
            public IActionResult Rename(string name)
            {
                var c = new Contact();
                c.Name = name;
                _audit.Renamed(c);
                c.Name = "anonymous";
                _audit.Created(c);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_cache_key_built_from_a_constant_is_clean_beside_one_built_from_the_request() => Expect("""
        public sealed class CacheKey
        {
            public CacheKey(string key) { Key = key; }
            public string Key { get; }
        }
        public class SqlCache
        {
            private readonly SqlConnection _c = new();
            public string Load(CacheKey key) => _c.ExecuteScalar<string>("SELECT v FROM cache WHERE k = '" + key.Key + "'");
            public string Search(CacheKey key) => _c.ExecuteScalar<string>("SELECT v FROM cache WHERE k LIKE '" + key.Key + "%'"); /*sink*/
        }
        public class ProductsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly SqlCache _cache = new();
            public IActionResult Find(string term)
            {
                var all = new CacheKey("products.all");
                var byTerm = new CacheKey("products.term." + term);
                _cache.Load(all);
                _cache.Search(byTerm);
                _c.Execute("DELETE FROM cache WHERE k = '" + all.Key + "'");
                _c.Execute("DELETE FROM cache WHERE k = '" + byTerm.Key + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_builder_chain_keeps_each_builders_own_text() => Expect("""
        public class QueryBuilder
        {
            private string _where = "";
            public QueryBuilder And(string clause) { _where += " AND " + clause; return this; }
            public string Build() => "SELECT * FROM items WHERE 1 = 1" + _where;
        }
        public class ItemsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult List(string owner)
            {
                var fixedSql = new QueryBuilder().And("active = 1").And("deleted = 0").Build();
                var ownerSql = new QueryBuilder().And("active = 1").And("owner = '" + owner + "'").Build();
                _c.Execute(fixedSql);
                _c.Execute(ownerSql); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_collection_member_is_element_insensitive_per_object() => Expect("""
        public class Basket { public List<string> Lines { get; } = new(); }
        public class BasketController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Add(string line)
            {
                var mine = new Basket();
                var shared = new Basket();
                mine.Lines.Add("fixed");
                mine.Lines.Add(line);
                shared.Lines.Add("fixed");
                _c.Execute("SELECT * FROM t WHERE l = '" + shared.Lines[0] + "'");
                _c.Execute("SELECT * FROM t WHERE l = '" + mine.Lines[0] + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- Strong updates ----

    [Fact]
    public void A_bound_models_member_overwritten_on_every_path_is_clean_and_its_others_stay_request_data() => Expect("""
        public class Filter { public string Column { get; set; } = ""; public string Value { get; set; } = ""; }
        public class ReportsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run([FromBody] Filter filter, bool admin)
            {
                if (admin) filter.Column = "created";
                else filter.Column = "name";
                _c.Execute("SELECT * FROM reports ORDER BY " + filter.Column);
                _c.Execute("SELECT * FROM reports WHERE v = '" + filter.Value + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_member_overwritten_on_one_branch_only_keeps_the_request_data() => Expect("""
        public class Filter { public string Column { get; set; } = ""; }
        public class ReportsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run([FromBody] Filter filter, bool admin)
            {
                if (admin) filter.Column = "created";
                _c.Execute("SELECT * FROM reports ORDER BY " + filter.Column); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_write_through_an_alias_ends_the_strong_update() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Copy(string name)
            {
                var a = new Contact();
                var b = a;
                a.Name = "fixed";
                b.Name = name;
                _c.Execute("SELECT * FROM t WHERE n = '" + a.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_call_that_may_write_the_object_ends_the_strong_update() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Renamer { public void Apply(Contact c, string name) { if (name.Length > 1) c.Name = name; } }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Renamer _renamer = new();
            public IActionResult Rename(string name)
            {
                var a = new Contact();
                a.Name = "fixed";
                _renamer.Apply(a, name);
                _c.Execute("SELECT * FROM t WHERE n = '" + a.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_callee_that_writes_a_member_on_every_path_overwrites_it_at_the_call() => Expect("""
        public class Contact { public string Name { get; set; } = ""; public string Note { get; set; } = ""; }
        public class Defaults { public void Reset(Contact c) { c.Name = "anonymous"; } }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Defaults _defaults = new();
            public IActionResult Save([FromBody] Contact contact)
            {
                _defaults.Reset(contact);
                _c.Execute("SELECT * FROM t WHERE n = '" + contact.Name + "'");
                _c.Execute("SELECT * FROM t WHERE n = '" + contact.Note + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_callee_writing_the_member_through_an_object_it_holds_ends_the_strong_update() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Registry
        {
            private Contact _current = new();
            public void Keep(Contact c) => _current = c;
            public void RenameCurrent(string name) => _current.Name = name;
        }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Registry _registry = new();
            public IActionResult Rename(string name)
            {
                var a = new Contact();
                a.Name = "fixed";
                _registry.Keep(a);
                _registry.RenameCurrent(name);
                _c.Execute("SELECT * FROM t WHERE n = '" + a.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_write_through_an_unknown_object_reaches_every_object_of_the_member() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Registry
        {
            private readonly List<Contact> _all = new();
            public void Keep(Contact c) => _all.Add(c);
            public void RenameFirst(string name) => _all[0].Name = name;
        }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Registry _registry = new();
            public IActionResult Rename(string name)
            {
                var a = new Contact();
                _registry.Keep(a);
                _registry.RenameFirst(name);
                _c.Execute("SELECT * FROM t WHERE n = '" + a.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_write_into_a_bound_models_member_stays_with_that_model() => Expect("""
        public class Filter { public string Column { get; set; } = ""; }
        public class ReportsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run([FromBody] Filter filter, [FromHeader] string sort)
            {
                var fallback = new Filter();
                if (sort.Length > 0) filter.Column = sort;
                _c.Execute("SELECT * FROM reports ORDER BY " + fallback.Column);
                _c.Execute("SELECT * FROM reports ORDER BY " + filter.Column); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- The bound on known objects ----

    [Fact]
    public void Eight_allocation_sites_in_one_variable_are_still_told_apart() => Expect(Picker(8));

    [Fact]
    public void A_ninth_allocation_site_falls_back_to_the_field_location_and_reports() => Expect(Picker(9));

    /// `pick` holds one of `sites` allocation sites; another object's member gets request data on one branch.
    private static string Picker(int sites)
    {
        var cases = string.Concat(Enumerable.Range(1, sites - 1).Select(i => $"            case {i}: pick = new Contact(); break;\n"));
        var sink = sites > 8 ? " /*sink*/" : "";
        return $$"""
            public class Contact { public string Name { get; set; } = ""; }
            public class ContactsController : ControllerBase
            {
                private readonly SqlConnection _c = new();
                public IActionResult Pick(int n, string name)
                {
                    var pick = new Contact();
                    switch (n)
                    {
            {{cases}}        }
                    var named = new Contact();
                    if (n > 100) named.Name = name;
                    _c.Execute("SELECT * FROM t WHERE n = '" + pick.Name + "'");{{sink}}
                    return Ok();
                }
            }
            """;
    }

    // ---- Recursion ----

    [Fact]
    public void A_recursive_fill_keeps_each_tree_apart() => Expect("""
        public class Tree { public string Name { get; set; } = ""; public List<Tree> Kids { get; } = new(); }
        public static class Trees
        {
            public static void Fill(Tree t, string name, int depth)
            {
                t.Name = name;
                if (depth <= 0) return;
                var kid = new Tree();
                Grow(kid, name, depth - 1);
                t.Kids.Add(kid);
            }
            private static void Grow(Tree t, string name, int depth) => Fill(t, name, depth);
        }
        public class TreesController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Build(string name)
            {
                var mine = new Tree();
                Trees.Fill(mine, name, 2);
                var fixedTree = new Tree();
                Trees.Fill(fixedTree, "root", 2);
                _c.Execute("SELECT * FROM t WHERE n = '" + fixedTree.Name + "'");
                _c.Execute("SELECT * FROM t WHERE n = '" + mine.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- Across projects ----

    [Fact]
    public void A_cache_key_crossing_projects_is_substituted_at_each_call()
    {
        const string contracts = """
            namespace Contracts;
            public sealed class CacheKey
            {
                public CacheKey(string key) { Key = key; }
                public string Key { get; }
            }
            public interface IKeyedStore { string Load(CacheKey key); string Search(CacheKey key); }
            """;
        const string services = """
            using Contracts;
            namespace Services;
            public class KeyedStore : IKeyedStore
            {
                private readonly SqlConnection _c = new();
                public string Load(CacheKey key) => new SqlCommand("SELECT v FROM cache WHERE k = '" + key.Key + "'", _c).ExecuteScalar() as string ?? "";
                public string Search(CacheKey key) => new SqlCommand("SELECT v FROM cache WHERE k LIKE '" + key.Key + "%'", _c).ExecuteScalar() as string ?? "";
            }
            """;
        const string web = """
            using Contracts;
            public class ProductsController : ControllerBase
            {
                private readonly IKeyedStore _store;
                public ProductsController(IKeyedStore store) => _store = store;
                public IActionResult Find(string term)
                {
                    _store.Load(new CacheKey("products.all"));
                    _store.Search(new CacheKey("products.term." + term));
                    return Ok();
                }
            }
            """;
        var c = Project("Contracts", contracts);
        var s = Project("Services", services, c);
        var w = Project("Web", web, c);
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(new LoadedSolution(new[] { c, s, w }), CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        Assert.Equal(0, result.Stats.FailedMethods);
        var lines = result.Findings.Select(f => (Path.GetFileName(f.Sink.SourceTree!.FilePath), f.Sink.GetLineSpan().StartLinePosition.Line + 1)).ToList();
        Assert.Equal(new[] { ("Services.cs", 7) }, lines);
    }

    // ---- The view model ----

    private const string ProfileModel = """
        public class ProfileModel
        {
            public string Bio { get; set; } = "";
            public string Banner { get; set; } = "";
        }

        """;

    private const string ProfileView = """
        Write(Html.Raw(Model.Banner));
        Write(Html.Raw(Model.Bio));
        """;

    [Fact]
    public void A_factory_that_overwrites_a_posted_models_member_before_View_leaves_that_member_clean()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileFactory
            {
                public ProfileModel Prepare(ProfileModel model)
                {
                    model.Banner = "<b>Welcome back</b>";
                    return model;
                }
            }
            public class ProfileController : Controller
            {
                private readonly ProfileFactory _factory = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model = _factory.Prepare(model);
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // Line 1: the factory replaced the posted banner. Line 2: the posted bio, raw.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_factory_that_fills_a_posted_model_in_place_before_View_leaves_that_member_clean()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileFactory
            {
                public void Fill(ProfileModel model) { model.Banner = "<b>Welcome back</b>"; }
            }
            public class ProfileController : Controller
            {
                private readonly ProfileFactory _factory = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    _factory.Fill(model);
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_posted_models_member_overwritten_on_one_branch_only_still_reaches_the_view()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileFactory
            {
                public ProfileModel Prepare(ProfileModel model, bool fresh)
                {
                    if (fresh) model.Banner = "<b>Welcome</b>";
                    return model;
                }
            }
            public class ProfileController : Controller
            {
                private readonly ProfileFactory _factory = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model, bool fresh)
                {
                    model = _factory.Prepare(model, fresh);
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:1", "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_view_rendered_by_two_actions_keeps_a_member_only_both_overwrite()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileController : Controller
            {
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    return View(model);
                }
                [HttpPost]
                public IActionResult Preview(ProfileModel model) => View("Save", model);
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // Preview renders the posted banner as it came: line 1 is reported through Preview's request.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:1", "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_call_that_writes_other_members_keeps_the_overwritten_member_clean()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class Paging { public void Defaults(ProfileModel model) { model.Bio = model.Bio.Trim(); } }
            public class ProfileController : Controller
            {
                private readonly Paging _paging = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    _paging.Defaults(model);
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // Defaults writes Bio only (its summary says so): Banner stays the constant.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_null_check_or_a_list_call_given_the_model_keeps_the_overwritten_member_clean()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class Stores
            {
                public void Prepare<TModel>(TModel model, List<string> names) where TModel : class
                {
                    ArgumentNullException.ThrowIfNull(model);
                    names.Add(model.ToString() ?? "");
                }
            }
            public class ProfileController : Controller
            {
                private readonly Stores _stores = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    _stores.Prepare(model, new List<string>());
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // ThrowIfNull and List.Add set no member of the model: the banner stays the constant.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_partial_given_the_views_model_keeps_what_the_action_overwrote()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileController : Controller
            {
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    return View(model);
                }
            }
            """,
            View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", """
                Write(await Html.PartialAsync("_Info", Model));
                """),
            View("Views_Profile__Info", "ProfileModel", "/src/App/Views/Profile/_Info.cshtml", ProfileView));

        // The partial renders the same model: its banner is the constant, its bio the posted one.
        Assert.Equal(new[] { "/src/App/Views/Profile/_Info.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_view_also_rendering_a_fresh_model_whose_member_got_request_data_reports_it()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileController : Controller
            {
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    return View(model);
                }
                public IActionResult Create([FromQuery] string banner)
                {
                    var fresh = new ProfileModel();
                    if (banner.Length > 0) fresh.Banner = banner;
                    return View("Save", fresh);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // Create's model carries no request data itself, but its banner does: line 1 is reported through Create.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:1", "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    [Fact]
    public void A_callee_handing_the_model_to_code_the_engine_does_not_see_ends_the_strong_update()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class Drafts
            {
                public void Restore(ProfileModel model, string json) => Newtonsoft.Json.JsonConvert.PopulateObject(json, model);
            }
            public class ProfileController : Controller
            {
                private readonly Drafts _drafts = new();
                [HttpPost]
                public IActionResult Save(ProfileModel model)
                {
                    model.Banner = "<b>Saved</b>";
                    _drafts.Restore(model, "{}");
                    return View(model);
                }
            }
            """, View("Views_Profile_Save", "ProfileModel", "/src/App/Views/Profile/Save.cshtml", ProfileView));

        // PopulateObject may set any member of the posted model again: the banner is the posted object's again.
        Assert.Equal(new[] { "/src/App/Views/Profile/Save.cshtml:1", "/src/App/Views/Profile/Save.cshtml:2" }, Found(result));
    }

    // ---- Fix round 1 (task-27-review.md): findings the strong updates must not lose ----

    private const string Shapes = """
        public class Address { public string City { get; set; } = ""; }
        public class Order { public Address Shipping { get; set; } = new(); public string Note { get; set; } = ""; }
        public struct Tag { public string Text; }

        """;

    [Fact]
    public void A_nested_member_written_through_a_longer_path_is_its_new_value() => Expect(Shapes + """
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Ship(string city)
            {
                var order = new Order();
                order.Shipping = new Address { City = "Oslo" };
                order.Shipping.City = city;
                _c.Execute("SELECT * FROM rates WHERE city = '" + order.Shipping.City + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_nested_member_written_through_an_alias_is_seen_through_the_longer_path() => Expect(Shapes + """
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Ship(string city)
            {
                var order = new Order();
                order.Shipping = new Address { City = "Oslo" };
                var shipping = order.Shipping;
                shipping.City = city;
                _c.Execute("SELECT * FROM rates WHERE city = '" + order.Shipping.City + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_nested_object_initializer_does_not_outlive_a_later_write() => Expect(Shapes + """
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Ship(string city)
            {
                var order = new Order { Shipping = new Address { City = "Oslo" } };
                order.Shipping.City = city;
                _c.Execute("SELECT * FROM rates WHERE city = '" + order.Shipping.City + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_callee_that_may_write_a_member_and_then_reads_it_sees_its_own_write() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Normalizer
        {
            private readonly SqlConnection _c = new();
            public void Apply(Contact c, string candidate)
            {
                if (candidate.Length > 3) c.Name = candidate;
                _c.Execute("UPDATE contacts SET n = '" + c.Name + "'"); /*sink*/
            }
        }
        public class ContactsController : ControllerBase
        {
            private readonly Normalizer _normalizer = new();
            public IActionResult Save(string name)
            {
                var c = new Contact();
                c.Name = "anonymous";
                _normalizer.Apply(c, name);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_callee_whose_own_callee_may_write_the_member_sees_that_write() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Normalizer
        {
            private readonly SqlConnection _c = new();
            public void Apply(Contact c, string candidate)
            {
                Maybe(c, candidate);
                _c.Execute("UPDATE contacts SET n = '" + c.Name + "'"); /*sink*/
            }
            public void Maybe(Contact c, string candidate) { if (candidate.Length > 3) c.Name = candidate; }
        }
        public class ContactsController : ControllerBase
        {
            private readonly Normalizer _normalizer = new();
            public IActionResult Save(string name)
            {
                var c = new Contact();
                c.Name = "anonymous";
                _normalizer.Apply(c, name);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_struct_passed_by_value_keeps_its_own_member() => Expect(Shapes + """
        public class Tags { public void Reset(Tag t) { t.Text = "none"; } }
        public class TagsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Tags _tags = new();
            public IActionResult Add(string text)
            {
                var t = new Tag();
                t.Text = text;
                _tags.Reset(t);
                _c.Execute("INSERT INTO tags VALUES ('" + t.Text + "')"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_member_written_after_View_reaches_the_view()
    {
        var result = AnalyzeWeb(ProfileModel + """
            public class ProfileController : Controller
            {
                public IActionResult Show([FromQuery] string banner)
                {
                    var model = new ProfileModel();
                    model.Banner = "<b>Hello</b>";
                    var result = View(model);
                    model.Banner = banner;
                    return result;
                }
            }
            """, View("Views_Profile_Show", "ProfileModel", "/src/App/Views/Profile/Show.cshtml", ProfileView));

        Assert.Equal(new[] { "/src/App/Views/Profile/Show.cshtml:1" }, Found(result));
    }

    /// The action overwrites the contact's name after giving it request data, calls `call`, and reads the name into SQL.
    private static string AfterCall(string call, string extra = "") => """
        public class Contact { public string Name { get; set; } = ""; }

        """ + extra + $$"""
        public class ContactsController : Controller
        {
            private readonly SqlConnection _c = new();
            public async Task<IActionResult> Save(string name)
            {
                var c = new Contact();
                c.Name = name;
                c.Name = "anonymous";
                {{call}}
                _c.Execute("SELECT * FROM t WHERE n = '" + c.Name + "'"); /*sink*/
                await Task.CompletedTask;
                return Ok();
            }
        }
        """;

    [Fact]
    public void Reflection_through_Type_InvokeMember_ends_a_strong_update() =>
        Expect(AfterCall("typeof(Contact).InvokeMember(\"Name\", System.Reflection.BindingFlags.SetProperty, null, c, new object[] { name });"));

    [Fact]
    public void A_delegate_run_by_DynamicInvoke_ends_a_strong_update() =>
        Expect(AfterCall("Action<Contact> set = x => { }; set.DynamicInvoke(c);"));

    [Fact]
    public void A_method_group_given_to_List_ForEach_ends_a_strong_update() =>
        Expect(AfterCall("Renames.Value = name; new List<Contact> { c }.ForEach(Renames.Apply);",
            "public static class Renames { public static string Value = \"\"; public static void Apply(Contact x) { x.Name = Value; } }\n"));

    [Fact]
    public void A_method_group_given_to_Parallel_ForEach_ends_a_strong_update() =>
        Expect(AfterCall("Renames.Value = name; Parallel.ForEach(new[] { c }, Renames.Apply);",
            "public static class Renames { public static string Value = \"\"; public static void Apply(Contact x) { x.Name = Value; } }\n"));

    [Fact]
    public void An_instance_method_group_given_to_Select_ends_a_strong_update() =>
        Expect(AfterCall("var renamer = new Renamer { Value = name }; var all = new[] { c }.Select(renamer.Apply).ToList();",
            "public class Renamer { public string Value = \"\"; public Contact Apply(Contact x) { x.Name = Value; return x; } }\n"));

    [Fact]
    public void A_delegate_parameter_given_to_List_ForEach_ends_a_strong_update() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Batch
        {
            private readonly SqlConnection _c = new();
            public void Run(Contact c, Action<Contact> step)
            {
                c.Name = "anonymous";
                new List<Contact> { c }.ForEach(step);
                _c.Execute("UPDATE contacts SET n = '" + c.Name + "'"); /*sink*/
            }
        }
        public class ContactsController : ControllerBase
        {
            private readonly Batch _batch = new();
            public IActionResult Save(string name)
            {
                _batch.Run(new Contact(), x => x.Name = name);
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_callee_that_assigns_its_parameter_first_does_not_overwrite_the_callers_object() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Defaults { public void Reset(Contact c) { c = new Contact(); c.Name = "anonymous"; } }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Defaults _defaults = new();
            public IActionResult Save(string name)
            {
                var c = new Contact();
                c.Name = name;
                _defaults.Reset(c);
                _c.Execute("SELECT * FROM t WHERE n = '" + c.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_async_callee_not_awaited_where_it_is_called_has_not_overwritten_the_member_yet() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class Defaults { public async Task ResetLater(Contact c) { await Task.Yield(); c.Name = "anonymous"; } }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private readonly Defaults _defaults = new();
            public async Task<IActionResult> Save(string name)
            {
                var c = new Contact();
                c.Name = name;
                var pending = _defaults.ResetLater(c);
                _c.Execute("SELECT * FROM t WHERE n = '" + c.Name + "'"); /*sink*/
                await pending;
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_variable_a_lambda_assigns_holds_unknown_objects() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class ContactsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Swap(string name)
            {
                var c = new Contact();
                var other = new Contact();
                if (name.Length > 1) other.Name = name;
                Action swap = () => c = other;
                swap();
                _c.Execute("SELECT * FROM t WHERE n = '" + c.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- Ruling R-E31 ----

    [Fact]
    public void A_record_with_copy_starts_with_the_source_members_and_takes_its_initializer() => Expect("""
        public record Filter(string Column, string Value);
        public class ReportsController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run(string value, string column)
            {
                var asked = new Filter("name", value);
                var sorted = asked with { Column = "created" };
                var other = new Filter(column, "x") with { Value = "y" };
                _c.Execute("SELECT * FROM t ORDER BY " + sorted.Column);
                _c.Execute("SELECT * FROM t WHERE v = '" + sorted.Value + "'"); /*sink*/
                _c.Execute("SELECT * FROM t ORDER BY " + other.Column); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void TryUpdateModelAsync_fills_the_model_with_request_data() => Expect("""
        public class Contact { public string Name { get; set; } = ""; }
        public class ContactsController : Controller
        {
            private readonly SqlConnection _c = new();
            public async Task<IActionResult> Edit()
            {
                var c = new Contact();
                c.Name = "anonymous";
                if (await TryUpdateModelAsync(c))
                    _c.Execute("SELECT * FROM t WHERE n = '" + c.Name + "'"); /*sink*/
                var d = new Contact();
                await TryUpdateModelAsync(d, "contact");
                _c.Execute("SELECT * FROM t WHERE n = '" + d.Name + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- Helpers ----

    private const string WebUsings = """
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Mvc.Rendering;

        """;

    /// A generated view class of model type `model` whose ExecuteAsync is `body`, mapped to `cshtml` from line 1.
    private static (string Path, string Code) View(string cls, string model, string cshtml, string body) => (
        "/src/App/obj/generated/" + cls + "_cshtml.g.cs",
        $$"""
        using Microsoft.AspNetCore.Mvc.Rendering;
        internal sealed class {{cls}} : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<{{model}}>
        {
            public async override global::System.Threading.Tasks.Task ExecuteAsync()
            {
        #line 1 "{{cshtml}}"
        {{body}}
        #line default
        #line hidden
                await global::System.Threading.Tasks.Task.CompletedTask;
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public IHtmlHelper<{{model}}> Html { get; private set; } = default!;
        }
        """);

    private static AnalysisResult AnalyzeWeb(string web, params (string Path, string Code)[] views)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new List<SyntaxTree>
        {
            CSharpSyntaxTree.ParseText(WebUsings + web, parse, "/src/App/Controllers.cs"),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "/src/App/obj/GlobalUsings.g.cs"),
        };
        trees.AddRange(views.Select(v => CSharpSyntaxTree.ParseText(v.Code, parse, v.Path)));
        var compilation = CSharpCompilation.Create("App", trees, FixtureReferences.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, string.Join("\n", errors));
        var input = new CompilationInput(
            "/src/App/App.csproj", "net8.0", "App", OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12, NullableContextOptions.Disable,
            Array.Empty<string>(), false, null, trees.Select(t => t.FilePath).ToList(), Array.Empty<string>(), Array.Empty<string>(), "/inputs/App.txt");
        var result = new TaintEngine(Snippet.Models, Snippet.Options)
            .Analyze(new LoadedSolution(new[] { new ProjectCompilation(input, compilation, errors) }), CancellationToken.None);
        Assert.True(result.Stats.FailedMethods == 0, string.Join("; ", result.Stats.FirstErrors));
        Assert.True(result.Complete, result.IncompleteReason);
        return result;
    }

    private static List<string> Found(AnalysisResult result, string rule = "csharp.xss") => result.Findings.Where(f => f.RuleId == rule)
        .Select(f => f.SinkSpan.Path + ":" + (f.SinkSpan.StartLinePosition.Line + 1)).OrderBy(p => p, StringComparer.Ordinal).ToList();

    private const string Usings = """
        global using global::System;
        global using global::System.Collections.Generic;
        global using global::System.Linq;
        global using global::Microsoft.AspNetCore.Mvc;
        global using global::Microsoft.Data.SqlClient;
        """;

    private static ProjectCompilation Project(string name, string code, params ProjectCompilation[] references)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new[] { CSharpSyntaxTree.ParseText(code, parse, name + ".cs"), CSharpSyntaxTree.ParseText(Usings, parse, name + ".Usings.g.cs") };
        var refs = FixtureReferences.All.Concat(references.Select(r => (MetadataReference)r.Compilation.ToMetadataReference()));
        var compilation = CSharpCompilation.Create(name, trees, refs, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, string.Join("\n", errors));
        var input = new CompilationInput(name + ".csproj", "net8.0", name, OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
            NullableContextOptions.Disable, Array.Empty<string>(), false, null, new[] { name + ".cs" }, Array.Empty<string>(), Array.Empty<string>(), name + ".csproj");
        return new ProjectCompilation(input, compilation, errors);
    }
}
