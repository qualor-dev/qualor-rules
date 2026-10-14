using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 20 (spec §5 "Heap" as amended, decision R-6): the heap is scoped to the request entry point. A member written with
/// request data in code reachable from an entry point (a controller action, a Razor Pages handler, a Minimal API handler)
/// is request data only where it is read in code reachable from the same entry point; an action reaches the view it
/// renders, and a view the partial views and view components it renders. Code reachable from no entry point reads the
/// heap clean. The shapes are the measurement's dominant false positives (engine-measurement.md "Noise", cause 1) and
/// the flows that must stay found, written anew from the ASP.NET Core docs.
public sealed class RequestScopedHeapTests
{
    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));

    [Fact]
    public void An_entity_property_written_in_one_action_is_no_request_data_for_a_background_service_or_another_action() => Expect("""
        using Microsoft.Extensions.Hosting;
        public class Order { public int Id { get; set; } public string Customer { get; set; } = ""; }
        public class OrderStore
        {
            private readonly List<Order> _orders = new();
            public Order Find(int id) => _orders.First(o => o.Id == id);
        }
        public class OrderRepo
        {
            private readonly SqlConnection _c = new();
            public void Save(Order o) => _c.Execute("UPDATE orders SET c = '" + o.Customer + "'"); /*sink*/
        }
        public class OrdersController : ControllerBase
        {
            private readonly OrderStore _store = new();
            private readonly OrderRepo _repo = new();
            private readonly SqlConnection _c = new();
            public IActionResult Rename(int id, string name)
            {
                _store.Find(id).Customer = name;
                return Ok();
            }
            public IActionResult Show(int id)
            {
                var o = _store.Find(id);
                _c.Query<Order>("SELECT * FROM audit WHERE c = '" + o.Customer + "'");
                return Ok();
            }
            public IActionResult Create(string name)
            {
                var o = new Order();
                o.Customer = name;
                _repo.Save(o);
                return Ok();
            }
        }
        public class AuditJob : BackgroundService
        {
            private readonly OrderStore _store = new();
            private readonly SqlConnection _c = new();
            protected override Task ExecuteAsync(CancellationToken ct)
            {
                _c.Execute("INSERT INTO audit VALUES ('" + _store.Find(1).Customer + "')");
                return Task.CompletedTask;
            }
        }
        """);

    [Fact]
    public void A_setting_changed_in_an_admin_action_is_no_request_data_in_a_public_action() => Expect("""
        public class CatalogSettings { public string SortColumn { get; set; } = "name"; public string Footer { get; set; } = ""; }
        public class SettingsController : Controller
        {
            private readonly CatalogSettings _settings;
            public SettingsController(CatalogSettings settings) => _settings = settings;
            [HttpPost]
            public IActionResult Save(string sort, string footer)
            {
                _settings.SortColumn = sort;
                _settings.Footer = footer;
                return RedirectToAction("Index");
            }
        }
        public class CatalogService
        {
            private readonly CatalogSettings _settings;
            private readonly SqlConnection _c = new();
            public CatalogService(CatalogSettings settings) => _settings = settings;
            public int Count() => _c.Execute("SELECT COUNT(*) FROM products ORDER BY " + _settings.SortColumn);
        }
        public class CatalogController : ControllerBase
        {
            private readonly CatalogSettings _settings;
            private readonly CatalogService _catalog;
            private readonly SqlConnection _c = new();
            public CatalogController(CatalogSettings settings, CatalogService catalog) { _settings = settings; _catalog = catalog; }
            public IActionResult List()
            {
                _c.Query<string>("SELECT * FROM products ORDER BY " + _settings.SortColumn);
                return Ok(_catalog.Count());
            }
        }
        """);

    /// A helper that reads the setting returns it to every caller in its summary; the heap data it returns reaches only
    /// the callers the writing action reaches (TaintValue.Scope), not another action or a migration that call the same
    /// helper (the measurement's picture-path setting, shape written anew).
    [Fact]
    public void Heap_data_a_shared_helper_returns_reaches_only_the_callers_of_the_writing_request() => Expect("""
        public class MediaSettings { public string Table { get; set; } = "pictures"; }
        public static class MediaExtensions
        {
            public static string TableOf(MediaSettings s) => "media_" + s.Table;
        }
        public class MediaController : ControllerBase
        {
            private readonly MediaSettings _settings;
            private readonly SqlConnection _c = new();
            public MediaController(MediaSettings settings) => _settings = settings;
            public IActionResult Move(string table)
            {
                _settings.Table = table;
                _c.Execute("DROP TABLE " + MediaExtensions.TableOf(_settings)); /*sink*/
                return Ok();
            }
            public IActionResult List()
            {
                _c.Query<string>("SELECT * FROM " + MediaExtensions.TableOf(_settings));
                return Ok();
            }
        }
        public class Migration
        {
            private readonly MediaSettings _settings = new();
            private readonly SqlConnection _c = new();
            public void Up() => _c.Execute("ALTER TABLE " + MediaExtensions.TableOf(_settings) + " ADD x int");
        }
        """);

    /// Request data read in a service is valid only in the requests that reach that service: a shared helper that both
    /// such a request and another action call writes it to the heap for the first only (the measurement's cookie read
    /// in a compare-products service turned into a cache key every action builds; shape written anew).
    [Fact]
    public void Request_data_read_in_a_service_reaches_the_heap_only_for_the_requests_that_reach_the_service() => Expect("""
        public class Key { public string Text { get; set; } = ""; }
        public static class Keys
        {
            public static Key Make(string part) { var k = new Key(); k.Text = part; return k; }
        }
        public class CompareService
        {
            private readonly IHttpContextAccessor _http;
            public CompareService(IHttpContextAccessor http) => _http = http;
            public Key Current() => Keys.Make(_http.HttpContext!.Request.Cookies["ids"] ?? "");
        }
        public class CompareController : ControllerBase
        {
            private readonly CompareService _compare;
            private readonly SqlConnection _c = new();
            public CompareController(CompareService compare) => _compare = compare;
            public IActionResult List()
            {
                _c.Execute("SELECT * FROM products WHERE id IN (" + _compare.Current().Text + ")"); /*sink*/
                return Ok();
            }
        }
        public class DownloadController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Get()
            {
                var k = Keys.Make("download");
                _c.Execute("SELECT * FROM downloads WHERE k = '" + k.Text + "'");
                return Ok();
            }
        }
        """);

    /// A typed HTTP client is built by DI (no call edge leads to its constructor): request data a helper reads from the
    /// request still reaches it there (firm core 16.38's kind of flow, in our own shape after Microsoft's typed-client
    /// example), while heap data would not.
    [Fact]
    public void Request_data_a_helper_reads_reaches_a_caller_the_call_graph_cannot_connect()
    {
        const string code = """
            public class SiteLinks
            {
                private readonly IHttpContextAccessor _http;
                public SiteLinks(IHttpContextAccessor http) => _http = http;
                public string Origin() => "https://" + _http.HttpContext!.Request.PathBase.Value + "/";
            }
            public class StatusClient
            {
                private readonly HttpClient _client;
                public StatusClient(HttpClient client, SiteLinks links)
                {
                    _client = client;
                    _client.BaseAddress = new Uri(links.Origin()); /*sink*/
                }
            }
            public class HomeController : ControllerBase
            {
                private readonly SiteLinks _links;
                public HomeController(SiteLinks links) => _links = links;
                public IActionResult Index() => Ok(_links.Origin());
            }
            """;
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.ssrf"));
    }

    [Fact]
    public void A_member_written_in_a_service_and_read_in_the_same_actions_other_service_stays_request_data() => Expect("""
        public class Filter { public string Text { get; set; } = ""; }
        public class FilterBuilder
        {
            public Filter Build(string q) { var f = new Filter(); f.Text = q.Trim(); return f; }
        }
        public class Search
        {
            private readonly SqlConnection _c = new();
            public int Run(Filter f) => _c.Execute("SELECT * FROM t WHERE n = '" + f.Text + "'"); /*sink*/
        }
        public class SearchController : ControllerBase
        {
            private readonly FilterBuilder _builder = new();
            private readonly Search _search = new();
            public IActionResult Find(string q) => Ok(_search.Run(_builder.Build(q)));
        }
        """);

    [Fact]
    public void Minimal_API_handlers_are_entry_points_of_their_own()
    {
        const string code = """
            var app = WebApplication.CreateBuilder(args).Build();
            var state = new State();
            app.MapPost("/a", (string q) => { state.Text = q; return "ok"; });
            app.MapGet("/b", () => { new SqlConnection().Execute("SELECT * FROM t WHERE n = '" + state.Text + "'"); return "ok"; });
            app.MapGet("/c", (string q) =>
            {
                state.Other = q;
                new SqlConnection().Execute("SELECT * FROM t WHERE n = '" + state.Other + "'"); /*sink*/
                return "ok";
            });
            app.MapGet("/d", Handlers.Read);
            app.MapGet("/e", Handlers.Write);
            app.Run();
            public class State { public string Text { get; set; } = ""; public string Other { get; set; } = ""; }
            public static class Handlers
            {
                public static State Shared = new();
                public static string Write(string q) { Shared.Text = q; return Read(); }
                public static string Read() { new SqlConnection().Execute("SELECT * FROM t WHERE n = '" + Shared.Text + "'"); /*sink*/ return "ok"; }
            }
            """;
        Expect(code);
    }

    [Fact]
    public void A_middleware_that_reads_the_request_itself_is_an_entry_point_of_its_own() => Expect("""
        public class TenantContext { public string Name { get; set; } = ""; }
        public class TenantMiddleware
        {
            private readonly RequestDelegate _next;
            private readonly TenantContext _tenant;
            public TenantMiddleware(RequestDelegate next, TenantContext tenant) { _next = next; _tenant = tenant; }
            public async Task InvokeAsync(HttpContext context)
            {
                _tenant.Name = context.Request.Query["tenant"].ToString();
                await _next(context);
                new SqlConnection().Execute("SELECT * FROM " + _tenant.Name + ".orders"); /*sink*/
            }
        }
        public class Startup
        {
            private readonly TenantContext _tenant = new();
            public void Migrate() => new SqlConnection().Execute("CREATE SCHEMA " + _tenant.Name);
        }
        """);

    // ---- Views ----

    private const string Web = """
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Mvc.Rendering;

        public class ProfileModel { public string Bio { get; set; } = ""; public string Motto { get; set; } = ""; }

        public class ProfileController : Controller
        {
            public IActionResult Show([FromQuery] string q)
            {
                var model = new ProfileModel();
                model.Bio = q;
                return View(model);
            }
            public IActionResult Other() => View(new ProfileModel());
            public IActionResult Edit([FromQuery] string q)
            {
                var model = new ProfileModel();
                model.Motto = q;
                return View("Motto", model);
            }
        }

        public class BioCardViewComponent : ViewComponent
        {
            public IViewComponentResult Invoke(ProfileModel model) => View(model);
        }
        """;

    /// A generated view: a class derived from RazorPage<T> whose ExecuteAsync writes `body`, mapped by `#line` to the
    /// .cshtml path; with `identifier` it also carries the generator's RazorCompiledItemMetadata attribute.
    private static (string Path, string Code) View(string cls, string cshtml, string body, string? identifier = null) => (
        "/src/App/obj/generated/" + cls + "_cshtml.g.cs",
        $$"""
        using Microsoft.AspNetCore.Mvc.Rendering;
        {{(identifier == null ? "" : $"[global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemMetadataAttribute(\"Identifier\", \"{identifier}\")]")}}
        internal sealed class {{cls}} : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<ProfileModel>
        {
            public async override global::System.Threading.Tasks.Task ExecuteAsync()
            {
        #line 1 "{{cshtml}}"
                {{body}}
        #line default
        #line hidden
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public IHtmlHelper<ProfileModel> Html { get; private set; } = default!;
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; } = default!;
        }
        """);

    private static readonly (string Path, string Code)[] Views =
    {
        View("Views_Profile_Show", "/src/App/Views/Profile/Show.cshtml",
            """Write(Html.Raw(Model.Bio)); Write(await Html.PartialAsync("_Card", Model)); Write(await Component.InvokeAsync("BioCard", Model));""",
            identifier: "/Views/Profile/Show.cshtml"),
        View("Views_Profile_Other", "/src/App/Views/Profile/Other.cshtml", "Write(Html.Raw(Model.Bio));"),
        View("Views_Profile_Motto", "/src/App/Views/Profile/Motto.cshtml", "Write(Html.Raw(Model.Motto));\nWrite(Html.Raw(Model.Bio));"),
        View("Views_Profile__Card", "/src/App/Views/Profile/_Card.cshtml", "Write(Html.Raw(Model.Bio));"),
        View("Views_Shared_Components_BioCard_Default", "/src/App/Views/Shared/Components/BioCard/Default.cshtml", "Write(Html.Raw(Model.Bio));"),
        View("Views_Shared__Unused", "/src/App/Views/Shared/_Unused.cshtml", "Write(Html.Raw(Model.Bio));"),
    };

    private static AnalysisResult AnalyzeWeb(string web, params (string Path, string Code)[] views) => AnalyzeWeb(web, null, views);

    /// The App project (`web` and the generated views), with `library` as a Framework project App references.
    private static AnalysisResult AnalyzeWeb(string web, string? library, params (string Path, string Code)[] views)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var projects = new List<ProjectCompilation>();
        var references = FixtureReferences.All.ToList();
        if (library != null)
        {
            var libTrees = new[]
            {
                CSharpSyntaxTree.ParseText(library, parse, "/src/Framework/Framework.cs"),
                CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "/src/Framework/obj/GlobalUsings.g.cs"),
            };
            var lib = CSharpCompilation.Create("Framework", libTrees, FixtureReferences.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            var libErrors = lib.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
            Assert.True(libErrors.Count == 0, string.Join("\n", libErrors));
            projects.Add(new ProjectCompilation(new CompilationInput(
                "/src/Framework/Framework.csproj", "net8.0", "Framework", OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12,
                NullableContextOptions.Disable, Array.Empty<string>(), false, null, libTrees.Select(t => t.FilePath).ToList(),
                Array.Empty<string>(), Array.Empty<string>(), "/inputs/Framework.txt"), lib, libErrors));
            references.Add(lib.ToMetadataReference());
        }
        var trees = new List<SyntaxTree>
        {
            CSharpSyntaxTree.ParseText(web, parse, "/src/App/Controllers.cs"),
            CSharpSyntaxTree.ParseText(FixtureRunner.ImplicitUsings, parse, "/src/App/obj/GlobalUsings.g.cs"),
        };
        trees.AddRange(views.Select(v => CSharpSyntaxTree.ParseText(v.Code, parse, v.Path)));
        var compilation = CSharpCompilation.Create("App", trees, references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, string.Join("\n", errors));
        var input = new CompilationInput(
            "/src/App/App.csproj", "net8.0", "App", OutputKind.DynamicallyLinkedLibrary, LanguageVersion.CSharp12, NullableContextOptions.Disable,
            Array.Empty<string>(), false, null, trees.Select(t => t.FilePath).ToList(), Array.Empty<string>(), Array.Empty<string>(), "/inputs/App.txt");
        projects.Add(new ProjectCompilation(input, compilation, errors));
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(new LoadedSolution(projects), CancellationToken.None);
        Assert.True(result.Stats.FailedMethods == 0, string.Join("; ", result.Stats.FirstErrors));
        Assert.True(result.Complete, result.IncompleteReason);
        return result;
    }

    private static List<string> Xss(AnalysisResult result) => result.Findings.Where(f => f.RuleId == "csharp.xss")
        .Select(f => f.SinkSpan.Path + ":" + (f.SinkSpan.StartLinePosition.Line + 1)).OrderBy(p => p, StringComparer.Ordinal).ToList();

    [Fact]
    public void An_action_reaches_its_view_and_the_partial_and_view_component_it_renders_and_no_other_view()
    {
        var result = AnalyzeWeb(Web, Views);

        // Show writes Bio and renders Views/Profile/Show (its default view), which renders the partial _Card and the
        // view component BioCard (its Default view): all three report Bio. Other renders Other.cshtml without writing
        // Bio; Edit writes Motto only and renders the named view Motto, whose Bio read (line 2) is quiet; _Unused is
        // rendered by nothing.
        Assert.Equal(new[]
        {
            "/src/App/Views/Profile/Motto.cshtml:1",
            "/src/App/Views/Profile/Show.cshtml:1",
            "/src/App/Views/Profile/_Card.cshtml:1",
            "/src/App/Views/Shared/Components/BioCard/Default.cshtml:1",
        }, Xss(result));
        Assert.Equal(0, result.Stats.UnresolvedViews);
        Assert.True(result.Stats.EntryPoints >= 3);
    }

    private static (string Path, string Code) Page(string cls, string model, string cshtml, string body) => (
        "/src/App/obj/generated/" + cls + "_cshtml.g.cs",
        $$"""
        using Microsoft.AspNetCore.Mvc.Rendering;
        internal sealed class {{cls}} : global::Microsoft.AspNetCore.Mvc.RazorPages.Page
        {
            public async override global::System.Threading.Tasks.Task ExecuteAsync()
            {
        #line 1 "{{cshtml}}"
                {{body}}
        #line default
        #line hidden
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public IHtmlHelper<{{model}}> Html { get; private set; } = default!;
            public {{model}} Model => ({{model}})PageContext.ViewData.Model;
        }
        """);

    [Fact]
    public void A_Razor_Pages_handler_reaches_its_own_page_and_no_other()
    {
        const string pages = """
            public class EditBioModel : Microsoft.AspNetCore.Mvc.RazorPages.PageModel
            {
                public string Bio { get; set; } = "";
                public void OnPost(string bio) => Bio = bio;
            }
            public class ShowBioModel : Microsoft.AspNetCore.Mvc.RazorPages.PageModel
            {
                public EditBioModel Last { get; set; } = new();
                public IActionResult OnGet() => Page();
            }
            """;
        var result = AnalyzeWeb(Web + pages, Views.Concat(new[]
        {
            Page("Pages_EditBio", "EditBioModel", "/src/App/Pages/EditBio.cshtml", "Write(Html.Raw(Model.Bio));"),
            Page("Pages_ShowBio", "ShowBioModel", "/src/App/Pages/ShowBio.cshtml", "Write(Html.Raw(Model.Last.Bio));"),
        }).ToArray());

        Assert.Contains("/src/App/Pages/EditBio.cshtml:1", Xss(result));
        Assert.DoesNotContain("/src/App/Pages/ShowBio.cshtml:1", Xss(result));
        Assert.Equal(0, result.Stats.UnresolvedViews);
    }

    /// A view no action names (a layout, rendered through _ViewStart) still runs in a request: it is an entry point of its
    /// own, so request data a helper reads and returns to it stays request data there.
    [Fact]
    public void A_view_no_action_names_is_request_code_of_its_own()
    {
        const string helper = """
            public static class PageHelper
            {
                public static string ThisUrl(HttpContext context) => context.Request.Path + context.Request.QueryString.ToString();
            }
            """;
        var result = AnalyzeWeb(Web + helper, Views.Append(
            View("Views_Shared__Layout", "/src/App/Views/Shared/_Layout.cshtml", "Write(Html.Raw(PageHelper.ThisUrl(Context)));")).ToArray());

        Assert.Contains("/src/App/Views/Shared/_Layout.cshtml:1", Xss(result));
        Assert.DoesNotContain("/src/App/Views/Shared/_Unused.cshtml:1", Xss(result));
    }

    [Fact]
    public void A_view_name_that_cannot_be_resolved_falls_back_to_every_view_of_the_project_and_is_counted()
    {
        var web = Web.Replace("return View(\"Motto\", model);", "return View(model.Motto.Length > 3 ? \"Motto\" : \"Other\", model);", StringComparison.Ordinal)
            .Replace("model.Motto = q;", "model.Motto = q; model.Bio = q;", StringComparison.Ordinal);
        var result = AnalyzeWeb(web, Views);

        // Edit's view is chosen at run time: every view of the project is reached from Edit (Other and _Unused included).
        Assert.Equal(1, result.Stats.UnresolvedViews);
        Assert.Contains("/src/App/Views/Shared/_Unused.cshtml:1", Xss(result));
        Assert.Contains("/src/App/Views/Profile/Other.cshtml:1", Xss(result));
        Assert.Contains("/src/App/Views/Profile/Motto.cshtml:2", Xss(result));
    }

    // ---- Fix round 1 (task-20-review.md) ----

    /// I1: code around the action (a controller's filter override, a filter, middleware, a DI-built constructor) runs in
    /// every request: what it writes from the request is request data for the actions (reviewer's probes P1–P4b).
    [Fact]
    public void A_controllers_OnActionExecuting_writes_request_data_its_actions_read() => Expect("""
        public class LangController : Controller
        {
            private string _lang = "en";
            private readonly SqlConnection _c = new();
            public override void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context)
            {
                _lang = Request.Query["lang"].ToString();
            }
            public IActionResult Index()
            {
                _c.Execute("SELECT * FROM t WHERE lang = '" + _lang + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    private const string TenantAction = """
        public class TenantCtx { public string Tenant { get; set; } = ""; }
        public class OrdersController : ControllerBase
        {
            private readonly TenantCtx _ctx;
            private readonly SqlConnection _c = new();
            public OrdersController(TenantCtx ctx) => _ctx = ctx;
            public IActionResult List()
            {
                _c.Execute("SELECT * FROM " + _ctx.Tenant + ".orders"); /*sink*/
                return Ok();
            }
        }

        """;

    [Fact]
    public void An_action_filter_writes_request_data_the_action_reads() => Expect(TenantAction + """
        public class TenantFilter : Microsoft.AspNetCore.Mvc.Filters.IActionFilter
        {
            private readonly TenantCtx _ctx;
            public TenantFilter(TenantCtx ctx) => _ctx = ctx;
            public void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context) =>
                _ctx.Tenant = context.HttpContext.Request.Headers["X-Tenant"].ToString();
            public void OnActionExecuted(Microsoft.AspNetCore.Mvc.Filters.ActionExecutedContext context) { }
        }
        """);

    [Fact]
    public void A_conventional_middleware_writes_request_data_the_action_reads() => Expect(TenantAction + """
        public class TenantMiddleware
        {
            private readonly RequestDelegate _next;
            public TenantMiddleware(RequestDelegate next) => _next = next;
            public async Task InvokeAsync(HttpContext context, TenantCtx ctx)
            {
                ctx.Tenant = context.Request.Headers["X-Tenant"].ToString();
                await _next(context);
            }
        }
        """);

    private const string CurrentTenantAction = """
        public class ReportsController : ControllerBase
        {
            private readonly CurrentTenant _t;
            private readonly SqlConnection _c = new();
            public ReportsController(CurrentTenant t) => _t = t;
            public IActionResult List()
            {
                _c.Execute("SELECT * FROM " + _t.Name + ".reports"); /*sink*/
                return Ok();
            }
        }

        """;

    [Fact]
    public void A_DI_built_constructor_writes_request_data_the_action_reads() => Expect(CurrentTenantAction + """
        public class CurrentTenant
        {
            public string Name { get; }
            public CurrentTenant(IHttpContextAccessor http) => Name = http.HttpContext!.Request.Headers["X-Tenant"].ToString();
        }
        """);

    [Fact]
    public void A_DI_built_constructor_writes_request_data_a_helper_read_and_the_action_reads_it() => Expect(CurrentTenantAction + """
        public static class Web
        {
            public static string Tenant(IHttpContextAccessor http) => http.HttpContext!.Request.Headers["X-Tenant"].ToString();
        }
        public class CurrentTenant
        {
            public string Name { get; }
            public CurrentTenant(IHttpContextAccessor http) => Name = Web.Tenant(http);
        }
        """);

    /// I2: a view creates a tag helper (CreateTagHelper<T>) and sets its properties; its Process runs in the view's
    /// request (reviewer's probe P5).
    [Fact]
    public void A_tag_helper_the_view_creates_receives_the_views_request_data()
    {
        const string web = Web + """

            public class BioTagHelper : Microsoft.AspNetCore.Razor.TagHelpers.TagHelper
            {
                public string Text { get; set; } = "";
                public override void Process(Microsoft.AspNetCore.Razor.TagHelpers.TagHelperContext context, Microsoft.AspNetCore.Razor.TagHelpers.TagHelperOutput output)
                {
                    output.Content.SetHtmlContent(Text);
                }
            }
            public class TaggedController : Controller
            {
                public IActionResult Show([FromQuery] string q)
                {
                    var model = new ProfileModel();
                    model.Bio = q;
                    return View(model);
                }
            }
            """;
        var line = web.Split('\n').Select((l, i) => (l, i)).First(x => x.l.Contains("SetHtmlContent(Text)", StringComparison.Ordinal)).i + 1;
        var result = AnalyzeWeb(web, Views.Append(View("Views_Tagged_Show", "/src/App/Views/Tagged/Show.cshtml",
            "var __bio = CreateTagHelper<BioTagHelper>(); __bio.Text = Model.Bio;")).ToArray());

        Assert.Contains("/src/App/Controllers.cs:" + line, Xss(result));
    }

    /// I3: a view component that renders through an abstract base's wrapper (nopCommerce NopViewComponent.ViewAsync)
    /// reaches its own Components/<Name>/ views: the default one, or any of them for a view name passed in.
    [Fact]
    public void A_view_component_rendering_through_a_base_class_wrapper_reaches_its_own_views()
    {
        const string web = """
            using Microsoft.AspNetCore.Mvc;
            public class ProfileModel { public string Bio { get; set; } = ""; public string Motto { get; set; } = ""; }
            public abstract class BaseViewComponent : ViewComponent
            {
                protected IViewComponentResult Render(object model) => View(model);
                protected IViewComponentResult Render(string viewName, object model) => View(viewName, model);
            }
            public class BioBoxViewComponent : BaseViewComponent
            {
                public IViewComponentResult Invoke(ProfileModel model) => Render(model);
            }
            public class MottoBoxViewComponent : BaseViewComponent
            {
                public IViewComponentResult Invoke(ProfileModel model, string view) => Render(view, model);
            }
            public class BoxController : Controller
            {
                public IActionResult Show([FromQuery] string q)
                {
                    var model = new ProfileModel();
                    model.Bio = q;
                    return View(model);
                }
            }
            """;
        var result = AnalyzeWeb(web,
            View("Views_Box_Show", "/src/App/Views/Box/Show.cshtml",
                """Write(await Component.InvokeAsync("BioBox", Model)); Write(await Component.InvokeAsync("MottoBox", new { model = Model, view = "Wide" }));"""),
            View("Views_Shared_Components_BioBox_Default", "/src/App/Views/Shared/Components/BioBox/Default.cshtml", "Write(Html.Raw(Model.Bio));"),
            View("Views_Shared_Components_MottoBox_Wide", "/src/App/Views/Shared/Components/MottoBox/Wide.cshtml", "Write(Html.Raw(Model.Bio));"),
            View("Views_Shared__Unused", "/src/App/Views/Shared/_Unused.cshtml", "Write(Html.Raw(Model.Bio));"));

        Assert.Equal(new[]
        {
            "/src/App/Views/Shared/Components/BioBox/Default.cshtml:1",
            "/src/App/Views/Shared/Components/MottoBox/Wide.cshtml:1",
        }, Xss(result));
        Assert.Equal(0, result.Stats.UnresolvedViews);
    }

    /// I3: a view name a library's base controller cannot resolve reaches the views of the projects that reference the
    /// library (the views live in the web project).
    [Fact]
    public void An_unresolved_view_name_in_a_library_reaches_the_views_of_the_projects_that_reference_it()
    {
        const string library = """
            namespace Framework;
            public abstract class BaseController : Microsoft.AspNetCore.Mvc.Controller
            {
                protected Microsoft.AspNetCore.Mvc.IActionResult Render(string name, object model) => View(name, model);
            }
            """;
        const string web = Web + """

            public class RenderController : Framework.BaseController
            {
                public IActionResult Go([FromQuery] string q)
                {
                    var model = new ProfileModel();
                    model.Bio = q;
                    return Render(q.Length > 3 ? "Other" : "Motto", model);
                }
            }
            """;
        var result = AnalyzeWeb(web, library, Views);

        Assert.Contains("/src/App/Views/Profile/Other.cshtml:1", Xss(result));
        Assert.Equal(1, result.Stats.UnresolvedViews);
    }

    /// I4: the reported path starts in a request that reaches the sink. Two actions write one member through a shared
    /// service; only the second reads it into SQL. The first's path is shorter but its request never reaches the sink.
    [Fact]
    public void The_reported_path_starts_in_a_request_that_reaches_the_sink()
    {
        const string code = """
            public class Box { public string Name { get; set; } = ""; }
            public class BoxService
            {
                private readonly Box _box = new();
                public void Set(string v) => _box.Name = v;
                public string Get() => _box.Name;
            }
            public class AdminController : ControllerBase
            {
                private readonly BoxService _s;
                public AdminController(BoxService s) => _s = s;
                public IActionResult A(string a) { _s.Set(a); return Ok(); }
            }
            public class ShopController : ControllerBase
            {
                private readonly BoxService _s;
                private readonly SqlConnection _c = new();
                public ShopController(BoxService s) => _s = s;
                public IActionResult B(string b)
                {
                    var t = b.Trim();
                    var u = t.ToUpperInvariant();
                    var w = u.Replace(" ", "");
                    _s.Set(w);
                    _c.Execute("SELECT * FROM t WHERE n = '" + _s.Get() + "'");
                    return Ok();
                }
            }
            """;
        var finding = Assert.Single(Snippet.Analyze(code).Findings, f => f.RuleId == "csharp.sql-injection");
        Assert.Contains("parameter 'b'", finding.Path[0].Message);
    }

    /// M1 (P6): a field initializer runs when the object is built: it reads what the building request wrote.
    [Fact]
    public void A_field_initializer_runs_in_the_request_that_builds_the_object() => Expect("""
        public static class Ctx { public static string Current = ""; }
        public class Report
        {
            private readonly string _sql = "SELECT * FROM " + Ctx.Current;
            private readonly SqlConnection _c = new();
            public int Run() => _c.Execute(_sql); /*sink*/
        }
        public class Export
        {
            private readonly string _sql = "SELECT * FROM x WHERE t = '" + Ctx.Current + "'";
            private readonly SqlConnection _c = new();
            public Export(int n) { _c.Open(); }
            public int Run() => _c.Execute(_sql); /*sink*/
        }
        public class ReportsController : ControllerBase
        {
            public IActionResult M(string q)
            {
                Ctx.Current = q;
                return Ok(new Report().Run() + new Export(1).Run());
            }
        }
        """);

    /// M1 (P8): a top-level local function a Minimal API lambda calls runs in that handler's request.
    [Fact]
    public void A_top_level_local_function_a_handler_calls_runs_in_its_request() => Expect("""
        var app = WebApplication.CreateBuilder(args).Build();
        app.MapGet("/x", (string q) => Run(q));
        app.Run();
        string Run(string q)
        {
            var s = new State();
            s.Text = q;
            new SqlConnection().Execute("SELECT * FROM t WHERE n = '" + s.Text + "'"); /*sink*/
            return "ok";
        }
        public class State { public string Text { get; set; } = ""; }
        """);

    /// M4: a layout no action names is an entry point of its own (R-E16): heap data it writes and reads in its own
    /// request stays request data (quiet without the implicit entry, where its reach is empty).
    [Fact]
    public void A_layout_reads_the_heap_data_its_own_request_wrote()
    {
        const string web = Web + """

            public class Title { public string Text { get; set; } = ""; }
            """;
        var result = AnalyzeWeb(web, Views.Append(View("Views_Shared__Layout", "/src/App/Views/Shared/_Layout.cshtml",
            """var t = new Title(); t.Text = Context.Request.Query["t"].ToString(); Write(Html.Raw(t.Text));""")).ToArray());

        Assert.Contains("/src/App/Views/Shared/_Layout.cshtml:1", Xss(result));
    }

    /// M3: an area controller's view is looked up in its area; a controller without an area never gets an area's view.
    [Fact]
    public void An_area_controller_renders_its_areas_view_and_not_the_root_one()
    {
        const string web = """
            using Microsoft.AspNetCore.Mvc;
            public class ProfileModel { public string Bio { get; set; } = ""; public string Motto { get; set; } = ""; }
            public class HomeController : Controller
            {
                public IActionResult Index() => View(new ProfileModel());
            }
            namespace AdminArea
            {
                [Area("Admin")]
                public abstract class AdminBase : Controller { }
                public class HomeController : AdminBase
                {
                    public IActionResult Index([FromQuery] string q)
                    {
                        var model = new ProfileModel();
                        model.Bio = q;
                        return View(model);
                    }
                }
            }
            """;
        var result = AnalyzeWeb(web,
            View("Views_Home_Index", "/src/App/Views/Home/Index.cshtml", "Write(Html.Raw(Model.Bio));", identifier: "/Views/Home/Index.cshtml"),
            View("Areas_Admin_Views_Home_Index", "/src/App/Areas/Admin/Views/Home/Index.cshtml", "Write(Html.Raw(Model.Bio));",
                identifier: "/Areas/Admin/Views/Home/Index.cshtml"));

        Assert.Equal(new[] { "/src/App/Areas/Admin/Views/Home/Index.cshtml:1" }, Xss(result));
        Assert.Equal(0, result.Stats.UnresolvedViews);
    }

    /// M5: a view named by a path that no compiled view has (runtime-compiled plugin views) is counted apart from the
    /// names that cannot be resolved.
    [Fact]
    public void A_path_named_view_that_is_not_compiled_is_counted_as_uncompiled()
    {
        const string web = Web + """

            public class PluginController : Controller
            {
                public IActionResult Configure() => View("~/Plugins/Payments.Manual/Views/Configure.cshtml", new ProfileModel());
            }
            """;
        var result = AnalyzeWeb(web, Views);

        Assert.Equal(1, result.Stats.UncompiledViews);
        Assert.Equal(0, result.Stats.UnresolvedViews);
    }

    // ---- Fix round 2 (task-20-review.md "Re-review 1") ----

    /// RR1 (Q1): a setter a filter calls with a header and one action calls too: what the filter writes is request data
    /// in every request, so another action reads it.
    [Fact]
    public void A_setter_a_filter_and_one_action_share_writes_request_data_every_action_reads() => Expect("""
        public class LangCtx { public string Lang { get; set; } = "en"; }
        public class LangService
        {
            private readonly LangCtx _ctx;
            public LangService(LangCtx ctx) => _ctx = ctx;
            public void Set(string lang) => _ctx.Lang = lang;
        }
        public class LangFilter : Microsoft.AspNetCore.Mvc.Filters.IActionFilter
        {
            private readonly LangService _lang;
            public LangFilter(LangService lang) => _lang = lang;
            public void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context) =>
                _lang.Set(context.HttpContext.Request.Headers["Accept-Language"].ToString());
            public void OnActionExecuted(Microsoft.AspNetCore.Mvc.Filters.ActionExecutedContext context) { }
        }
        public class CommonController : ControllerBase
        {
            private readonly LangService _lang;
            public CommonController(LangService lang) => _lang = lang;
            public IActionResult SetLanguage(string lang) { _lang.Set(lang); return Ok(); }
        }
        public class OrdersController : ControllerBase
        {
            private readonly LangCtx _ctx;
            private readonly SqlConnection _c = new();
            public OrdersController(LangCtx ctx) => _ctx = ctx;
            public IActionResult List()
            {
                _c.Execute("SELECT * FROM orders WHERE lang = '" + _ctx.Lang + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    /// RR1 (Q6): a helper that reads the request itself, called by a middleware and by one action: what it stores is
    /// request data in every request.
    [Fact]
    public void A_request_reading_helper_a_middleware_and_one_action_share_stores_request_data_every_action_reads() => Expect("""
        public class Ctx { public string Ip { get; set; } = ""; }
        public class SiteLinks
        {
            private readonly IHttpContextAccessor _http;
            private readonly Ctx _ctx;
            public SiteLinks(IHttpContextAccessor http, Ctx ctx) { _http = http; _ctx = ctx; }
            public void Remember() => _ctx.Ip = _http.HttpContext!.Request.Headers["X-Forwarded-For"].ToString();
        }
        public class IpMiddleware
        {
            private readonly RequestDelegate _next;
            public IpMiddleware(RequestDelegate next) => _next = next;
            public async Task InvokeAsync(HttpContext context, SiteLinks links)
            {
                links.Remember();
                await _next(context);
            }
        }
        public class DebugController : ControllerBase
        {
            private readonly SiteLinks _links;
            public DebugController(SiteLinks links) => _links = links;
            public IActionResult Refresh() { _links.Remember(); return Ok(); }
        }
        public class AuditController : ControllerBase
        {
            private readonly Ctx _ctx;
            private readonly SqlConnection _c = new();
            public AuditController(Ctx ctx) => _ctx = ctx;
            public IActionResult Log()
            {
                _c.Execute("INSERT INTO audit VALUES ('" + _ctx.Ip + "')"); /*sink*/
                return Ok();
            }
        }
        """);

    /// RR1 (Q7): an admin action saves a setting through a service a filter also calls (with a constant): the admin's
    /// data keeps its own scope, so the public action's read stays quiet.
    [Fact]
    public void An_admin_setting_saved_through_a_service_a_filter_also_calls_stays_out_of_the_public_action() => Expect("""
        public class SiteSettings { public string Theme { get; set; } = "default"; }
        public class SettingService
        {
            private readonly SiteSettings _settings;
            public SettingService(SiteSettings settings) => _settings = settings;
            public void SetTheme(string theme) => _settings.Theme = theme;
        }
        public class ThemeFilter : Microsoft.AspNetCore.Mvc.Filters.IActionFilter
        {
            private readonly SettingService _service;
            public ThemeFilter(SettingService service) => _service = service;
            public void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context) => _service.SetTheme("default");
            public void OnActionExecuted(Microsoft.AspNetCore.Mvc.Filters.ActionExecutedContext context) { }
        }
        public class AdminController : ControllerBase
        {
            private readonly SettingService _service;
            public AdminController(SettingService service) => _service = service;
            public IActionResult SaveTheme(string theme) { _service.SetTheme(theme); return Ok(); }
        }
        public class ShopController : ControllerBase
        {
            private readonly SiteSettings _settings;
            private readonly SqlConnection _c = new();
            public ShopController(SiteSettings settings) => _settings = settings;
            public IActionResult Home()
            {
                _c.Execute("SELECT * FROM themes WHERE name = '" + _settings.Theme + "'");
                return Ok();
            }
        }
        """);

    /// RR3 (Q3): a constructor DI builds (its type is injected into another constructor) is around code even when an
    /// action also builds it with `new`.
    [Fact]
    public void An_injected_types_constructor_is_around_code_even_when_an_action_also_news_it() => Expect(CurrentTenantAction + """
        public class CurrentTenant
        {
            public string Name { get; }
            public CurrentTenant(IHttpContextAccessor http) => Name = http.HttpContext!.Request.Headers["X-Tenant"].ToString();
        }
        public class ToolsController : ControllerBase
        {
            private readonly IHttpContextAccessor _http;
            public ToolsController(IHttpContextAccessor http) => _http = http;
            public IActionResult Probe() => Ok(new CurrentTenant(_http) != null);
        }
        """);
}
