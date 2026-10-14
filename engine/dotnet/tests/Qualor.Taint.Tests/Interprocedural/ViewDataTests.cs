using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 22 (recall gaps): what an action hands its view besides the view model's properties.
/// - ViewData and ViewBag entries are keyed, request-scoped heap locations: an entry written with request data in an
///   action (or in code around it, ruling R-E17) is request data where the views that action renders read the same key,
///   also in the partials and view components those views render. ViewBag.K is ViewData["K"]. A key that is not a
///   constant writes an "any key" entry every read joins. TempData crosses requests (R-6) and is not followed.
/// - The model given to View(model), PartialView(model), a view component's View(model) or a partial is the view's
///   Model as a value (a list iterated in the view included), scoped to the requests that render that view.
/// - HttpContext.Items entries are keyed request-scoped locations the same way.
/// The shapes are written anew from the ASP.NET Core docs (views, view components, partial views, filters).
public sealed class ViewDataTests
{
    private const string Usings = """
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.AspNetCore.Mvc.Filters;
        using Microsoft.AspNetCore.Mvc.Rendering;
        using System.Text.Encodings.Web;

        """;

    /// A generated view of model type `model`: ExecuteAsync writes `body` (one line per .cshtml line from line 1).
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
            }
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public IHtmlHelper<{{model}}> Html { get; private set; } = default!;
            [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
            public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; } = default!;
        }
        """);

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
            public global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<{{model}}> ViewData => (global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<{{model}}>)PageContext.ViewData;
            public {{model}} Model => ViewData.Model;
        }
        """);

    private static AnalysisResult Analyze(string web, params (string Path, string Code)[] views)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12);
        var trees = new List<SyntaxTree>
        {
            CSharpSyntaxTree.ParseText(Usings + web, parse, "/src/App/Controllers.cs"),
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

    /// The findings of `rule` as "<file>:<line>" (a view's sink at its .cshtml line), sorted.
    private static List<string> Found(AnalysisResult result, string rule = "csharp.xss") => result.Findings.Where(f => f.RuleId == rule)
        .Select(f => f.SinkSpan.Path + ":" + (f.SinkSpan.StartLinePosition.Line + 1)).OrderBy(p => p, StringComparer.Ordinal).ToList();

    /// The lines of the controllers file marked `/*sink*/`, as Found gives them.
    private static List<string> Marked(string web) => Snippet.Marked(Usings + web).Select(l => "/src/App/Controllers.cs:" + l).ToList();

    // ---- ViewData and ViewBag ----

    [Fact]
    public void A_ViewData_entry_reaches_the_same_key_in_the_actions_own_view_only()
    {
        const string web = """
            public class SearchController : Controller
            {
                public IActionResult Find([FromQuery] string term)
                {
                    ViewData["Term"] = term;
                    ViewData["Hint"] = "type a word";
                    return View();
                }
                public IActionResult Browse() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_Search_Find", "object", "/src/App/Views/Search/Find.cshtml", """
                Write(Html.Raw(ViewData["Term"]));
                Write(Html.Raw(ViewData["Hint"]));
                Write(ViewData["Term"]);
                Write(Html.Raw(ViewData["Term"] as string));
                Write(Html.Raw(System.Text.Encodings.Web.HtmlEncoder.Default.Encode((string)ViewData["Term"])));
                """),
            View("Views_Search_Browse", "object", "/src/App/Views/Search/Browse.cshtml", """
                Write(Html.Raw(ViewData["Term"]));
                """));

        // Line 1 and 4: the entry, raw. Line 2: another key (a constant). Line 3: encoded by Write. Line 5: encoded first.
        // Browse's view reads the key, but Browse never writes it: Find's request is another request (R-6).
        Assert.Equal(new[] { "/src/App/Views/Search/Find.cshtml:1", "/src/App/Views/Search/Find.cshtml:4" }, Found(result));
    }

    [Fact]
    public void ViewBag_K_and_ViewData_K_are_one_entry_whatever_the_case_of_the_key()
    {
        const string web = """
            public class GreetController : Controller
            {
                public IActionResult Hello([FromQuery] string name, [FromQuery] string title)
                {
                    ViewBag.Greeting = "Hello " + name;
                    ViewData["PageTitle"] = title;
                    ViewBag.Footer = "(c) us";
                    return View();
                }
            }
            """;
        var result = Analyze(web,
            View("Views_Greet_Hello", "object", "/src/App/Views/Greet/Hello.cshtml", """
                Write(Html.Raw(ViewData["greeting"]));
                Write(Html.Raw(ViewBag.PageTitle));
                Write(Html.Raw(ViewBag.Footer));
                Write(ViewBag.Greeting);
                Write(Html.Raw((string)ViewBag.Greeting));
                """));

        // Line 1: ViewBag.Greeting read as ViewData["greeting"]. Line 2: ViewData["PageTitle"] read through ViewBag (a call
        // bound at run time). Line 3: a constant entry. Line 4: encoded. Line 5: the same entry, cast to string.
        Assert.Equal(new[] { "/src/App/Views/Greet/Hello.cshtml:1", "/src/App/Views/Greet/Hello.cshtml:2", "/src/App/Views/Greet/Hello.cshtml:5" },
            Found(result));
    }

    [Fact]
    public void A_key_that_is_not_a_constant_writes_an_entry_every_read_joins()
    {
        const string web = """
            public class SlotController : Controller
            {
                public IActionResult Fill([FromQuery] string slot, [FromQuery] string text)
                {
                    ViewData["slot-" + slot] = text;
                    return View();
                }
                public IActionResult Pick([FromQuery] string text, int n)
                {
                    ViewData["Chosen"] = text;
                    ViewData.Add("Extra", text);
                    return View();
                }
            }
            """;
        var result = Analyze(web,
            View("Views_Slot_Fill", "object", "/src/App/Views/Slot/Fill.cshtml", """
                Write(Html.Raw(ViewData["slot-a"]));
                Write(Html.Raw(ViewData["Anything"]));
                """),
            View("Views_Slot_Pick", "object", "/src/App/Views/Slot/Pick.cshtml", """
                var key = "Cho" + "sen".ToString();
                Write(Html.Raw(ViewData[key]));
                Write(Html.Raw(ViewData["Other"]));
                if (ViewData.TryGetValue("Extra", out var extra)) Write(Html.Raw(extra));
                """));

        // Fill writes under a key it builds: every read of Fill's view joins it. Pick writes constant keys: a read with a key
        // that is not a constant (line 2) joins them all, a read of another constant key (line 3) is quiet; Add and
        // TryGetValue are the same entries as the indexer.
        Assert.Equal(new[]
        {
            "/src/App/Views/Slot/Fill.cshtml:1",
            "/src/App/Views/Slot/Fill.cshtml:2",
            "/src/App/Views/Slot/Pick.cshtml:2",
            "/src/App/Views/Slot/Pick.cshtml:4",
        }, Found(result));
    }

    [Fact]
    public void A_ViewData_entry_reaches_the_partials_and_view_components_the_view_renders()
    {
        const string web = """
            public class NewsController : Controller
            {
                public IActionResult Story([FromQuery] string banner)
                {
                    SetBanner(banner);
                    return View();
                }
                public IActionResult Archive() => View();
                private void SetBanner(string text) => ViewData["Banner"] = text;
            }
            public class BannerViewComponent : ViewComponent
            {
                public IViewComponentResult Invoke() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_News_Story", "object", "/src/App/Views/News/Story.cshtml", """
                Write(await Html.PartialAsync("_Strip"));
                Write(await Component.InvokeAsync("Banner"));
                """),
            View("Views_News_Archive", "object", "/src/App/Views/News/Archive.cshtml", """
                Write(Html.Raw(Html.ViewData["Banner"]));
                """),
            View("Views_News__Strip", "object", "/src/App/Views/News/_Strip.cshtml", """
                Write(Html.Raw(ViewData["Banner"]));
                """),
            View("Views_Shared_Components_Banner_Default", "object", "/src/App/Views/Shared/Components/Banner/Default.cshtml", """
                Write(Html.Raw(ViewBag.Banner));
                """));

        // A helper of the action writes the entry (through its summary); the partial and the view component's view of
        // Story's view read it; Archive's own view does not (another request).
        Assert.Equal(new[]
        {
            "/src/App/Views/News/_Strip.cshtml:1",
            "/src/App/Views/Shared/Components/Banner/Default.cshtml:1",
        }, Found(result));
    }

    [Fact]
    public void A_ViewData_entry_written_around_the_action_reaches_every_view()
    {
        const string web = """
            public class ThemeFilter : IActionFilter
            {
                public void OnActionExecuting(ActionExecutingContext context)
                {
                    if (context.Controller is Controller c) c.ViewBag.Theme = context.HttpContext.Request.Cookies["theme"];
                }
                public void OnActionExecuted(ActionExecutedContext context) { }
            }
            public class ShopController : Controller
            {
                public override void OnActionExecuting(ActionExecutingContext context)
                {
                    ViewData["Lang"] = Request.Query["lang"].ToString();
                }
                public IActionResult Cart() => View();
            }
            public class HomeController : Controller
            {
                public IActionResult Index() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_Shop_Cart", "object", "/src/App/Views/Shop/Cart.cshtml", """
                Write(Html.Raw(ViewData["Lang"]));
                """),
            View("Views_Home_Index", "object", "/src/App/Views/Home/Index.cshtml", """
                Write(Html.Raw(ViewData["Theme"]));
                """));

        // The controller's own OnActionExecuting and a global filter run around every action (R-E17).
        Assert.Equal(new[] { "/src/App/Views/Home/Index.cshtml:1", "/src/App/Views/Shop/Cart.cshtml:1" }, Found(result));
    }

    [Fact]
    public void TempData_crosses_requests_and_is_not_followed()
    {
        const string web = """
            public class FlashController : Controller
            {
                public IActionResult Save([FromQuery] string note)
                {
                    TempData["Note"] = note;
                    return RedirectToAction("Show");
                }
                public IActionResult Show() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_Flash_Show", "object", "/src/App/Views/Flash/Show.cshtml", """
                Write(Html.Raw(TempData["Note"]));
                Write(Html.Raw(ViewData["Note"]));
                """));

        Assert.Empty(Found(result));
    }

    // ---- The view model as a value ----

    [Fact]
    public void A_list_model_given_to_View_is_the_views_Model_iterated_in_the_view()
    {
        const string web = """
            public class Card { public string Bio { get; set; } = ""; public string Name { get; set; } = ""; }
            public class CardsController : Controller
            {
                public IActionResult Preview([FromQuery] string line) => View(new List<string> { line });
                public IActionResult Draft([FromBody] Card draft) => View(new List<Card> { draft });
                public IActionResult Safe([FromQuery] string line) => View("Preview", new List<string> { HtmlEncoder.Default.Encode(line) });
                public IActionResult Empty() => View("Preview", new List<string>());
            }
            """;
        var result = Analyze(web,
            View("Views_Cards_Preview", "List<string>", "/src/App/Views/Cards/Preview.cshtml", """
                foreach (var x in Model) { Write(Html.Raw(x)); }
                """),
            View("Views_Cards_Draft", "List<Card>", "/src/App/Views/Cards/Draft.cshtml", """
                foreach (var c in Model) { Write(Html.Raw(c.Bio)); }
                foreach (var c in Model) { Write(c.Bio); }
                """));

        // Preview's list carries the query. Draft's list holds the bound card: its members are request data (line 2 is
        // encoded). Safe encodes before View(): its value reaches Preview's view clean (the finding at line 1 is
        // Preview's own); Empty gives a list with nothing in it.
        Assert.Equal(new[] { "/src/App/Views/Cards/Draft.cshtml:1", "/src/App/Views/Cards/Preview.cshtml:1" }, Found(result));
    }

    [Fact]
    public void A_sanitized_list_model_is_quiet()
    {
        const string web = """
            public class NotesController : Controller
            {
                public IActionResult Safe([FromQuery] string line) => View(new List<string> { HtmlEncoder.Default.Encode(line) });
            }
            """;
        var result = Analyze(web,
            View("Views_Notes_Safe", "List<string>", "/src/App/Views/Notes/Safe.cshtml", """
                foreach (var x in Model) { Write(Html.Raw(x)); }
                """));

        Assert.Empty(Found(result));
    }

    [Fact]
    public void A_bound_model_reaches_its_members_and_elements_in_the_view_and_its_partial()
    {
        const string web = """
            public class Feed { public List<string> Items { get; set; } = new(); public string Title { get; set; } = ""; }
            public class FeedController : Controller
            {
                public IActionResult Preview([FromBody] Feed feed) => View(feed);
                public IActionResult Rows([FromBody] Feed feed) => PartialView("_Rows", feed.Items);
                public IActionResult Fresh() => View("Preview", new Feed());
            }
            """;
        var result = Analyze(web,
            View("Views_Feed_Preview", "Feed", "/src/App/Views/Feed/Preview.cshtml", """
                Write(Html.Raw(Model.Items[0]));
                Write(Html.Raw(Model.Title));
                Write(await Html.PartialAsync("_Rows", Model.Items));
                Write(Model.Title);
                """),
            View("Views_Feed__Rows", "List<string>", "/src/App/Views/Feed/_Rows.cshtml", """
                for (var i = 0; i < Model.Count; i++) { Write(Html.Raw(Model[i])); }
                """));

        Assert.Equal(new[]
        {
            "/src/App/Views/Feed/Preview.cshtml:1",
            "/src/App/Views/Feed/Preview.cshtml:2",
            "/src/App/Views/Feed/_Rows.cshtml:1",
        }, Found(result));
    }

    /// The view model is keyed by type: a view in the same request whose model type the given model cannot be (a view
    /// component's own model, a view typed `dynamic`) does not read it.
    [Fact]
    public void A_model_reaches_only_the_views_whose_model_type_it_can_be()
    {
        const string web = """
            public class Feed { public string Title { get; set; } = ""; }
            public class SpecialFeed : Feed { }
            public class MenuModel { public string Title { get; set; } = ""; }
            public class FeedController : Controller
            {
                public IActionResult Preview([FromBody] SpecialFeed feed) => View(feed);
            }
            public class MenuViewComponent : ViewComponent
            {
                public IViewComponentResult Invoke() => View(new MenuModel());
            }
            public class BadgeViewComponent : ViewComponent
            {
                public IViewComponentResult Invoke() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_Feed_Preview", "Feed", "/src/App/Views/Feed/Preview.cshtml", """
                Write(Html.Raw(Model.Title));
                Write(await Component.InvokeAsync("Menu"));
                Write(await Component.InvokeAsync("Badge"));
                """),
            View("Views_Shared_Components_Menu_Default", "MenuModel", "/src/App/Views/Shared/Components/Menu/Default.cshtml", """
                Write(Html.Raw(Model.Title));
                """),
            View("Views_Shared_Components_Badge_Default", "dynamic", "/src/App/Views/Shared/Components/Badge/Default.cshtml", """
                Write(Html.Raw((string)Model.Title));
                """));

        // A SpecialFeed is a Feed: Preview's view reads it. The menu's view renders a MenuModel and the badge's a dynamic
        // model, in the same request: quiet.
        Assert.Equal(new[] { "/src/App/Views/Feed/Preview.cshtml:1" }, Found(result));
    }

    /// A generic helper that gives its type-parameter model to View() (a base view component's wrapper) writes the model
    /// under the type each caller gives it; generic arguments are part of the type.
    [Fact]
    public void A_generic_wrapper_keeps_each_callers_model_type_and_generic_arguments_count()
    {
        const string web = """
            public class Note { public string Text { get; set; } = ""; }
            public class Link { public string Title { get; set; } = ""; }
            public abstract class BaseComponent : ViewComponent
            {
                protected IViewComponentResult Render<TModel>(string view, TModel model) => View(view, model);
            }
            public class NotesViewComponent : BaseComponent
            {
                public IViewComponentResult Invoke() => Render("Default", new List<string> { HttpContext.Request.Query["n"].ToString() });
            }
            public class LinksViewComponent : BaseComponent
            {
                public IViewComponentResult Invoke() => Render("Default", new List<Link>());
            }
            public class HomeController : Controller
            {
                public IActionResult Index() => View();
            }
            """;
        var result = Analyze(web,
            View("Views_Home_Index", "object", "/src/App/Views/Home/Index.cshtml", """
                Write(await Component.InvokeAsync("Notes"));
                Write(await Component.InvokeAsync("Links"));
                """),
            View("Views_Shared_Components_Notes_Default", "IList<string>", "/src/App/Views/Shared/Components/Notes/Default.cshtml", """
                foreach (var n in Model) { Write(Html.Raw(n)); }
                """),
            View("Views_Shared_Components_Links_Default", "IList<Link>", "/src/App/Views/Shared/Components/Links/Default.cshtml", """
                foreach (var l in Model) { Write(Html.Raw(l.Title)); }
                """));

        // The notes list carries the query (through the wrapper, as a List<string>, which an IList<string> view can be
        // given); the links view renders IList<Link>, which a List<string> cannot be.
        Assert.Equal(new[] { "/src/App/Views/Shared/Components/Notes/Default.cshtml:1" }, Found(result));
    }

    /// A key given by a static member that is a constant in all but name (a static property returning a literal, a static
    /// readonly field initialised with one) is that constant.
    [Fact]
    public void A_key_held_in_a_static_property_or_readonly_field_is_its_constant()
    {
        const string web = """
            public static class Keys
            {
                public static string Theme => "theme";
                public static readonly string Culture = "culture";
            }
            public class ThemeMiddleware
            {
                private readonly RequestDelegate _next;
                public ThemeMiddleware(RequestDelegate next) => _next = next;
                public Task InvokeAsync(HttpContext context)
                {
                    context.Items[Keys.Theme] = context.Request.Cookies["theme"];
                    context.Items[Keys.Culture] = context.Request.Cookies["culture"];
                    return _next(context);
                }
            }
            public class PagesController : ControllerBase
            {
                private readonly SqlConnection _c = new();
                public IActionResult Show()
                {
                    _c.Execute("SELECT * FROM t WHERE x = '" + HttpContext.Items["license"] + "'");
                    _c.Execute("SELECT * FROM t WHERE x = '" + HttpContext.Items["theme"] + "'"); /*sink*/
                    _c.Execute("SELECT * FROM t WHERE x = '" + HttpContext.Items[Keys.Culture] + "'"); /*sink*/
                    return Ok();
                }
            }
            """;
        var code = "using Microsoft.Data.SqlClient;\nusing Dapper;\n" + web;
        Assert.Equal(Marked(code), Found(Analyze(code), "csharp.sql-injection"));
    }

    [Fact]
    public void A_model_given_in_one_action_is_not_the_Model_of_another_actions_view()
    {
        const string web = """
            public class Wall { public List<string> Posts { get; set; } = new(); }
            public class WallController : Controller
            {
                public IActionResult Post([FromQuery] string text) => View("Posted", new List<string> { text });
                public IActionResult Show() => View(new List<string>());
            }
            """;
        var result = Analyze(web,
            View("Views_Wall_Posted", "List<string>", "/src/App/Views/Wall/Posted.cshtml", "Write(Model.Count);"),
            View("Views_Wall_Show", "List<string>", "/src/App/Views/Wall/Show.cshtml", """
                foreach (var x in Model) { Write(Html.Raw(x)); }
                """));

        Assert.Empty(Found(result));
    }

    [Fact]
    public void A_view_components_model_is_its_views_Model()
    {
        const string web = """
            public class TagsViewComponent : ViewComponent
            {
                public IViewComponentResult Invoke() => View(((string)ViewData["Tags"]).Split(',').ToList());
            }
            public class PostController : Controller
            {
                public IActionResult Read([FromQuery] string tags) { ViewData["Tags"] = tags; return View(); }
                public IActionResult Other() => View("Read");
            }
            """;
        var result = Analyze(web,
            View("Views_Post_Read", "object", "/src/App/Views/Post/Read.cshtml", """
                Write(await Component.InvokeAsync("Tags"));
                """),
            View("Views_Shared_Components_Tags_Default", "List<string>", "/src/App/Views/Shared/Components/Tags/Default.cshtml", """
                foreach (var t in Model) { Write(Html.Raw(t)); }
                """));

        // The component reads the action's ViewData entry and gives the split list to its view as the model.
        Assert.Equal(new[] { "/src/App/Views/Shared/Components/Tags/Default.cshtml:1" }, Found(result));
    }

    [Fact]
    public void A_Razor_Pages_list_property_reaches_the_page()
    {
        const string pages = """
            public class LinesModel : Microsoft.AspNetCore.Mvc.RazorPages.PageModel
            {
                public List<string> Lines { get; set; } = new();
                public IActionResult OnGet([FromQuery] string first) { Lines = new List<string> { first }; return Page(); }
            }
            """;
        var result = Analyze(pages,
            Page("Pages_Lines", "LinesModel", "/src/App/Pages/Lines.cshtml", """
                foreach (var l in Model.Lines) { Write(Html.Raw(l)); }
                """));

        Assert.Equal(new[] { "/src/App/Pages/Lines.cshtml:1" }, Found(result));
    }

    // ---- HttpContext.Items ----

    [Fact]
    public void An_HttpContext_Items_entry_is_a_keyed_request_scoped_location()
    {
        const string web = """
            public class TenantMiddleware
            {
                private readonly RequestDelegate _next;
                public TenantMiddleware(RequestDelegate next) => _next = next;
                public Task InvokeAsync(HttpContext context)
                {
                    context.Items["tenant"] = context.Request.Headers["X-Tenant"].ToString();
                    context.Items["region"] = "eu";
                    return _next(context);
                }
            }
            public class ReportsController : ControllerBase
            {
                private readonly SqlConnection _c = new();
                public IActionResult Count()
                {
                    var tenant = HttpContext.Items["tenant"] as string;
                    var region = HttpContext.Items["region"] as string;
                    _c.Execute("SELECT COUNT(*) FROM " + tenant + "_orders"); /*sink*/
                    _c.Execute("SELECT COUNT(*) FROM " + region + "_orders");
                    if (HttpContext.Items.TryGetValue("tenant", out var t)) _c.Execute("DELETE FROM " + t); /*sink*/
                    return Ok();
                }
            }
            public class StampController : ControllerBase
            {
                private readonly SqlConnection _c = new();
                public IActionResult Mark([FromQuery] string who) { HttpContext.Items["who"] = who; return Ok(); }
                public IActionResult Read() { _c.Execute("SELECT * FROM t WHERE w = '" + HttpContext.Items["who"] + "'"); return Ok(); }
            }
            """;
        var code = "using Microsoft.Data.SqlClient;\nusing Dapper;\n" + web;
        var result = Analyze(code);

        // The middleware runs around every action: its tenant entry is request data in Count (the indexer and
        // TryGetValue); the region entry is a constant. Mark's entry is not Read's (another request, R-6).
        Assert.Equal(Marked(code), Found(result, "csharp.sql-injection"));
    }
}
