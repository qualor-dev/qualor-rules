using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Model validation as a sanitizer (Task 31, decision R-12; models/README.md "Model validation"). A bound value whose
/// validation attributes leave it no character a rule's sink needs is clean for that rule where validation is known to
/// hold: on the branch where `ModelState.IsValid` (or `TryValidateModel(...)`) is true, and in every action of an
/// `[ApiController]` (the automatic HTTP 400), unless SuppressModelStateInvalidFilter is set somewhere in the source.
/// What each attribute admits follows Microsoft's documentation (System.ComponentModel.DataAnnotations; ASP.NET Core
/// "Model validation" and "Create web APIs"). Each test holds found lines (`/*sink*/`) and quiet controls, with the
/// shipped models.
public sealed class ModelValidationTests
{
    /// The snippet after the usings and the forms; a first line `[assembly: ...]` goes before the forms (an empty line
    /// keeps the snippet's line numbers).
    private static void Expect(string code, string rule = "csharp.sql-injection")
    {
        var head = "";
        if (code.StartsWith("[assembly:", StringComparison.Ordinal))
        {
            var end = code.IndexOf('\n') + 1;
            head = code[..end];
            code = "\n" + code[end..];
        }
        var prefix = Usings + head + Prelude;
        var offset = prefix.Split('\n').Length - 1;
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(prefix + code, rule).Select(l => l - offset).ToList());
    }

    private const string Usings = """
        using System.ComponentModel.DataAnnotations;
        using System.Diagnostics;
        using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
        using Microsoft.Extensions.DependencyInjection;

        """;

    /// The forms every snippet binds (no finding is expected in them).
    private const string Prelude = """
        public enum Shelf { Top, Middle, Bottom }
        public class Basket
        {
            [Range(1, 100)] public int Count { get; set; }
            [Range(1, 100)] public string Size { get; set; } = "";
            [Range(0.5, 9.5)] public string Weight { get; set; } = "";
            [Range(typeof(DateTime), "2020-01-01", "2030-12-31")] public string Day { get; set; } = "";
            [StringLength(8)] public string Note { get; set; } = "";
            [MaxLength(8), Required] public string Tag { get; set; } = "";
            [RegularExpression("^[a-z0-9]+$")] public string Code { get; set; } = "";
            [RegularExpression("[a-z]+")] public string Word { get; set; } = "";
            [RegularExpression(".*[a-z]+.*")] public string Hit { get; set; } = "";
            [RegularExpression(@"^[a-z0-9' ]+$")] public string Quoted { get; set; } = "";
            [RegularExpression("^[a-z0-9._,|-]{1,40}$")] public string Container { get; set; } = "";
            [RegularExpression("^[a-z/]+$")] public string Folder { get; set; } = "";
            [RegularExpression(@"^\w+$")] public string Name { get; set; } = "";
            [RegularExpression(@"^[a-z]+(?=')$")] public string Ahead { get; set; } = "";
            [RegularExpression(@"^[a-z]+\x27$")] public string Escaped { get; set; } = "";
            [RegularExpression(@"(?x) ^ [a-z]+ $")] public string Spaced { get; set; } = "";
            [EnumDataType(typeof(Shelf))] public string Shelf { get; set; } = "";
            public Shelf Place { get; set; }
            [EmailAddress] public string Email { get; set; } = "";
            [Url] public string Site { get; set; } = "";
            [Phone] public string Phone { get; set; } = "";
            [ValidateNever, RegularExpression("^[a-z]+$")] public string Skipped { get; set; } = "";
            public Address Address { get; set; } = new();
            public List<Address> Others { get; set; } = new();
            public string Plain { get; set; } = "";
        }
        public class Address
        {
            [RegularExpression("^[0-9]{5}$")] public string Zip { get; set; } = "";
            public string Street { get; set; } = "";
        }
        public interface IRefill { void Refill(Basket basket); }

        """;

    // ---- What an attribute admits ----

    /// [Range] constrains a value to a number of its operand type ("Specifies the numeric range constraints"; a string
    /// value is converted to the operand type first): a number's text cannot carry an injection. A range over another
    /// operand type (a date) is no number. [StringLength], [MaxLength] and [Required] limit the length or presence only.
    [Fact]
    public void A_range_cleans_and_length_limits_do_not() => Expect("""
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET n = " + basket.Count, _db);
                new SqlCommand("UPDATE b SET s = '" + basket.Size + "'", _db);
                new SqlCommand("UPDATE b SET w = '" + basket.Weight + "'", _db);
                new SqlCommand("UPDATE b SET d = '" + basket.Day + "'", _db); /*sink*/
                new SqlCommand("UPDATE b SET t = '" + basket.Note + "'", _db); /*sink*/
                new SqlCommand("UPDATE b SET g = '" + basket.Tag + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// [RegularExpression]: "The regular expression searches for an exact match, not using ^ before and $ at the end of
    /// the pattern produces the same results as using it" (RegularExpressionAttribute, Remarks). So every pattern is held
    /// to the whole value, anchored or not, and the value's characters are the ones the pattern's consuming parts admit.
    /// `^[a-z0-9]+$` and `[a-z]+` hold no SQL metacharacter; `.*[a-z]+.*` (the documented "search hit" form) and a class
    /// holding a quote do, and so does `\w`: letters of every script include U+02BC MODIFIER LETTER APOSTROPHE, a
    /// look-alike the SQL model counts (a best-fit code page conversion may turn it into a quote). A lookahead consumes
    /// nothing; an escape is the character it names; a pattern in the free-spacing mode (`(?x)`) is not read.
    [Fact]
    public void A_regular_expression_cleans_by_the_characters_it_admits() => Expect("""
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("SELECT * FROM b WHERE c = '" + basket.Code + "'", _db);
                new SqlCommand("SELECT * FROM b WHERE w = '" + basket.Word + "'", _db);
                new SqlCommand("SELECT * FROM b WHERE a = '" + basket.Ahead + "'", _db);
                new SqlCommand("SELECT * FROM b WHERE n = '" + basket.Name + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM b WHERE h = '" + basket.Hit + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM b WHERE q = '" + basket.Quoted + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM b WHERE e = '" + basket.Escaped + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM b WHERE s = '" + basket.Spaced + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// The metacharacters are the rule's (validation: in its model): a container name of letters, digits and `._,|-`
    /// holds no path separator, so it is clean for path-traversal, but `,`, `|` and `-` keep it request data for
    /// sql-injection; a pattern admitting `/` is not clean for path-traversal.
    [Fact]
    public void Each_rule_has_its_own_metacharacters()
    {
        const string code = """
            public class MediaController : Controller
            {
                private readonly SqlConnection _db = new("Server=.;Database=media");
                public IActionResult Play(Basket basket)
                {
                    if (!ModelState.IsValid) return BadRequest();
                    System.IO.File.ReadAllText("/media/segment." + basket.Container);
                    System.IO.File.ReadAllText("/media/" + basket.Folder); /*sink*/
                    new SqlCommand("SELECT * FROM m WHERE c = '" + basket.Container + "'", _db); /*sink*/
                    new SqlCommand("SELECT * FROM m WHERE c = '" + basket.Code + "'", _db);
                    return Ok();
                }
            }
            """;
        var path = code.Replace("basket.Container + \"'\", _db); /*sink*/", "basket.Container + \"'\", _db);");
        Expect(path, "csharp.path-traversal");
        var sql = code.Replace("System.IO.File.ReadAllText(\"/media/\" + basket.Folder); /*sink*/", "System.IO.File.ReadAllText(\"/media/\" + basket.Folder);");
        Expect(sql);
    }

    /// Ruling R-E34: validation never cleans command-injection. A token of letters chosen by the request can name the
    /// program to run (`reboot`), and the values [Range] and [EnumDataType] accept carry signs, separators and spaces
    /// (" 5", "-5", "1E+2", "Top, Middle"): an option or a second argument where they reach a command line.
    [Fact]
    public void Validation_never_cleans_command_injection() => Expect("""
        public class RunController : Controller
        {
            public IActionResult Run([RegularExpression("^[a-z]+$")] string tool, [Range(-100, 100)] string n, [EnumDataType(typeof(Shelf))] string shelf)
            {
                if (!ModelState.IsValid) return BadRequest();
                Process.Start("/usr/bin/" + tool); /*sink*/
                Process.Start("/bin/sh", "-c \"tool " + n + "\""); /*sink*/
                Process.Start("/bin/sh", "-c \"shelve " + shelf + "\""); /*sink*/
                return Ok();
            }
        }
        """, "csharp.command-injection");

    /// Ruling R-E34: a value of ASCII digits cleans ssrf, as an int parameter does (the scalar policy); its cost is a
    /// host written as one decimal number (`http://2130706433/` is 127.0.0.1) or a chosen port. Letters do not clean.
    [Fact]
    public void Only_digits_clean_ssrf() => Expect("""
        public class FetchController : Controller
        {
            public async Task<IActionResult> Get([RegularExpression("^[0-9]+$")] string port, [RegularExpression("^[a-z]+$")] string host)
            {
                if (!ModelState.IsValid) return BadRequest();
                using var client = new HttpClient();
                await client.GetStringAsync("http://" + host + "/status"); /*sink*/
                return Ok(await client.GetStringAsync("http://10.0.0.1:" + port + "/status"));
            }
        }
        """, "csharp.ssrf");

    /// An enum-typed member holds a named value; [EnumDataType] holds a string to one of the enum's values.
    [Fact]
    public void An_enum_cleans() => Expect("""
        public class ShelfController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Move(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET shelf = '" + basket.Shelf + "'", _db);
                new SqlCommand("UPDATE b SET place = '" + basket.Place + "'", _db);
                new SqlCommand("UPDATE b SET plain = '" + basket.Plain + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// [EmailAddress], [Url] and [Phone]: the documentation says only that the value "has an email format" (a URL, a
    /// telephone number format) and does not name the characters it admits, so they clean nothing.
    [Fact]
    public void Email_url_and_phone_clean_nothing() => Expect("""
        public class ContactController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("SELECT * FROM c WHERE mail = '" + basket.Email + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM c WHERE site = '" + basket.Site + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM c WHERE phone = '" + basket.Phone + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM c WHERE code = '" + basket.Code + "'", _db);
                return Ok();
            }
        }
        """);

    /// [ValidateNever] leaves a member out of validation: its pattern says nothing.
    [Fact]
    public void A_member_left_out_of_validation_is_not_clean() => Expect("""
        public class SkipController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("SELECT * FROM c WHERE s = '" + basket.Skipped + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM c WHERE c = '" + basket.Code + "'", _db);
                return Ok();
            }
        }
        """);

    // ---- Where validation holds ----

    /// A plain controller: "it's the app's responsibility to inspect ModelState.IsValid"; without the check an invalid
    /// value reaches the action.
    [Fact]
    public void Without_a_validity_check_a_plain_controller_reports() => Expect("""
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket, [RegularExpression("^[0-9a-f]{32}$")] string id)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                new SqlCommand("UPDATE b SET s = '" + basket.Size + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM b WHERE id = '" + id + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// The branch where the check failed (or the code after a check that does not leave) is not clean: `if (IsValid)`'s
    /// else, `if (!IsValid)`'s then, `IsValid == false`.
    [Fact]
    public void The_branch_where_the_model_is_invalid_reports() => Expect("""
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (ModelState.IsValid)
                {
                    new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db);
                    return Ok();
                }
                new SqlCommand("INSERT INTO rejected VALUES ('" + basket.Code + "')", _db); /*sink*/
                return View(basket);
            }
            public IActionResult Check(Basket basket)
            {
                if (!ModelState.IsValid)
                {
                    new SqlCommand("INSERT INTO rejected VALUES ('" + basket.Code + "')", _db); /*sink*/
                }
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                if (ModelState.IsValid == false) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db);
                return Ok();
            }
            // Another ModelStateDictionary says nothing about the action's model.
            public IActionResult Other(Basket basket)
            {
                var other = new Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary();
                if (!other.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// A parameter's own attribute (a top-level node: "Model-bound top-level nodes are validated"): clean where IsValid
    /// holds, unless the parameter is assigned in the body.
    [Fact]
    public void A_parameter_attribute_cleans_where_the_model_is_valid() => Expect("""
        public class OrderController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Find([RegularExpression("^[0-9a-f]{32}$")] string id, string other)
            {
                if (!ModelState.IsValid) return BadRequest();
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db);
                new SqlCommand("SELECT * FROM o WHERE other = '" + other + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Load([RegularExpression("^[0-9a-f]{32}$")] string id)
            {
                if (id.Length == 0) id = Request.Query["fallback"];
                if (!ModelState.IsValid) return BadRequest();
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// TryValidateModel(model) validates the model and returns whether the ModelState is valid: where it is true, the
    /// model's validated members (an object built in the action too) and the bound values are clean.
    [Fact]
    public void Try_validate_model_cleans_where_it_returned_true() => Expect("""
        public class DraftController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save()
            {
                var draft = new Basket { Code = Request.Query["code"], Plain = Request.Query["plain"] };
                if (TryValidateModel(draft))
                {
                    new SqlCommand("UPDATE d SET c = '" + draft.Code + "'", _db);
                    new SqlCommand("UPDATE d SET p = '" + draft.Plain + "'", _db); /*sink*/
                    return Ok();
                }
                new SqlCommand("INSERT INTO rejected VALUES ('" + draft.Code + "')", _db); /*sink*/
                return View(draft);
            }
        }
        """);

    /// [ApiController] on the controller or a base class: "model validation errors automatically trigger an HTTP 400
    /// response", so the action runs only with a valid model: no check needed.
    [Fact]
    public void An_api_controller_needs_no_check() => Expect("""
        [ApiController]
        public class ApiBase : ControllerBase { }
        [ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket, [FromQuery, RegularExpression("^[0-9a-f]{32}$")] string id)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "' WHERE id = '" + id + "'", _db);
                new SqlCommand("UPDATE b SET z = '" + basket.Address.Zip + "'", _db);
                new SqlCommand("UPDATE b SET p = '" + basket.Plain + "'", _db); /*sink*/
                new SqlCommand("UPDATE b SET m = '" + basket.Email + "'", _db); /*sink*/
                return Ok();
            }
        }
        [Route("api/shelves")]
        public class ShelvesController : ApiBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE s SET c = '" + basket.Code + "'", _db);
                new SqlCommand("UPDATE s SET p = '" + basket.Plain + "'", _db); /*sink*/
                return Ok();
            }
        }
        [Route("plain")]
        public class PlainController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE s SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// A validated parameter of an [ApiController] action is clean from the entry: copied into an object a callee reads
    /// (a job whose file name ends in the validated part), it stays clean for the rules its pattern cleans; the
    /// unvalidated parameter beside it does not.
    [Fact]
    public void A_validated_parameter_stays_clean_in_a_callee() => Expect("""
        public class Job { public string Container { get; set; } = ""; public string Other { get; set; } = ""; }
        public class Segments
        {
            public string Read(Job job)
            {
                System.IO.File.ReadAllText("/cache/segment." + job.Container);
                return System.IO.File.ReadAllText("/cache/" + job.Other); /*sink*/
            }
        }
        [ApiController]
        [Route("media")]
        public class SegmentsController : ControllerBase
        {
            private readonly Segments _segments = new();
            [HttpGet]
            public IActionResult Get([FromQuery, RegularExpression("^[a-z0-9._,|-]{1,40}$")] string container, [FromQuery] string other)
            {
                var job = new Job { Container = container, Other = other };
                return Ok(_segments.Read(job));
            }
        }
        """, "csharp.path-traversal");

    /// [assembly: ApiController]: "all controllers in the assembly have the [ApiController] attribute applied".
    [Fact]
    public void An_assembly_api_controller_attribute_applies_to_every_controller() => Expect("""
        [assembly: ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db);
                new SqlCommand("UPDATE b SET p = '" + basket.Plain + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// SuppressModelStateInvalidFilter = true anywhere in the source turns the automatic 400 off ("To disable the
    /// automatic 400 behavior"): an [ApiController] action then needs the IsValid check as any other.
    [Fact]
    public void A_suppressed_filter_needs_the_check_again() => Expect("""
        public static class Setup
        {
            public static void Api(IServiceCollection services) =>
                services.Configure<ApiBehaviorOptions>(options => { options.SuppressModelStateInvalidFilter = true; });
        }
        [ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            [HttpPut]
            public IActionResult Update(Basket basket)
            {
                if (!ModelState.IsValid) return ValidationProblem(ModelState);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db);
                return Ok();
            }
        }
        """);

    /// Razor Pages: a bound page-model property ("Page model properties" are top-level nodes) checked with IsValid.
    [Fact]
    public void A_bound_page_property_is_clean_where_the_model_is_valid() => Expect("""
        public class CheckoutModel : PageModel
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [BindProperty] public Basket Input { get; set; } = new();
            public IActionResult OnPost()
            {
                new SqlCommand("UPDATE b SET c = '" + Input.Code + "'", _db); /*sink*/
                if (!ModelState.IsValid) return Page();
                new SqlCommand("UPDATE b SET c = '" + Input.Code + "'", _db);
                new SqlCommand("UPDATE b SET p = '" + Input.Plain + "'", _db); /*sink*/
                return RedirectToPage("/Done");
            }
        }
        """);

    /// The automatic 400 is a controller behaviour ("Create web APIs": the attribute applies to controllers); a Razor
    /// Pages handler must check ModelState.IsValid even under `[assembly: ApiController]` or the attribute on its class.
    [Fact]
    public void An_assembly_api_controller_attribute_does_not_cover_razor_pages() => Expect("""
        [assembly: ApiController]
        public class CheckoutModel : PageModel
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [BindProperty] public Basket Input { get; set; } = new();
            public IActionResult OnPost([RegularExpression("^[a-z]+$")] string id)
            {
                new SqlCommand("UPDATE b SET c = '" + Input.Code + "'", _db); /*sink*/
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                if (!ModelState.IsValid) return Page();
                new SqlCommand("UPDATE b SET c = '" + Input.Code + "' WHERE id = '" + id + "'", _db);
                return Page();
            }
        }
        """);

    [Fact]
    public void An_api_controller_attribute_on_a_page_model_has_no_effect() => Expect("""
        [ApiController]
        public class OrderModel : PageModel
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult OnPost([RegularExpression("^[a-z]+$")] string id)
            {
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                return Page();
            }
        }
        """);

    /// The automatic 400 also goes when InvalidModelStateResponseFactory is replaced (the factory decides the response)
    /// or ApiBehaviorOptions are bound from configuration (SuppressModelStateInvalidFilter may be set there): then only
    /// the IsValid check counts.
    [Theory]
    [InlineData("services.Configure<ApiBehaviorOptions>(o => o.InvalidModelStateResponseFactory = c => new OkResult());")]
    [InlineData("services.Configure<ApiBehaviorOptions>(configuration.GetSection(\"Api\"));")]
    public void Other_ways_to_turn_the_automatic_400_off_count(string setup) => Expect($$"""
        public static class Setup
        {
            public static void Api(IServiceCollection services, Microsoft.Extensions.Configuration.IConfiguration configuration)
            {
                {{setup}}
            }
        }
        [ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// [ValidateNever] is inherited (AttributeUsage Inherited = true): a form deriving from a class that carries it is
    /// not validated.
    [Fact]
    public void Validate_never_on_a_base_class_is_inherited() => Expect("""
        [ValidateNever] public class LooseForm { }
        public class SearchForm : LooseForm { [RegularExpression("^[a-z]+$")] public string Term { get; set; } = ""; }
        public class SearchController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Find(SearchForm form)
            {
                if (!ModelState.IsValid) return BadRequest();
                new SqlCommand("SELECT * FROM p WHERE t = '" + form.Term + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- What ends the fact ----

    /// IsValid speaks for the values binding validated only while ModelState is as validation left it. Removing or
    /// clearing an entry, marking a field valid or skipped, setting a value, or handing ModelState to other code (which
    /// may do any of that) makes the later check say nothing; reads and AddModelError (which only makes it invalid) keep
    /// it.
    [Fact]
    public void Changing_model_state_before_the_check_reports() => Expect("""
        public static class StateFixes { public static void Drop(Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary s) => s.Remove("Code"); }
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Remove(Basket basket)
            {
                ModelState.Remove(nameof(Basket.Code));
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Clear(Basket basket)
            {
                ModelState.Clear();
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Mark([RegularExpression("^[a-z]+$")] string id)
            {
                ModelState.MarkFieldValid("id");
                if (!ModelState.IsValid) return BadRequest();
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Helper(Basket basket)
            {
                StateFixes.Drop(ModelState);
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Through(Basket basket)
            {
                ViewData.ModelState.Remove("Code");
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Reads(Basket basket, [RegularExpression("^[a-z]+$")] string id)
            {
                if (basket.Plain.Length == 0) ModelState.AddModelError("Plain", "required");
                if (ModelState.ErrorCount > 10 || ModelState.ContainsKey("x")) return BadRequest();
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "' WHERE id = '" + id + "'", _db);
                ModelState.Clear();
                return Ok();
            }
        }
        """);

    /// The value validated is the one bound: a member written after the check (or before it), or given to a call that
    /// may change it (the guard rules of Task 21), is request data again.
    [Fact]
    public void A_member_written_after_validation_reports() => Expect("""
        public class BasketController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            private readonly IRefill _refill;
            public BasketController(IRefill refill) { _refill = refill; }
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db);
                basket.Code = Request.Query["code"];
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Refill(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                _refill.Refill(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
            public IActionResult Early(Basket basket)
            {
                basket.Code = Request.Query["code"];
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        [ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                basket.Code = Request.Query["code"];
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- Only the framework's call is validated (review C1) ----

    /// Validation speaks for the values model binding gave the action, not for what project code passes when it calls
    /// the action (or a public helper of the controller) itself: the caller's value is cleaned nowhere.
    [Fact]
    public void An_api_action_called_by_another_keeps_the_callers_finding() => Expect("""
        [ApiController]
        [Route("api/orders")]
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpGet("raw")]
            public IActionResult Raw([FromQuery] string raw) => Find(raw);
            [HttpGet("find")]
            public IActionResult Find([FromQuery, RegularExpression("^[a-z]+$")] string id)
            {
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_action_called_by_another_after_its_check_keeps_the_callers_finding() => Expect("""
        public class OrdersController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Raw(string raw) => Find(raw);
            public IActionResult Find([RegularExpression("^[a-z]+$")] string id)
            {
                if (!ModelState.IsValid) return BadRequest();
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_model_built_by_the_caller_keeps_the_callers_finding() => Expect("""
        [ApiController]
        [Route("api/baskets")]
        public class BasketsController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpGet("quick")]
            public IActionResult Quick([FromQuery] string code) => Save(new Basket { Code = code });
            [HttpPost]
            public IActionResult Save(Basket basket)
            {
                new SqlCommand("UPDATE b SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        public class ShelvesController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Quick(string code) => Store(new Basket { Code = code });
            public IActionResult Store(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE s SET c = '" + basket.Code + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);

    /// The bound values themselves stay clean in such an action: its own request data (no caller) is what validation
    /// constrains.
    [Fact]
    public void The_bound_values_stay_clean_when_nobody_calls_the_action() => Expect("""
        [ApiController]
        [Route("api/orders")]
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            [HttpGet("find")]
            public IActionResult Find([FromQuery, RegularExpression("^[a-z]+$")] string id, Basket basket)
            {
                new SqlCommand("SELECT * FROM o WHERE id = '" + id + "' AND c = '" + basket.Code + "'", _db);
                return Ok();
            }
        }
        """);

    /// Task 28's witnesses: a value joined from a validated parameter (clean for sql-injection) and an unvalidated one is
    /// reported for sql-injection through the unvalidated one, with high confidence; for xss (where the pattern cleans
    /// nothing it holds: none of `[a-z]` is an xss metacharacter, so the validated one is clean there too) through the
    /// unvalidated one as well.
    [Fact]
    public void The_witness_of_a_finding_is_a_value_validation_did_not_clean()
    {
        const string code = """
            [ApiController]
            [Route("api/notes")]
            public class NotesController : ControllerBase
            {
                private readonly SqlConnection _db = new("Server=.;Database=shop");
                [HttpGet]
                public IActionResult Show([FromQuery, RegularExpression("^[a-z]+$")] string id, [FromQuery] string note)
                {
                    var both = id + note;
                    new SqlCommand("SELECT * FROM n WHERE k = '" + both + "'", _db);
                    return new ContentResult { Content = "<p>" + both + "</p>", ContentType = "text/html" };
                }
            }
            """;
        var result = Snippet.Analyze(Usings + Prelude + code);
        foreach (var rule in new[] { "csharp.sql-injection", "csharp.xss" })
        {
            var finding = Assert.Single(result.Findings, f => f.RuleId == rule);
            Assert.Contains("parameter 'note'", finding.Path[0].Message, StringComparison.Ordinal);
            Assert.Equal(Confidence.High, finding.Confidence);
        }
    }

    // ---- Nested members ----

    /// "ValidationVisitor traverses the object graph of the model": a nested object's validated member is clean; its
    /// other members are not, and neither is an element of a collection member (the documentation does not say elements
    /// are validated member by member).
    [Fact]
    public void A_nested_member_is_validated_and_collection_elements_are_not() => Expect("""
        public class AddressController : Controller
        {
            private readonly SqlConnection _db = new("Server=.;Database=shop");
            public IActionResult Save(Basket basket)
            {
                if (!ModelState.IsValid) return View(basket);
                new SqlCommand("UPDATE a SET zip = '" + basket.Address.Zip + "'", _db);
                new SqlCommand("UPDATE a SET street = '" + basket.Address.Street + "'", _db); /*sink*/
                new SqlCommand("UPDATE a SET zip = '" + basket.Others[0].Zip + "'", _db); /*sink*/
                foreach (var other in basket.Others)
                    new SqlCommand("UPDATE a SET zip = '" + other.Zip + "'", _db); /*sink*/
                return Ok();
            }
        }
        """);
}
