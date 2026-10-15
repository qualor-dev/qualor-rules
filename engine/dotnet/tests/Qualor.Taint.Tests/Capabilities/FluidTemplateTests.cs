using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 34, firm core 25.30: Fluid templates (the package's README, "Hello World", "Thread-safety", "Converting CLR types",
/// "Encoding", and its API documentation, Fluid.xml). Values reach a template through the TemplateContext: its model
/// (`new TemplateContext(model)`) and the values set on it (`context.SetValue(name, value)`, a FluidValue made by
/// `FluidValue.Create(value, options)` or a CLR value); `template.Render(context)` and `RenderAsync` give the rendered text,
/// or write it to a TextWriter. "By default Fluid doesn't encode the output"; an HtmlEncoder given to Render encodes the
/// values, but the template can still write one raw (`| raw`, `{% raw %}`), and the engine does not read the template: the
/// rendered text holds the values for every rule.
public sealed class FluidTemplateTests
{
    private const string Header = """
        using Fluid;
        using Fluid.Values;
        using System.Text.Encodings.Web;
        public static class Templates
        {
            public static readonly FluidParser Parser = new();
            public static readonly TemplateOptions Options = new();
            public static IFluidTemplate Parse(string source) => Parser.Parse(source);
        }
        public record User(string Name);
        """;

    [Fact]
    public void Values_set_on_the_context_reach_the_rendered_text() => Expect(Header + """
        public class ReportController : ControllerBase
        {
            private readonly SqlConnection _db = new();
            public async Task<IActionResult> Run(string region, string owner)
            {
                var template = Templates.Parse("SELECT * FROM sales WHERE region = '{{ region }}'");
                var context = new TemplateContext(Templates.Options);
                context.SetValue("region", FluidValue.Create(region, Templates.Options));
                var sql = await template.RenderAsync(context, NullEncoder.Default);
                _db.Query<User>(sql); /*sink*/
                var other = new TemplateContext(Templates.Options);
                other.SetValue("owner", owner);
                _db.Query<User>(template.Render(other)); /*sink*/
                return Ok();
            }
        }
        """, "csharp.sql-injection");

    [Fact]
    public void The_model_and_values_handed_through_a_list_of_pairs_reach_the_rendered_text() => Expect(Header + """
        public record Filter(string Region);
        public class QueryRunner
        {
            private readonly SqlConnection _db = new();
            public async Task<IEnumerable<User>> Run(string source, IDictionary<string, object> parameters)
            {
                var values = parameters.Select(p => new KeyValuePair<string, FluidValue>(p.Key, FluidValue.Create(p.Value, Templates.Options)));
                var context = new TemplateContext(Templates.Options);
                foreach (var value in values) context.SetValue(value.Key, value.Value);
                var sql = await Templates.Parse(source).RenderAsync(context, NullEncoder.Default);
                return _db.Query<User>(sql); /*sink*/
            }
        }
        public class ReportController : ControllerBase
        {
            private readonly QueryRunner _runner = new();
            private readonly SqlConnection _db = new();
            public async Task<IActionResult> Run(string source, [FromBody] Dictionary<string, object> parameters) =>
                Ok(await _runner.Run(source, parameters));
            public IActionResult ByModel(Filter filter)
            {
                var context = new TemplateContext(filter, Templates.Options, true);
                var writer = new StringWriter();
                Templates.Parse("SELECT * FROM sales WHERE region = '{{ Region }}'").RenderAsync(writer, NullEncoder.Default, context).AsTask().Wait();
                _db.Query<User>(writer.ToString()); /*sink*/
                return Ok();
            }
        }
        """, "csharp.sql-injection");

    [Fact]
    public void A_context_without_request_values_renders_server_text() => Expect(Header + """
        public class ReportController : ControllerBase
        {
            private readonly SqlConnection _db = new();
            public IActionResult Run(string region)
            {
                var template = Templates.Parse("SELECT * FROM sales WHERE region = '{{ region }}'");
                var context = new TemplateContext(Templates.Options);
                context.SetValue("region", FluidValue.Create("north", Templates.Options));
                var unused = new TemplateContext(Templates.Options);
                unused.SetValue("region", region);
                _db.Query<User>(template.Render(context));
                return Ok();
            }
        }
        """, "csharp.sql-injection");

    [Fact]
    public void Rendered_html_holds_the_values_with_or_without_an_html_encoder() => Expect(Header + """
        public class PageController : ControllerBase
        {
            public IActionResult Show(string name)
            {
                var template = Templates.Parse("<h1>{{ name }}</h1>");
                var context = new TemplateContext(Templates.Options);
                context.SetValue("name", name);
                var plain = template.Render(context);
                var encoded = template.Render(context, HtmlEncoder.Default);
                if (name.Length > 3) return Content(plain, "text/html"); /*sink*/
                return Content(encoded, "text/html"); /*sink*/
            }
        }
        """, "csharp.xss");

    private static void Expect(string code, string rule) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, rule));
}
