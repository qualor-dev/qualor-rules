using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 34, firm core 01.33: a Minimal API handler's complex-type parameter without a binding attribute is bound from
/// the request body (learn.microsoft.com aspnet/core/fundamentals/minimal-apis/parameter-binding, "Binding Precedence":
/// explicit attributes, then the special types, then a static BindAsync, then string or a static TryParse (route or
/// query), then a service provided by dependency injection, and last "The parameter is from the body"). "The HTTP
/// methods GET, HEAD, OPTIONS, and DELETE don't implicitly bind from body." A service is a type registered in the
/// container, which the engine reads from the solution's registrations: every type a registration names (the service and
/// the implementation type of `AddSingleton<IClock, Clock>` alike, the safe side for noise), a DbContext.
public sealed class MinimalApiBodyTests
{
    private const string Types = """
        public record User(string Name);
        public record Order(string Note, int Qty);
        """;

    [Fact]
    public void A_complex_parameter_of_a_post_put_or_patch_handler_is_the_request_body() => Expect("""
        var app = WebApplication.Create(args);
        app.MapPost("/o", (Order order, SqlConnection c) => c.Query<User>($"SELECT * FROM u WHERE n = '{order.Note}'")); /*sink*/
        app.MapPut("/o/{id}", (int id, Order? order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order!.Note + "'")); /*sink*/
        app.MapPatch("/o", Handlers.Patch);
        app.MapPost("/many", (List<Order> orders, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + orders[0].Note + "'")); /*sink*/
        app.MapMethods("/m", new[] { "POST" }, (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'")); /*sink*/
        app.MapPost("/j", (System.Text.Json.Nodes.JsonObject doc, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + doc.ToJsonString() + "'")); /*sink*/
        app.Run();
        public static class Handlers
        {
            public static IEnumerable<User> Patch(Order order, SqlConnection c) =>
                c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"); /*sink*/
        }
        """ + Types);

    [Fact]
    public void A_body_parameter_beside_registered_services_is_still_the_body() => Expect("""
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton<Audit>();
        var app = builder.Build();
        app.MapPost("/o", (Order order, Audit audit, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "' AND a = '" + audit.Tag + "'")); /*sink*/
        app.Run();
        public class Audit { public string Tag { get; set; } = ""; }
        """ + Types);

    [Fact]
    public void Get_head_options_and_delete_handlers_do_not_bind_the_body() => Expect("""
        var app = WebApplication.Create(args);
        app.MapGet("/o", (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"));
        app.MapDelete("/o", (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"));
        app.MapMethods("/m", new[] { "GET", "HEAD" }, (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"));
        app.MapMethods("/opt", [HttpMethods.Options], (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"));
        app.Run();
        """ + Types);

    [Fact]
    public void Registered_services_are_not_the_body() => Expect("""
        using Microsoft.EntityFrameworkCore;
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddScoped<Settings>();
        builder.Services.AddTransient(typeof(Repo));
        builder.Services.AddSingleton<IClock, Clock>();
        builder.AddStore<Store>("main");
        builder.Services.AddDbContext<ShopDb>();
        var app = builder.Build();
        app.MapPost("/a", (Settings s, SqlConnection c) => c.Query<User>("SELECT * FROM " + s.Schema + ".u"));
        app.MapPost("/b", (Repo r, SqlConnection c) => c.Query<User>("SELECT * FROM " + r.Table));
        app.MapPost("/c", (Store st, SqlConnection c) => c.Query<User>("SELECT * FROM " + st.Name));
        app.MapPost("/d", (ShopDb db, SqlConnection c) => c.Query<User>("SELECT * FROM " + db.Schema));
        app.MapPost("/e", (OtherDb db, SqlConnection c) => c.Query<User>("SELECT * FROM " + db.Schema));
        app.MapPost("/f", (Clock clock, SqlConnection c) => c.Query<User>("SELECT * FROM t" + clock.Zone));
        app.Run();
        public class Settings { public string Schema { get; set; } = ""; }
        public class Repo { public string Table { get; set; } = ""; }
        public class Store { public string Name { get; set; } = ""; }
        public interface IClock { }
        public class Clock : IClock { public string Zone { get; set; } = ""; }
        public class ShopDb : DbContext { public string Schema { get; set; } = ""; }
        public class OtherDb : DbContext { public string Schema { get; set; } = ""; }
        public static class StoreSetup
        {
            public static void AddStore<T>(this IHostApplicationBuilder builder, string name) where T : class => builder.Services.AddSingleton<T>();
        }
        """ + Types.Replace("public record Order(string Note, int Qty);", ""));

    /// The BindAsync and TryParse below ignore their input, so their objects hold no request data here. A type that binds
    /// itself from the request or is parsed from the route or query is request data, but not the body; the engine does not
    /// take it for a source (fix round 1 of Task 34, M1: a recorded FN, sources.yml step 4).
    [Fact]
    public void Special_types_custom_bound_parsed_library_and_interface_types_are_not_the_body() => Expect("""
        using System.Reflection;
        using System.Security.Claims;
        var app = WebApplication.Create(args);
        app.MapPost("/a", (ClaimsPrincipal user, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + user.Identity!.Name + "'"));
        app.MapPost("/b", (Paging p, SqlConnection c) => c.Query<User>("SELECT * FROM u ORDER BY " + p.Sort));
        app.MapPost("/c", (Point p, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + p.Text + "'"));
        app.MapPost("/d", (LinkGenerator links, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + links.GetPathByName("x") + "'"));
        app.MapPost("/e", (IOrderSource src, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + src.Note + "'"));
        app.MapPost("/f", ([FromServices] Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'"));
        app.MapPost("/g", (CancellationToken ct, HttpContext ctx, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + ctx.TraceIdentifier + "'"));
        app.Run();
        public class Paging
        {
            public string Sort { get; set; } = "";
            public static ValueTask<Paging?> BindAsync(HttpContext context, ParameterInfo parameter) => ValueTask.FromResult<Paging?>(new Paging());
        }
        public class Point
        {
            public string Text { get; set; } = "";
            public static bool TryParse(string? value, out Point result) { result = new Point(); return true; }
        }
        public interface IOrderSource { string Note { get; } }
        """ + Types);

    /// Fix round 1 of Task 34, I3: a registration whose type arguments the compiler infers (an instance, a factory) and one
    /// made through a project's plain static helper given the service collection name their types too.
    [Fact]
    public void Registrations_with_inferred_types_or_through_a_plain_helper_are_services() => Expect("""
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton(new Branding());
        builder.Services.AddTransient(provider => new Ledger());
        Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions.TryAddSingleton(builder.Services, new Tariff());
        Plumbing.Wire<Ledger2>(builder.Services, true);
        var app = builder.Build();
        app.MapPut("/a", (Branding b, SqlConnection c) => c.Query<User>("SELECT * FROM " + b.Theme));
        app.MapPut("/b", (Ledger l, SqlConnection c) => c.Query<User>("SELECT * FROM " + l.Book));
        app.MapPut("/c", (Tariff t, SqlConnection c) => c.Query<User>("SELECT * FROM " + t.Zone));
        app.MapPut("/d", (Ledger2 l, SqlConnection c) => c.Query<User>("SELECT * FROM " + l.Book));
        app.MapPut("/e", (Order o, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + o.Note + "'")); /*sink*/
        app.Run();
        public class Branding { public string Theme { get; set; } = ""; }
        public class Ledger { public string Book { get; set; } = ""; }
        public class Ledger2 { public string Book { get; set; } = ""; }
        public class Tariff { public string Zone { get; set; } = ""; }
        public static class Plumbing
        {
            public static void Wire<T>(IServiceCollection target, bool shared) where T : class
            {
                if (shared) target.AddSingleton<T>(); else target.AddScoped<T>();
            }
        }
        """ + Types);

    /// Fix round 1 of Task 34, M2: `Map` (every HTTP method) and `MapFallback` map handlers too
    /// (learn.microsoft.com dotnet/api/microsoft.aspnetcore.builder.endpointroutebuilderextensions.map,
    /// .fallbackendpointroutebuilderextensions.mapfallback); no verb keeps them from binding the body.
    [Fact]
    public void Map_and_MapFallback_handlers_take_request_data_and_the_body() => Expect("""
        var app = WebApplication.Create(args);
        app.Map("/o", (Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + order.Note + "'")); /*sink*/
        app.Map("/q", (string term, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE n = '" + term + "'")); /*sink*/
        app.MapFallback((Order order, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE m = '" + order.Note + "'")); /*sink*/
        app.MapFallback("/x/{**rest}", (string rest, SqlConnection c) => c.Query<User>("SELECT * FROM u WHERE r = '" + rest + "'")); /*sink*/
        app.Run();
        """ + Types);

    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));
}
