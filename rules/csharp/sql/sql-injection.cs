using System.Text;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using MySqlConnector;
using Npgsql;

var app = WebApplication.Create(args);

// Minimal APIs: string-like handler parameters are bound from the route or the query string.
app.MapGet("/users", (string name, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.Query<User>($"SELECT * FROM users WHERE name = '{name}'");
});

// An expression-bodied handler.
// ruleid: csharp.sql-injection
app.MapGet("/users/search", (string q, SqlConnection conn) => conn.Query<User>("SELECT * FROM users WHERE name LIKE '%" + q + "%'"));

app.MapGet("/users/by-id", (int id, SqlConnection conn) =>
{
    // ok: csharp.sql-injection
    return conn.Query<User>($"SELECT * FROM users WHERE id = {id}");
});

app.MapGet("/orders", (string status, ShopContext db) =>
{
    // ok: csharp.sql-injection
    return db.Orders.FromSql($"SELECT * FROM orders WHERE status = {status}").ToList();
});

// A DI service parameter is not request data.
app.MapGet("/report", (ReportQuery query, ReportService svc) =>
{
    // ok: csharp.sql-injection
    return svc.Run(query.ToString());
});

// Async handlers, nullable strings and StringValues.
app.MapPost("/users/tags", async (string? owner, StringValues tags, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    await conn.ExecuteAsync("UPDATE users SET tags = '" + tags.ToString() + "' WHERE owner = @owner", new { owner });
    // ok: csharp.sql-injection
    return await conn.ExecuteAsync("UPDATE users SET seen = 1 WHERE owner = @owner", new { owner });
});

// ruleid: csharp.sql-injection
app.MapDelete("/users/{login}", async (string login, SqlConnection conn) => await conn.ExecuteAsync("DELETE FROM users WHERE login = '" + login + "'"));

app.MapPut("/users/batch", (string[] logins, SqlConnection conn) =>
{
    var list = string.Join("','", logins);
    // ruleid: csharp.sql-injection
    return conn.Execute("UPDATE users SET active = 1 WHERE login IN ('" + list + "')");
});

// Form collections and uploaded files.
app.MapPatch("/notes", (IFormCollection form, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.Execute("UPDATE notes SET body = '" + form["body"] + "'");
});

app.MapPost("/uploads", (IFormFile file, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.Execute("INSERT INTO uploads (name) VALUES ('" + file.FileName + "')");
});

// Parameters bound with an attribute: a header, a JSON body, an [AsParameters] type.
app.MapMethods("/tenants", new[] { "PUT" }, ([FromHeader(Name = "X-Tenant")] string tenant, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.Execute("UPDATE tenants SET seen = 1 WHERE code = '" + tenant + "'");
});

app.MapPost("/orders/filter", ([FromBody] OrderFilter filter, ShopContext db) =>
{
    // ruleid: csharp.sql-injection
    return db.Orders.FromSqlRaw("SELECT * FROM orders WHERE status = '" + filter.Status + "'").ToList();
});

// ruleid: csharp.sql-injection
app.MapPut("/orders/status", ([FromBody] OrderFilter filter, ShopContext db) => db.Database.ExecuteSqlRaw("UPDATE orders SET status = '" + filter.Status + "'"));

app.MapGet("/orders/page", ([AsParameters] OrderPage page, ShopContext db) =>
{
    // ruleid: csharp.sql-injection
    return db.Orders.FromSqlRaw("SELECT * FROM orders ORDER BY " + page.Sort).ToList();
});

// The request object itself.
app.MapGet("/lookup", (HttpRequest request, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.QueryFirstOrDefault<User>("SELECT * FROM users WHERE name = '" + request.Query["name"] + "'");
});

app.MapGet("/audit", (HttpContext context, SqlConnection conn) =>
{
    // ruleid: csharp.sql-injection
    return conn.Execute("INSERT INTO audit (agent) VALUES ('" + context.Request.Headers["User-Agent"] + "')");
});

app.MapPost("/orders/flag", async (HttpRequest request, ShopContext db) =>
{
    var filter = await request.ReadFromJsonAsync<OrderFilter>();
    // ruleid: csharp.sql-injection
    return await db.Database.ExecuteSqlRawAsync("UPDATE orders SET flagged = 1 WHERE status = '" + filter!.Status + "'");
});

app.MapPost("/raw", async (Stream body, SqlConnection conn) =>
{
    var text = await new StreamReader(body).ReadToEndAsync();
    // ruleid: csharp.sql-injection
    return conn.Execute(text);
});

// A complex type bound implicitly from the JSON body cannot be told from a DI service without
// types: not a source (Known limit).
app.MapPost("/users", (NewUser user, SqlConnection conn) =>
{
    // todoruleid: csharp.sql-injection
    return conn.Execute("INSERT INTO users (name) VALUES ('" + user.Name + "')");
});

// A lambda given to another API is not a request handler.
Retry.Run("cleanup", (string table) =>
{
    // ok: csharp.sql-injection
    return new SqlCommand("DELETE FROM " + table + " WHERE expired = 1").ExecuteNonQuery();
});

// Handlers given as method groups.
app.MapGet("/tags/{tag}", FindByTag).WithName("FindByTag");

// A handler declared in another class is not followed (Known limit).
app.MapGet("/audit/recent", AuditHandlers.Recent);

app.Run();

static IEnumerable<User> FindByTag(string tag, SqlConnection conn)
{
    // ruleid: csharp.sql-injection
    return conn.Query<User>("SELECT * FROM users WHERE tag = '" + tag + "'");
}

// A local function that no route uses.
static int CountRows(string table, SqlConnection conn)
{
    // ok: csharp.sql-injection
    return conn.ExecuteScalar<int>("SELECT COUNT(*) FROM " + table);
}

public record User(int Id, string Name);
public record Order(int Id, string Status);
public record ReportQuery(string Year);
public record NewUser(string Name);
public record OrderFilter(string Status);
public record OrderPage(string Sort, int Index);
public record TenantInfo(string Schema);
public enum SortOrder { Name, Date }

public interface ISchemaProvider
{
    string Name { get; }
}

public class ShopContext : DbContext
{
    public DbSet<Order> Orders => Set<Order>();
}

public static class UserEndpoints
{
    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/users");
        group.MapGet("/by-email", ByEmail)
            .WithName("ByEmail");
        group.MapPost("/import", Import);
        return routes;
    }

    public static IResult ByEmail(string email, SqlConnection conn)
    {
        // ruleid: csharp.sql-injection
        var user = conn.QuerySingle<User>("SELECT * FROM users WHERE email = '" + email + "'");
        return Results.Ok(user);
    }

    public static IResult Import([FromBody] NewUser user, SqlConnection conn)
    {
        // ruleid: csharp.sql-injection
        conn.Execute("INSERT INTO users (name) VALUES ('" + user.Name + "')");
        return Results.Ok();
    }

    public static string Normalize(string input, SqlConnection conn)
    {
        // ok: csharp.sql-injection
        return conn.ExecuteScalar<string>("SELECT lower('" + input + "')");
    }
}

public static class AuditHandlers
{
    public static IResult Recent(string user, SqlConnection conn)
    {
        // todoruleid: csharp.sql-injection
        var rows = conn.Query("SELECT * FROM audit WHERE login = '" + user + "'");
        return Results.Ok(rows);
    }
}

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    private static readonly Dictionary<string, string> SortColumns = new()
    {
        ["name"] = "name",
        ["price"] = "unit_price",
    };

    private static readonly Dictionary<string, string> Filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        { "cheap", "unit_price < 10" },
        { "new", "created > now() - interval '7 days'" }
    };

    private static readonly Dictionary<string, string> Aliases = new() { ["p"] = "products" };

    private static readonly Dictionary<string, string> Views = new() { ["all"] = "products" };

    private static readonly Dictionary<string, string> Schemas = new() { ["main"] = "dbo" };

    private static readonly Dictionary<string, string> Columns = new() { ["custom"] = Environment.GetEnvironmentVariable("SORT_COLUMN") ?? "name" };

    private readonly SqlConnection _conn;
    private readonly ShopContext _db;
    private readonly NpgsqlDataSource _dataSource;
    private readonly SavedReports _reports = new();

    public ProductsController(SqlConnection conn, ShopContext db, NpgsqlDataSource dataSource)
    {
        _conn = conn;
        _db = db;
        _dataSource = dataSource;
    }

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q)
    {
        // ruleid: csharp.sql-injection
        var cmd = new SqlCommand("SELECT * FROM products WHERE name = '" + q + "'", _conn);
        var safe = new SqlCommand("SELECT * FROM products WHERE name = @name", _conn);
        safe.Parameters.AddWithValue("@name", q);
        // ok: csharp.sql-injection
        safe.ExecuteReader();
        return Ok();
    }

    [HttpGet("{id}")]
    public IActionResult Get(int id, Guid tenant, long? page)
    {
        // ok: csharp.sql-injection
        var cmd = new SqlCommand($"SELECT * FROM products WHERE id = {id} AND tenant = '{tenant}' OFFSET {page}", _conn);
        return Ok();
    }

    [HttpGet("many")]
    public IActionResult Many([FromQuery] int[] ids, [FromQuery] List<long> shops)
    {
        // ok: csharp.sql-injection
        var rows = _conn.Query<User>("SELECT * FROM products WHERE id IN (" + string.Join(",", ids) + ") AND shop IN (" + string.Join(",", shops) + ")");
        return Ok(rows);
    }

    [HttpGet("by-name")]
    public IActionResult ByName(string name)
    {
        // ruleid: csharp.sql-injection
        var rows = _db.Orders.FromSqlRaw($"SELECT * FROM orders WHERE name = '{name}'").ToList();
        // ok: csharp.sql-injection
        var rows2 = _db.Orders.FromSqlInterpolated($"SELECT * FROM orders WHERE name = {name}").ToList();
        // ok: csharp.sql-injection
        var rows3 = _db.Orders.FromSqlRaw("SELECT * FROM orders WHERE name = {0}", name).ToList();
        return Ok(rows);
    }

    [HttpGet("sorted")]
    public IActionResult Sorted()
    {
        var sort = Request.Query["sort"].ToString();
        // ruleid: csharp.sql-injection
        var rows = _conn.Query<User>("SELECT * FROM users ORDER BY " + sort);
        var cmd = _conn.CreateCommand();
        // ruleid: csharp.sql-injection
        cmd.CommandText = "DELETE FROM users WHERE name = '" + HttpContext.Request.Query["n"] + "'";
        return Ok(rows);
    }

    [HttpGet("by-region")]
    public IActionResult ByRegion([FromHeader(Name = "X-Region")] string region)
    {
        // ruleid: csharp.sql-injection
        using var cmd = new NpgsqlCommand($"SELECT * FROM products WHERE region = '{region}'");
        return Ok();
    }

    [HttpGet("themed")]
    public IActionResult Themed()
    {
        var theme = Request.Cookies["theme"];
        // ruleid: csharp.sql-injection
        using var cmd = new SqliteCommand("SELECT * FROM themes WHERE name = '" + theme + "'");
        return Ok();
    }

    [HttpPost("note")]
    public IActionResult Note()
    {
        // ruleid: csharp.sql-injection
        using var cmd = new MySqlCommand("INSERT INTO notes (body) VALUES ('" + Request.Form["body"] + "')");
        return Ok();
    }

    [HttpGet("{slug}/export")]
    public IActionResult Export()
    {
        var slug = Request.RouteValues["slug"]?.ToString();
        // ruleid: csharp.sql-injection
        var adapter = new SqlDataAdapter("SELECT * FROM products WHERE slug = '" + slug + "'", _conn);
        return Ok();
    }

    [HttpGet("trace")]
    public IActionResult Trace()
    {
        // ruleid: csharp.sql-injection
        using var cmd = new SqlCommand { CommandText = "INSERT INTO hits (path) VALUES ('" + Request.Path + "')", Connection = _conn };
        // ruleid: csharp.sql-injection
        using var cmd2 = _dataSource.CreateCommand("INSERT INTO hits (query) VALUES ('" + Request.QueryString + "')");
        var batch = new NpgsqlBatch();
        // ruleid: csharp.sql-injection
        batch.BatchCommands.Add(new NpgsqlBatchCommand("INSERT INTO hits (base) VALUES ('" + this.Request.PathBase + "')"));
        // ruleid: csharp.sql-injection
        using var cmd3 = new SqlCommand("INSERT INTO hits (agent) VALUES ('" + Request.Headers.UserAgent + "')");
        // ok: csharp.sql-injection
        using var cmd4 = new SqlCommand("INSERT INTO hits (scheme, json) VALUES ('" + Request.Scheme + "', '" + Request.HasJsonContentType() + "')");
        return Ok();
    }

    [HttpPost("import")]
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var script = await reader.ReadToEndAsync();
        // ruleid: csharp.sql-injection
        await _db.Database.ExecuteSqlRawAsync(script);
        var filter = await Request.ReadFromJsonAsync<OrderFilter>();
        // ruleid: csharp.sql-injection
        _db.Database.ExecuteSqlRaw("UPDATE orders SET flagged = 1 WHERE status = '" + filter!.Status + "'");
        var form = await HttpContext.Request.ReadFormAsync();
        // ruleid: csharp.sql-injection
        var ids = _db.Database.SqlQueryRaw<int>("SELECT id FROM orders WHERE note = '" + form["note"] + "'").ToList();
        var more = await Request.ReadFormAsync();
        // ruleid: csharp.sql-injection
        _db.Database.ExecuteSqlRaw("UPDATE orders SET note = '" + more["extra"] + "'");
        var result = await Request.BodyReader.ReadAsync();
        var chunk = Encoding.UTF8.GetString(result.Buffer.FirstSpan);
        // ruleid: csharp.sql-injection
        _db.Database.ExecuteSqlRaw(chunk);
        // ok: csharp.sql-injection
        _db.Database.ExecuteSql($"UPDATE orders SET flagged = 1 WHERE status = {filter.Status}");
        // ok: csharp.sql-injection
        _db.Database.ExecuteSqlInterpolated($"UPDATE orders SET note = {form["note"]}");
        // ok: csharp.sql-injection
        var ids2 = _db.Database.SqlQuery<int>($"SELECT id FROM orders WHERE note = {script}").ToList();
        return Ok(ids);
    }

    // Older EF Core: FromSql and ExecuteSqlCommand with a plain string run it as it is; with an
    // interpolated string they make parameters.
    [HttpGet("legacy")]
    public async Task<IActionResult> Legacy(string status)
    {
        // ruleid: csharp.sql-injection
        var rows = _db.Orders.FromSql("SELECT * FROM orders WHERE status = '" + status + "'").ToList();
        // ruleid: csharp.sql-injection
        _db.Database.ExecuteSqlCommand("DELETE FROM orders WHERE status = '" + status + "'");
        // ruleid: csharp.sql-injection
        await _db.Database.ExecuteSqlCommandAsync("UPDATE orders SET seen = 1 WHERE status = '" + status + "'");
        // ok: csharp.sql-injection
        _db.Database.ExecuteSqlCommand($"DELETE FROM orders WHERE status = {status}");
        // A FormattableString variable is also made into parameters (Known limit).
        FormattableString query = $"SELECT * FROM orders WHERE status = {status}";
        // todook: csharp.sql-injection
        var rows2 = _db.Orders.FromSql(query).ToList();
        return Ok(rows);
    }

    [HttpGet("dapper")]
    public async Task<IActionResult> DapperForms(string name)
    {
        // ruleid: csharp.sql-injection
        var all = _conn.Query("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: csharp.sql-injection
        var some = await _conn.QueryAsync<User>("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: csharp.sql-injection
        var count = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM users WHERE name = '" + name + "'");
        // ruleid: csharp.sql-injection
        using var grid = _conn.QueryMultiple("SELECT * FROM users WHERE name = '" + name + "'; SELECT 1");
        // ruleid: csharp.sql-injection
        var def = new CommandDefinition("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: csharp.sql-injection
        var bound = await _conn.QueryAsync<User>("SELECT * FROM users WHERE name = @name", new { name });
        // ok: csharp.sql-injection
        var fixedRows = _conn.Query<User>("SELECT * FROM users");
        // Another library's method of the same name in a file that imports Dapper (Known limit).
        // todook: csharp.sql-injection
        var answer = await _graph.ExecuteAsync(name);
        return Ok(all);
    }

    // Conversions to numbers, dates and enums.
    [HttpGet("converted")]
    public IActionResult Converted(string a, string b, string c, string d, string e, string f, string g, string h)
    {
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE id = " + int.Parse(a));
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE id = " + long.Parse(b));
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE token = '" + Guid.Parse(c) + "'");
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE created < '" + DateTime.Parse(d).ToString("o") + "'");
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE id = " + Convert.ToInt32(e));
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE id = " + Convert.ToInt64(f));
        // ok: csharp.sql-injection
        _conn.Execute("SELECT * FROM carts ORDER BY " + Enum.Parse<SortOrder>(g));
        // ok: csharp.sql-injection
        _conn.Execute("SELECT * FROM carts ORDER BY " + Enum.Parse(typeof(SortOrder), h));
        if (int.TryParse(a, out var n))
        {
            // ok: csharp.sql-injection
            _conn.Execute("DELETE FROM carts WHERE id = " + n);
        }
        return Ok();
    }

    // An enum parameter cannot carry SQL, but enums are not told apart from classes (Known limit).
    [HttpGet("ordered")]
    public IActionResult Ordered(SortOrder order)
    {
        // todook: csharp.sql-injection
        var rows = _conn.Query<User>("SELECT * FROM users ORDER BY " + order);
        return Ok(rows);
    }

    // Allow-lists: a lookup in a table of literals that nothing changes.
    [HttpGet("listed")]
    public IActionResult Listed(string sort, string filter, string alias, string view)
    {
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY " + SortColumns[sort]);
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY " + SortColumns.GetValueOrDefault(sort, "name"));
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products WHERE " + Filters.GetValueOrDefault(filter));
        if (SortColumns.TryGetValue(sort, out var column))
        {
            // ok: csharp.sql-injection
            _conn.Query<User>("SELECT * FROM products ORDER BY " + column);
        }
        var direction = sort == "desc" ? "DESC" : "ASC";
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY name " + direction);
        var col = sort switch { "price" => "unit_price", _ => "name" };
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY " + col);
        // ruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY " + SortColumns.GetValueOrDefault(sort, sort));
        // ruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM products ORDER BY " + Columns[sort]);
        // ruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + Aliases[alias]);
        // ruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + Views[view]);
        // ruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + Schemas[view] + ".products");
        // OpenGrep takes GetValueOrDefault(key) for a read of the dictionary, not of the key
        // (Known limit): a table that request data changes is missed there.
        // todoruleid: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + Schemas.GetValueOrDefault(view) + ".products");
        return Ok();
    }

    [HttpPost("alias")]
    public IActionResult AddAlias(string key, string table)
    {
        Aliases[key] = table;
        Views.Add(key, table);
        Schemas.TryAdd(key, table);
        return Ok();
    }

    // SQL text assembled with a StringBuilder.
    [HttpGet("built")]
    public IActionResult Built(string term)
    {
        var sb = new StringBuilder("SELECT * FROM products WHERE 1 = 1");
        sb.Append(" AND name = '").Append(term).Append("'");
        // ruleid: csharp.sql-injection
        _conn.Query<User>(sb.ToString());
        var sb2 = new StringBuilder();
        sb2.Append("SELECT * FROM products WHERE name = '" + term + "'");
        // ruleid: csharp.sql-injection
        _conn.Query<User>(sb2.ToString());
        var sb3 = new StringBuilder();
        sb3.AppendLine("SELECT * FROM products");
        sb3.AppendLine("WHERE name = '" + term + "'");
        // ruleid: csharp.sql-injection
        _conn.Query<User>(sb3.ToString());
        var sb4 = new StringBuilder();
        sb4.AppendFormat("SELECT * FROM products WHERE name = '{0}'", term);
        // ruleid: csharp.sql-injection
        _conn.Query<User>(sb4.ToString());
        var sb5 = new StringBuilder(" ORDER BY name");
        sb5.Insert(0, "SELECT * FROM products WHERE name = '" + term + "'");
        // ruleid: csharp.sql-injection
        _conn.Query<User>(sb5.ToString());
        var sb6 = new StringBuilder();
        sb6.Append("SELECT * FROM products WHERE name = @name");
        // ok: csharp.sql-injection
        _conn.Query<User>(sb6.ToString(), new { name = term });
        return Ok();
    }

    [HttpGet("tried")]
    public IActionResult Tried()
    {
        var request = HttpContext.Request;
        // ruleid: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE coupon = '" + request.Query["coupon"] + "'");
        var current = Request;
        // ruleid: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE region = '" + current.Headers["X-Region"] + "'");
        if (Request.Query.TryGetValue("owner", out var owner))
        {
            // ruleid: csharp.sql-injection
            _conn.Execute("DELETE FROM carts WHERE owner = '" + owner + "'");
        }
        // A query stored by the application, not read from the request.
        var saved = _reports.Find("weekly");
        // ok: csharp.sql-injection
        _conn.Query<User>(saved.Query);
        // A request value read in a helper of this file.
        // ruleid: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE term = '" + TermOf(Request) + "'");
        // OpenGrep does not carry taint out of an expression-bodied helper (Known limit).
        // todoruleid: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE tag = '" + TagOf(Request) + "'");
        // ok: csharp.sql-injection
        _conn.Execute("DELETE FROM carts WHERE id = " + CountFor("carts"));
        return Ok();
    }

    // Services and other parameters that are not bound from the request.
    [HttpGet("tenant")]
    public IActionResult ForTenant([FromServices] TenantInfo tenant, [FromKeyedServices("archive")] TenantInfo archive, ISchemaProvider schema)
    {
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + tenant.Schema + ".orders");
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + archive.Schema + ".orders");
        // ok: csharp.sql-injection
        _conn.Query<User>("SELECT * FROM " + schema.Name + ".orders");
        return Ok();
    }

    [NonAction]
    public int Purge(string table)
    {
        // ok: csharp.sql-injection
        return _conn.Execute("DELETE FROM " + table);
    }

    private static string TermOf(HttpRequest request)
    {
        return request.Query["term"].ToString();
    }

    private static string TagOf(HttpRequest request) => request.Query["tag"].ToString();

    private int CountFor(string table)
    {
        // ok: csharp.sql-injection
        return _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM " + table);
    }
}

// A controller found by its base class, and a controller found by its name.
public abstract class BaseApiController : ControllerBase
{
}

public class Inventory : BaseApiController
{
    private readonly SqlConnection _conn;

    public Inventory(SqlConnection conn) => _conn = conn;

    public IActionResult Find(string sku)
    {
        // ruleid: csharp.sql-injection
        return Ok(_conn.Query<User>("SELECT * FROM stock WHERE sku = '" + sku + "'"));
    }
}

public class StatusController
{
    private readonly SqlConnection _conn;

    public StatusController(SqlConnection conn) => _conn = conn;

    public int Ping(string node) => _conn.Execute(
        // ruleid: csharp.sql-injection
        "UPDATE nodes SET seen = 1 WHERE name = '" + node + "'");
}

// A controller marked only with [Controller] is not recognised (Known limit).
[Controller]
public class Health
{
    private readonly SqlConnection _conn;

    public Health(SqlConnection conn) => _conn = conn;

    public int Check(string probe)
    {
        // todoruleid: csharp.sql-injection
        return _conn.Execute("UPDATE probes SET seen = 1 WHERE name = '" + probe + "'");
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class SearchModel : PageModel
{
    private readonly SqlConnection _conn;

    public SearchModel(SqlConnection conn) => _conn = conn;

    [BindProperty]
    public string Term { get; set; } = "";

    [BindProperty(SupportsGet = true)]
    public string? Category { get; set; }

    [BindProperty]
    public int PageIndex { get; set; }

    public string Message { get; set; } = "";

    public void OnPost()
    {
        // ruleid: csharp.sql-injection
        _conn.Execute("UPDATE stats SET last = '" + Term + "'");
        // ruleid: csharp.sql-injection
        _conn.Execute("UPDATE stats SET category = '" + this.Category + "'");
        // ok: csharp.sql-injection
        _conn.Execute("UPDATE stats SET page = " + PageIndex);
        // ok: csharp.sql-injection
        _conn.Execute("UPDATE stats SET message = '" + Message + "'");
    }

    public async Task OnGetAsync(string sort, int page)
    {
        // ruleid: csharp.sql-injection
        await _conn.QueryAsync<User>("SELECT * FROM products ORDER BY " + sort);
        // ok: csharp.sql-injection
        await _conn.QueryAsync<User>("SELECT * FROM products OFFSET " + page);
    }

    public void OnPostArchive([FromServices] TenantInfo tenant)
    {
        // ok: csharp.sql-injection
        _conn.Execute("INSERT INTO " + tenant.Schema + ".archive SELECT * FROM stats");
    }

    public string Describe(string text)
    {
        // ok: csharp.sql-injection
        return _conn.ExecuteScalar<string>("SELECT describe('" + text + "')");
    }
}

// A page model with its own base class.
public abstract class BasePageModel : PageModel
{
}

public class ArchiveModel : BasePageModel
{
    private readonly SqlConnection _conn;

    public ArchiveModel(SqlConnection conn) => _conn = conn;

    public IActionResult OnGet(string year)
    {
        // ruleid: csharp.sql-injection
        var rows = _conn.Query<User>("SELECT * FROM archive WHERE year = '" + year + "'");
        return Page();
    }
}

[BindProperties]
public class EditModel : PageModel
{
    private readonly SqlConnection _conn;

    public EditModel(SqlConnection conn) => _conn = conn;

    public string Title { get; set; } = "";

    public string? Slug { get; set; }

    public void OnPost()
    {
        // ruleid: csharp.sql-injection
        _conn.Execute("UPDATE pages SET title = '" + Title + "'");
        // ruleid: csharp.sql-injection
        _conn.Execute("UPDATE pages SET slug = '" + Slug + "'");
    }
}

// A method named like a page handler in a class that is not a PageModel.
public class ImportJob
{
    private readonly SqlConnection _conn;

    public ImportJob(SqlConnection conn) => _conn = conn;

    public void OnPostProcess(string batch)
    {
        // ok: csharp.sql-injection
        _conn.Execute("UPDATE batches SET done = 1 WHERE name = '" + batch + "'");
    }
}

// A method named like a page handler in a class whose base class is not a page model.
public class MetricsListener : ListenerBase
{
    private readonly SqlConnection _conn;

    public MetricsListener(SqlConnection conn) => _conn = conn;

    public void OnGetSnapshot(string label)
    {
        // ok: csharp.sql-injection
        _conn.Execute("INSERT INTO snapshots (label) VALUES ('" + label + "')");
    }
}

// A plain service: its parameters are not request data.
public class ReportService
{
    private readonly SqlConnection _conn;

    public ReportService(SqlConnection conn) => _conn = conn;

    public int Run(string year)
    {
        // ok: csharp.sql-injection
        return _conn.Execute("INSERT INTO runs VALUES ('" + year + "')");
    }
}
