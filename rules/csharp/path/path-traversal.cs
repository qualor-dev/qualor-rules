// No `using System.IO;`: the qualified and the short names (File, Path, Directory) are tested
// apart (with the using, either pattern matches both).
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;

var app = WebApplication.Create(args);
const string Root = "/srv/files";

// Minimal APIs: route values and query strings in a file path.
app.MapGet("/files/{name}", (string name) =>
{
    // ruleid: csharp.path-traversal
    return Results.Text(File.ReadAllText(Path.Combine(Root, name)));
});

// ruleid: csharp.path-traversal
app.MapGet("/download", (string path) => Results.File(path, "application/octet-stream"));

// ruleid: csharp.path-traversal
app.MapGet("/raw", (string path) => Results.PhysicalFile(Path.Join(Root, path)));

// ruleid: csharp.path-traversal
app.MapGet("/typed", (string path) => TypedResults.PhysicalFile(Root + "/" + path));

app.MapPost("/notes/{name}", async (string name, HttpRequest request) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync();
    // ruleid: csharp.path-traversal
    await File.WriteAllTextAsync($"{Root}/notes/{name}.txt", body);
    // The text written is not a path.
    // ok: csharp.path-traversal
    await File.WriteAllTextAsync(Path.Combine(Root, "notes", "latest.txt"), body);
    return Results.Ok();
});

// Uploads: the client's file name, and the safe forms the documentation shows.
app.MapPost("/upload", async (IFormFile file) =>
{
    // ruleid: csharp.path-traversal
    using var stream = new FileStream(Path.Combine(Root, file.FileName), FileMode.Create);
    await file.CopyToAsync(stream);
    // ok: csharp.path-traversal
    using var safe = File.Create(Path.Combine(Root, Path.GetRandomFileName()));
    // ok: csharp.path-traversal
    using var named = new FileStream(Path.Combine(Root, Path.GetFileName(file.FileName)), FileMode.Create);
    var bare = Path.GetFileNameWithoutExtension(file.FileName);
    // ok: csharp.path-traversal
    File.Delete(Path.Combine(Root, bare + ".tmp"));
    // ok: csharp.path-traversal
    using var kept = File.Create(Path.Combine(Root, Guid.NewGuid() + Path.GetExtension(file.FileName)));
    // ok: csharp.path-traversal
    using var qualified = File.Create(Path.Combine(Root, System.IO.Path.GetFileName(file.FileName)));
    // ok: csharp.path-traversal
    using var stem = File.Create(Path.Combine(Root, System.IO.Path.GetFileNameWithoutExtension(file.FileName) + ".bin"));
    // ok: csharp.path-traversal
    using var ext = File.Create(Path.Combine(Root, "upload" + System.IO.Path.GetExtension(file.FileName)));
    return Results.Ok();
});

// The qualified names, calls written over several lines, and File and Directory methods that only
// test for existence.
app.MapPut("/qualified", (string dir, string name) =>
{
    // ruleid: csharp.path-traversal
    var files = System.IO.Directory.GetFiles(dir);
    // ruleid: csharp.path-traversal
    System.IO.Directory.Move("/srv/inbox", dir);
    // ruleid: csharp.path-traversal
    using var stream = new System.IO.FileStream(name, FileMode.Open);
    // ruleid: csharp.path-traversal
    var info = new System.IO.FileInfo(name);
    // ruleid: csharp.path-traversal
    var folder = new System.IO.DirectoryInfo(dir);
    File.Copy(
        "/srv/template.txt",
        // ruleid: csharp.path-traversal
        name);
    Directory.CreateDirectory(
        // ruleid: csharp.path-traversal
        dir);
    using var opened = new FileStream(
        // ruleid: csharp.path-traversal
        name,
        FileMode.Open);
    var sent = Results.PhysicalFile(
        // ruleid: csharp.path-traversal
        name,
        "text/plain");
    File.WriteAllText(
        // ruleid: csharp.path-traversal
        name,
        "text");
    // ok: csharp.path-traversal
    var exists = File.Exists(name);
    // ok: csharp.path-traversal
    var dirExists = Directory.Exists(dir);
    return Results.Ok();
});

app.MapDelete("/dirs", ([FromQuery] string dir, [FromHeader(Name = "X-Target")] string target) =>
{
    // ruleid: csharp.path-traversal
    Directory.Delete(Path.Combine(Root, dir), true);
    // ruleid: csharp.path-traversal
    Directory.Move(Path.Combine(Root, "inbox"), Path.Combine(Root, target));
    // ruleid: csharp.path-traversal
    File.Copy("/srv/template.txt", target);
    return Results.Ok();
});

// A lambda given to another API is not a request handler.
Retry.Run("cleanup", (string path) =>
{
    // ok: csharp.path-traversal
    File.Delete(path);
});

app.Run();

public record ExportRequest(string Folder, string Name);
public enum Kind { Text, Image }

[ApiController]
[Route("api/[controller]")]
public class FilesController : ControllerBase
{
    private const string Storage = "/var/app/storage";
    private static readonly Dictionary<string, string> Reports = new() { ["daily"] = "daily.csv", ["weekly"] = "weekly.csv" };

    private readonly IFileProvider _files;

    public FilesController(IFileProvider files) => _files = files;

    // Path.Combine drops the base when a later argument is rooted ("/etc/passwd").
    [HttpGet("read")]
    public IActionResult Read(string name)
    {
        var path = Path.Combine(Storage, name);
        // ruleid: csharp.path-traversal
        var text = System.IO.File.ReadAllText(path);
        // ruleid: csharp.path-traversal
        var bytes = System.IO.File.ReadAllBytes(Storage + "/" + name);
        // ruleid: csharp.path-traversal
        return PhysicalFile(path, "text/plain");
    }

    [HttpGet("open")]
    public async Task<IActionResult> Open([FromQuery] string file)
    {
        // ruleid: csharp.path-traversal
        using var reader = System.IO.File.OpenText(file);
        // ruleid: csharp.path-traversal
        var lines = await System.IO.File.ReadAllLinesAsync(file);
        // ruleid: csharp.path-traversal
        var info = new FileInfo(Path.Combine(Storage, file));
        // ruleid: csharp.path-traversal
        var folder = new DirectoryInfo(file);
        // ruleid: csharp.path-traversal
        var entries = Directory.GetFiles(Path.Combine(Storage, file));
        // ruleid: csharp.path-traversal
        foreach (var e in Directory.EnumerateFiles(file, "*.txt")) { }
        // ruleid: csharp.path-traversal
        Directory.CreateDirectory(Storage + "/" + file);
        // ruleid: csharp.path-traversal
        return this.PhysicalFile(file, "application/octet-stream");
    }

    [HttpPost("export")]
    public IActionResult Export([FromBody] ExportRequest request)
    {
        var target = Path.Combine(Storage, request.Folder, request.Name);
        // ruleid: csharp.path-traversal
        System.IO.File.AppendAllText(target, "exported");
        // ruleid: csharp.path-traversal
        System.IO.File.Move(Path.Combine(Storage, "tmp.csv"), target);
        // ruleid: csharp.path-traversal
        return new PhysicalFileResult(target, "text/csv");
    }

    // The request object.
    [HttpGet("by-header")]
    public IActionResult ByHeader()
    {
        var name = Request.Headers["X-File"].ToString();
        // ruleid: csharp.path-traversal
        var stream = new FileStream(Path.Combine(Storage, name), FileMode.Open, FileAccess.Read);
        // ruleid: csharp.path-traversal
        System.IO.File.Delete(Path.Combine(Storage, Request.Query["old"]!));
        // ruleid: csharp.path-traversal
        var cookie = System.IO.File.OpenRead(Path.Combine(Storage, HttpContext.Request.Cookies["last"]!));
        if (Request.RouteValues.TryGetValue("slug", out var slug))
        {
            // ruleid: csharp.path-traversal
            var found = System.IO.File.Exists(Path.Combine(Storage, slug!.ToString()!)) ? System.IO.File.ReadAllText(Path.Combine(Storage, slug.ToString()!)) : "";
        }
        return File(stream, "application/octet-stream");
    }

    // Checks: the full path inside the storage folder, a file name, a number, an allow-list.
    [HttpGet("checked")]
    public IActionResult Checked(string name, string id, string report, Kind kind)
    {
        var full = Path.GetFullPath(Path.Combine(Storage, name));
        if (!full.StartsWith(Storage + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        // ok: csharp.path-traversal
        var text = System.IO.File.ReadAllText(full);
        // ok: csharp.path-traversal
        var byId = System.IO.File.ReadAllText(Path.Combine(Storage, int.Parse(id) + ".txt"));
        // ok: csharp.path-traversal
        var listed = System.IO.File.ReadAllText(Path.Combine(Storage, Reports[report]));
        // ok: csharp.path-traversal
        var typed = System.IO.File.ReadAllText(Path.Combine(Storage, kind + ".txt"));
        // ok: csharp.path-traversal
        return PhysicalFile(Path.Combine(Storage, Path.GetFileName(name)), "text/plain");
    }

    [HttpGet("checked3")]
    public IActionResult Checked3(string a, string b, string c, string d)
    {
        string first;
        first = Path.GetFullPath(Path.Combine(Storage, a));
        if (!first.StartsWith(Storage)) return NotFound();
        // ok: csharp.path-traversal
        var one = System.IO.File.ReadAllText(first);
        var second = Path.GetFullPath(Path.Combine(Storage, b));
        if (!second.StartsWith(Storage))
        {
            throw new UnauthorizedAccessException();
        }
        // ok: csharp.path-traversal
        var two = System.IO.File.ReadAllText(second);
        var third = Path.GetFullPath(Path.Combine(Storage, c));
        if (!third.StartsWith(Storage))
        {
            _logger.LogWarning("Refused {Path}", third);
            return NotFound();
        }
        // ok: csharp.path-traversal
        var three = System.IO.File.ReadAllText(third);
        var fourth = Path.GetFullPath(Path.Combine(Storage, d));
        if (!fourth.StartsWith(Storage))
        {
            _logger.LogWarning("Refused {Path}", fourth);
            throw new UnauthorizedAccessException();
        }
        // ok: csharp.path-traversal
        return PhysicalFile(fourth, "text/plain");
    }

    [HttpGet("checked2")]
    public IActionResult Checked2(string name)
    {
        string resolved = Path.GetFullPath(Path.Combine(Storage, name));
        if (!resolved.StartsWith(Storage)) throw new UnauthorizedAccessException();
        // ok: csharp.path-traversal
        return PhysicalFile(resolved, "text/plain");
    }

    // Inside the guard the path is the one that failed the check.
    [HttpGet("rejected")]
    public IActionResult Rejected(string name)
    {
        var full = Path.GetFullPath(Path.Combine(Storage, name));
        if (!full.StartsWith(Storage))
        {
            // ruleid: csharp.path-traversal
            System.IO.File.AppendAllText(full, "rejected");
            return BadRequest();
        }
        return Ok();
    }

    // A check that does not leave the method, and a check without GetFullPath ("/srv/x/../.."
    // starts with "/srv/x").
    [HttpGet("unchecked")]
    public IActionResult Unchecked(string name, string other)
    {
        var full = Path.GetFullPath(Path.Combine(Storage, name));
        if (!full.StartsWith(Storage))
        {
            _ = Ok();
        }
        // ruleid: csharp.path-traversal
        var text = System.IO.File.ReadAllText(full);
        var joined = Path.Combine(Storage, other);
        if (!joined.StartsWith(Storage)) return BadRequest();
        // ruleid: csharp.path-traversal
        return PhysicalFile(joined, "text/plain");
    }

    // Look-alikes: a file provider (it refuses paths outside its root), a virtual file, other
    // classes' File and Delete methods, and a path that is only logged or compared.
    [HttpGet("lookalikes")]
    public IActionResult LookAlikes(string name)
    {
        // ok: csharp.path-traversal
        var fileInfo = _files.GetFileInfo(name);
        // ok: csharp.path-traversal
        var archive = _archive.Delete(name);
        // ok: csharp.path-traversal
        _logger.LogInformation("Reading {Path}", Path.Combine(Storage, name));
        // ok: csharp.path-traversal
        var same = string.Equals(Path.GetExtension(name), ".txt", StringComparison.OrdinalIgnoreCase);
        // ok: csharp.path-traversal
        return File(name, "text/plain");
    }

    // Known limits.
    [HttpGet("limits")]
    public IActionResult Limits(string name, string other)
    {
        // A StreamReader or StreamWriter given a path is not checked (its Stream overloads take
        // request bodies).
        // todoruleid: csharp.path-traversal
        using var reader = new StreamReader(Path.Combine(Storage, name));
        // A check written in the condition itself, on another variable, is not recognised.
        if (Path.GetFullPath(Path.Combine(Storage, other)).StartsWith(Storage))
        {
            // todook: csharp.path-traversal
            return PhysicalFile(Path.Combine(Storage, other), "text/plain");
        }
        return Ok();
    }

    // The result of a service given request data is taken for request data (Known limit): a
    // stored file found by an id, a file a processor of another class made.
    [HttpGet("stored/{id}")]
    public IActionResult Stored(string id)
    {
        var document = _store.Find(id);
        // todook: csharp.path-traversal
        return PhysicalFile(document.StoragePath, "application/pdf");
    }

    // Results.File with request bytes or a request stream is not a path (Known limit).
    [HttpPost("echo")]
    public IResult Echo()
    {
        // todook: csharp.path-traversal
        return Results.File(Request.Body, "application/octet-stream");
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried(string dir)
    {
        // todoruleid: csharp.path-traversal
        var a = System.IO.File.ReadAllText(PathOf(Request));
        // todoruleid: csharp.path-traversal
        var b = System.IO.File.ReadAllText(Section);
        // todoruleid: csharp.path-traversal
        var c = System.IO.File.ReadAllText(Channel);
        return Ok();
    }

    [HttpGet("prio")]
    public IActionResult Prio(Level level)
    {
        // todook: csharp.path-traversal
        return PhysicalFile(Path.Combine(Storage, level + ".txt"), "text/plain");
    }

    [HttpGet("guards")]
    public IActionResult Guards(string report, string other)
    {
        if (report != "daily" && report != "weekly")
        {
            return BadRequest();
        }
        // todook: csharp.path-traversal
        var a = System.IO.File.ReadAllText(Path.Combine(Storage, report));
        var chosen = Enumerable.Contains(Reports.Keys, other) ? other : "daily";
        // todook: csharp.path-traversal
        var b = System.IO.File.ReadAllText(Path.Combine(Storage, chosen));
        if (!Reports.ContainsKey(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.path-traversal
        return PhysicalFile(Path.Combine(Storage, other), "text/plain");
    }

    [NonAction]
    public string Load(string name)
    {
        // ok: csharp.path-traversal
        return System.IO.File.ReadAllText(Path.Combine(Storage, name));
    }

    private static string PathOf(HttpRequest request) => request.Query["path"].ToString();

    private string Section => Request.Headers["X-Section"].ToString();

    private string Channel
    {
        get { return Request.Query["channel"].ToString(); }
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class ExportEndpoints
{
    public static IEndpointRouteBuilder MapExportEndpoints(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/exports", (ExportRequest request) =>
        {
            // todoruleid: csharp.path-traversal
            File.WriteAllText(Path.Combine("/srv", request.Name), "x");
            return Results.Ok();
        });
        routes.MapGet("/exports/{name}", ReadExport);
        routes.MapGet("/exports/other", OtherHandlers.Read);
        return routes;
    }

    public static IResult ReadExport(string name)
    {
        // ruleid: csharp.path-traversal
        return Results.File(Path.Combine("/srv/exports", name));
    }
}

public static class OtherHandlers
{
    public static IResult Read(string name)
    {
        // todoruleid: csharp.path-traversal
        return Results.File(Path.Combine("/srv/exports", name));
    }
}

public abstract class AppBase : ControllerBase
{
}

public class ArchiveController : AppBase
{
    public IActionResult Get(string name)
    {
        // todoruleid: csharp.path-traversal
        return PhysicalFile(Path.Combine("/srv/archive", name), "application/zip");
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class DocumentModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string Document { get; set; } = "";

    public string Content { get; private set; } = "";

    public void OnGet()
    {
        // ruleid: csharp.path-traversal
        Content = System.IO.File.ReadAllText(Path.Combine("/srv/docs", Document));
    }

    public IActionResult OnGetDownload(string name)
    {
        // ruleid: csharp.path-traversal
        return PhysicalFile(Path.Combine("/srv/docs", name), "application/pdf");
    }
}

// A plain service: its parameters are not request data.
public class ReportStore
{
    public string Load(string name)
    {
        // ok: csharp.path-traversal
        return File.ReadAllText(Path.Combine("/srv/reports", name));
    }
}

public enum Level { Low, High }
