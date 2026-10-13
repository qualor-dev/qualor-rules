// No `using System.Diagnostics;`: the qualified and the short names of Process.Start are
// tested apart (with the using, either pattern matches both).
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Primitives;

var app = WebApplication.Create(args);

// Minimal APIs: the program itself chosen by the request.
app.MapGet("/tools/run", (string tool) =>
{
    // ruleid: csharp.command-injection
    Process.Start(tool);
    return Results.Ok();
});

// ruleid: csharp.command-injection
app.MapGet("/tools/open", (string path) => Process.Start(path, "--readonly"));

// Request data in the command line of a shell.
app.MapGet("/ping", (string host) =>
{
    // ruleid: csharp.command-injection
    Process.Start("cmd.exe", "/c ping -n 1 " + host);
    // ruleid: csharp.command-injection
    Process.Start("/bin/sh", $"-c \"ping -c 1 {host}\"");
    // ruleid: csharp.command-injection
    System.Diagnostics.Process.Start("bash", string.Format("-lc \"nslookup {0}\"", host));
    // A fixed program given arguments: argument injection (CWE-88) is out of scope (Known limit).
    // ok: csharp.command-injection
    Process.Start("ping", "-c 1 " + host);
    // A shell running a fixed script: the request data is an argument of the script.
    // ok: csharp.command-injection
    Process.Start("bash", "/opt/tools/check.sh " + host);
    return Results.Ok();
});

app.MapPost("/scripts", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    // ruleid: csharp.command-injection
    Process.Start("powershell.exe", "-NoProfile -Command " + form["script"]);
    // ruleid: csharp.command-injection
    Process.Start(@"C:\Program Files\PowerShell\7\pwsh.exe", "-c \"Get-Item " + form["item"] + "\"");
    // ruleid: csharp.command-injection
    Process.Start("pwsh", "-EncodedCommand " + form["encoded"]);
    // PowerShell's -File runs a script file; the later arguments are its parameters.
    // ok: csharp.command-injection
    Process.Start("pwsh", "-NoProfile -File ./report.ps1 -Name " + form["name"]);
    return Results.Ok();
});

// A command line held in a variable before it reaches the shell.
app.MapGet("/files/type", (string name) =>
{
    var line = "/c type " + name;
    // ruleid: csharp.command-injection
    Process.Start("cmd.exe", line);
    return Results.Ok();
});

// Argument vectors: only the script of a POSIX shell (after -c) is shell code; for cmd /c and
// PowerShell -Command every later element is.
app.MapGet("/lookup", ([FromQuery] string domain) =>
{
    // ruleid: csharp.command-injection
    Process.Start("/bin/bash", new[] { "-c", "dig " + domain });
    // ruleid: csharp.command-injection
    Process.Start("cmd", new List<string> { "/c", "nslookup", domain });
    // ruleid: csharp.command-injection
    Process.Start("pwsh", new string[] { "-NoProfile", "-Command", "Resolve-DnsName", domain });
    // The value after the script is a positional parameter ($0), not shell code.
    // ok: csharp.command-injection
    Process.Start("/bin/sh", new[] { "-c", "dig \"$0\"", domain });
    // A fixed non-shell program with an argument vector.
    // ok: csharp.command-injection
    Process.Start("dig", new[] { "+short", domain });
    // ok: csharp.command-injection
    Process.Start("git", new List<string> { "log", "--author", domain });
    return Results.Ok();
});

// A lambda given to another API is not a request handler.
Retry.Run("cleanup", (string script) =>
{
    // ok: csharp.command-injection
    Process.Start("/bin/sh", "-c " + script);
});

app.Run();

public record Job(string Command, string Name);
public record Archive(string Folder);
public enum Shell { Bash, Pwsh }

[ApiController]
[Route("api/[controller]")]
public class ToolsController : ControllerBase
{
    private static readonly HashSet<string> Commands = new() { "uptime", "df -h" };

    private readonly JobScheduler _jobs;

    public ToolsController(JobScheduler jobs) => _jobs = jobs;

    // ProcessStartInfo: the program, and the command line of a shell.
    [HttpPost("start")]
    public IActionResult Start([FromBody] Job job)
    {
        // ruleid: csharp.command-injection
        var info = new ProcessStartInfo(job.Name);
        // ruleid: csharp.command-injection
        var info2 = new ProcessStartInfo("/bin/sh", "-c '" + job.Command + "'");
        var info3 = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            // ruleid: csharp.command-injection
            Arguments = "/c " + job.Command,
            UseShellExecute = false,
        };
        var info4 = new ProcessStartInfo()
        {
            // ruleid: csharp.command-injection
            Arguments = $"-c \"{job.Command}\"",
            RedirectStandardOutput = true,
            FileName = "/usr/bin/bash",
        };
        var info5 = new ProcessStartInfo
        {
            // ruleid: csharp.command-injection
            FileName = job.Name,
            UseShellExecute = true,
        };
        var info6 = new ProcessStartInfo
        {
            FileName = "/usr/bin/git",
            // ok: csharp.command-injection
            Arguments = "log --grep " + job.Command,
        };
        return Ok();
    }

    [HttpPost("run")]
    public IActionResult Run(string command, string program)
    {
        var psi = new ProcessStartInfo();
        // ruleid: csharp.command-injection
        psi.FileName = program;
        var shell = new ProcessStartInfo();
        shell.FileName = "/bin/bash";
        // ruleid: csharp.command-injection
        shell.Arguments = "-c \"" + command + "\"";
        // ok: csharp.command-injection
        Process.Start(shell);
        using var process = new Process();
        process.StartInfo.FileName = "cmd.exe";
        // ruleid: csharp.command-injection
        process.StartInfo.Arguments = "/C " + command;
        var later = new Process();
        // ruleid: csharp.command-injection
        later.StartInfo.Arguments = "/k " + command;
        later.StartInfo.FileName = "cmd";
        var proc = new Process();
        // ruleid: csharp.command-injection
        proc.StartInfo.FileName = program;
        ProcessStartInfo typed = new ProcessStartInfo();
        // ruleid: csharp.command-injection
        typed.FileName = program;
        // ruleid: csharp.command-injection
        var started = new ProcessStartInfo(program, "--help");
        // ok: csharp.command-injection
        Process.Start(started);
        // ruleid: csharp.command-injection
        Process.Start("C:\\Windows\\System32\\cmd.exe", new[] { "/c", "type", command });
        var assigned = new Process { StartInfo = new ProcessStartInfo("/bin/true") };
        // ok: csharp.command-injection
        assigned.Start();
        var git = new ProcessStartInfo("git");
        // ok: csharp.command-injection
        git.Arguments = "show " + command;
        // A ProcessStartInfo given to Process.Start is checked where its parts are set.
        // ok: csharp.command-injection
        Process.Start(typed);
        // ok: csharp.command-injection
        Process.Start(git);
        // ok: csharp.command-injection
        Process.Start(new ProcessStartInfo("git") { Arguments = "log " + command });
        var gitProcess = new Process();
        gitProcess.StartInfo.FileName = "git";
        gitProcess.StartInfo.Arguments = "log " + command;
        // ok: csharp.command-injection
        Process.Start(gitProcess.StartInfo);
        Launch(new ProcessStartInfo("git") { Arguments = "log " + command });
        // Shells created by a constructor or an initializer, then given Arguments.
        var bourne = new ProcessStartInfo("/bin/sh");
        // ruleid: csharp.command-injection
        bourne.Arguments = "-c \"" + command + "\"";
        var windowsShell = new ProcessStartInfo { FileName = "cmd.exe", CreateNoWindow = true };
        // ruleid: csharp.command-injection
        windowsShell.Arguments = "/c " + command;
        ProcessStartInfo field;
        field = new ProcessStartInfo("bash");
        // ruleid: csharp.command-injection
        field.Arguments = "-c \"" + command + "\"";
        ProcessStartInfo other;
        other = new ProcessStartInfo();
        // ruleid: csharp.command-injection
        other.FileName = program;
        return Ok();
    }

    private static void Launch(ProcessStartInfo info)
    {
        // ok: csharp.command-injection
        Process.Start(info);
    }

    // Argument vectors given to ProcessStartInfo, and arrays and lists in every form.
    [HttpGet("vectors")]
    public IActionResult Vectors(string command)
    {
        // ruleid: csharp.command-injection
        Process.Start("sh", new string[] { "-c", command });
        // ruleid: csharp.command-injection
        Process.Start("bash", new List<string> { "-ec", command });
        // ruleid: csharp.command-injection
        var a = new ProcessStartInfo("/bin/sh", new[] { "-c", command });
        // ruleid: csharp.command-injection
        var b = new ProcessStartInfo("zsh", new string[] { "-c", command });
        // ruleid: csharp.command-injection
        var c = new ProcessStartInfo("bash", new List<string> { "-c", command });
        // ruleid: csharp.command-injection
        var d = new ProcessStartInfo("cmd.exe", new[] { "/c", "echo", command });
        // ruleid: csharp.command-injection
        var e = new ProcessStartInfo("pwsh", new string[] { "-Command", "Get-Item", command });
        // ruleid: csharp.command-injection
        var f = new ProcessStartInfo("powershell", new List<string> { "-c", "Write-Output", command });
        // ruleid: csharp.command-injection
        var g = new ProcessStartInfo("pwsh", new[] { "-NoProfile", "-cwa", command, "arg" });
        // ok: csharp.command-injection
        var h = new ProcessStartInfo("pwsh", new[] { "-NoProfile", "-cwa", "Write-Output $args", command });
        // ok: csharp.command-injection
        var i = new ProcessStartInfo("git", new List<string> { "-c", "user.name=" + command, "log" });
        var git = new ProcessStartInfo("git");
        git.ArgumentList.Add("-c");
        // ok: csharp.command-injection
        git.ArgumentList.Add("user.name=" + command);
        var windows = OperatingSystem.IsWindows();
        var j = new ProcessStartInfo
        {
            // ruleid: csharp.command-injection
            Arguments = windows ? "/c echo " + command : "-c \"echo " + command + "\"",
            FileName = windows ? "cmd.exe" : "/bin/sh",
        };
        ProcessStartInfo k;
        k = new ProcessStartInfo("/bin/bash");
        k.ArgumentList.Add("-c");
        // ruleid: csharp.command-injection
        k.ArgumentList.Add(command);
        // A constructor with an initializer.
        // ruleid: csharp.command-injection
        var l = new ProcessStartInfo("cmd.exe") { Arguments = "/c " + command };
        var m = new ProcessStartInfo("bash") { RedirectStandardOutput = true };
        // ruleid: csharp.command-injection
        m.Arguments = "-c \"" + command + "\"";
        var n = new ProcessStartInfo("sh") { UseShellExecute = false };
        n.ArgumentList.Add("-c");
        n.ArgumentList.Add(
            // ruleid: csharp.command-injection
            command);
        var o = new ProcessStartInfo("git") { Arguments = "log " + command };
        // ok: csharp.command-injection
        Process.Start(o);
        ProcessStartInfo q;
        q = new ProcessStartInfo("git") { Arguments = "log " + command };
        // ok: csharp.command-injection
        Process.Start(q);
        // ruleid: csharp.command-injection
        System.Diagnostics.Process.Start(command);
        // ruleid: csharp.command-injection
        System.Diagnostics.Process.Start(command, "--version");
        return Ok();
    }

    // A shell chosen by the operating system.
    [HttpGet("du")]
    public IActionResult DiskUsage(string folder)
    {
        var windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        var psi = new ProcessStartInfo
        {
            FileName = windows ? "cmd.exe" : "/bin/sh",
            // ruleid: csharp.command-injection
            Arguments = windows ? "/c dir " + folder : "-c \"du -sh " + folder + "\"",
        };
        return Ok();
    }

    // ArgumentList: escaped arguments, but a shell still runs its script.
    [HttpGet("grep")]
    public IActionResult Grep(string pattern)
    {
        var sh = new ProcessStartInfo("/bin/sh");
        sh.ArgumentList.Add("-c");
        // ruleid: csharp.command-injection
        sh.ArgumentList.Add("grep -r " + pattern + " /var/log/app");
        var cmd = new ProcessStartInfo { FileName = "cmd.exe" };
        cmd.ArgumentList.Add("/c");
        cmd.ArgumentList.Add("findstr");
        // ruleid: csharp.command-injection
        cmd.ArgumentList.Add(pattern);
        var ps = new ProcessStartInfo();
        ps.FileName = "powershell";
        ps.ArgumentList.Add("-Command");
        // ruleid: csharp.command-injection
        ps.ArgumentList.Add("Select-String -Pattern " + pattern);
        var posix = new ProcessStartInfo("bash");
        posix.ArgumentList.Add("-c");
        posix.ArgumentList.Add("grep -r -- \"$1\" /var/log/app");
        posix.ArgumentList.Add("bash");
        // ok: csharp.command-injection
        posix.ArgumentList.Add(pattern);
        var grep = new ProcessStartInfo("grep");
        grep.ArgumentList.Add("-r");
        // ok: csharp.command-injection
        grep.ArgumentList.Add(pattern);
        return Ok();
    }

    // The request object.
    [HttpGet("trace")]
    public IActionResult Trace()
    {
        var target = Request.Query["target"].ToString();
        // ruleid: csharp.command-injection
        Process.Start("sh", "-c \"traceroute " + target + "\"");
        // ruleid: csharp.command-injection
        Process.Start(Request.Headers["X-Tool"].ToString());
        // ruleid: csharp.command-injection
        Process.Start("cmd.exe", "/c tracert " + HttpContext.Request.Form["host"]);
        if (Request.Cookies.TryGetValue("tool", out var tool))
        {
            // ruleid: csharp.command-injection
            Process.Start(tool!);
        }
        return Ok();
    }

    // Conversions and allow-lists.
    [HttpGet("safe")]
    public IActionResult Safe(string count, string name, string command, Shell shell)
    {
        // ok: csharp.command-injection
        Process.Start("cmd.exe", "/c ping -n " + int.Parse(count) + " localhost");
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + (Commands.Contains(command) ? command : "uptime") + "\"");
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"echo " + shell + "\"");
        // ok: csharp.command-injection
        Process.Start("/usr/bin/uptime");
        if (!Commands.Contains(name))
        {
            return BadRequest();
        }
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + name + "\"");
        return Ok();
    }

    // An allow-list guard: inside it the value is the one that failed the check.
    [HttpGet("checked")]
    public IActionResult Checked(string command)
    {
        if (!Commands.Contains(command))
        {
            // ruleid: csharp.command-injection
            Process.Start("/bin/sh", "-c \"logger rejected " + command + "\"");
            return BadRequest();
        }
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + command + "\"");
        return Ok();
    }

    // Look-alikes: other APIs with a FileName, Arguments or Start member.
    [HttpPost("lookalikes")]
    public IActionResult LookAlikes(string name, string args)
    {
        var header = new ContentDispositionHeaderValue("attachment")
        {
            // ok: csharp.command-injection
            FileName = name,
        };
        var download = new DownloadOptions();
        // ok: csharp.command-injection
        download.FileName = name;
        // ok: csharp.command-injection
        _jobs.Start(name);
        // ok: csharp.command-injection
        _jobs.Start("cmd.exe", "/c " + args);
        var options = new TaskOptions { FileName = "cmd.exe", Arguments = "/c " + args };
        // ok: csharp.command-injection
        options.Arguments = "/c " + args;
        // ok: csharp.command-injection
        var running = Process.GetProcessesByName(name);
        return Ok();
    }

    // Known limits.
    private const string Bash = "/bin/bash";

    [HttpGet("limits")]
    public IActionResult Limits(string command, string script)
    {
        // A shell named through a constant or a local variable holding a literal.
        // ruleid: csharp.command-injection
        Process.Start(Bash, "-c \"" + command + "\"");
        var cmdExe = "cmd.exe";
        // ruleid: csharp.command-injection
        Process.Start(cmdExe, "/c " + command);
        // A shell chosen by a ternary in place, outside an initializer, is not recognised.
        var windows = OperatingSystem.IsWindows();
        // todoruleid: csharp.command-injection
        Process.Start(windows ? "cmd.exe" : "/bin/sh", windows ? "/c " + command : "-c \"" + command + "\"");
        // An argument vector held in a variable is taken as a whole: request data anywhere in it
        // is reported, also as a positional parameter after the script.
        var argv = new List<string> { "-c", command };
        // ruleid: csharp.command-injection
        Process.Start("/bin/sh", argv);
        var positional = new List<string> { "-c", "echo \"$0\"", script };
        // todook: csharp.command-injection
        Process.Start("/bin/sh", positional);
        // A POSIX shell's arguments string: data after the script is taken for shell code.
        // todook: csharp.command-injection
        Process.Start("/bin/sh", "-c 'echo \"$0\"' " + script);
        return Ok();
    }

    // The shared source block's limits.
    [HttpGet("tried")]
    public IActionResult Tried()
    {
        // A helper written as an expression-bodied method that reads the request, or a property
        // getter.
        // todoruleid: csharp.command-injection
        Process.Start(ToolOf(Request));
        // An expression-bodied helper that passes its argument on is followed here.
        var raw = Request.Query["cmd"].ToString();
        // ruleid: csharp.command-injection
        Process.Start("cmd.exe", Wrap(raw));
        // todoruleid: csharp.command-injection
        Process.Start(Tool);
        // todoruleid: csharp.command-injection
        Process.Start(Channel);
        return Ok();
    }

    // An enum declared after its use (Shell above is declared before).
    [HttpGet("prio")]
    public IActionResult Prio(Level level)
    {
        // todook: csharp.command-injection
        Process.Start("/bin/sh", "-c \"renice " + level + "\"");
        return Ok();
    }

    // An equality guard, a static Enumerable.Contains check, and a value assigned again after a
    // guard.
    [HttpGet("guards")]
    public IActionResult Guards(string command, string other)
    {
        if (command != "uptime" && command != "df -h")
        {
            return BadRequest();
        }
        // todook: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + command + "\"");
        var chosen = Enumerable.Contains(Commands, other) ? other : "uptime";
        // todook: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + chosen + "\"");
        if (!Commands.Contains(other)) return BadRequest();
        other = Request.Query["again"].ToString();
        // todoruleid: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + other + "\"");
        return Ok();
    }

    [NonAction]
    public void Exec(string command)
    {
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + command + "\"");
    }

    private static string ToolOf(HttpRequest request) => request.Query["tool"].ToString();

    private static string Wrap(string command) => "/c " + command;

    private string Tool => Request.Headers["X-Tool"].ToString();

    private string Channel
    {
        get { return Request.Query["channel"].ToString(); }
    }
}

// A Minimal API DTO bound from the body without [FromBody], and a handler of another class.
public static class JobEndpoints
{
    public static IEndpointRouteBuilder MapJobEndpoints(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/jobs", (Job job) =>
        {
            // todoruleid: csharp.command-injection
            Process.Start("/bin/sh", "-c \"" + job.Command + "\"");
            return Results.Ok();
        });
        routes.MapPost("/jobs/run", RunJob);
        routes.MapGet("/jobs/other", OtherHandlers.Run);
        return routes;
    }

    public static IResult RunJob(string command)
    {
        // ruleid: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + command + "\"");
        return Results.Ok();
    }
}

public static class OtherHandlers
{
    public static IResult Run(string command)
    {
        // todoruleid: csharp.command-injection
        Process.Start("/bin/sh", "-c \"" + command + "\"");
        return Results.Ok();
    }
}

// A controller whose base class is named otherwise.
public abstract class AppBase : ControllerBase
{
}

public class BackupController : AppBase
{
    public IActionResult Run(string folder)
    {
        // todoruleid: csharp.command-injection
        Process.Start("/bin/sh", "-c \"tar czf /tmp/b.tgz " + folder + "\"");
        return Ok();
    }
}

// Razor Pages: [BindProperty] properties and handler parameters.
public class ConsoleModel : PageModel
{
    [BindProperty]
    public string Command { get; set; } = "";

    public void OnPost()
    {
        // ruleid: csharp.command-injection
        Process.Start("cmd.exe", "/c " + Command);
    }

    public void OnGetRun(string program)
    {
        // ruleid: csharp.command-injection
        Process.Start(new ProcessStartInfo(program) { UseShellExecute = false });
    }
}

// A plain service: its parameters are not request data.
public class BuildService
{
    public void Build(string target)
    {
        // ok: csharp.command-injection
        Process.Start("/bin/sh", "-c \"make " + target + "\"");
    }
}

public enum Level { Low, High }
