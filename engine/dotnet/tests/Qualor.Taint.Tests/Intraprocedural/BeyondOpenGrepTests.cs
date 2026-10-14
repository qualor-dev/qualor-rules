namespace Qualor.Taint.Tests.Intraprocedural;

/// Task 29 (decision R-10, ruling R-E22): the shipped models on sources and sinks the OpenGrep rules keep in the backlog
/// (BACKLOG.md rows csharp.ssrf#request-host-source, csharp.sql-injection#null-conditional-request,
/// csharp.sql-injection#datatable-select, csharp.command-injection#shell-stdin,
/// csharp.unsafe-deserialization#request-chosen-type), and the request's own origin (Host, Scheme, PathBase and the Host
/// header) for open-redirect and xss. Each test holds the shapes that must be found (`/*sink*/`) and quiet controls.
public sealed class BeyondOpenGrepTests
{
    private static void Expect(string rule, string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, rule));

    // ---- csharp.ssrf#request-host-source ----

    [Fact]
    public void The_request_host_is_a_source_of_ssrf() => Expect("csharp.ssrf", """
        public class MirrorController : ControllerBase
        {
            private readonly HttpClient _http = new HttpClient();

            public async Task<IActionResult> Pull()
            {
                _http.BaseAddress = new Uri("https://" + Request.Host + "/"); /*sink*/
                await _http.GetStringAsync($"https://{Request.Host.Value}/api/items"); /*sink*/
                var host = HttpContext.Request.Host;
                await _http.GetStringAsync("http://" + host.ToUriComponent() + "/feed"); /*sink*/
                await _http.GetStringAsync("https://" + Request.Headers.Host + "/api"); /*sink*/
                await _http.GetStringAsync($"https://{Request.Headers["Host"]}{Request.PathBase}/status"); /*sink*/
                // A fixed origin before the host: only the path or query is chosen.
                await _http.GetStringAsync("https://api.contoso.test/hosts/" + Request.Host);
                await _http.GetStringAsync("https://api.contoso.test/ping");
                return Ok();
            }
        }
        """);

    [Fact]
    public void The_request_host_is_no_source_of_the_other_rules()
    {
        const string code = """
            using Microsoft.Data.SqlClient;
            public class HostController : ControllerBase
            {
                public IActionResult Show(SqlConnection connection)
                {
                    var host = Request.Host.Value;
                    new SqlCommand("SELECT * FROM Sites WHERE Host = '" + host + "'", connection);
                    Content("<p>" + Request.Host + "</p>", "text/html");
                    Content("<p>" + host + "</p>", "text/html");
                    System.IO.File.ReadAllText("/sites/" + host);
                    // Joined with other request data, that data is still reported.
                    new SqlCommand("SELECT * FROM Sites WHERE Host = '" + host + Request.Query["q"] + "'", connection); /*sink*/
                    return Redirect("https://" + Request.Host + "/home");
                }
            }
            """;
        Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.sql-injection"));
        foreach (var rule in new[] { "csharp.xss", "csharp.path-traversal", "csharp.open-redirect" })
            Assert.Empty(Snippet.Findings(code, rule));
    }

    // ---- R-E22: the request's own origin for open-redirect and xss ----

    [Fact]
    public void A_redirect_to_the_request_own_origin_is_quiet_and_other_request_data_is_reported() => Expect("csharp.open-redirect", """
        using Microsoft.Net.Http.Headers;
        public class AccountController : Controller
        {
            public IActionResult Back(bool secure, string next)
            {
                Redirect("https://" + Request.Headers["Host"] + "/home");
                Redirect("https://" + Request.Headers[HeaderNames.Host] + Request.Path);
                Redirect($"https://{Request.Headers.Host}{Request.PathBase}{Request.Path}{Request.QueryString}");
                Redirect(Uri.UriSchemeHttps + Uri.SchemeDelimiter + Request.Headers["host"] + Request.PathBase + Request.Path);
                Redirect($"{(secure ? Uri.UriSchemeHttps : Uri.UriSchemeHttp)}{Uri.SchemeDelimiter}{Request.Headers.Host}{Request.Path}");
                Redirect(Request.Scheme + "://" + Request.Headers.Host + Request.Path);
                Redirect(Request.PathBase + "/orders");
                if (Request.Headers.TryGetValue("HOST", out var origin)) Redirect("https://" + origin + "/start");
                Request.Headers.TryGetValue(HeaderNames.Host, out var named);
                Redirect("https://" + named + "/start");
                Request.Headers.TryGetValue("Origin", out var other);
                Redirect("https://" + other + "/start"); /*sink*/
                // The path with nothing known before it can start with "//" (another host).
                Redirect($"{Request.Headers.Host}{Request.Path}"); /*sink*/
                Redirect(Uri.SchemeDelimiter + Request.Path); /*sink*/
                // Request data of another kind.
                Redirect("https://" + Request.Headers["X-Forwarded-Host"] + "/home"); /*sink*/
                Redirect($"{Uri.UriSchemeHttps}{Uri.SchemeDelimiter}{next}{Request.Path}"); /*sink*/
                return Redirect(Request.Headers.Referer.ToString()); /*sink*/
            }
        }
        """);

    [Fact]
    public void The_own_origin_written_into_html_is_quiet_but_the_unescaped_path_base_value_is_reported() => Expect("csharp.xss", """
        using System.Text;
        using Microsoft.Net.Http.Headers;
        public class PagesController : ControllerBase
        {
            public IActionResult Show()
            {
                Content("<p>" + Request.Headers["Host"] + "</p>", "text/html");
                Content("<p>" + Request.Headers[HeaderNames.Host] + "</p>", "text/html");
                Content($"<p>{Request.Headers.Host}</p>", "text/html");
                if (Request.Headers.TryGetValue(HeaderNames.Host, out var host)) Content("<p>" + host + "</p>", "text/html");
                if (Request.Headers.TryGetValue(HeaderNames.UserAgent, out var agent)) Content("<p>" + agent + "</p>", "text/html"); /*sink*/
                Content("<p>" + Request.Host + Request.Scheme + "</p>", "text/html");
                var sb = new StringBuilder();
                sb.AppendFormat("<script src=\"{0}{1}\"></script>", Request.PathBase, "/js/site.js");
                Content(sb.ToString(), "text/html");
                // The unescaped Value read on the request's PathBase in place, as the OpenGrep rule (xss.cs:193).
                Content("<p>" + HttpContext.Request.PathBase.Value + "</p>", "text/html"); /*sink*/
                Content("<p>" + Request.Headers["X-Forwarded-Host"] + "</p>", "text/html"); /*sink*/
                Content("<p>" + Request.Headers.Referer + "</p>", "text/html"); /*sink*/
                return Content("<p>" + Request.Path.Value + "</p>", "text/html"); /*sink*/
            }
        }
        """);

    [Fact]
    public void The_host_header_and_path_base_stay_sources_of_ssrf_and_sql()
    {
        const string code = """
            using Microsoft.Data.SqlClient;
            public class SyncController : ControllerBase
            {
                public async Task<IActionResult> Run(HttpClient http, SqlConnection connection)
                {
                    await http.GetStringAsync("https://" + Request.Headers["Host"] + Request.PathBase + "/sync"); /*sink*/
                    new SqlCommand("SELECT * FROM T WHERE H = '" + Request.Headers["Host"] + "'", connection); /*sink*/
                    return Ok();
                }
            }
            """;
        Assert.Equal(new[] { 6 }, Snippet.Findings(code, "csharp.ssrf"));
        Assert.Equal(new[] { 7 }, Snippet.Findings(code, "csharp.sql-injection"));
    }

    // ---- known text of BCL string constants (string-prefix) ----

    [Fact]
    public void Uri_scheme_constants_have_known_text_for_a_fixed_origin() => Expect("csharp.ssrf", """
        public class FeedController : ControllerBase
        {
            public async Task Get(string q, HttpClient http)
            {
                await http.GetStringAsync(Uri.UriSchemeHttps + Uri.SchemeDelimiter + "api.contoso.test/items/" + q);
                await http.GetStringAsync($"{Uri.UriSchemeHttp}{Uri.SchemeDelimiter}feed.contoso.test/{q}");
                await http.GetStringAsync(Uri.UriSchemeHttps + Uri.SchemeDelimiter + q); /*sink*/
                await http.GetStringAsync(Uri.SchemeDelimiter + q); /*sink*/
            }
        }
        """);

    // ---- csharp.sql-injection#null-conditional-request ----

    [Fact]
    public void Request_members_read_through_a_null_conditional_are_sources() => Expect("csharp.sql-injection", """
        using Microsoft.Data.SqlClient;
        public class TenantLookup
        {
            private readonly IHttpContextAccessor _accessor;
            public TenantLookup(IHttpContextAccessor accessor) => _accessor = accessor;

            public void Find(SqlConnection connection)
            {
                var q = _accessor.HttpContext?.Request.Query["q"].ToString();
                new SqlCommand("SELECT * FROM T WHERE N = '" + q + "'", connection); /*sink*/
                var f = _accessor.HttpContext?.Request?.Form["f"];
                new SqlCommand("SELECT * FROM T WHERE F = '" + f + "'", connection); /*sink*/
                new SqlCommand("SELECT * FROM T WHERE C = '" + _accessor.HttpContext?.Request.Cookies["c"] + "'", connection); /*sink*/
                // Not request data: a count, the method.
                new SqlCommand("SELECT TOP " + _accessor.HttpContext?.Request.Query.Count + " * FROM T", connection);
                new SqlCommand("SELECT * FROM T WHERE M = '" + _accessor.HttpContext?.Request.Method + "'", connection);
            }
        }
        public class ReportsController : ControllerBase
        {
            public IActionResult List(SqlConnection connection)
            {
                new SqlCommand("SELECT * FROM R WHERE T = '" + HttpContext?.Request.Headers["X-Tenant"] + "'", connection); /*sink*/
                return Ok();
            }
        }
        """);

    // ---- csharp.sql-injection#datatable-select ----

    [Fact]
    public void A_DataTable_filter_expression_built_from_request_data_is_reported_under_sql_injection() => Expect("csharp.sql-injection", """
        using System.Data;
        public class StockController : ControllerBase
        {
            public IActionResult Search(string warehouse, string sku, DataTable stock)
            {
                var low = stock.Select($"Warehouse = '{warehouse}' AND Quantity < 5"); /*sink*/
                stock.DefaultView.RowFilter = "Sku LIKE '" + sku + "%'"; /*sink*/
                var byShelf = new DataView(stock) { RowFilter = "Shelf = '" + sku + "'" }; /*sink*/
                var named = new DataView(stock, RowFilter: $"Sku = '{sku}'", Sort: "Sku", RowState: DataViewRowState.CurrentRows); /*sink*/
                var total = stock.Compute("Sum(Quantity)", "Warehouse = '" + warehouse + "'"); /*sink*/
                // Quiet: the sort order, a number, constant filters.
                var sorted = stock.Select("Quantity > 0", sku + " DESC");
                var one = stock.Select("Bin = " + long.Parse(sku));
                var empty = stock.Select("Quantity = 0");
                byShelf.RowFilter = "Discontinued = false";
                return Ok(low.Length + named.Count + sorted.Length + one.Length + empty.Length + (int)total);
            }
        }
        """);

    [Fact]
    public void A_DataTable_filter_finding_says_it_is_a_filter_expression()
    {
        var result = Snippet.Analyze("""
            using System.Data;
            public class StockController : ControllerBase
            {
                public IActionResult Count(string bin, DataTable stock, Microsoft.Data.SqlClient.SqlConnection c)
                {
                    stock.Select($"Bin = '{bin}'");
                    new Microsoft.Data.SqlClient.SqlCommand($"SELECT COUNT(*) FROM Bins WHERE Code = '{bin}'", c);
                    return Ok();
                }
            }
            """);
        var findings = result.Findings.Where(f => f.RuleId == "csharp.sql-injection").OrderBy(f => f.Sink.SourceSpan.Start).ToList();
        Assert.Equal(2, findings.Count);
        Assert.Contains("filter expression", findings[0].Message, StringComparison.Ordinal);
        Assert.Null(findings[1].Message);
    }

    // ---- csharp.command-injection#shell-stdin ----

    /// A shell started without a command or a script reads its standard input as commands (cmd: "/c" runs one command
    /// and ends, "/k" keeps reading; PowerShell: about_pwsh's "-Command -" and "-File -" read the command text from
    /// standard input; bash and sh: without "-c" or a script operand, or with "-s"). Option values are no script.
    [Fact]
    public void Request_data_written_to_a_started_shell_standard_input_is_reported() => Expect("csharp.command-injection", """
        using System.Diagnostics;
        using System.IO;
        public class AgentController : ControllerBase
        {
            public async Task<int> Ping(string target)
            {
                var info = new ProcessStartInfo
                {
                    FileName = Environment.OSVersion.Platform == PlatformID.Win32NT ? "cmd.exe" : "bash",
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                };
                using var console = new Process { StartInfo = info };
                console.Start();
                await console.StandardInput.WriteLineAsync($"ping -c 1 {target}"); /*sink*/
                await console.StandardInput.WriteLineAsync("exit");
                await console.WaitForExitAsync();
                return console.ExitCode;
            }

            public void Assigned(string line)
            {
                var info = new ProcessStartInfo("pwsh") { RedirectStandardInput = true };
                var runner = new Process();
                runner.StartInfo = info;
                runner.Start();
                runner.StandardInput.Write(line); /*sink*/
            }

            public void Inline(string line)
            {
                var runner = new Process { StartInfo = { FileName = "/bin/sh", RedirectStandardInput = true } };
                runner.Start();
                using (StreamWriter input = runner.StandardInput)
                {
                    input.WriteLine(line); /*sink*/
                }
            }

            public void Started(string line)
            {
                using var shell = Process.Start(new ProcessStartInfo("powershell.exe") { RedirectStandardInput = true });
                shell!.StandardInput.WriteLine(line); /*sink*/
            }

            public void StartedWithInfo(string line)
            {
                var info = new ProcessStartInfo { FileName = "/usr/bin/bash", RedirectStandardInput = true };
                var shell = Process.Start(info);
                shell!.StandardInput.WriteLine(line); /*sink*/
            }

            public void PwshCommandFromInput(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-NoLogo -NoProfile -Command -";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PowerShellFileFromInput(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell";
                p.StartInfo.Arguments = "-ExecutionPolicy RemoteSigned -WindowStyle Hidden -File -";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void CmdKeepsReading(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "cmd";
                p.StartInfo.Arguments = "/k title agent";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void BashOptionValues(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "bash";
                p.StartInfo.Arguments = "-o errexit -s ready";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void BashOptionValue(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "/bin/bash";
                p.StartInfo.Arguments = "--norc -o pipefail";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PowerShellConsoleFile(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell.exe";
                p.StartInfo.Arguments = "-NoLogo -PSConsoleFile agent.psc1";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PowerShellEncodedArguments(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell.exe";
                p.StartInfo.Arguments = "-EncodedArguments YQBnAGUAbgB0AA==";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PwshAbbreviatedPolicy(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-nop -execution RemoteSigned -windows Minimized";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PwshQuotedDirectory(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-WorkingDirectory \"C:/Agent Jobs/build 7\" -NoProfile";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PowerShellSlashSwitches(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell";
                p.StartInfo.Arguments = "/NoLogo /NoProfile /InputFormat Text";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void GitBashOnWindows(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = @"D:\Tools\Git\bin\BASH.EXE";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            public void PowerShellSlashCommand(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell.exe";
                p.StartInfo.Arguments = "/NoProfile /Command Get-ChildItem";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void PwshQuotedScript(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-NoProfile \"C:/Agent Jobs/collect.ps1\"";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void PwshAbsoluteScript(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "/opt/agent/collect.ps1 -Verbose";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void GitBashCommand(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = @"C:\Program Files\Git\usr\bin\sh.exe";
                p.StartInfo.Arguments = "-c \"cat > out.txt\"";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void PwshNoExit(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-NoExit -Command Set-Location /srv";
                p.Start();
                p.StandardInput.WriteLine(line); /*sink*/
            }

            // Quiet: no shell, a command that reads the input as data, a script, a variable holding two processes.
            public void Count(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "wc";
                p.StartInfo.Arguments = "-l";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void BashCommand(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "bash";
                p.StartInfo.Arguments = "-eu -c 'tee -a /var/log/agent.log'";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void CmdCommand(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c more > notes.txt";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void PwshCommand(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "pwsh";
                p.StartInfo.Arguments = "-NonInteractive -Command Out-File notes.txt";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void PowerShellScript(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "powershell";
                p.StartInfo.Arguments = "-ExecutionPolicy Bypass ./collect.ps1";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void ShScript(string line)
            {
                var p = new Process();
                p.StartInfo.FileName = "sh";
                p.StartInfo.Arguments = "-x ./collect.sh";
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void StartedWithCommand(string line)
            {
                var p = Process.Start("bash", "-c \"sort -u > /tmp/names\"");
                p!.StandardInput.WriteLine(line);
            }

            public void InfoOfAnotherProgram(string line)
            {
                var info = new ProcessStartInfo("sort") { RedirectStandardInput = true };
                var p = new Process { StartInfo = info };
                p.Start();
                p.StandardInput.WriteLine(line);
            }

            public void TwoProcesses(string line, bool b)
            {
                var p = Process.Start("bash");
                if (b) p = Process.Start("sort");
                p!.StandardInput.WriteLine(line);
            }

            public void OtherWriter(string line, StreamWriter writer) => writer.WriteLine(line);
        }
        """);

    // ---- csharp.unsafe-deserialization#request-chosen-type ----

    [Fact]
    public void A_serializer_built_for_a_type_the_request_names_is_reported() => Expect("csharp.unsafe-deserialization", """
        using System.Collections.Generic;
        using System.Reflection;
        using System.Runtime.Serialization;
        using System.Runtime.Serialization.Json;
        using System.Xml;
        using System.Xml.Serialization;
        public class Invoice { public decimal Total { get; set; } }
        public class SyncController : ControllerBase
        {
            private static readonly Dictionary<string, string> Kinds = new() { ["invoice"] = "Billing.Invoice" };

            public IActionResult Receive(string payloadType, string extra)
            {
                var a = new XmlSerializer(Type.GetType(payloadType)!); /*sink*/
                var chosen = Type.GetType("Billing." + payloadType, throwOnError: true);
                var b = new DataContractSerializer(chosen!); /*sink*/
                var c = new DataContractJsonSerializer(Type.GetType(payloadType)!); /*sink*/
                var d = new XmlSerializer(Type.GetType(payloadType)!, new XmlRootAttribute("payload")); /*sink*/
                var e = new XmlSerializer(typeof(Invoice), new[] { Type.GetType(extra)! }); /*sink*/
                var f = new DataContractSerializer(typeof(Invoice), new[] { Type.GetType(extra)! }); /*sink*/
                var g = new XmlSerializerFactory().CreateSerializer(Type.GetType(extra)!); /*sink*/
                var h = XmlSerializer.FromTypes(new[] { typeof(Invoice).Assembly.GetType(extra) }); /*sink*/
                // Quiet: fixed types, a constant type name, a name from a table of constants.
                var i = new XmlSerializer(typeof(Invoice));
                var j = new XmlSerializer(Type.GetType("Billing.Invoice")!);
                var k = new DataContractSerializer(typeof(Invoice), new[] { typeof(decimal) });
                var l = new XmlSerializer(Type.GetType(Kinds[payloadType])!);
                return Ok();
            }

            public IActionResult Queue()
            {
                using var reader = XmlReader.Create(Request.Body);
                reader.MoveToContent();
                var job = Type.GetType("Jobs." + reader.GetAttribute("kind"), throwOnError: false);
                var contract = new DataContractSerializer(job!); /*sink*/
                return Ok(contract.ReadObject(reader));
            }
        }
        """);

    /// XmlDocument.Load of a Stream, TextReader or XmlReader holds the data it reads (propagators.yml `param-types:`);
    /// Load of a file whose name the request chose reads the file, not the name (Jellyfin measurement, Task 29).
    [Fact]
    public void Xml_loaded_from_the_request_body_is_request_data_but_a_file_named_by_the_request_is_not() => Expect("csharp.xpath-injection", """
        using System.Xml;
        public class BooksController : ControllerBase
        {
            public IActionResult Find(string file)
            {
                var fromFile = new XmlDocument();
                fromFile.Load("/data/books/" + file);
                var title = fromFile.DocumentElement!.GetAttribute("title");
                fromFile.SelectSingleNode("//book[@title='" + title + "']");
                var posted = new XmlDocument();
                posted.Load(Request.Body);
                var name = posted.DocumentElement!.GetAttribute("name");
                posted.SelectSingleNode("//book[@name='" + name + "']"); /*sink*/
                var text = new XmlDocument();
                text.LoadXml(file);
                text.SelectSingleNode("//book[@id='" + text.DocumentElement!.GetAttribute("id") + "']"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_request_chosen_type_finding_says_the_type_comes_from_the_request()
    {
        var result = Snippet.Analyze("""
            using System.Xml.Serialization;
            public class ImportController : ControllerBase
            {
                public IActionResult Import(string typeName) => Ok(new XmlSerializer(Type.GetType(typeName)!));
            }
            """);
        var finding = Assert.Single(result.Findings, f => f.RuleId == "csharp.unsafe-deserialization");
        Assert.Contains("type", finding.Message, StringComparison.Ordinal);
        Assert.Contains("comes from the request", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_type_the_request_names_is_request_data_for_deserialization_only()
    {
        const string code = """
            using Microsoft.Data.SqlClient;
            public class TypesController : ControllerBase
            {
                public IActionResult Show(string typeName, SqlConnection connection)
                {
                    var type = Type.GetType(typeName)!;
                    new SqlCommand("SELECT * FROM T WHERE K = '" + type.FullName + "'", connection);
                    System.IO.File.ReadAllText("/types/" + type.Name);
                    return Content("<p>" + type.AssemblyQualifiedName + "</p>", "text/html");
                }
            }
            """;
        foreach (var rule in new[] { "csharp.sql-injection", "csharp.path-traversal", "csharp.xss" })
            Assert.Empty(Snippet.Findings(code, rule));
    }
}
