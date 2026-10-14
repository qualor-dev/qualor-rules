namespace Qualor.Taint.Tests.Capabilities;

/// Conditional sinks (models/README.md, `when:`): a sink that applies only when the call's other arguments, the
/// properties of the object it acts on, the literal text of the sink argument or the elements before it say so.
public sealed class ConditionalSinkTests : ProbeModels
{
    private const string Shell = "'(?i)^(.*[\\\\/])?(sh|bash|cmd)(\\.exe)?$'";

    private ModelSet ArgumentModels() => Probe($"""
        sinks:
          - method: System.Diagnostics.Process.Start
            args: [1]
            param-types: [System.String]
            when:
              - arg: 0
                matches: {Shell}
              - literal-text: '(^|\s)(-c|/c)(\s|$)'
          - method: System.Diagnostics.Process.Start
            args: [1]
            param-types: [System.Collections.Generic.IEnumerable`1]
            when:
              - arg: 0
                matches: {Shell}
              - literal-text: '(^|\s)(-c|/c)(\s|$)'
          - method: System.Diagnostics.Process.Start
            args: [1]
            param-types: [System.Collections.Generic.IEnumerable`1]
            when:
              - arg: 0
                matches: {Shell}
              - after: '^-c$'
                next: true
          - method: System.Diagnostics.Process.Start
            args: [1]
            param-types: [System.Collections.Generic.IEnumerable`1]
            when:
              - arg: 0
                matches: {Shell}
              - after: '^/c$'
        """);

    [Fact]
    public void An_argument_sink_applies_when_another_argument_is_a_matching_constant() => Expect(ArgumentModels(), """
        using System.Diagnostics;
        public class ToolsController : ControllerBase
        {
            private const string Bash = "/bin/bash";
            public void Run(string q, bool windows)
            {
                Process.Start("/bin/sh", "-c " + q); /*sink*/
                Process.Start("git", "-c " + q);
                Process.Start(Bash, "-c " + q); /*sink*/
                var exe = "cmd.exe";
                Process.Start(exe, "/c " + q); /*sink*/
                Process.Start(windows ? "cmd.exe" : "/bin/sh", windows ? "/c " + q : "-c " + q); /*sink*/
                Process.Start(windows ? "cmd.exe" : q, "/c dir");
                Process.Start(q, "-c " + q);
            }
        }
        """);

    [Fact]
    public void Conditions_hold_in_a_lambda_too() => Expect(ArgumentModels(), """
        using System.Diagnostics;
        var app = WebApplication.Create(args);
        app.MapGet("/run", (string q) =>
        {
            var shell = "/bin/sh";
            Process.Start(shell, "-c " + q); /*sink*/
            Process.Start("git", "-c " + q);
            return Results.Ok();
        });
        app.MapGet("/vector", (string q) => Process.Start("sh", new[] { "-c", q })); /*sink*/
        app.Run();
        """);

    [Fact]
    public void Literal_text_must_match_unless_the_argument_has_none() => Expect(ArgumentModels(), """
        using System.Diagnostics;
        public class ToolsController : ControllerBase
        {
            public void Run(string q)
            {
                Process.Start("sh", "/opt/check.sh " + q);
                Process.Start("sh", q); /*sink*/
                var line = "-c " + q;
                Process.Start("sh", line); /*sink*/
                Process.Start("sh", string.Format("-c \"echo {0}\"", q)); /*sink*/
                Process.Start("sh", $"-c \"echo {q}\""); /*sink*/
                Process.Start("sh", $"/opt/check.sh {q}");
            }
        }
        """);

    [Fact]
    public void An_element_after_a_matching_element_of_a_vector_written_in_place_is_the_sink() => Expect(ArgumentModels(), """
        using System.Diagnostics;
        public class ToolsController : ControllerBase
        {
            public void Run(string q)
            {
                Process.Start("/bin/sh", new[] { "-c", "dig " + q }); /*sink*/
                Process.Start("/bin/sh", new[] { "-c", "dig \"$0\"", q });
                Process.Start("cmd", new List<string> { "/c", "type", q }); /*sink*/
                Process.Start("cmd", new string[] { "/k", "type", q });
                Process.Start("git", new[] { "-c", q });
                Process.Start("sh", new[] {
                    "-c",
                    q }); /*sink*/
                var argv = new List<string> { "-c", "echo", q };
                Process.Start("sh", argv); /*sink*/
            }
        }
        """);

    private ModelSet PropertyModels() => Probe($"""
        sinks:
          - property-set: System.Diagnostics.ProcessStartInfo.Arguments
            when:
              - property: FileName
                matches: {Shell}
          - method: System.Collections.ObjectModel.Collection`1.Add
            args: [0]
            when:
              - receiver: System.Diagnostics.ProcessStartInfo.ArgumentList
              - property: FileName
                matches: {Shell}
              - after: '^-c$'
                next: true
          - method: Microsoft.AspNetCore.Http.HttpResponseWritingExtensions.WriteAsync
            args: [1]
            when:
              - property: ContentType
                of: 0
                matches: '^text/html'
        """);

    [Fact]
    public void A_property_sink_applies_when_the_object_has_a_matching_property_set_anywhere_in_the_body() => Expect(PropertyModels(), """
        using System.Diagnostics;
        public class ToolsController : ControllerBase
        {
            private ProcessStartInfo _psi = new();
            public void Run(string q, bool windows)
            {
                var a = new ProcessStartInfo { FileName = "sh", Arguments = q }; /*sink*/
                var b = new ProcessStartInfo { Arguments = q, FileName = "bash" }; /*sink*/
                var c = new ProcessStartInfo("cmd.exe") { Arguments = q }; /*sink*/
                var d = new ProcessStartInfo { FileName = "git", Arguments = q };
                var e = new ProcessStartInfo();
                e.Arguments = q; /*sink*/
                e.FileName = "/bin/sh";
                var f = new ProcessStartInfo("bash");
                f.Arguments = q; /*sink*/
                ProcessStartInfo g;
                g = new ProcessStartInfo("git");
                g.Arguments = q;
                var p = new Process();
                p.StartInfo.FileName = "cmd";
                p.StartInfo.Arguments = q; /*sink*/
                var h = new ProcessStartInfo { FileName = windows ? "cmd.exe" : "/bin/sh", Arguments = q }; /*sink*/
                _psi.FileName = "sh";
                _psi.Arguments = q; /*sink*/
                var other = new ProcessStartInfo();
                other.Arguments = q;
                var reused = new ProcessStartInfo { FileName = "bash", Arguments = "-c uptime" };
                reused = new ProcessStartInfo { FileName = "git" };
                reused.Arguments = q;
            }
        }
        """);

    [Fact]
    public void An_Add_to_a_receiver_property_follows_the_earlier_Adds_to_the_same_collection() => Expect(PropertyModels(), """
        using System.Diagnostics;
        public class ToolsController : ControllerBase
        {
            public void Run(string q)
            {
                var sh = new ProcessStartInfo("/bin/sh");
                sh.ArgumentList.Add("-c");
                sh.ArgumentList.Add(q); /*sink*/
                var later = new ProcessStartInfo("/bin/sh");
                later.ArgumentList.Add("-c");
                later.ArgumentList.Add("echo \"$0\"");
                later.ArgumentList.Add(q);
                var git = new ProcessStartInfo("git");
                git.ArgumentList.Add("-c");
                git.ArgumentList.Add(q);
                var p1 = new ProcessStartInfo("/bin/sh") { ArgumentList = { "-c", q } }; /*sink*/
                var p2 = new ProcessStartInfo { ArgumentList = { "-c", q }, FileName = "bash" }; /*sink*/
                var p3 = new ProcessStartInfo("/bin/sh") { ArgumentList = { "-c", "echo", q } };
                var list = new System.Collections.ObjectModel.Collection<string>();
                list.Add("-c");
                list.Add(q);
            }
        }
        """);

    [Fact]
    public void A_property_condition_of_an_argument_follows_that_object() => Expect(PropertyModels(), """
        public class PagesController : ControllerBase
        {
            public async Task Html(string q)
            {
                Response.ContentType = "text/html";
                await Response.WriteAsync("<p>" + q + "</p>"); /*sink*/
            }

            public async Task Plain(string q)
            {
                Response.ContentType = "text/plain";
                await Response.WriteAsync(q);
            }

            public async Task Other(string q, HttpContext context)
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(q); /*sink*/
                await Response.WriteAsync(q);
            }
        }
        """);
}
