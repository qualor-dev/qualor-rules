using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Interprocedural;

/// Task 28 (decision R-9, ruling R-E29): each finding has a confidence. A path is `medium` when a step of it reads a
/// field or property from the heap, a keyed store's "any key" entry, an element found by a request key (R-E9/R-E18), a
/// keyed entry or view model reached only through an unresolved view name, or a call resolved by the class-hierarchy
/// fallback to several implementations; otherwise `high`. Of the paths to one sink the engine reports a high one when it
/// finds one. A line marked `/*high*/` or `/*medium*/` must be reported with that confidence; no other line is reported.
public sealed class ConfidenceTests
{
    private static void Expect(string code, string rule = "csharp.sql-injection")
    {
        var marked = code.Split('\n').Select((l, i) => (l, i))
            .Where(x => x.l.Contains("/*high*/", StringComparison.Ordinal) || x.l.Contains("/*medium*/", StringComparison.Ordinal))
            .ToDictionary(x => x.i + 1, x => x.l.Contains("/*high*/", StringComparison.Ordinal) ? Confidence.High : Confidence.Medium);
        var found = Snippet.Analyze(code).Findings
            .Where(f => f.RuleId == rule && Path.GetFileName(f.Sink.SourceTree!.FilePath) == "Snippet.cs")
            .ToDictionary(f => f.Sink.GetLineSpan().StartLinePosition.Line + 1, f => f.Confidence);
        Assert.Equal(marked.OrderBy(p => p.Key), found.OrderBy(p => p.Key));
    }

    [Fact]
    public void A_local_flow_and_a_bound_objects_member_are_high() => Expect("""
        public class Note { public string Text { get; set; } = ""; }
        public class NotesController : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Find(string q)
            {
                var sql = "SELECT * FROM notes WHERE t = '" + q + "'";
                _c.Execute(sql); /*high*/
                return Ok();
            }
            public IActionResult Save([FromBody] Note n)
            {
                Store(n);
                return Ok();
            }
            private void Store(Note n) => _c.Execute("INSERT INTO notes VALUES ('" + n.Text + "')"); /*high*/
        }
        """);

    [Fact]
    public void A_heap_read_is_medium_and_a_high_path_to_the_same_sink_wins() => Expect("""
        public class Holder { public string Value = ""; }
        public class HeapController : ControllerBase
        {
            private readonly Holder _h = new();
            private readonly SqlConnection _c = new();
            public IActionResult Set(string q)
            {
                _h.Value = q;
                Use();
                Both(q);
                return Ok();
            }
            private void Use() => _c.Execute("SELECT * FROM t WHERE v = '" + _h.Value + "'"); /*medium*/
            private void Both(string q) => _c.Execute("SELECT * FROM t WHERE v = '" + (q.Length > 3 ? _h.Value : q) + "'"); /*high*/
            public IActionResult Mix(string q)
            {
                _h.Value = q;
                var a = q; var b = a; var c = b; var d = c; var e = d;
                var s = q.Length > 3 ? _h.Value : e;
                _c.Execute("SELECT * FROM t WHERE v = '" + s + "'"); /*high*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_high_path_cleaned_for_the_rule_is_no_witness_of_its_finding() => Expect("""
        using System.Text.Encodings.Web;
        public class Holder { public string Value = ""; }
        public class PageController : Controller
        {
            private readonly Holder _h = new();
            public IActionResult Show(string q)
            {
                _h.Value = q;
                var s = q.Length > 3 ? HtmlEncoder.Default.Encode(q) : _h.Value;
                return Content(s, "text/html"); /*medium*/
            }
        }
        """, "csharp.xss");

    // ---- Fix round 1 (I1, R-E32 revised): the witness is chosen per finding, for its rule and its request ----

    [Fact]
    public void A_high_path_cleaned_only_for_another_rule_is_the_witness_of_this_rule() => Expect("""
        using System.Text.Encodings.Web;
        public class Holder { public string Value = ""; }
        public class C1Controller : ControllerBase
        {
            private readonly Holder _h = new();
            private readonly SqlConnection _c = new();
            public IActionResult Run(string q)
            {
                _h.Value = q;
                var s = q.Length > 3 ? HtmlEncoder.Default.Encode(q) : _h.Value;
                _c.Execute("SELECT * FROM t WHERE v = '" + s + "'"); /*high*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void The_reported_path_starts_in_the_request_that_reaches_the_sink()
    {
        const string code = """
            using System.Text.Encodings.Web;
            public class Holder { public string X = ""; public string Y = ""; public string Z = ""; }
            public class C7Controller : ControllerBase
            {
                private static readonly Holder H = new();
                private readonly SqlConnection _c = new();
                public IActionResult A(string q)
                {
                    H.X = HtmlEncoder.Default.Encode(q);
                    Shared(q.Length);
                    UseA();
                    return Ok();
                }
                public IActionResult B(string r)
                {
                    H.Y = r;
                    Shared(r.Length);
                    return Ok();
                }
                private void Shared(int n) => H.Z = n > 3 ? H.X : H.Y;
                private void UseA() => _c.Execute("SELECT * FROM t WHERE v = '" + H.Z + "'");
            }
            """;
        var finding = Assert.Single(Snippet.Analyze(code).Findings, f => f.RuleId == "csharp.sql-injection");

        // UseA runs only in A's request: the path starts at A's parameter q (line 7), never at B's r (line 14).
        Assert.Equal(7, finding.Path[0].Span.StartLinePosition.Line + 1);
    }

    [Fact]
    public void A_target_only_reflection_opens_is_medium_beside_a_registered_one() => Expect("""
        public interface IExporter { void Export(string filter); }
        public class CsvExporter : IExporter
        {
            private readonly SqlConnection _c = new();
            public void Export(string filter) => _c.Execute("SELECT * FROM csv WHERE " + filter); /*high*/
        }
        public class XmlExporter : IExporter
        {
            private readonly SqlConnection _c = new();
            public void Export(string filter) => _c.Execute("SELECT * FROM xml WHERE " + filter); /*medium*/
        }
        public class ExportController : ControllerBase
        {
            private readonly IExporter _exporter;
            public ExportController(IExporter exporter) => _exporter = exporter;
            public IActionResult Run(string q)
            {
                _exporter.Export(q);
                return Ok();
            }
        }
        public static class Registration
        {
            public static void Add(IServiceCollection services) => services.AddScoped<IExporter, CsvExporter>();
            public static object Make() => System.Activator.CreateInstance(typeof(XmlExporter))!;
        }
        """);

    [Fact]
    public void An_auto_property_read_through_a_fallback_call_is_medium_also_for_a_value_tracked_in_the_body() => Expect("""
        public interface IHas { string Name { get; } }
        public class A1 : IHas
        {
            private readonly SqlConnection _c = new();
            public string Name { get; set; } = "";
            public void Use(string q)
            {
                Name = q;
                IHas me = this;
                _c.Execute("SELECT * FROM t WHERE v = '" + me.Name + "'"); /*medium*/
            }
        }
        public class B1 : IHas { public string Name { get; set; } = ""; }
        public class HasController : ControllerBase
        {
            public IActionResult Run(string q)
            {
                ((A1)System.Activator.CreateInstance(typeof(A1))!).Use(q);
                System.Activator.CreateInstance(typeof(B1));
                return Ok();
            }
        }
        """);

    // ---- Fix round 2 (RR1): a label's paths are chosen per rule too, for a sink inside a callee ----

    private const string Fmt = """
        using System.Text.Encodings.Web;
        public interface IFmt { string F(string s); }
        public class F1 : IFmt { public string F(string s) => s + "1"; }
        public class F2 : IFmt { public string F(string s) => s + "2"; }

        """;

    /// The finding's confidence and whether its reported path goes through the fallback call `_f.F` (the other side is
    /// the encoded one: a sanitizer adds no step).
    private static (Confidence Confidence, bool ThroughFallback) Only(string code, string rule)
    {
        var f = Assert.Single(Snippet.Analyze(code).Findings, x => x.RuleId == rule);
        return (f.Confidence, f.Path.Any(s => s.Kind == StepKind.DispatchFallback));
    }

    [Fact]
    public void R3_an_encoded_high_path_is_the_sql_witness_in_the_action() => Assert.Equal((Confidence.High, false), Only(Fmt + """
        public class R3Controller : Controller
        {
            private readonly SqlConnection _c = new();
            private readonly IFmt _f;
            public R3Controller(IFmt f) => _f = f;
            public IActionResult Run(string p)
            {
                var s = p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(p);
                _c.Execute("SELECT '" + s + "'");
                return Ok();
            }
        }
        """, "csharp.sql-injection"));

    [Fact]
    public void L3_an_encoded_high_path_is_the_sql_witness_in_a_callee() => Assert.Equal((Confidence.High, false), Only(Fmt + """
        public class L3Controller : Controller
        {
            private readonly SqlConnection _c = new();
            private readonly IFmt _f;
            public L3Controller(IFmt f) => _f = f;
            public IActionResult Run(string q) => Show(q);
            private IActionResult Show(string p)
            {
                var s = p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(p);
                _c.Execute("SELECT '" + s + "'");
                return Ok();
            }
        }
        """, "csharp.sql-injection"));

    [Fact]
    public void R4_an_xss_finding_never_reports_the_encoded_path_in_the_action() => Assert.Equal((Confidence.Medium, true), Only(Fmt + """
        public class R4Controller : Controller
        {
            private readonly IFmt _f;
            public R4Controller(IFmt f) => _f = f;
            public IActionResult Run(string p)
            {
                var s = p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(System.IO.Path.GetFileName(p));
                return Content(s, "text/html");
            }
        }
        """, "csharp.xss"));

    [Fact]
    public void L4_an_xss_finding_never_reports_the_encoded_path_in_a_callee() => Assert.Equal((Confidence.Medium, true), Only(Fmt + """
        public class L4Controller : Controller
        {
            private readonly IFmt _f;
            public L4Controller(IFmt f) => _f = f;
            public IActionResult Run(string q) => Show(q);
            private IActionResult Show(string p)
            {
                var s = p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(System.IO.Path.GetFileName(p));
                return Content(s, "text/html");
            }
        }
        """, "csharp.xss"));

    // ---- Fix round 3 (RR2): a call edge keeps one path per cleanliness ----

    [Fact]
    public void R5_an_xss_finding_in_a_callee_given_the_request_value_never_reports_the_encoded_path() =>
        Assert.Equal((Confidence.Medium, true), Only(Fmt + """
            public class R5Controller : Controller
            {
                private readonly IFmt _f;
                public R5Controller(IFmt f) => _f = f;
                public IActionResult Run(string p) => Sink(p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(System.IO.Path.GetFileName(p)));
                private IActionResult Sink(string s) => Content(s, "text/html");
            }
            """, "csharp.xss"));

    [Fact]
    public void L5_an_xss_finding_two_calls_deep_never_reports_the_encoded_path() =>
        Assert.Equal((Confidence.Medium, true), Only(Fmt + """
            public class L5Controller : Controller
            {
                private readonly IFmt _f;
                public L5Controller(IFmt f) => _f = f;
                public IActionResult Run(string q) => Mid(q);
                private IActionResult Mid(string p) => Sink(p.Length > 3 ? HtmlEncoder.Default.Encode(p) : _f.F(System.IO.Path.GetFileName(p)));
                private IActionResult Sink(string s) => Content(s, "text/html");
            }
            """, "csharp.xss"));

    // ---- Fix round 4 (RR3, ruling R-E35): a member exact within one method is high ----

    [Fact]
    public void V1_an_own_field_written_and_read_in_one_method_is_high() => Expect("""
        public class V1Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string _own = "";
            public IActionResult Run(string q) { _own = q; _c.Execute("SELECT '" + _own + "'"); return Ok(); } /*high*/
        }
        """);

    [Fact]
    public void V2_an_own_auto_property_written_and_read_in_one_method_is_high() => Expect("""
        public class V2Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string Own { get; set; } = "";
            public IActionResult Run(string q) { Own = q; _c.Execute("SELECT '" + Own + "'"); return Ok(); } /*high*/
        }
        """);

    [Fact]
    public void H1_a_member_of_an_object_allocated_and_written_in_one_method_is_high() => Expect("""
        public class Note { public string Text { get; set; } = ""; public Note? Inner { get; set; } }
        public class H1Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run(string q)
            {
                var n = new Note();
                n.Text = q;
                _c.Execute("SELECT '" + n.Text + "'"); /*high*/
                var m = new Note { Inner = new Note() };
                m.Inner.Text = q;
                _c.Execute("SELECT '" + m.Inner.Text + "'"); /*high*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void V5_an_own_field_a_callee_wrote_is_medium_after_the_call() => Expect("""
        public class V5Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string _own = "";
            public IActionResult Run(string q) { Init(q); _c.Execute("SELECT '" + _own + "'"); return Ok(); } /*medium*/
            private void Init(string s) { _own = s; }
        }
        """);

    [Fact]
    public void V6_an_own_field_the_caller_wrote_is_medium_in_the_callee() => Expect("""
        public class V6Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            private string _own = "";
            public IActionResult Set(string q) { _own = q; Use(); return Ok(); }
            private void Use() => _c.Execute("SELECT '" + _own + "'"); /*medium*/
        }
        """);

    [Fact]
    public void H2_a_member_written_through_an_alias_is_medium() => Expect("""
        public class Note { public string Text { get; set; } = ""; }
        public class H2Controller : ControllerBase
        {
            private readonly SqlConnection _c = new();
            public IActionResult Run(string q)
            {
                var n = new Note();
                var m = n;
                m.Text = q;
                _c.Execute("SELECT '" + n.Text + "'"); /*medium*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void An_element_found_by_a_request_key_is_medium_and_the_tables_own_data_high() => Expect("""
        public class LookupController : ControllerBase
        {
            private static readonly Dictionary<string, string> Names = new();
            private readonly SqlConnection _c = new();
            public IActionResult Show(string k)
            {
                _c.Execute("SELECT * FROM " + Names[k]); /*medium*/
                _c.Execute("SELECT * FROM " + Names.GetValueOrDefault(k)); /*medium*/
                var mine = new Dictionary<string, string> { ["a"] = k };
                _c.Execute("SELECT * FROM " + mine["a"]); /*high*/
                return Ok();
            }
            public static void Register(string k, string v) => Names[k] = v;
        }
        """);

    private const string Exporters = """
        public interface IExporter { void Export(string filter); }
        public class CsvExporter : IExporter
        {
            private readonly SqlConnection _c = new();
            public void Export(string filter) => _c.Execute("SELECT * FROM csv WHERE " + filter); @CSV@
        }
        public class XmlExporter : IExporter
        {
            private readonly SqlConnection _c = new();
            public void Export(string filter) => _c.Execute("SELECT * FROM xml WHERE " + filter); @XML@
        }
        public class ExportController : ControllerBase
        {
            private readonly IExporter _exporter;
            public ExportController(IExporter exporter) => _exporter = exporter;
            public IActionResult Run(string q)
            {
                _exporter.Export(q);
                return Ok();
            }
        }
        """;

    [Fact]
    public void A_call_the_class_hierarchy_resolves_to_several_implementations_is_medium() =>
        Expect(Exporters.Replace("@CSV@", "/*medium*/", StringComparison.Ordinal).Replace("@XML@", "/*medium*/", StringComparison.Ordinal));

    [Fact]
    public void A_call_resolved_by_a_registration_is_high() =>
        Expect(Exporters.Replace("@CSV@", "/*high*/", StringComparison.Ordinal).Replace("@XML@", "", StringComparison.Ordinal) + """
            public static class Registration
            {
                public static void Add(IServiceCollection services) => services.AddScoped<IExporter, CsvExporter>();
            }
            """);

    [Fact]
    public void A_call_the_class_hierarchy_resolves_to_one_implementation_is_high() => Expect("""
        public interface IReport { void Run(string filter); }
        public class SqlReport : IReport
        {
            private readonly SqlConnection _c = new();
            public void Run(string filter) => _c.Execute("SELECT * FROM r WHERE " + filter); /*high*/
        }
        public class ReportController : ControllerBase
        {
            private readonly IReport _report;
            public ReportController(IReport report) => _report = report;
            public IActionResult Run(string q)
            {
                _report.Run(q);
                return Ok();
            }
        }
        """);

    [Fact]
    public void The_stats_count_the_findings_by_confidence()
    {
        var result = Snippet.Analyze(Exporters.Replace("@CSV@", "", StringComparison.Ordinal).Replace("@XML@", "", StringComparison.Ordinal) + """
            public class DirectController : ControllerBase
            {
                public IActionResult Run(string q) { new SqlConnection().Execute(q); return Ok(); }
            }
            """);

        Assert.Equal(1, result.Stats.HighFindings);
        Assert.Equal(2, result.Stats.MediumFindings);
    }
}
