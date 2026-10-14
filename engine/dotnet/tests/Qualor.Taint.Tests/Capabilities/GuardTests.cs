namespace Qualor.Taint.Tests.Capabilities;

/// Guards on the control-flow graph (models/README.md, `guards:`, "Allow-lists", "Equality"): a value is clean on the
/// branch where a check of it succeeded, and only there.
public sealed class GuardTests : ProbeModels
{
    private ModelSet RedirectModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
            args: [0]
        guards:
          - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl
            arg: 0
            clean-when: true
        """);

    [Fact]
    public void A_guard_cleans_the_checked_value_where_the_check_holds() => Expect(RedirectModels(), """
        public class AccountController : ControllerBase
        {
            public IActionResult A(string u)
            {
                if (Url.IsLocalUrl(u)) return Redirect(u);
                return Redirect(u); /*sink*/
            }
            public IActionResult B(string u)
            {
                if (!Url.IsLocalUrl(u)) return BadRequest();
                return Redirect(u);
            }
            public IActionResult C(string u) => Url.IsLocalUrl(u) ? Redirect(u) : Redirect(u); /*sink*/
            public IActionResult D(string u, string other)
            {
                if (u.Length > 3 && Url.IsLocalUrl(u)) Redirect(u);
                if (u.Length > 9 || !Url.IsLocalUrl(other)) throw new ArgumentException("x");
                Redirect(other);
                if (Url.IsLocalUrl(other)) return Redirect(u); /*sink*/
                return Ok();
            }
            public IActionResult E(string u)
            {
                var target = Url.IsLocalUrl(u) ? u : "/";
                return Redirect(target);
            }
        }
        """);

    [Fact]
    public void A_failing_branch_that_does_not_leave_or_reassigns_from_request_data_keeps_the_value() => Expect(RedirectModels(), """
        public class AccountController : ControllerBase
        {
            public IActionResult A(string u)
            {
                if (!Url.IsLocalUrl(u)) Console.WriteLine("not local");
                return Redirect(u); /*sink*/
            }
            public IActionResult B(string u)
            {
                if (!Url.IsLocalUrl(u))
                {
                    Redirect(u); /*sink*/
                    return BadRequest();
                }
                return Redirect(u);
            }
            public IActionResult C(string u, string v)
            {
                if (!Url.IsLocalUrl(u)) u = "/";
                Redirect(u);
                if (!Url.IsLocalUrl(v)) v = v + "/";
                return Redirect(v); /*sink*/
            }
            public IActionResult D(string u)
            {
                if (!Url.IsLocalUrl(u)) return BadRequest();
                u = Request.Query["again"].ToString();
                return Redirect(u); /*sink*/
            }
        }
        """);

    [Fact]
    public void A_guard_in_a_helper_cleans_what_the_helper_passes_on() => Expect(RedirectModels(), """
        public class Ticket { public string Destination { get; set; } = "/"; public string Hint { get; set; } = ""; }
        public class AccountController : ControllerBase
        {
            public IActionResult A(string u, string hint)
            {
                var t = Prepare(u, hint);
                Redirect(t.Hint); /*sink*/
                return Redirect(t.Destination);
            }
            private Ticket Prepare(string u, string hint)
            {
                var t = new Ticket { Hint = hint };
                if (!Url.IsLocalUrl(u)) return t;
                t.Destination = u;
                return t;
            }
        }
        """);

    private ModelSet ContainmentModels() => Probe("""
        sinks:
          - method: System.IO.File.ReadAllText
            args: [0]
        guards:
          - method: System.String.StartsWith
            arg: this
            clean-when: true
            when:
              - assigned-from: System.IO.Path.GetFullPath
              - arg: 0
                text: '[\\/]$'
        """);

    [Fact]
    public void A_guard_with_conditions_checks_how_the_value_was_assigned_and_the_text_of_an_argument() => Expect(ContainmentModels(), """
        public class FilesController : ControllerBase
        {
            private const string Root = "/srv/files";
            private readonly string _root = Environment.GetEnvironmentVariable("ROOT") ?? "/srv";
            public void Get(string name, string prefix)
            {
                var a = Path.GetFullPath(Path.Combine(Root, name));
                if (!a.StartsWith(Root + Path.DirectorySeparatorChar)) return;
                System.IO.File.ReadAllText(a);
                var b = Path.GetFullPath(Path.Combine(Root, name));
                if (!b.StartsWith(_root + "/")) return;
                System.IO.File.ReadAllText(b);
                var c = Path.GetFullPath(Path.Combine(Root, name));
                if (!c.StartsWith(Root)) return;
                System.IO.File.ReadAllText(c); /*sink*/
                var d = Path.GetFullPath(Path.Combine(Root, name));
                if (!d.StartsWith(prefix + "/")) return;
                System.IO.File.ReadAllText(d); /*sink*/
                var e = Path.Combine(Root, name);
                if (!e.StartsWith(Root + "/")) return;
                System.IO.File.ReadAllText(e); /*sink*/
                var f = Path.GetFullPath(Path.Combine(Root, name));
                if (f.StartsWith($"{_root}{Path.AltDirectorySeparatorChar}")) System.IO.File.ReadAllText(f);
                if (!f.StartsWith(Root + '/'))
                {
                    System.IO.File.ReadAllText(f); /*sink*/
                }
            }
        }
        """);

    private ModelSet ContextModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
            args: [0]
        guards:
          - method: Acme.IInteraction.GetContextAsync
            arg: 0
            clean-when: not-null
        """);

    [Fact]
    public void A_not_null_guard_cleans_the_argument_where_the_held_result_is_not_null() => Expect(ContextModels(), """
        namespace Acme
        {
            public interface IInteraction { Task<object?> GetContextAsync(string returnUrl); }
            public class LoginController : ControllerBase
            {
                private readonly IInteraction _i;
                public LoginController(IInteraction i) => _i = i;
                public async Task<IActionResult> A(string u, string v, string w)
                {
                    var context = await _i.GetContextAsync(u);
                    if (context != null) Redirect(u);
                    else Redirect(u); /*sink*/
                    var other = await _i.GetContextAsync(v).ConfigureAwait(false);
                    if (other is null) return BadRequest();
                    Redirect(v);
                    var third = await _i.GetContextAsync(w);
                    if (third is not null) Redirect(v);
                    return Redirect(w); /*sink*/
                }
            }
        }
        """);

    private ModelSet TableModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Content
            args: [0]
            param-types: [System.String]
        sanitizers:
          - allow-list: literal-tables
        """);

    [Fact]
    public void Lookups_in_a_table_of_constants_that_nothing_changes_are_clean() => Expect(TableModels(), """
        public class ListController : ControllerBase
        {
            private const string Asc = "ASC";
            private static readonly Dictionary<string, string> Columns = new() { ["name"] = "name", ["price"] = "unit_price" };
            private static readonly Dictionary<string, string> Sorts = new(StringComparer.OrdinalIgnoreCase) { { "a", Asc }, { "d", "DESC" } };
            private static readonly string[] Regions = { "eu", "us" };
            private static readonly HashSet<string> Grown = new() { "a" };
            private static readonly Dictionary<string, string> Changed = new() { ["a"] = "b" };
            private static readonly Dictionary<string, string> Computed = new() { ["a"] = Environment.MachineName };
            private readonly Dictionary<string, string> _instance = new() { ["a"] = "b" };
            private static Dictionary<string, string> Writable = new() { ["a"] = "b" };
            public void Get(string k, string i)
            {
                Content(Columns[k]);
                Content(Columns.GetValueOrDefault(k, "name"));
                Content(Columns.GetValueOrDefault(k));
                Content(Columns.GetValueOrDefault(k, k)); /*sink*/
                if (Sorts.TryGetValue(k, out var sort)) Content(sort);
                Content(Regions[int.Parse(i)]);
                Content(Changed[k]); /*sink*/
                Content(Computed[k]); /*sink*/
                Content(_instance[k]); /*sink*/
                Content(Writable[k]); /*sink*/
            }
            public void Grow(string k, string v)
            {
                Grown.Add(k);
                Changed[k] = v;
            }
        }
        """);

    [Fact]
    public void Membership_in_a_table_cleans_the_checked_value_where_it_holds() => Expect(TableModels(), """
        public class ListController : ControllerBase
        {
            private static readonly HashSet<string> Directions = new(StringComparer.OrdinalIgnoreCase) { "ASC", "DESC" };
            private static readonly string[] Regions = ["eu", "us"];
            private static readonly List<string> Grown = new() { "a" };
            private static readonly Dictionary<string, string> Reports = new() { ["daily"] = "d.csv" };
            public void Get(string dir, string region, string g, string r, string fallback)
            {
                Content(Directions.Contains(dir) ? dir : "ASC");
                Content(Directions.Contains(dir) ? dir : fallback); /*sink*/
                Content(Enumerable.Contains(Regions, region) ? region : "eu");
                Content(Reports.Keys.Contains(r) ? r : "daily");
                if (!Grown.Contains(g)) return;
                Content(g); /*sink*/
                if (!Regions.Contains(region))
                {
                    Content(region); /*sink*/
                    return;
                }
                Content(region);
                if (!Reports.ContainsKey(r)) throw new ArgumentException(r);
                Content(r);
                Content(Directions.Equals(dir) ? dir : "x"); /*sink*/
            }
            public void Grow(string v) => Grown.Insert(0, v);
        }
        """);

    [Fact]
    public void A_value_equal_to_a_constant_is_clean_where_it_is_equal() => Expect(TableModels(), """
        public class ListController : ControllerBase
        {
            public void Get(string dir, string mode, string other)
            {
                if (dir != "ASC" && dir != "DESC") return;
                Content(dir);
                if (mode == "x") Content(mode);
                if (mode.Equals("y")) Content(mode);
                if (string.Equals(mode, "z", StringComparison.OrdinalIgnoreCase)) Content(mode);
                if (mode is "a" or "b") Content(mode);
                Content(mode); /*sink*/
                if (mode == other) Content(mode); /*sink*/
                if (mode != "q") Content(mode); /*sink*/
            }
        }
        """);

    [Fact]
    public void Guards_and_their_conditions_are_read()
    {
        var path = Assert.Single(ContainmentModels().Rules.Single(r => r.RuleId == Rule).Guards);
        Assert.Equal(-1, path.Arg);
        Assert.Equal(GuardKind.Result, path.Kind);
        Assert.Equal(new[] { GuardConditionKind.AssignedFrom, GuardConditionKind.ArgumentText }, path.When.Select(c => c.Kind));
        Assert.Equal(GuardKind.NotNull, Assert.Single(ContextModels().Rules.Single(r => r.RuleId == Rule).Guards).Kind);
        Assert.True(TableModels().Rules.Single(r => r.RuleId == Rule).AllowLists);

        foreach (var (yaml, line) in new[]
        {
            ("guards:\n  - method: A.B\n    arg: this\n    clean-when: not-null\n", 8),
            ("guards:\n  - method: A.B\n    arg: 0\n    clean-when: true\n    when: []\n", 10),
            ("guards:\n  - method: A.B\n    arg: 0\n    clean-when: true\n    when:\n      - text: x\n", 11),
            ("guards:\n  - method: A.B\n    arg: 0\n    clean-when: true\n    when:\n      - assigned-from: A.C\n        arg: 0\n", 12),
            ("sanitizers:\n  - allow-list: tables\n", 7),
        })
        {
            var e = Assert.Throws<ModelException>(() => Probe("sinks:\n  - method: A.B\n    args: [0]\n" + yaml));
            Assert.Equal(line, e.Line);
        }
    }
}
