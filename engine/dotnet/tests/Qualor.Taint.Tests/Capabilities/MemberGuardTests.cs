namespace Qualor.Taint.Tests.Capabilities;

/// Guards on a member (Task 21; models/README.md, "Guards on members"): a check of `x.M` (or `x.M.N`) makes that access
/// path clean on the branch where the check succeeded. A write to x, to x.M or to a prefix of the path, a ref or out use of
/// x, or a call that may change x ends it; where branches meet, the path stays clean only if it is clean on every one of
/// them. Other members of x keep their taint.
public sealed class MemberGuardTests : ProbeModels
{
    private ModelSet Models() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
            args: [0]
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Content
            args: [0]
            param-types: [System.String]
        guards:
          - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl
            arg: 0
            clean-when: true
          - method: Acme.IInteraction.GetContextAsync
            arg: 0
            clean-when: not-null
        sanitizers:
          - allow-list: literal-tables
        """);

    /// The types the snippets share (no finding is expected in them).
    private const string Prelude = """
        using Acme;
        namespace Acme
        {
            public class SignInContext { public string Client { get; set; } = ""; }
            public interface IInteraction { Task<SignInContext?> GetContextAsync(string returnUrl); }
            public class Paging { public string ReturnUrl { get; set; } = ""; public string Sort { get; set; } = ""; }
            public class SignInForm
            {
                public string User { get; set; } = "";
                public string Password { get; set; } = "";
                public bool Remember { get; set; }
                public string ReturnUrl { get; set; } = "";
                public string FallbackUrl { get; set; } = "";
                public Paging Paging { get; set; } = new();
                public void UseFallback() => ReturnUrl = FallbackUrl;
                public string Host { get; set; } = "";
                public string Path { get; set; } = "";
                public string Joined => Host + Path;
                public string Raw = "";
                public string Alias { get => FallbackUrl; set { ReturnUrl = value; } }
            }
            public class Holder
            {
                public SignInForm Form;
                public Holder(SignInForm form) { Form = form; }
                public void Reset() => Form.ReturnUrl = Form.FallbackUrl;
            }
            public struct FormRef { public SignInForm Form; }
            public static class FormOps
            {
                public static void Reset(SignInForm form) => form.ReturnUrl = form.FallbackUrl;
                public static void ResetMany(List<SignInForm> forms) { foreach (var f in forms) f.ReturnUrl = f.FallbackUrl; }
                public static void ResetPair((SignInForm Form, int N) pair) => pair.Form.ReturnUrl = pair.Form.FallbackUrl;
                public static void ResetRef(FormRef r) => r.Form.ReturnUrl = r.Form.FallbackUrl;
                public static async Task ResetLaterAsync(SignInForm form) { await Task.Yield(); form.ReturnUrl = form.FallbackUrl; }
                public static int Count(List<string> names, (string Name, int N) pair, CancellationToken token) => names.Count + pair.N;
            }
            public class ListQuery { public string Sort { get; set; } = ""; public string Dir { get; set; } = ""; public string Kind { get; set; } = ""; }
        }

        """;

    private void Check(string code) => Expect(Models(), Prelude + code);

    /// Member guards on a posted form's return URL, in shapes of our own: the interaction service's context guard (its
    /// documented contract: no context for a return URL it does not know) and Url.IsLocalUrl, each with a call between the
    /// check and the redirect that is given only another member of the form; and a save action redirecting through a
    /// shared helper (its plain and its escaped redirect) only where Url.IsLocalUrl holds for the form's return URL.
    [Fact]
    public void Member_guards_on_a_posted_return_url_are_quiet() => Check("""
        public interface IAudit { Task NoteAsync(string user); }
        public static class RedirectExtensions
        {
            public static IActionResult Go(this ControllerBase controller, string url, bool escaped)
            {
                if (!escaped) return controller.Redirect(url);
                return controller.Redirect(Uri.EscapeDataString(url));
            }
        }
        public class ReturnController : Controller
        {
            private readonly IInteraction _interaction;
            private readonly IAudit _audit;
            public ReturnController(IInteraction interaction, IAudit audit) { _interaction = interaction; _audit = audit; }
            public async Task<IActionResult> Resume(SignInForm form)
            {
                var context = await _interaction.GetContextAsync(form.ReturnUrl);
                if (context == null) return BadRequest();
                await _audit.NoteAsync(form.User);
                return Redirect(form.ReturnUrl);
            }
            public async Task<IActionResult> Back(SignInForm form)
            {
                if (!Url.IsLocalUrl(form.ReturnUrl)) return Redirect("/");
                await _audit.NoteAsync(form.User);
                return Redirect(form.ReturnUrl);
            }
            public IActionResult Save(SignInForm form) => Url.IsLocalUrl(form.ReturnUrl) ? this.Go(form.ReturnUrl, true) : RedirectToAction("Index");
        }
        """);

    /// Task 11's guard shapes, on members: if, a failing check that leaves, a ternary, && and ||, a null-conditional
    /// access, the not-null guard (ConfigureAwait, `is null`), a member of a member, a bound property of the controller.
    [Fact]
    public void The_model_guard_shapes_hold_for_a_member() => Check("""
        public class ShapesController : Controller
        {
            private readonly IInteraction _interaction;
            public ShapesController(IInteraction interaction) => _interaction = interaction;
            [BindProperty] public string Next { get; set; } = "";
            public IActionResult A(SignInForm f)
            {
                if (Url.IsLocalUrl(f.ReturnUrl)) Redirect(f.ReturnUrl);
                Redirect(f.ReturnUrl); /*sink*/
                if (f.User.Length > 1 && Url.IsLocalUrl(f.FallbackUrl)) Redirect(f.FallbackUrl);
                if (!Url.IsLocalUrl(f.Paging.ReturnUrl)) return BadRequest();
                Redirect(f.Paging.ReturnUrl);
                return Redirect(Url.IsLocalUrl(f.ReturnUrl) ? f.ReturnUrl : "/");
            }
            public IActionResult B(SignInForm f)
            {
                if (f.User.Length > 9 || !Url.IsLocalUrl(f.ReturnUrl)) throw new ArgumentException("x");
                return Redirect(f.ReturnUrl);
            }
            public async Task<IActionResult> C(SignInForm f)
            {
                var context = await _interaction.GetContextAsync(f.ReturnUrl).ConfigureAwait(false);
                if (context is null) return Redirect(f.ReturnUrl); /*sink*/
                return Redirect(f.ReturnUrl);
            }
            public IActionResult D()
            {
                if (!Url.IsLocalUrl(Next)) return BadRequest();
                return Redirect(Next);
            }
            public IActionResult E(SignInForm? f) => Url.IsLocalUrl(f?.ReturnUrl) ? Redirect(f?.ReturnUrl!) : Redirect("/");
        }
        """);

    /// Task 11's allow-list membership and equality on members (a switch on a member too).
    [Fact]
    public void Membership_and_equality_hold_for_a_member() => Check("""
        public class ListController : Controller
        {
            private static readonly HashSet<string> Sorts = new(StringComparer.OrdinalIgnoreCase) { "name", "date" };
            private static readonly Dictionary<string, string> Columns = new() { ["name"] = "name" };
            private static readonly string[] Kinds = ["a", "b"];
            public void Get(ListQuery q)
            {
                if (!Sorts.Contains(q.Sort)) return;
                Content(q.Sort);
                if (Columns.ContainsKey(q.Dir)) Content(q.Dir);
                if (Enumerable.Contains(Kinds, q.Kind)) Content(q.Kind);
                if (Columns.Keys.Contains(q.Dir)) Content(q.Dir);
                Content(q.Dir); /*sink*/
            }
            public void Eq(ListQuery q)
            {
                if (q.Dir != "ASC" && q.Dir != "DESC") return;
                Content(q.Dir);
                if (q.Kind == "x") Content(q.Kind);
                if (q.Kind.Equals("y")) Content(q.Kind);
                if (string.Equals(q.Kind, "z", StringComparison.OrdinalIgnoreCase)) Content(q.Kind);
                if (q.Kind is "a" or "b") Content(q.Kind);
                switch (q.Sort)
                {
                    case "name":
                        Content(q.Sort);
                        break;
                    default:
                        Content(q.Sort); /*sink*/
                        break;
                }
                if (q.Kind == q.Sort) Content(q.Kind); /*sink*/
                if (q.Kind != "q") Content(q.Kind); /*sink*/
            }
        }
        """);

    /// What ends a member guard, or never was one: a write of the member, of the variable or of a prefix; the failing
    /// branch; another member; a write through a copy of the variable taken before the check, and a read through it; a ref
    /// argument; a call given the object (typed as it is or as object), called on it, or on the controller holding a bound
    /// property; a lambda that writes the member; a check on one branch only; a write between the not-null guard's call
    /// and its null check (and the null check of an earlier call's result after the member was written and checked again).
    [Fact]
    public void Writes_calls_aliases_and_other_branches_end_a_member_guard() => Check("""
        public class NegativeController : Controller
        {
            private readonly IInteraction _interaction;
            public NegativeController(IInteraction interaction) => _interaction = interaction;
            [BindProperty] public string Next { get; set; } = "";
            public IActionResult Member(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                f.ReturnUrl = f.FallbackUrl;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult Variable(SignInForm f, SignInForm g)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                f = g;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult Prefix(SignInForm f, Paging p)
            {
                if (!Url.IsLocalUrl(f.Paging.ReturnUrl)) return BadRequest();
                f.Paging = p;
                return Redirect(f.Paging.ReturnUrl); /*sink*/
            }
            public IActionResult FailingBranch(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl))
                {
                    return Redirect(f.ReturnUrl); /*sink*/
                }
                return Redirect(f.ReturnUrl);
            }
            public IActionResult OtherMember(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Redirect(f.FallbackUrl); /*sink*/
                return Redirect(f.Paging.ReturnUrl); /*sink*/
            }
            public IActionResult AliasWrite(SignInForm f)
            {
                var copy = f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                copy.ReturnUrl = f.FallbackUrl;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult AliasRead(SignInForm f)
            {
                var copy = f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                return Redirect(copy.ReturnUrl); /*sink*/
            }
            public IActionResult ByRef(SignInForm f, SignInForm g)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Replace(ref f, g);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult GivenToACall(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Reset(f);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult GivenAsObject(SignInForm f)
            {
                object boxed = f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Touch(boxed);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult CalledOn(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                f.UseFallback();
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult OwnCall()
            {
                if (!Url.IsLocalUrl(Next)) return BadRequest();
                Clear();
                return Redirect(Next); /*sink*/
            }
            public IActionResult InALambda(SignInForm f, List<string> urls)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                urls.ForEach(u => f.ReturnUrl = u);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult OneBranch(SignInForm f, bool strict)
            {
                if (strict && !Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult BothBranches(SignInForm f, bool strict)
            {
                if (strict)
                {
                    if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                }
                else if (f.ReturnUrl != "/home")
                {
                    return BadRequest();
                }
                return Redirect(f.ReturnUrl);
            }
            public async Task<IActionResult> Late(SignInForm f, SignInForm g)
            {
                var context = await _interaction.GetContextAsync(f.ReturnUrl);
                f.ReturnUrl = g.ReturnUrl;
                if (context == null) return BadRequest();
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public async Task<IActionResult> Rechecked(SignInForm f, SignInForm g)
            {
                var first = await _interaction.GetContextAsync(f.ReturnUrl);
                f.ReturnUrl = g.ReturnUrl;
                var second = await _interaction.GetContextAsync(f.ReturnUrl);
                if (first == null) return BadRequest();
                Redirect(f.ReturnUrl); /*sink*/
                if (second == null) return BadRequest();
                return Redirect(f.ReturnUrl);
            }
            private static void Replace(ref SignInForm target, SignInForm with) => target = with;
            private static void Reset(SignInForm form) => form.ReturnUrl = form.FallbackUrl;
            private void Clear() => Next = "";
            private static void Touch(object o)
            {
                if (o is SignInForm s) s.ReturnUrl = s.FallbackUrl;
            }
        }
        """);

    /// In a loop: a check in each iteration holds for that iteration; a write later in the body, or the variable taken
    /// for the next element, reaches the loop's head and ends a check made before the loop.
    [Fact]
    public void A_member_guard_in_a_loop_holds_until_the_back_edge_brings_a_write() => Check("""
        public class LoopController : Controller
        {
            public void Each(List<SignInForm> forms)
            {
                foreach (var f in forms)
                {
                    if (!Url.IsLocalUrl(f.ReturnUrl)) continue;
                    Redirect(f.ReturnUrl);
                }
            }
            public void Kept(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return;
                for (var i = 0; i < 3; i++) Redirect(f.ReturnUrl);
            }
            public void Rewritten(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return;
                for (var i = 0; i < 3; i++)
                {
                    Redirect(f.ReturnUrl); /*sink*/
                    f.ReturnUrl = f.FallbackUrl;
                }
            }
            public void Reassigned(List<SignInForm> forms)
            {
                var f = forms[0];
                if (!Url.IsLocalUrl(f.ReturnUrl)) return;
                foreach (var g in forms)
                {
                    Redirect(f.ReturnUrl); /*sink*/
                    f = g;
                }
            }
        }
        """);

    /// Fix round 1 (review I1): a lambda or local function that calls a method on the object or gives it to a call, a
    /// method-group delegate bound to it, a task started with it in a lambda: each may change the member at any later
    /// call, so the check on it is no guard. A lambda that only reads the object keeps the guard.
    [Fact]
    public void Nested_bodies_and_method_groups_that_may_change_the_object_end_a_member_guard() => Check("""
        public class NestedController : Controller
        {
            public IActionResult Bound(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Action later = f.UseFallback;
                later();
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult LambdaCallsOn(SignInForm f, List<string> names)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                names.ForEach(n => f.UseFallback());
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult LambdaGives(SignInForm f, List<string> names)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                names.ForEach(n => FormOps.Reset(f));
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public async Task<IActionResult> Started(SignInForm f)
            {
                var work = Task.Run(() => FormOps.Reset(f));
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                await work;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult LocalFunction(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                Restore();
                return Redirect(f.ReturnUrl); /*sink*/
                void Restore() => f.UseFallback();
            }
            public IActionResult ReadOnlyLambda(SignInForm f, List<string> names)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                var hits = names.Count(n => n == f.User);
                return Redirect(f.ReturnUrl);
            }
        }
        """);

    /// Fix round 1 (review I2): a property of the project with a getter body (computed, or backed by a field) reads
    /// state that a write of something else changes: a check on it is no guard.
    [Fact]
    public void A_path_through_a_computed_or_field_backed_property_is_no_guard() => Check("""
        public class ComputedController : Controller
        {
            private string _next = "";
            public string Next { get => _next; set => _next = value; }
            public IActionResult Computed(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.Joined)) return BadRequest();
                f.Path = f.FallbackUrl;
                return Redirect(f.Joined); /*sink*/
            }
            public IActionResult Backed(SignInForm f)
            {
                Next = f.ReturnUrl;
                if (!Url.IsLocalUrl(Next)) return BadRequest();
                _next = f.FallbackUrl;
                return Redirect(Next); /*sink*/
            }
        }
        """);

    /// Fix round 1 (review I3): a call given a collection, a tuple, a struct or an object that holds the guarded object
    /// may change it; one given only strings, numbers, a token and a collection of strings does not.
    [Fact]
    public void A_call_given_what_holds_the_object_ends_a_member_guard() => Check("""
        public class HeldController : Controller
        {
            public IActionResult Wrapped(SignInForm f)
            {
                var holder = new Holder(f);
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                holder.Reset();
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult InAList(SignInForm f)
            {
                var forms = new List<SignInForm> { f };
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                FormOps.ResetMany(forms);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult InATuple(SignInForm f)
            {
                var pair = (f, 1);
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                FormOps.ResetPair(pair);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult InAStruct(SignInForm f)
            {
                var r = new FormRef { Form = f };
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                FormOps.ResetRef(r);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult Unrelated(SignInForm f, List<string> names, CancellationToken token)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                FormOps.Count(names, ("a", 1), token);
                return Redirect(f.ReturnUrl);
            }
        }
        """);

    /// Fix round 1 (review M1, M2, M3): a write through a ref local (to the member or to the variable), a dynamic call,
    /// and an await of a task started before the check (it was given the object) end every member guard.
    [Fact]
    public void Ref_locals_dynamic_calls_and_earlier_tasks_end_member_guards() => Check("""
        public class IndirectController : Controller
        {
            public IActionResult RefToMember(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.Raw)) return BadRequest();
                ref string slot = ref f.Raw;
                slot = f.FallbackUrl;
                return Redirect(f.Raw); /*sink*/
            }
            public IActionResult RefToVariable(SignInForm f, SignInForm g)
            {
                ref SignInForm slot = ref f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                slot = g;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult Dynamic(SignInForm f)
            {
                dynamic d = f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                FormOps.Reset(d);
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public async Task<IActionResult> EarlierTask(SignInForm f)
            {
                var pending = FormOps.ResetLaterAsync(f);
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                await pending;
                return Redirect(f.ReturnUrl); /*sink*/
            }
        }
        """);

    /// Fix round 1 (review M4): a setter with a body runs code on its object (here it writes the guarded member), and an
    /// assignment the engine does not follow (a dynamic member) may write anything.
    [Fact]
    public void A_setter_with_a_body_and_an_unfollowed_assignment_end_a_member_guard() => Check("""
        public class SetterController : Controller
        {
            public IActionResult Setter(SignInForm f)
            {
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                f.Alias = f.FallbackUrl;
                return Redirect(f.ReturnUrl); /*sink*/
            }
            public IActionResult DynamicMember(SignInForm f)
            {
                dynamic d = f;
                if (!Url.IsLocalUrl(f.ReturnUrl)) return BadRequest();
                d.ReturnUrl = f.FallbackUrl;
                return Redirect(f.ReturnUrl); /*sink*/
            }
        }
        """);
}
