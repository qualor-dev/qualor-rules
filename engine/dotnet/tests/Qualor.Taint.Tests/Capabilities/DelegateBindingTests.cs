using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 35: a lambda given to one of .NET's members gets in each parameter what the member's documented signature passes
/// there (a dictionary's factory: the key, then the factory argument; a list's or an array's callback: an element; a
/// LINQ selector: an element of its own sequence; a task's state), no longer the join of the receiver and every
/// argument; a parameter whose binding is not documented here keeps that join.
public sealed class DelegateBindingTests
{
    private static void ExpectPath(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.path-traversal"));

    private const string Usings = """
        using System.Collections.Concurrent;

        """;

    [Fact]
    public void A_factory_gets_the_key_and_the_factory_argument_apart() => ExpectPath(Usings + """
        public sealed record Library(string Folder, string Extension);
        public class TopicsController : ControllerBase
        {
            private static readonly HashSet<string> Known = new() { "intro", "faq" };
            private readonly ConcurrentDictionary<string, string> _texts = new();
            private readonly Library _library = new("/srv/topics", ".md");
            public string Registered(string code) => _texts.GetOrAdd(code, (c, lib) =>
            {
                var file = Path.Combine(lib.Folder, c + lib.Extension);
                return Known.Contains(c) ? System.IO.File.ReadAllText(file) : "";
            }, _library);
            public string FixedFolder(string code) => _texts.GetOrAdd(code, static (c, folder) => System.IO.File.ReadAllText(Path.Combine(folder, "index.md")), "/srv/topics");
            public string KeyRead(string code) => _texts.GetOrAdd(code, static (c, owner) => System.IO.File.ReadAllText(c), this); /*sink*/
            public string ArgumentRead(string code, string folder) => _texts.GetOrAdd(code, static (c, f) => System.IO.File.ReadAllText(Path.Combine(f, "index.md")), folder); /*sink*/
            public string KeyOnly(string code) => _texts.GetOrAdd(code, c => System.IO.File.ReadAllText(c)); /*sink*/
        }
        """);

    [Fact]
    public void An_update_factory_gets_the_stored_value_as_given() => ExpectPath(Usings + """
        public class CountersController : ControllerBase
        {
            private readonly ConcurrentDictionary<string, string> _last = new();
            public void Touch(string name, string path) =>
                _last.AddOrUpdate(name, k => "/srv/new", (k, old) => { System.IO.File.Delete(old); return path; }); /*sink*/
        }
        """);

    [Fact]
    public void A_linq_selector_gets_the_elements_of_its_own_sequence() => ExpectPath("""
        public class PairsController : ControllerBase
        {
            private static readonly string[] Fixed = { "/srv/a", "/srv/b" };
            public void Left(string[] names) => Fixed.Zip(names, (a, b) => System.IO.File.ReadAllText(a)).ToList();
            public void Right(string[] names) => Fixed.Zip(names, (a, b) => System.IO.File.ReadAllText(b)).ToList(); /*sink*/
            public void Joined(string[] names) =>
                Fixed.Join(names, a => a.Length, b => b.Length, (a, b) => System.IO.File.ReadAllText(a)).ToList();
            public void Selected(string[] names) => names.Select(n => System.IO.File.ReadAllText(n)).ToList(); /*sink*/
            public void Indexed(string[] names) => Fixed.Select((f, i) => System.IO.File.ReadAllText(f)).ToList();
        }
        """);

    [Fact]
    public void Join_key_selectors_get_their_own_side() => ExpectPath("""
        public class MatchController : ControllerBase
        {
            private static readonly string[] Known = { "/srv/a", "/srv/b" };
            public void OuterKeyReads(string[] asked) =>
                Known.Join(asked, k => System.IO.File.ReadAllText(k), q => q, (k, q) => k).ToList();
            public void InnerKeyReads(string[] asked) =>
                Known.Join(asked, k => k, q => System.IO.File.ReadAllText(q), (k, q) => k).ToList(); /*sink*/
            public void GroupedOuterKey(string[] asked) =>
                Known.GroupJoin(asked, k => System.IO.File.ReadAllText(k), q => q, (k, g) => k).ToList();
            public void GroupedInnerKey(string[] asked) =>
                Known.GroupJoin(asked, k => k, q => System.IO.File.ReadAllText(q), (k, g) => k).ToList(); /*sink*/
        }
        """);

    [Fact]
    public void A_continuation_gets_the_task_and_its_state_apart() => ExpectPath("""
        public class LaterController : ControllerBase
        {
            public void StateRead(string path) =>
                Task.FromResult("/srv/done").ContinueWith((done, s) => System.IO.File.Delete((string)s!), path); /*sink*/
            public void TaskRead(string path) =>
                Task.FromResult("/srv/done").ContinueWith((done, s) => System.IO.File.Delete(done.Result), path);
            public void RequestTask(string path) =>
                Task.FromResult(path).ContinueWith(done => System.IO.File.Delete(done.Result)); /*sink*/
        }
        """);

    [Fact]
    public void A_list_or_array_callback_gets_an_element() => ExpectPath("""
        public class CleanupController : ControllerBase
        {
            public void Posted([FromBody] List<string> paths) => paths.ForEach(p => System.IO.File.Delete(p)); /*sink*/
            public void PostedArray([FromBody] string[] paths) => Array.ForEach(paths, p => System.IO.File.Delete(p)); /*sink*/
            public void Found([FromBody] List<string> paths) => System.IO.File.Delete(paths.Find(p => p.Length > 0)!); /*sink*/
        }
        """);

    [Fact]
    public void A_task_gets_its_state_and_an_unknown_binding_keeps_the_join() => ExpectPath("""
        public class JobsController : ControllerBase
        {
            public void Started(string path) => Task.Factory.StartNew(s => System.IO.File.Delete((string)s!), path); /*sink*/
            public void Folded(string[] names) =>
                names.Aggregate("/srv", (acc, n) => { System.IO.File.Delete(acc); return acc + n; }); /*sink*/
        }
        """);
}
