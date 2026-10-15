using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 35: three more guards as project code writes them (models/README.md, "Guards in project code").
/// - Provenance: a check that makes a value one of the server's (membership, a registered key found, equality with a
///   constant) also cleans a local computed from that value alone before the check.
/// - A containment helper whose "is the root itself" answer is an early `return true` of its own (the path it is given
///   normalised again, which changes nothing for a full path).
/// - A value checked for directory separators (both of them where a platform has two) is a single segment.
/// Each with the controls that must stay found.
public sealed class GuardLeverTests
{
    private static void ExpectPath(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, "csharp.path-traversal"));

    // ---- (a) provenance ----

    private const string Catalog = """
        public sealed class Entry { public string Code { get; init; } = ""; public int Size { get; init; } }
        public static class Disk { public const string Root = "/srv/catalog"; }
        """;

    [Fact]
    public void A_registered_key_found_cleans_a_path_computed_from_the_key_alone_before_the_search() => ExpectPath(Catalog + """
        public class CatalogController : ControllerBase
        {
            private readonly Entry[] _entries;
            public CatalogController() => _entries = new[] { new Entry { Code = "maps", Size = 1 }, new Entry { Code = "logs", Size = 2 } };
            private readonly List<Entry> _shelf = new() { new Entry { Code = "maps" } };
            private string Blob(string code) => $"{Disk.Root}/{code.ToUpperInvariant()}.bin";
            public string ByHelper(string code)
            {
                string target = Blob(code);
                if (_shelf.Find(e => e.Code == code) == null) return "missing";
                return System.IO.File.ReadAllText(target);
            }
            public string Chained(string code)
            {
                var lower = code.ToLowerInvariant();
                var target = Path.Combine(Disk.Root, lower, "index.dat");
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target);
            }
            public string FirstFound(string code)
            {
                string target = $"{Disk.Root}/{code}.dat";
                var entry = _entries.First(e => e.Code == code);
                return System.IO.File.ReadAllText(target) + entry.Size;
            }
        }
        """);

    [Fact]
    public void A_value_computed_from_the_key_and_other_request_data_stays_found() => ExpectPath(Catalog + """
        public class CatalogController : ControllerBase
        {
            private readonly Entry[] _entries;
            public CatalogController() => _entries = new[] { new Entry { Code = "maps" } };
            private string LocateUnder(string code) => Path.Combine(Request.Query["area"].ToString(), code);
            public string OtherArgument(string code, string suffix)
            {
                string target = $"{Disk.Root}/{code}{suffix}";
                if (_entries.FirstOrDefault(e => e.Code == code) == null) return "unknown";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
            public string HelperReadsTheRequest(string code)
            {
                var target = LocateUnder(code);
                var known = _entries.Single(e => e.Code == code);
                return System.IO.File.ReadAllText(target) + known.Size; /*sink*/
            }
            public string SourceInPlace(string code)
            {
                var target = Path.Combine(Disk.Root, code, HttpContext.Request.Headers["X-Part"].ToString());
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
        }
        """);

    /// Request data that reaches the derived value by another way than the checked key: a stored prefix read in a helper
    /// or in place, the request's item store, a computed property or a method over a field the request wrote, a posted
    /// member through the item store, and the key written through a `ref` alias before the check.
    [Fact]
    public void A_derived_value_that_takes_request_data_by_another_way_stays_found() => ExpectPath("""
        public class ArchiveController : Controller
        {
            private const string Root = "/srv/archive";
            private static readonly string[] Shelves = { "old", "new" };
            private static string _prefix = "/srv/archive";
            private string[] _pieces = Array.Empty<string>();
            private string Tail => _pieces[1];
            private string TailOf() => _pieces[1];
            private string Outer() => Inner();
            private string Inner() => _pieces[1];
            private static readonly System.Text.StringBuilder Scratch = new();
            private static string Held() => Scratch.ToString();
            private static string Drain()
            {
                var sb = Scratch;
                return sb.ToString();
            }
            private static string Render(System.Text.StringBuilder sb) => sb.ToString();
            private static string Peek(AsyncLocal<string> slot) => slot.Value ?? "";
            private static readonly AsyncLocal<string> Ambient = new();
            private static IDictionary<object, object?> _bag = new Dictionary<object, object?>();
            private static string TailFromBag() => _bag.TryGetValue("tail", out var v) ? (string)v! : "";
            public void Prefix(string prefix) => _prefix = prefix;
            private static string UnderPrefix(string shelf) => Path.Combine(_prefix, shelf);
            public string StoredPrefixInHelper(string shelf)
            {
                var file = UnderPrefix(shelf);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string StoredPrefixInPlace(string shelf)
            {
                var file = Path.Combine(_prefix, shelf);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string ThroughItems(string pair)
            {
                var bits = pair.Split('|');
                HttpContext.Items["rest"] = bits[1];
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, (string)HttpContext.Items["rest"]!);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string ThroughProperty(string pair)
            {
                _pieces = pair.Split('|');
                var shelf = _pieces[0];
                var file = Path.Combine(Root, shelf, Tail);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string ThroughMethod(string pair)
            {
                _pieces = pair.Split('|');
                var shelf = _pieces[0];
                var file = Path.Combine(Root, shelf, TailOf());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string MemberThroughItems([FromBody] Shelf form)
            {
                HttpContext.Items["sub"] = form.Sub;
                var shelf = form.Name;
                var file = Path.Combine(Root, (string)HttpContext.Items["sub"]!, shelf);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string StaticBuilder(string pair)
            {
                var bits = pair.Split('|');
                Scratch.Clear();
                Scratch.Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Scratch.ToString());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string StaticBuilderInHelper(string pair)
            {
                var bits = pair.Split('|');
                Scratch.Clear();
                Scratch.Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Held());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string AmbientValue(string pair)
            {
                var bits = pair.Split('|');
                Ambient.Value = bits[1];
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Ambient.Value);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string StaticStoreAlias(string pair)
            {
                var bits = pair.Split('|');
                _bag = HttpContext.Items;
                HttpContext.Items["tail"] = bits[1];
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, (string)_bag["tail"]!);
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string StoreAliasInHelper(string pair)
            {
                var bits = pair.Split('|');
                _bag = HttpContext.Items;
                HttpContext.Items["tail"] = bits[1];
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, TailFromBag());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string BuilderCopiedInHelper(string pair)
            {
                var bits = pair.Split('|');
                Scratch.Clear();
                Scratch.Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Drain());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string BuilderGivenToHelper(string pair)
            {
                var bits = pair.Split('|');
                Scratch.Clear();
                Scratch.Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Render(Scratch));
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string BuilderFormattedInPlace(string pair)
            {
                var bits = pair.Split('|');
                Scratch.Clear();
                Scratch.Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, string.Format("{0}", Scratch));
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string AmbientGivenToHelper(string pair)
            {
                var bits = pair.Split('|');
                Ambient.Value = bits[1];
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, Peek(Ambient));
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string TwoHelpersDeep(string pair)
            {
                _pieces = pair.Split('|');
                var shelf = _pieces[0];
                var file = Path.Combine(Root, shelf, Outer());
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string LocalThroughRef(string shelf, string other)
            {
                var key = shelf;
                var file = Path.Combine(Root, key);
                ref var alias = ref key;
                alias = other;
                if (!Shelves.Contains(key)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string KeyThroughRef(string shelf, string other)
            {
                var file = Path.Combine(Root, shelf);
                ref string alias = ref shelf;
                alias = other;
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
        }
        public class Shelf { public string Name { get; set; } = ""; public string Sub { get; set; } = ""; }
        """);

    /// A project object handed to .NET code that may call its own override (ToString through Concat, an interpolation
    /// hole, `+` with a string, a generic parameter): the walk does not follow the override, so the derivation ends.
    [Fact]
    public void A_project_object_given_to_dotnet_code_that_may_call_its_override_stays_found() => ExpectPath("""
        public sealed class Label
        {
            public readonly System.Text.StringBuilder Text = new();
            public override string ToString() => Text.ToString();
        }
        public class TagController : ControllerBase
        {
            private const string Root = "/srv/tags";
            private static readonly string[] Shelves = { "old", "new" };
            private static readonly Label Current = new();
            public string Concatenated(string pair)
            {
                var bits = pair.Split('|');
                Current.Text.Clear().Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, string.Concat(Current));
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string Interpolated(string pair)
            {
                var bits = pair.Split('|');
                Current.Text.Clear().Append(bits[1]);
                var shelf = bits[0];
                var file = $"{Root}/{shelf}/{Current}";
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string Added(string pair)
            {
                var bits = pair.Split('|');
                Current.Text.Clear().Append(bits[1]);
                var shelf = bits[0];
                var file = Root + "/" + shelf + "/" + Current;
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
            public string Joined(string pair)
            {
                var bits = pair.Split('|');
                Current.Text.Clear().Append(bits[1]);
                var shelf = bits[0];
                var file = Path.Combine(Root, shelf, string.Join<Label>("", new List<Label> { Current }));
                if (!Shelves.Contains(shelf)) return "";
                return System.IO.File.ReadAllText(file); /*sink*/
            }
        }
        """);

    /// Uri.Equals ignores the user info and the fragment (learn.microsoft.com, Uri.Equals): a Uri found among known ones
    /// says nothing of a part computed from it, so provenance extends only from values compared as text (or numbers,
    /// enums).
    [Fact]
    public void A_part_computed_from_a_checked_uri_stays_found() => ExpectPath("""
        public class FeedController : ControllerBase
        {
            private const string Root = "/srv/feeds";
            private static readonly Uri[] Known = { new("https://feeds.example/a") };
            public string Piece(Uri feed)
            {
                var piece = feed.Fragment;
                if (!Known.Contains(feed)) return "";
                return System.IO.File.ReadAllText(Path.Combine(Root, piece)); /*sink*/
            }
        }
        """);

    [Fact]
    public void In_a_helper_only_the_keys_part_of_a_derived_value_is_cleaned() => ExpectPath(Catalog + """
        public class CatalogController : ControllerBase
        {
            private readonly Entry[] _entries;
            public CatalogController() => _entries = new[] { new Entry { Code = "maps" } };
            private string ReadIn(string code, string folder)
            {
                var target = Path.Combine(folder, code + ".dat");
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target);
            }
            private string ReadUnder(string code, string folder)
            {
                var target = Path.Combine(folder, code + ".dat");
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
            private string ReadSecond(string[] codes)
            {
                // the target also holds the first code, which only the same caller's value stands for
                var code = codes[0];
                var first = code;
                code = codes[1];
                var target = Path.Combine(Disk.Root, first, code);
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
            public string Fixed(string code) => ReadIn(code, Disk.Root);
            public string Chosen(string code, string folder) => ReadUnder(code, folder);
            public string Pair(string[] codes) => ReadSecond(codes);
        }
        """);

    [Fact]
    public void A_key_that_changed_or_failed_cleans_nothing_computed_from_it() => ExpectPath(Catalog + """
        public class CatalogController : ControllerBase
        {
            private readonly Entry[] _entries;
            public CatalogController() => _entries = new[] { new Entry { Code = "maps" } };
            public string FailingBranch(string code)
            {
                var target = Path.Combine(Disk.Root, code);
                if (_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
            public string KeyReplaced(string code, string other)
            {
                var target = Path.Combine(Disk.Root, code);
                code = other;
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
            public string TargetAssignedTwice(string code, bool flat, string other)
            {
                var target = Path.Combine(Disk.Root, code);
                if (flat) target = other;
                if (!_entries.Any(e => e.Code == code)) return "";
                return System.IO.File.ReadAllText(target); /*sink*/
            }
        }
        """);

    [Fact]
    public void Membership_and_equality_clean_derived_values_and_containment_does_not() => ExpectPath("""
        public class LogController : ControllerBase
        {
            private const string Root = "/srv/logs";
            private static readonly string[] Kinds = { "access", "error" };
            public string Member(string kind)
            {
                var file = Path.Combine(Root, kind + ".log");
                if (!Kinds.Contains(kind)) return "";
                return System.IO.File.ReadAllText(file);
            }
            public string Constant(string mode)
            {
                var file = Path.Combine(Root, mode + ".log");
                if (mode != "daily" && mode != "weekly") return "";
                return System.IO.File.ReadAllText(file);
            }
            public string Contained(string rel)
            {
                // a path below the root, with `..` added to it, may be outside
                var parent = rel + "/..";
                var full = Path.GetFullPath(Path.Combine(Root, rel));
                if (!full.StartsWith(Root + "/")) return "";
                return System.IO.File.ReadAllText(Path.Combine(Root, parent)); /*sink*/
            }
        }
        """);

    // ---- (b) a containment helper that answers "the root itself" on its own ----

    /// The base folder's own full path is accepted first; then anything under it with a slash after the base.
    private const string Bounds = """
        public static class Bounds
        {
            public static bool Holds(string candidate, string baseDir)
            {
                var baseFull = Path.GetFullPath(baseDir);
                var slashBase = baseFull + "/";
                var full = Path.GetFullPath(candidate);
                if (full == baseFull) return true;
                if (full.StartsWith(slashBase, StringComparison.OrdinalIgnoreCase)) return true;
                return false;
            }
        }
        """;

    [Fact]
    public void A_helper_that_returns_true_for_the_root_itself_guards_a_full_path() => ExpectPath(Bounds + """
        public class UploadController : ControllerBase
        {
            private const string Store = "/srv/uploads";
            public void Save(string name)
            {
                var target = Path.GetFullPath(Path.Combine(Store, name));
                if (Bounds.Holds(target, Store)) System.IO.File.WriteAllText(target, "");
            }
            public void SaveRaw(string name)
            {
                var target = Path.Combine(Store, name);
                if (!Bounds.Holds(target, Store)) return;
                System.IO.File.WriteAllText(target, "");
            }
            public void Batch(string[] names)
            {
                foreach (var n in names)
                {
                    string dest = Path.GetFullPath(Store + "/" + n);
                    if (!Bounds.Holds(dest, Store)) continue;
                    System.IO.File.AppendAllText(dest, "x");
                }
            }
        }
        """);

    [Fact]
    public void A_root_the_request_chooses_or_the_failing_branch_stays_found() => ExpectPath(Bounds + """
        public class UploadController : ControllerBase
        {
            private const string Store = "/srv/uploads";
            public void ChosenRoot(string folder, string name)
            {
                var target = Path.GetFullPath(Path.Combine(folder, name));
                if (Bounds.Holds(target, folder)) System.IO.File.WriteAllText(target, ""); /*sink*/
            }
            public void Failing(string name)
            {
                var target = Path.GetFullPath(Path.Combine(Store, name));
                if (Bounds.Holds(target, Store)) return;
                System.IO.File.WriteAllText(target, ""); /*sink*/
            }
            public void Other(string name, string other)
            {
                var target = Path.GetFullPath(Path.Combine(Store, name));
                if (!Bounds.Holds(target, Store)) return;
                System.IO.File.WriteAllText(other, ""); /*sink*/
            }
            public void RootChosenHere(string folder, string name)
            {
                // the root holds this request's data where the check runs
                var top = Path.GetFullPath(folder);
                var full = Path.GetFullPath(Path.Combine(top, name));
                if (full.Equals(top, StringComparison.Ordinal)) System.IO.Directory.Delete(full, true); /*sink*/
                if (!full.StartsWith(top + Path.DirectorySeparatorChar, StringComparison.Ordinal)) return;
                System.IO.File.WriteAllText(full, ""); /*sink*/
            }
        }
        """);

    [Fact]
    public void An_equality_with_a_stored_value_that_no_containment_check_uses_is_no_root() => ExpectPath("""
        public class RecentController : ControllerBase
        {
            private static string _last = "/srv/recent/a";
            public void Remember(string path) => _last = Path.GetFullPath(path);
            public void Again(string path)
            {
                var full = Path.GetFullPath(path);
                if (!full.Equals(_last, StringComparison.Ordinal)) return;
                System.IO.File.Delete(full); /*sink*/
            }
        }
        """);

    [Fact]
    public void An_early_true_for_anything_but_the_root_is_no_guard() => ExpectPath("""
        public static class Lax
        {
            public static bool Folder(string folder, string path)
            {
                var full = Path.GetFullPath(path);
                bool longName = full.Length > folder.Length + 40;
                if (longName) return true;
                var withSlash = Path.GetFullPath(folder) + "/";
                return full.StartsWith(withSlash, StringComparison.OrdinalIgnoreCase);
            }
            public static bool OtherRoot(string folder, string path, string other)
            {
                var full = Path.GetFullPath(path);
                var elsewhere = Path.GetFullPath(other);
                var under = full.StartsWith(Path.GetFullPath(folder) + "/", StringComparison.OrdinalIgnoreCase);
                return under || full == elsewhere;
            }
        }
        public class UploadController : ControllerBase
        {
            private const string Store = "/srv/uploads";
            public void Long(string name)
            {
                var target = Path.GetFullPath(Path.Combine(Store, name));
                if (Lax.Folder(Store, target)) System.IO.File.WriteAllText(target, ""); /*sink*/
            }
            public void Elsewhere(string name, string other)
            {
                var target = Path.GetFullPath(Path.Combine(Store, name));
                if (Lax.OtherRoot(Store, target, other)) System.IO.File.WriteAllText(target, ""); /*sink*/
            }
        }
        """);

    // ---- membership written as a counting loop (the stored-data check reads an element's collection, not its index) ----

    private const string Names = """
        public static class Names
        {
            public static bool Lists(string[] names, string name)
            {
                for (int n = 0; n < names.Length; n++)
                    if (string.Equals(names[n], name, StringComparison.Ordinal)) return true;
                return false;
            }
        }
        """;

    [Fact]
    public void An_element_read_by_a_counting_index_is_its_collections_data() => ExpectPath(Names + """
        public class ExportController : ControllerBase
        {
            private readonly string[] _formats = { "csv", "tsv" };
            private static readonly List<string> Recent = new();
            public void Remember(string format) => Recent.Add(format);
            public void Server(string format)
            {
                if (!Names.Lists(_formats, format)) throw new ArgumentException(format);
                System.IO.File.Create("/srv/export." + format);
            }
            public void Failing(string format)
            {
                if (Names.Lists(_formats, format)) return;
                System.IO.File.Create("/srv/export." + format); /*sink*/
            }
            public void RequestFilled(string format)
            {
                // another request writes the list
                if (!Names.Lists(Recent.ToArray(), format)) return;
                System.IO.File.Create("/srv/export." + format); /*sink*/
            }
        }
        """);

    // ---- (c) no directory separator ----

    [Fact]
    public void A_value_with_no_directory_separator_is_a_single_segment() => ExpectPath("""
        public class SubtitleController : ControllerBase
        {
            private const string Root = "/srv/subtitles";
            public void InvalidNameChars(string lang)
            {
                if (lang.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new ArgumentException(lang);
                System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
            public void SpanPair(string lang)
            {
                var lower = lang.ToLowerInvariant();
                if (lower.AsSpan().IndexOfAny(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) != -1) return;
                System.IO.File.WriteAllText(Path.Combine(Root, "movie." + lower + ".srt"), "");
            }
            public void BothFieldsJoined(string lang)
            {
                if (lang.Contains(Path.DirectorySeparatorChar) || lang.Contains(Path.AltDirectorySeparatorChar)) throw new ArgumentException(lang);
                System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
            public void BothLiteralsApart(string lang)
            {
                if (lang.Contains('/')) return;
                if (lang.IndexOf('\\') >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
            public void OrdinalStrings(string lang)
            {
                if (lang.IndexOf("/", StringComparison.Ordinal) >= 0 || lang.Contains('\\', StringComparison.OrdinalIgnoreCase)) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
            public void ContainsString(string lang)
            {
                // Contains(string) is an ordinal search
                if (lang.Contains("/") || lang.Contains("\\")) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
            public void PositiveBranch(string lang)
            {
                if (lang.IndexOfAny(new[] { '\\', '/' }) < 0) System.IO.File.WriteAllText(Path.Combine(Root, lang), "");
            }
        }
        """);

    [Fact]
    public void One_separator_checked_the_failing_branch_or_another_value_stays_found() => ExpectPath("""
        public class SubtitleController : ControllerBase
        {
            private const string Root = "/srv/subtitles";
            public void PrimaryOnly(string lang)
            {
                // on Windows `/` separates folders too
                if (lang.Contains(Path.DirectorySeparatorChar)) throw new ArgumentException(lang);
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void SlashOnly(string lang)
            {
                if (lang.IndexOf('/') >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void PathChars(string lang)
            {
                // the invalid path characters hold no separator
                if (lang.IndexOfAny(Path.GetInvalidPathChars()) >= 0) throw new ArgumentException(lang);
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void Failing(string lang)
            {
                if (lang.IndexOfAny(Path.GetInvalidFileNameChars()) < 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void Replaced(string lang, string other)
            {
                if (lang.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return;
                lang = other;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void AnotherValue(string lang, string other)
            {
                if (other.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void BuiltBeforeTheCheck(string lang, string folder)
            {
                // a single segment says nothing of a value computed from it earlier (no provenance for this check)
                var file = Path.Combine(lang, folder);
                if (lang.Contains('/') || lang.Contains('\\')) return;
                System.IO.File.WriteAllText(Path.Combine(Root, file), ""); /*sink*/
            }
            public void CultureString(string lang)
            {
                // IndexOf(string) compares by the current culture: a combining mark can hide a separator
                if (lang.IndexOf("/") >= 0 || lang.IndexOf("\\") >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void CultureChar(string lang)
            {
                if (lang.IndexOf('/', StringComparison.CurrentCulture) >= 0 || lang.IndexOf('\\', StringComparison.CurrentCulture) >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void InvariantContains(string lang)
            {
                if (lang.Contains('/', StringComparison.InvariantCultureIgnoreCase) || lang.Contains('\\', StringComparison.InvariantCultureIgnoreCase)) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void CultureSpan(string lang)
            {
                if (lang.AsSpan().IndexOf("/".AsSpan(), StringComparison.CurrentCulture) >= 0 || lang.AsSpan().IndexOf("\\".AsSpan(), StringComparison.CurrentCulture) >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void FromAnOffset(string lang)
            {
                // the search starts after the first character
                if (lang.IndexOf('/', 1) >= 0 || lang.IndexOf('\\', 1) >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void ASubstring(string lang)
            {
                // the two characters together, not each of them
                if (lang.Contains("/\\") || lang.IndexOf("\\/", StringComparison.Ordinal) >= 0) return;
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
            public void OneOfEachOnDifferentPaths(string lang, bool first)
            {
                if (first) { if (lang.Contains('/')) return; }
                else { if (lang.Contains('\\')) return; }
                System.IO.File.WriteAllText(Path.Combine(Root, lang), ""); /*sink*/
            }
        }
        """);
}
