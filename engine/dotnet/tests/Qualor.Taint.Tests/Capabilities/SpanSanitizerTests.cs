using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 34, G5: the `ReadOnlySpan<char>` overloads of Path.GetFileName, GetFileNameWithoutExtension and GetExtension
/// (learn.microsoft.com dotnet/api/system.io.path.getfilename, .getfilenamewithoutextension, .getextension: the span
/// overloads return the same characters as the string ones, as a span) clean as the string overloads do: in place, after a
/// project helper over spans, and once passed on to another method.
public sealed class SpanSanitizerTests
{
    private const string PathRule = "csharp.path-traversal";

    [Fact]
    public void The_span_overloads_of_the_file_name_sanitizers_clean_like_the_string_ones() => Expect("""
        public class UploadController : ControllerBase
        {
            public void Save(string fileName, string body)
            {
                var ext = Path.GetExtension(fileName.AsSpan()).ToString();
                System.IO.File.WriteAllText("/srv/reports/summary" + ext, body);
                ReadOnlySpan<char> name = Path.GetFileName(fileName.AsSpan());
                System.IO.File.WriteAllText("/srv/up/" + name.ToString(), body);
                System.IO.File.WriteAllText("/srv/up/" + new string(Path.GetFileNameWithoutExtension(fileName.AsSpan())) + ".txt", body);
                var trimmed = Path.GetExtension(fileName.AsSpan()).TrimStart('.');
                System.IO.File.WriteAllText("/srv/up/a." + trimmed.ToString(), body);
            }
        }
        """);

    /// A project helper over spans that returns part of its argument (here: what follows a fixed count of characters).
    private const string Archive = """
        public static class Spans
        {
            public static ReadOnlySpan<char> Skip(this ReadOnlySpan<char> text, int count) => count >= text.Length ? ReadOnlySpan<char>.Empty : text.Slice(count);
        }
        public class Archive
        {
            private readonly string _root = "/var/archive";
            public void Put(string suffix, string body) => Store(_root + "/item-" + suffix, body);
            private static void Store(string target, string body) => System.IO.File.AppendAllText(target, body); /*sink*/
        }
        """;

    [Fact]
    public void A_span_sanitizer_result_given_to_a_project_span_helper_stays_clean() => Expect("""
        public class UploadController : ControllerBase
        {
            public void Save(string fileName, string body)
            {
                var kind = Path.GetExtension(fileName.AsSpan()).Skip(1).ToString();
                System.IO.File.AppendAllText("/var/notes/" + kind.ToUpperInvariant(), body);
                var raw = fileName.AsSpan().Skip(1).ToString();
                System.IO.File.AppendAllText("/var/notes/" + raw, body); /*sink*/
            }
        }
        """ + Archive.Replace("/*sink*/", ""));

    [Fact]
    public void A_span_sanitizer_result_stays_clean_when_it_is_passed_on_to_another_method() => Expect((Archive + """
        public class UploadController : ControllerBase
        {
            private readonly Archive _archive = new();
            public void Save(string fileName, string body)
            {
                _archive.Put(Path.GetExtension(fileName.AsSpan()).Skip(1).ToString(), body);
                _archive.Put(Path.GetExtension(fileName.AsSpan()).ToString(), body);
                _archive.Put(Path.GetExtension(fileName).TrimStart('.'), body);
                var name = Path.GetFileName(fileName.AsSpan());
                _archive.Put(name.ToString(), body);
            }
        }
        """).Replace("/*sink*/", ""));

    [Fact]
    public void A_span_sanitizer_result_stays_clean_from_a_validated_api_controller_parameter() => Expect((Archive + """
        [ApiController]
        public class UploadController : ControllerBase
        {
            private readonly Archive _archive = new();
            [HttpPost("up")]
            public void Save([FromQuery, System.ComponentModel.DataAnnotations.Required] string fileName, string body)
            {
                _archive.Put(Path.GetFileNameWithoutExtension(fileName.AsSpan()).Skip(2).ToString(), body);
            }
        }
        """).Replace("/*sink*/", ""));

    [Fact]
    public void An_unsanitized_span_passed_on_to_another_method_is_still_found() => Expect(Archive + """
        public class UploadController : ControllerBase
        {
            private readonly Archive _archive = new();
            public void Save(string fileName, string body)
            {
                _archive.Put(fileName.AsSpan().Skip(1).ToString(), body);
            }
        }
        """);

    [Fact]
    public void A_span_of_the_request_value_that_no_sanitizer_cut_stays_request_data() => Expect("""
        public class UploadController : ControllerBase
        {
            public void Save(string fileName, string body)
            {
                var raw = fileName.AsSpan().Trim().ToString();
                System.IO.File.WriteAllText("/srv/up/" + raw, body); /*sink*/
                var folder = Path.GetDirectoryName(fileName.AsSpan()).ToString();
                System.IO.File.WriteAllText(folder + "/a.txt", body); /*sink*/
                var name = Path.GetFileName(fileName.AsSpan());
                System.IO.File.WriteAllText(fileName + name.ToString(), body); /*sink*/
            }
        }
        """);

    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, PathRule));
}
