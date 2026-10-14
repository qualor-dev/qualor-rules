namespace Qualor.Taint.Tests.Capabilities;

/// The Task 11 sanitizer and sink kinds: `by-name:`, `receiver-type:`, awaited `lookup:`, `param-names:`, the `arg`
/// condition with `is:` and on an indexer, `receiver` on a property-set sink; and how PathString keeps request data.
public sealed class SanitizerKindTests : ProbeModels
{
    private ModelSet NamedModels() => Probe("""
        sinks:
          - property-set: System.DirectoryServices.DirectorySearcher.Filter
        sanitizers:
          - by-name: Encoder.LdapFilterEncode
        """);

    [Fact]
    public void A_sanitizer_by_name_cleans_a_method_of_that_name_on_any_type_so_named_whatever_its_body() => Expect(NamedModels(), """
        using System.DirectoryServices;
        namespace Microsoft.Security.Application { public static class Encoder { public static string LdapFilterEncode(string v) => v; public static string LdapDistinguishedNameEncode(string v) => v; } }
        namespace Acme { public static class Encoder { public static string LdapFilterEncode(string v) => v; } public static class Escaper { public static string LdapFilterEncode(string v) => v; } }
        public class StaffController : ControllerBase
        {
            public void Find(string name)
            {
                var s = new DirectorySearcher();
                s.Filter = "(cn=" + Microsoft.Security.Application.Encoder.LdapFilterEncode(name) + ")";
                s.Filter = "(cn=" + Acme.Encoder.LdapFilterEncode(name) + ")";
                s.Filter = "(cn=" + Acme.Escaper.LdapFilterEncode(name) + ")"; /*sink*/
                s.Filter = "(cn=" + Microsoft.Security.Application.Encoder.LdapDistinguishedNameEncode(name) + ")"; /*sink*/
                s.Filter = Microsoft.Security.Application.Encoder.LdapFilterEncode(name) + name; /*sink*/
            }
        }
        """);

    private ModelSet ReceiverModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Http.HttpResponse.Redirect
            args: [0]
        sanitizers:
          - method: System.Text.Encodings.Web.TextEncoder.Encode
            receiver-type: System.Text.Encodings.Web.UrlEncoder
        """);

    [Fact]
    public void A_sanitizer_with_a_receiver_type_cleans_only_on_a_receiver_of_that_type() => Expect(ReceiverModels(), """
        using System.Text.Encodings.Web;
        public class GoController : ControllerBase
        {
            public void Go(string q)
            {
                Response.Redirect(UrlEncoder.Default.Encode(q));
                Response.Redirect(HtmlEncoder.Default.Encode(q)); /*sink*/
                TextEncoder e = UrlEncoder.Default;
                Response.Redirect(e.Encode(q)); /*sink*/
            }
        }
        """);

    private ModelSet AwaitedModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Http.HttpResponse.Redirect
            args: [0]
        sanitizers:
          - lookup: '^(Get|Find|Load)\w*$'
            awaited: true
        """);

    [Fact]
    public void An_awaited_lookup_cleans_only_an_awaited_result() => Expect(AwaitedModels(), """
        public class Doc { public string Link { get; set; } = ""; }
        public interface IArchive { Task<Doc> GetDocAsync(string id); Doc FindDoc(string id); Task<string> ShortenAsync(string url); string GetLink(string id); }
        public class ArchiveController : ControllerBase
        {
            private readonly IArchive _a;
            public ArchiveController(IArchive a) => _a = a;
            public async Task Open(string id)
            {
                Response.Redirect((await _a.GetDocAsync(id)).Link);
                Response.Redirect((await _a.GetDocAsync(id).ConfigureAwait(false)).Link);
                Response.Redirect(_a.FindDoc(id).Link); /*sink*/
                Response.Redirect(_a.GetLink(id)); /*sink*/
                Response.Redirect(await _a.ShortenAsync(id)); /*sink*/
                Response.Redirect(await OwnAsync(id)); /*sink*/
            }
            private async Task<string> GetOwnAsync(string v) { await Task.Yield(); return v; }
            private Task<string> OwnAsync(string v) => GetOwnAsync(v);
        }
        """);

    private ModelSet NamesModels() => Probe("""
        sinks:
          - method: System.Text.RegularExpressions.Regex.Replace
            args: [1]
            param-names: [pattern]
        """);

    [Fact]
    public void Param_names_limit_a_sink_to_parameters_so_named() => Expect(NamesModels(), """
        using System.Text.RegularExpressions;
        public class TextController : ControllerBase
        {
            public void Go(string q)
            {
                Regex.Replace("abc", q, "x"); /*sink*/
                new Regex("a+").Replace("abc", q);
            }
        }
        """);

    private ModelSet HeaderModels() => Probe("""
        sinks:
          - property-set: Microsoft.AspNetCore.Http.IHeaderDictionary.Item
            when:
              - arg: 0
                matches: '(?i)^location$'
          - property-set: Microsoft.AspNetCore.Http.IHeaderDictionary.Item
            when:
              - arg: 0
                is: Microsoft.Net.Http.Headers.HeaderNames.Location
          - method: System.Collections.Generic.IDictionary`2.Add
            args: [1]
            when:
              - receiver: Microsoft.AspNetCore.Http.HttpResponse.Headers
              - arg: 0
                matches: '(?i)^location$'
          - property-set: Microsoft.AspNetCore.Http.IHeaderDictionary.ContentType
            when:
              - receiver: Microsoft.AspNetCore.Http.HttpResponse.Headers
        """);

    [Fact]
    public void Conditions_read_an_indexer_argument_a_named_member_and_a_property_sinks_receiver() => Expect(HeaderModels(), """
        using Microsoft.Net.Http.Headers;
        public class GoController : ControllerBase
        {
            public void Go(string q)
            {
                Response.Headers["Location"] = q; /*sink*/
                Response.Headers["location"] = q; /*sink*/
                Response.Headers["Link"] = q;
                Response.Headers[HeaderNames.Location] = q; /*sink*/
                Response.Headers[HeaderNames.ContentLocation] = q;
                Response.Headers.Add("Location", q); /*sink*/
                Request.Headers.Add("Location", q);
                var d = new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>();
                d.Add("Location", q);
                Response.Headers.ContentType = q; /*sink*/
                Request.Headers.ContentType = q;
            }
        }
        """);

    private ModelSet PathModels() => Probe("""
        sinks:
          - method: Microsoft.AspNetCore.Mvc.ControllerBase.Content
            args: [0]
            param-types: [System.String]
        sanitizers:
          - method: Microsoft.AspNetCore.Http.PathString.op_Implicit
          - string-prefix: '^(https?|\uFFFC)://\uFFFC+$'
            type: Microsoft.AspNetCore.Http.PathString
        """);

    [Fact]
    public void A_PathString_made_from_request_data_keeps_it_and_only_its_conversion_to_string_is_cleaned() => Expect(PathModels(), """
        using Microsoft.AspNetCore.Http;
        public class PagesController : ControllerBase
        {
            public void Get(string q)
            {
                PathString p = q;
                Content(p.Value!); /*sink*/
                Content(new PathString(q).Value!); /*sink*/
                Content(Request.PathBase.Add(q).Value!); /*sink*/
                Content(PathString.FromUriComponent(q).Value!); /*sink*/
                Content(Request.Path);
                Content("https://" + Request.Host + Request.Path);
                Content($"https://{Request.Host}{Request.Path}");
                Content("https://" + Request.Host + p);
                Content("https://" + Request.Host + Request.Path.Value); /*sink*/
                Content("/a" + Request.Path); /*sink*/
            }
        }
        """);

    [Fact]
    public void The_new_sanitizer_and_sink_keys_are_read()
    {
        var named = NamedModels().Rules.Single(r => r.RuleId == Rule);
        Assert.Equal(new[] { ("Encoder", "LdapFilterEncode") }, named.NamedSanitizers);
        var typed = Assert.Single(ReceiverModels().Rules.Single(r => r.RuleId == Rule).ReceiverSanitizers);
        Assert.Equal("System.Text.Encodings.Web.UrlEncoder", typed.ReceiverType);
        Assert.Single(AwaitedModels().Rules.Single(r => r.RuleId == Rule).AwaitedLookupSanitizers);
        Assert.Empty(AwaitedModels().Rules.Single(r => r.RuleId == Rule).LookupSanitizers);
        Assert.Equal(new[] { "pattern" }, NamesModels().Rules.Single(r => r.RuleId == Rule).Sinks[0].ParamNames);
        var isCondition = HeaderModels().Rules.Single(r => r.RuleId == Rule).Sinks[1].When[0];
        Assert.Equal(new MemberPattern("Microsoft.Net.Http.Headers.HeaderNames", "Location", false, MemberKind.PropertyGet), isCondition.Member);
        Assert.Null(isCondition.Pattern);

        foreach (var (yaml, line) in new[]
        {
            ("sanitizers:\n  - by-name: A.B.C\n", 7),
            ("sanitizers:\n  - method: A.B\n    awaited: true\n", 8),
            ("sanitizers:\n  - lookup: x\n    receiver-type: A.B\n", 8),
            ("sanitizers:\n  - method: A.B\n    lookup: x\n", 7),
            ("sinks2: x\n", 6),
        })
        {
            var e = Assert.Throws<ModelException>(() => Probe("sinks:\n  - method: A.B\n    args: [0]\n" + yaml));
            Assert.Equal(line, e.Line);
        }
        var both = Assert.Throws<ModelException>(() => Probe("sinks:\n  - method: A.B\n    args: [0]\n    when:\n      - arg: 1\n        matches: x\n        is: A.C\n"));
        Assert.Equal(7, both.Line);
        var names = Assert.Throws<ModelException>(() => Probe("sinks:\n  - property-set: A.B\n    param-names: [x]\n"));
        Assert.Equal(5, names.Line);
    }
}
