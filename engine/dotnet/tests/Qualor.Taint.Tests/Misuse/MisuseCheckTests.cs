using Qualor.Taint.Tests.Intraprocedural;
using static Qualor.Taint.Tests.Misuse.MisuseSnippet;

namespace Qualor.Taint.Tests.Misuse;

/// The `kind: misuse` checks (models/README.md, `misuse:`) with the shipped models of the three misuse rules: lines
/// marked `/*sink*/` are the findings, every other line is quiet.
public sealed class MisuseCheckTests
{
    private static void Expect(string rule, string code) => Assert.Equal(Snippet.Marked(code), Lines(code, rule));

    // `calls:` — a call, or a read of a property, of a member the model names, by the receiver's type.

    [Fact]
    public void A_formatter_call_is_reported_by_its_receiver_type_wherever_the_formatter_comes_from() => Expect(Deserialization, """
        using System.Runtime.Serialization.Formatters.Binary;
        #pragma warning disable SYSLIB0011
        public class Formatters
        {
            private static BinaryFormatter Make() => new BinaryFormatter();
            public object FromHelper(Stream s) => Make().Deserialize(s); /*sink*/
            public object Chained(Stream s) => Make()
                .Deserialize(s); /*sink*/
            public void Write(Stream s, object o) => new BinaryFormatter().Serialize(s, o);
            public object LookAlike(Stream s) => new CsvFormatter().Deserialize(s);
        }
        public class CsvFormatter { public object Deserialize(Stream s) => s; }
        """);

    [Fact]
    public void A_read_of_a_named_property_is_reported() => Expect(Tls, """
        public class Handlers
        {
            public HttpClientHandler Dangerous()
            {
                var h = new HttpClientHandler();
                h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; /*sink*/
                var keep = h.ServerCertificateCustomValidationCallback;
                return h;
            }
        }
        """);

    // `enum-values:` — a constant of the enum other than a safe member, written to a field or property.

    [Fact]
    public void An_unsafe_enum_constant_written_anywhere_is_reported_by_its_value() => Expect(Deserialization, """
        using Newtonsoft.Json;
        public class Settings
        {
            private const TypeNameHandling Mode = TypeNameHandling.All;
            public JsonSerializerSettings FromConst() => new JsonSerializerSettings { TypeNameHandling = Mode }; /*sink*/
            public void FromCast(JsonSerializer s) { s.TypeNameHandling = (TypeNameHandling)4; } /*sink*/
            public void Safe(JsonSerializerSettings s) { s.TypeNameHandling = TypeNameHandling.None; }
            public void FromParameter(JsonSerializerSettings s, TypeNameHandling h) { s.TypeNameHandling = h; }
            public void LookAlike(Wire w) { w.TypeNameHandling = WireMode.Auto; }
            // s.TypeNameHandling = TypeNameHandling.Auto in a comment
            public string Text() => "[JsonProperty(TypeNameHandling = TypeNameHandling.Auto)]";
            public TypeNameHandling Own { get; set; } = TypeNameHandling.Objects; /*sink*/
            private TypeNameHandling _field = TypeNameHandling.Arrays; /*sink*/
            public TypeNameHandling Field => _field;
        }
        public class Envelope
        {
            [JsonProperty(ItemTypeNameHandling = TypeNameHandling.Auto)] /*sink*/
            public object[] Items { get; set; } = [];
            [JsonProperty("x", TypeNameHandling = TypeNameHandling.None)]
            public object? X { get; set; }
        }
        public enum WireMode { None, Auto }
        public class Wire { public WireMode TypeNameHandling { get; set; } }
        """);

    // `values:` with `created:` — a creation of the type given to the member, in place or through a local.

    private const string JavaScriptShim = """
        namespace System.Web.Script.Serialization
        {
            public abstract class JavaScriptTypeResolver { }
            public class SimpleTypeResolver : JavaScriptTypeResolver { }
            public class JavaScriptSerializer
            {
                public JavaScriptSerializer() { }
                public JavaScriptSerializer(JavaScriptTypeResolver resolver) { }
            }
        }
        """;

    [Fact]
    public void A_created_value_is_reported_in_place_and_through_a_local() => Expect(Deserialization, """
        using System.Web.Script.Serialization;
        public class Scripts
        {
            public object InPlace() => new JavaScriptSerializer(new SimpleTypeResolver()); /*sink*/
            public object Local() { var r = new SimpleTypeResolver(); return new JavaScriptSerializer(r); } /*sink*/
            public object Given(JavaScriptTypeResolver r) => new JavaScriptSerializer(r);
            public object Own() => new JavaScriptSerializer(new OwnResolver());
            public object None() => new JavaScriptSerializer();
            public object Reused(bool b) { JavaScriptTypeResolver r = new OwnResolver(); if (b) r = new SimpleTypeResolver(); return new JavaScriptSerializer(r); } /*sink*/
            public object TargetTyped() { JavaScriptSerializer s = new(new SimpleTypeResolver()); return s; } /*sink*/
            public object OutWritten() { var r = new SimpleTypeResolver(); Replace(out r); return new JavaScriptSerializer(r); }
            private static void Replace(out SimpleTypeResolver r) => r = new OwnResolver();
        }
        public class OwnResolver : SimpleTypeResolver { }
        """ + JavaScriptShim);

    [Fact]
    public void A_resolver_created_with_an_initializer_and_no_parentheses_is_reported() => Expect(Xxe, """
        using System.Xml;
        public class Documents
        {
            public XmlDocument Initializer() => new XmlDocument { XmlResolver = new XmlUrlResolver { Credentials = null } }; /*sink*/
            public void Assigned(XmlDocument d) { d.XmlResolver = new XmlUrlResolver { Credentials = null }; } /*sink*/
            public void Local(XmlDocument d) { var r = new XmlUrlResolver(); d.XmlResolver = r; } /*sink*/
            public void Secure(XmlDocument d) { d.XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), "https://example.com/"); }
            public void LookAlike(TemplateDocument t) { t.XmlResolver = new XmlUrlResolver(); }
        }
        public class TemplateDocument { public XmlResolver? XmlResolver { get; set; } }
        """);

    // `with:` / `without:` — another property of the same object, anywhere in the body; `at: object`.

    [Fact]
    public void A_with_condition_reads_the_same_object_in_the_whole_body() => Expect(Xxe, """
        using System.Xml;
        public class ReaderSettings
        {
            public XmlReaderSettings InitializerThenStatement()
            {
                var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
                s.XmlResolver = new XmlUrlResolver(); /*sink*/
                return s;
            }
            public XmlReaderSettings NoParse()
            {
                var s = new XmlReaderSettings();
                s.XmlResolver = new XmlUrlResolver();
                return s;
            }
            public XmlReaderSettings OtherObject()
            {
                var a = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
                var b = new XmlReaderSettings();
                b.XmlResolver = new XmlUrlResolver();
                return a;
            }
            public XmlReaderSettings ParseFromLocal()
            {
                var mode = DtdProcessing.Parse;
                var s = new XmlReaderSettings /*sink*/
                {
                    DtdProcessing = mode,
                    XmlResolver = new XmlUrlResolver(),
                };
                return s;
            }
            public void Field()
            {
                _shared.DtdProcessing = DtdProcessing.Parse;
                _shared.XmlResolver = new XmlUrlResolver(); /*sink*/
            }
            private readonly XmlReaderSettings _shared = new();
        }
        """);

    [Fact]
    public void A_without_condition_keeps_the_value_quiet_when_the_object_has_the_property_set() => Expect(Xxe, """
        using System.Xml;
        public class TextReaders
        {
            public XmlTextReader Default(Stream st) { var r = new XmlTextReader(st); r.XmlResolver = new XmlUrlResolver(); return r; } /*sink*/
            public XmlTextReader Prohibit(Stream st) { var r = new XmlTextReader(st); r.XmlResolver = new XmlUrlResolver(); r.DtdProcessing = DtdProcessing.Prohibit; return r; }
            public XmlTextReader Initializer(Stream st) => new XmlTextReader(st) { DtdProcessing = DtdProcessing.Ignore, XmlResolver = new XmlUrlResolver() };
            public XmlTextReader Other(Stream st) { var a = new XmlTextReader(st); var b = new XmlTextReader(st); a.DtdProcessing = DtdProcessing.Ignore; b.XmlResolver = new XmlUrlResolver(); return b; } /*sink*/
        }
        """);

    // `values:` with `accepts-all:` — a lambda or anonymous method whose every return is true, given to the real member.

    [Fact]
    public void An_accept_all_callback_is_reported_where_it_is_given_to_the_real_types() => Expect(Tls, """
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class Callbacks
        {
            public void OrTrue(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None || true; } /*sink*/
            public void FromLocal(HttpClientHandler h)
            {
                Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> all = (m, c, ch, e) => true;
                h.ServerCertificateCustomValidationCallback = all; /*sink*/
            }
            public void LookAlike(Wrapper w) { w.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true; }
            public void Checks(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => { if (e != SslPolicyErrors.None) return false; return true; }; }
            public void NestedLambda(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => { Func<bool> inner = () => false; return true; }; } /*sink*/
            public void Throws(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None ? true : throw new InvalidOperationException(); }
            public SslStream Ternary(Stream s) => new SslStream(s, false, (o, c, ch, e) => e == SslPolicyErrors.None ? true : true); /*sink*/
            public void Created() { var cb = new RemoteCertificateValidationCallback(delegate { return true; }); } /*sink*/
            public void Conditional(HttpClientHandler h, bool dev) { h.ServerCertificateCustomValidationCallback = dev ? (m, c, ch, e) => true : null; } /*sink*/
            public void Options(SslServerAuthenticationOptions o) { o.RemoteCertificateValidationCallback += (s, c, ch, e) => true; } /*sink*/
            public SocketsHttpHandler Nested() => new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (s, c, ch, e) => true } }; /*sink*/
        }
        public class Wrapper { public Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? ServerCertificateCustomValidationCallback { get; set; } }
        """);

    // `accepts-all-methods:` — a method or local function with an SslPolicyErrors parameter that accepts all.

    [Fact]
    public void An_accept_all_method_is_reported_at_its_declaration() => Expect(Tls, """
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class Methods
        {
            private static bool Logs(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) { Console.WriteLine(e); return true; } /*sink*/
            private static bool Checks(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) => e == SslPolicyErrors.None;
            private static bool OrTrue(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) => e == SslPolicyErrors.None || true; /*sink*/
            private static bool NoErrors(object s, X509Certificate? c) => true;
            private static int Count(SslPolicyErrors e) => 1;
            private static bool Throws(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) { if (e != SslPolicyErrors.None) throw new InvalidOperationException(); return true; }
            public RemoteCertificateValidationCallback Local()
            {
                static bool Inner(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) => true; /*sink*/
                return new RemoteCertificateValidationCallback(Inner);
            }
        }
        public interface IValidator { bool Validate(SslPolicyErrors e); }
        public abstract class Validator { public abstract bool Validate(SslPolicyErrors e); }
        """);
}
