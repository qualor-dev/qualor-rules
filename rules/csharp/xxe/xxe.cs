using System.IO;
using System.Xml;
using System.Xml.Linq;

public class ReaderSettings
{
    // DTD processing on and a resolver that fetches what the DTD names.
    public XmlReader InitializerBoth(Stream s)
    {
        // ruleid: csharp.xxe
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
        return XmlReader.Create(s, settings);
    }

    public XmlReader InitializerReversed(Stream s)
    {
        // ruleid: csharp.xxe
        var settings = new XmlReaderSettings
        {
            XmlResolver = new XmlUrlResolver(),
            ValidationType = ValidationType.DTD,
            DtdProcessing = DtdProcessing.Parse,
        };
        return XmlReader.Create(s, settings);
    }

    public XmlReader Statements(Stream s)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        // ruleid: csharp.xxe
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(s, settings);
    }

    public XmlReader StatementsReversed(Stream s)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        // ruleid: csharp.xxe
        settings.XmlResolver = new XmlUrlResolver();
        settings.DtdProcessing = DtdProcessing.Parse;
        return XmlReader.Create(s, settings);
    }

    public XmlReader Qualified(Stream s)
    {
        var settings = new System.Xml.XmlReaderSettings();
        settings.DtdProcessing = System.Xml.DtdProcessing.Parse;
        // ruleid: csharp.xxe
        settings.XmlResolver = new System.Xml.XmlUrlResolver();
        return XmlReader.Create(s, settings);
    }

    // The defaults: DTDs are refused and no resolver is set.
    public XmlReader Defaults(Stream s)
    {
        // ok: csharp.xxe
        var settings = new XmlReaderSettings();
        return XmlReader.Create(s, settings);
    }

    public XmlReader Prohibit(Stream s)
    {
        // ok: csharp.xxe
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = new XmlUrlResolver() };
        return XmlReader.Create(s, settings);
    }

    public XmlReader Ignore(Stream s)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        // ok: csharp.xxe
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(s, settings);
    }

    // DTDs parsed without a resolver: external references are not fetched (.NET Framework 4.5.2
    // and later, .NET Core and .NET 5+).
    public XmlReader ParseNoResolver(Stream s)
    {
        // ok: csharp.xxe
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        return XmlReader.Create(s, settings);
    }

    public XmlReader ParseNullResolver(Stream s)
    {
        // ok: csharp.xxe
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null };
        return XmlReader.Create(s, settings);
    }

    public XmlReader ParseSecureResolver(Stream s)
    {
        // ok: csharp.xxe
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), "https://schemas.example.com/") };
        return XmlReader.Create(s, settings);
    }

    public XmlReader ParseThrowingResolver(Stream s)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        // ok: csharp.xxe
        settings.XmlResolver = XmlResolver.ThrowingResolver;
        return XmlReader.Create(s, settings);
    }

    // A resolver that is not an XmlUrlResolver is not assumed to fetch anything.
    public XmlReader ParseCustomResolver(Stream s)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        // ok: csharp.xxe
        settings.XmlResolver = new LocalDtdResolver();
        return XmlReader.Create(s, settings);
    }

    public XmlReader ParseSecureStatements(Stream s)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        // ok: csharp.xxe
        settings.XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), "https://schemas.example.com/");
        return XmlReader.Create(s, settings);
    }

    public FeedSettings LookAlikeInitializer()
    {
        // ok: csharp.xxe
        return new FeedSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
    }

    // The settings of another library with the same property names.
    public void LookAlike(FeedSettings feed)
    {
        feed.DtdProcessing = DtdProcessing.Parse;
        // ok: csharp.xxe
        feed.XmlResolver = new XmlUrlResolver();
    }

    // Parse is set in another method than the resolver.
    public void SeparateMethods(XmlReaderSettings shared)
    {
        // todoruleid: csharp.xxe
        shared.XmlResolver = new XmlUrlResolver();
    }

    public void EnableParse(XmlReaderSettings shared)
    {
        shared.DtdProcessing = DtdProcessing.Parse;
    }

    // The resolver is a variable: its type is not known here.
    public XmlReader ResolverVariable(Stream s, XmlResolver given)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        // todoruleid: csharp.xxe
        settings.XmlResolver = given;
        return XmlReader.Create(s, settings);
    }
}

public class Documents
{
    private readonly XmlDocument _field = new XmlDocument();

    public XmlDocument Local(string path)
    {
        var doc = new XmlDocument();
        // ruleid: csharp.xxe
        doc.XmlResolver = new XmlUrlResolver();
        doc.Load(path);
        return doc;
    }

    public XmlDocument Typed(string path)
    {
        XmlDocument doc = new XmlDocument();
        // ruleid: csharp.xxe
        doc.XmlResolver = new XmlUrlResolver();
        doc.Load(path);
        return doc;
    }

    public XmlDocument Initializer(string xml)
    {
        // ruleid: csharp.xxe
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.LoadXml(xml);
        return doc;
    }

    public void FromField(string xml)
    {
        // ruleid: csharp.xxe
        _field.XmlResolver = new XmlUrlResolver();
        _field.LoadXml(xml);
    }

    public void FromParameter(XmlDocument given, string xml)
    {
        // ruleid: csharp.xxe
        given.XmlResolver = new System.Xml.XmlUrlResolver();
        given.LoadXml(xml);
    }

    // The default: no resolver (.NET Framework 4.5.2 and later, .NET Core and .NET 5+).
    public XmlDocument Default(string xml)
    {
        // ok: csharp.xxe
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return doc;
    }

    public XmlDocument NullResolver(string xml)
    {
        var doc = new XmlDocument();
        // ok: csharp.xxe
        doc.XmlResolver = null;
        doc.LoadXml(xml);
        return doc;
    }

    public XmlDocument SecureResolver(string xml)
    {
        var doc = new XmlDocument();
        // ok: csharp.xxe
        doc.XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), "https://schemas.example.com/");
        doc.LoadXml(xml);
        return doc;
    }

    public XDocument Linq(string xml)
    {
        // ok: csharp.xxe
        return XDocument.Parse(xml);
    }

    // A document class of another library.
    public void LookAlike(TemplateDocument template)
    {
        // ok: csharp.xxe
        template.XmlResolver = new XmlUrlResolver();
    }

    // The document is loaded through a reader that refuses DTDs, so the resolver is never used;
    // the rule does not follow the reader.
    public XmlDocument SafeReader(Stream s)
    {
        var doc = new XmlDocument();
        // todook: csharp.xxe
        doc.XmlResolver = new XmlUrlResolver();
        using var reader = XmlReader.Create(s, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        doc.Load(reader);
        return doc;
    }
}

public class TextReaders
{
    // XmlTextReader parses DTDs by default, so a resolver alone is enough.
    public XmlTextReader Default(Stream s)
    {
        var reader = new XmlTextReader(s);
        // ruleid: csharp.xxe
        reader.XmlResolver = new XmlUrlResolver();
        return reader;
    }

    public XmlTextReader Initializer(Stream s)
    {
        // ruleid: csharp.xxe
        return new XmlTextReader(s) { XmlResolver = new XmlUrlResolver() };
    }

    public XmlTextReader ExplicitParse(string path)
    {
        XmlTextReader reader = new XmlTextReader(path);
        reader.DtdProcessing = DtdProcessing.Parse;
        // ruleid: csharp.xxe
        reader.XmlResolver = new XmlUrlResolver();
        return reader;
    }

    public XmlTextReader Prohibit(Stream s)
    {
        var reader = new XmlTextReader(s);
        reader.DtdProcessing = DtdProcessing.Prohibit;
        // ok: csharp.xxe
        reader.XmlResolver = new XmlUrlResolver();
        return reader;
    }

    public XmlTextReader Ignore(Stream s)
    {
        // ok: csharp.xxe
        return new XmlTextReader(s) { DtdProcessing = DtdProcessing.Ignore, XmlResolver = new XmlUrlResolver() };
    }

    public XmlTextReader IgnoreStatement(Stream s)
    {
        var reader = new XmlTextReader(s);
        reader.DtdProcessing = System.Xml.DtdProcessing.Ignore;
        // ok: csharp.xxe
        reader.XmlResolver = new XmlUrlResolver();
        return reader;
    }

    public XmlTextReader ProhibitInitializer(Stream s)
    {
        // ok: csharp.xxe
        return new XmlTextReader(s) { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = new XmlUrlResolver() };
    }

    public XmlTextReader SecureResolver(Stream s)
    {
        var reader = new XmlTextReader(s);
        // ok: csharp.xxe
        reader.XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), "https://schemas.example.com/");
        return reader;
    }

    // No resolver: external references are not resolved (.NET Framework 4.5.2 and later, .NET Core).
    public XmlTextReader NoResolver(Stream s)
    {
        // ok: csharp.xxe
        return new XmlTextReader(s);
    }

    public XmlTextReader NullResolver(Stream s)
    {
        var reader = new XmlTextReader(s);
        // ok: csharp.xxe
        reader.XmlResolver = null;
        return reader;
    }

    public XmlReader Create(Stream s)
    {
        // ok: csharp.xxe
        return XmlReader.Create(s);
    }
}
