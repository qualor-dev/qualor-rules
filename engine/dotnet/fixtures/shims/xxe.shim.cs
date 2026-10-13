// Shim for the engine harness: xxe
// Classes of the project that carry the same property names as XmlReaderSettings and XmlDocument.
public class LocalDtdResolver : System.Xml.XmlResolver
{
    public override object GetEntity(System.Uri absoluteUri, string role, System.Type ofObjectToReturn) => null;
}

public class FeedSettings
{
    public System.Xml.DtdProcessing DtdProcessing { get; set; }
    public System.Xml.XmlResolver XmlResolver { get; set; }
}

public class TemplateDocument
{
    public System.Xml.XmlResolver XmlResolver { get; set; }
}
