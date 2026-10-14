using System.Runtime.Serialization;
using System.Xml;
using System.Xml.Serialization;

namespace Scheduler.Import;

public sealed class Envelope
{
    public string Sender { get; set; } = "";
}

// Reads queued jobs posted as XML; the root element names the job's contract type in its "kind" attribute
// (learn.microsoft.com: XmlReader.Create, DataContractSerializer, XmlSerializer extraTypes, Type.GetType).
public static class JobReader
{
    public static object Read(Stream posted)
    {
        using var reader = XmlReader.Create(posted);
        reader.MoveToContent();
        var contract = Type.GetType("Scheduler.Jobs." + reader.GetAttribute("kind"), throwOnError: true);
        // ruleid: csharp.unsafe-deserialization
        var serializer = new DataContractSerializer(contract);
        return serializer.ReadObject(reader);
    }

    public static object ReadWrapped(Stream posted, string payloadClass)
    {
        // ruleid: csharp.unsafe-deserialization
        var serializer = new XmlSerializer(typeof(Envelope), new[] { Type.GetType(payloadClass) });
        return serializer.Deserialize(posted);
    }

    public static object ReadEnvelope(Stream posted)
    {
        // ok: csharp.unsafe-deserialization
        var serializer = new XmlSerializer(typeof(Envelope));
        return serializer.Deserialize(posted);
    }
}
