// Shim for the engine harness: unsafe-deserialization
// Json.NET and System.Text.Json both name JsonSerializer and the fixture imports both namespaces; the alias picks
// Json.NET's (the line that calls System.Text.Json's static Deserialize is listed under uncompilable).
global using JsonSerializer = Newtonsoft.Json.JsonSerializer;

// .NET Framework types the fixture imports (System.Web.Script.Serialization, System.Web.UI, the SOAP formatter and
// NetDataContractSerializer are not in .NET 8) and classes of the project.
namespace System.Runtime.Serialization.Formatters.Soap
{
    public sealed class SoapFormatter : IFormatter
    {
        public SerializationBinder Binder { get; set; }
        public StreamingContext Context { get; set; }
        public ISurrogateSelector SurrogateSelector { get; set; }
        public object Deserialize(System.IO.Stream serializationStream) => null;
        public void Serialize(System.IO.Stream serializationStream, object graph) { }
    }
}

namespace System.Runtime.Serialization
{
    public sealed class NetDataContractSerializer : IFormatter
    {
        public SerializationBinder Binder { get; set; }
        public StreamingContext Context { get; set; }
        public ISurrogateSelector SurrogateSelector { get; set; }
        public object Deserialize(System.IO.Stream serializationStream) => null;
        public void Serialize(System.IO.Stream serializationStream, object graph) { }
        public object ReadObject(System.IO.Stream stream) => null;
    }
}

namespace System.Web.Script.Serialization
{
    public abstract class JavaScriptTypeResolver { }

    public class SimpleTypeResolver : JavaScriptTypeResolver { }

    public class JavaScriptSerializer
    {
        public JavaScriptSerializer() { }
        public JavaScriptSerializer(JavaScriptTypeResolver resolver) { }
        public object DeserializeObject(string input) => null;
        public T Deserialize<T>(string input) => default;
        public object Deserialize(string input, System.Type targetType) => null;
    }
}

namespace System.Web.UI
{
    public sealed class LosFormatter
    {
        public object Deserialize(System.IO.Stream stream) => null;
        public object Deserialize(string input) => null;
    }

    public sealed class ObjectStateFormatter
    {
        public object Deserialize(System.IO.Stream inputStream) => null;
        public object Deserialize(string inputString) => null;
    }
}

public class Order { }

public class MyBinder : System.Runtime.Serialization.SerializationBinder
{
    public override System.Type BindToType(string assemblyName, string typeName) => null;
}

public class AllowListBinder : Newtonsoft.Json.Serialization.ISerializationBinder
{
    public System.Type BindToType(string assemblyName, string typeName) => null;
    public void BindToName(System.Type serializedType, out string assemblyName, out string typeName) { assemblyName = null; typeName = null; }
}

public class CsvFormatter
{
    public object Deserialize(System.IO.Stream stream) => null;
}

public enum WireMode { None, Auto }

public class WireOptions
{
    public WireMode TypeNameHandling { get; set; }
}

public static class FormatterFactory
{
    public static System.Runtime.Serialization.IFormatter Create() => null;
}
