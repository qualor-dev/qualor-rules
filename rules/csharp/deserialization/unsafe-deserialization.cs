using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text.Json;
using System.Web.Script.Serialization;
using System.Web.UI;
using Newtonsoft.Json;

public class Formatters
{
    private readonly BinaryFormatter _field = new BinaryFormatter();

    // The formatter named in the same expression.
    public object InPlace(Stream s)
    {
        // ruleid: csharp.unsafe-deserialization
        return new BinaryFormatter().Deserialize(s);
    }

    // A local variable, typed or declared with var.
    public object Local(Stream s)
    {
        BinaryFormatter typed = new BinaryFormatter();
        // ruleid: csharp.unsafe-deserialization
        return typed.Deserialize(s);
    }

    public object LocalVar(Stream s)
    {
        var formatter = new BinaryFormatter();
        formatter.Binder = new MyBinder();
        // ruleid: csharp.unsafe-deserialization
        return formatter.Deserialize(s);
    }

    // A field and a parameter.
    public object FromField(Stream s)
    {
        // ruleid: csharp.unsafe-deserialization
        return _field.Deserialize(s);
    }

    public object FromParameter(BinaryFormatter given, Stream s)
    {
        // ruleid: csharp.unsafe-deserialization
        return given.Deserialize(s);
    }

    // Fully qualified type names.
    public object Qualified(Stream s)
    {
        var f = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
        // ruleid: csharp.unsafe-deserialization
        return f.Deserialize(s);
    }

    public object Soap(Stream s)
    {
        var f = new SoapFormatter();
        // ruleid: csharp.unsafe-deserialization
        return f.Deserialize(s);
    }

    public object NetDataContract(Stream s)
    {
        var f = new NetDataContractSerializer();
        // ruleid: csharp.unsafe-deserialization
        return f.Deserialize(s);
    }

    public object NetDataContractRead(Stream s)
    {
        var f = new NetDataContractSerializer();
        // ruleid: csharp.unsafe-deserialization
        return f.ReadObject(s);
    }

    public object Los(string state)
    {
        var f = new LosFormatter();
        // ruleid: csharp.unsafe-deserialization
        return f.Deserialize(state);
    }

    public object ObjectState(string state)
    {
        var f = new ObjectStateFormatter();
        // ruleid: csharp.unsafe-deserialization
        return f.Deserialize(state);
    }

    // Serialising is not the danger.
    public void Write(Stream s, object o)
    {
        var f = new BinaryFormatter();
        // ok: csharp.unsafe-deserialization
        f.Serialize(s, o);
    }

    // The safe serializers named in the Microsoft guidance.
    public object Safe(Stream s, string text)
    {
        var xml = new System.Xml.Serialization.XmlSerializer(typeof(Order));
        // ok: csharp.unsafe-deserialization
        var a = xml.Deserialize(s);
        var dc = new DataContractSerializer(typeof(Order));
        // ok: csharp.unsafe-deserialization
        var b = dc.ReadObject(s);
        // ok: csharp.unsafe-deserialization
        return JsonSerializer.Deserialize<Order>(text);
    }

    // A look-alike class with the same method names.
    public object LookAlike(Stream s)
    {
        var f = new CsvFormatter();
        // ok: csharp.unsafe-deserialization
        return f.Deserialize(s);
    }
}

public class JsonNet
{
    public Order Settings(string json)
    {
        // ruleid: csharp.unsafe-deserialization
        var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
        return JsonConvert.DeserializeObject<Order>(json, s);
    }

    public Order All(string json)
    {
        return JsonConvert.DeserializeObject<Order>(json, new JsonSerializerSettings
        {
            Formatting = Formatting.None,
            // ruleid: csharp.unsafe-deserialization
            TypeNameHandling = TypeNameHandling.All,
        });
    }

    public Order Objects(string json)
    {
        var s = new JsonSerializerSettings();
        // ruleid: csharp.unsafe-deserialization
        s.TypeNameHandling = TypeNameHandling.Objects;
        return JsonConvert.DeserializeObject<Order>(json, s);
    }

    public Order Arrays(string json)
    {
        var serializer = new JsonSerializer();
        // ruleid: csharp.unsafe-deserialization
        serializer.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Arrays;
        return serializer.Deserialize<Order>(new JsonTextReader(new StringReader(json)));
    }

    public void Defaults()
    {
        // ruleid: csharp.unsafe-deserialization
        JsonConvert.DefaultSettings = () => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
    }

    // The settings of an ASP.NET Core or Web API formatter.
    public void Mvc(Microsoft.AspNetCore.Mvc.MvcNewtonsoftJsonOptions o)
    {
        // ruleid: csharp.unsafe-deserialization
        o.SerializerSettings.TypeNameHandling = TypeNameHandling.Auto;
    }

    // None is the default and safe.
    public Order None(string json)
    {
        // ok: csharp.unsafe-deserialization
        var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        // ok: csharp.unsafe-deserialization
        s.TypeNameHandling = TypeNameHandling.None;
        return JsonConvert.DeserializeObject<Order>(json, s);
    }

    public Order Plain(string json)
    {
        // ok: csharp.unsafe-deserialization
        return JsonConvert.DeserializeObject<Order>(json);
    }

    // Another library with a property of that name.
    public void LookAlike(WireOptions o)
    {
        // ok: csharp.unsafe-deserialization
        o.TypeNameHandling = WireMode.Auto;
    }
}

// Attributes of Json.NET.
public class Envelope
{
    // ruleid: csharp.unsafe-deserialization
    [JsonProperty(TypeNameHandling = TypeNameHandling.Auto)]
    public object Payload { get; set; }

    // ruleid: csharp.unsafe-deserialization
    [JsonProperty("items", TypeNameHandling = TypeNameHandling.Arrays)]
    public object[] Items { get; set; }

    // ok: csharp.unsafe-deserialization
    [JsonProperty(TypeNameHandling = TypeNameHandling.None)]
    public object Safe { get; set; }
}

// ruleid: csharp.unsafe-deserialization
[JsonObject(ItemTypeNameHandling = TypeNameHandling.Objects)]
public class Wrapper
{
}

public class Scripts
{
    public object Simple(string json)
    {
        // ruleid: csharp.unsafe-deserialization
        var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
        return serializer.DeserializeObject(json);
    }

    public object NoResolver(string json)
    {
        // ok: csharp.unsafe-deserialization
        var serializer = new JavaScriptSerializer();
        return serializer.DeserializeObject(json);
    }

    public object Null(string json)
    {
        // ok: csharp.unsafe-deserialization
        var serializer = new JavaScriptSerializer(null);
        return serializer.DeserializeObject(json);
    }
}

public class Limits
{
    public Order FromVariable(string json, TypeNameHandling handling)
    {
        // The value is not visible here.
        // todoruleid: csharp.unsafe-deserialization
        var s = new JsonSerializerSettings { TypeNameHandling = handling };
        return JsonConvert.DeserializeObject<Order>(json, s);
    }

    public Order WithBinder(string json)
    {
        // A binder that allows only listed types makes TypeNameHandling acceptable; it is not looked at.
        // todook: csharp.unsafe-deserialization
        var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto, SerializationBinder = new AllowListBinder() };
        return JsonConvert.DeserializeObject<Order>(json, s);
    }

    public object ResolverInVariable(string json)
    {
        var resolver = new SimpleTypeResolver();
        // The resolver is not followed through a variable.
        // todoruleid: csharp.unsafe-deserialization
        var serializer = new JavaScriptSerializer(resolver);
        return serializer.DeserializeObject(json);
    }

    public object FromFactory(Stream s)
    {
        // The formatter comes from a helper of unknown type.
        // todoruleid: csharp.unsafe-deserialization
        return FormatterFactory.Create().Deserialize(s);
    }
}
