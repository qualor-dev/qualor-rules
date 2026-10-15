using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 34, ruling R-E38: JSON text deserialized into an object makes that object, and its members, request data when the
/// text is (learn.microsoft.com dotnet/api/system.text.json.jsonserializer.deserialize: "Parses the text representing a
/// single JSON value into a TValue", .deserializeasync; newtonsoft.com/json/help JsonConvert.DeserializeObject:
/// "Deserializes the JSON to the specified .NET type", JToken.ToObject: "Creates an instance of the specified .NET type
/// from the JToken"). The result is the deserializer's own, whatever its static type: a bare `T` inside a project's
/// generic wrapper is kept, as a DTO, a dictionary or an object are.
public sealed class DeserializationTests
{
    private const string Types = """
        using System.Text.Json;
        using Newtonsoft.Json;
        using Newtonsoft.Json.Linq;
        public class Filter { public string Region { get; set; } = ""; }
        public static class Json
        {
            public static T Read<T>(string text) => System.Text.Json.JsonSerializer.Deserialize<T>(text)!;
            public static T ReadNewtonsoft<T>(string text) => JsonConvert.DeserializeObject<T>(text)!;
        }
        """;

    [Fact]
    public void Request_text_deserialized_into_an_object_is_request_data() => Expect(Types + """
        public class ReportController : ControllerBase
        {
            private readonly SqlConnection _db = new();
            public async Task<IActionResult> Run(string json)
            {
                var a = System.Text.Json.JsonSerializer.Deserialize<Filter>(json)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + a.Region + "'"); /*sink*/
                var b = (Filter)System.Text.Json.JsonSerializer.Deserialize(json, typeof(Filter))!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + b.Region + "'"); /*sink*/
                var c = (await System.Text.Json.JsonSerializer.DeserializeAsync<Filter>(Request.Body))!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + c.Region + "'"); /*sink*/
                var d = JsonConvert.DeserializeObject<Filter>(json)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + d.Region + "'"); /*sink*/
                var e = JObject.Parse(json).ToObject<Filter>()!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + e.Region + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void A_bare_type_parameter_result_of_a_generic_wrapper_is_kept() => Expect(Types + """
        public class ReportController : ControllerBase
        {
            private readonly SqlConnection _db = new();
            public IActionResult Run(string json)
            {
                var p = Json.Read<Dictionary<string, object>>(json);
                _db.Execute("SELECT * FROM sales WHERE region = '" + p["region"] + "'"); /*sink*/
                var f = Json.ReadNewtonsoft<Filter>(json);
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void Constant_json_deserializes_into_server_data() => Expect(Types + """
        public class ReportController : ControllerBase
        {
            private const string Defaults = "{\"Region\":\"north\"}";
            private readonly SqlConnection _db = new();
            public IActionResult Run(string json)
            {
                var a = System.Text.Json.JsonSerializer.Deserialize<Filter>(Defaults)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + a.Region + "'");
                var b = Json.Read<Filter>("{\"Region\":\"south\"}");
                _db.Execute("SELECT * FROM sales WHERE region = '" + b.Region + "'");
                var c = JsonConvert.DeserializeObject<Filter>(Defaults)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + c.Region + "'");
                return Ok();
            }
        }
        """);

    private const string Cache = """
        public class JsonCache
        {
            private readonly Dictionary<string, string> _entries = new();
            private readonly Microsoft.Extensions.Caching.Distributed.IDistributedCache _shared;
            public JsonCache(Microsoft.Extensions.Caching.Distributed.IDistributedCache shared) => _shared = shared;
            public string Text(string key) => _entries[key];
            public T Get<T>(string key) => System.Text.Json.JsonSerializer.Deserialize<T>(_entries[key])!;
            public T Shared<T>(string key) => JsonConvert.DeserializeObject<T>(System.Text.Encoding.UTF8.GetString(_shared.Get(key)!))!;
        }
        """;

    [Fact]
    public void Cached_json_found_by_a_request_key_deserializes_into_stored_data() => Expect(Types + Cache + """
        public class ReportController : ControllerBase
        {
            private readonly Dictionary<string, string> _cache = new();
            private readonly SqlConnection _db = new();
            private readonly JsonCache _json;
            public ReportController(JsonCache json) => _json = json;
            public IActionResult Run(string key)
            {
                var a = System.Text.Json.JsonSerializer.Deserialize<Filter>(_cache[key])!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + a.Region + "'");
                _cache.TryGetValue(key, out var text);
                var b = JsonConvert.DeserializeObject<Filter>(text!)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + b.Region + "'");
                var c = JToken.Parse(_json.Text(key)).ToObject<Filter>()!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + c.Region + "'");
                _db.Execute("SELECT * FROM sales WHERE region = '" + _json.Get<Filter>(key).Region + "'");
                _db.Execute("SELECT * FROM sales WHERE region = '" + _json.Shared<Filter>(key).Region + "'");
                _cache.TryGetValue(key, out var stored);
                _db.Execute("SELECT * FROM sales WHERE region = '" + Json.Read<Filter>(stored!).Region + "'");
                _db.Execute("SELECT * FROM sales WHERE region = '" + Json.ReadNewtonsoft<Filter>(_json.Text(key)).Region + "'");
                _db.Execute("SELECT * FROM sales WHERE note = '" + _cache[key] + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    [Fact]
    public void Json_holding_request_data_beside_a_key_lookup_is_still_request_data() => Expect(Types + Cache + """
        public class ReportController : ControllerBase
        {
            private readonly Dictionary<string, string> _cache = new();
            private readonly SqlConnection _db = new();
            public IActionResult Run(string key, string json)
            {
                var mixed = System.Text.Json.JsonSerializer.Deserialize<Filter>(_cache[key] + json)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + mixed.Region + "'"); /*sink*/
                var chosen = System.Text.Json.JsonSerializer.Deserialize<Filter>(key.Length > 3 ? _cache[key] : json)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + chosen.Region + "'"); /*sink*/
                var body = System.Text.Json.JsonSerializer.Deserialize<Filter>(json)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + body.Region + "'"); /*sink*/
                _db.Execute("SELECT * FROM sales WHERE region = '" + Json.Read<Filter>(_cache[key] + json).Region + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    /// Ruling R-E40: a value put into an IMemoryCache (CacheExtensions.Set, CreateEntry and the entry's Value) or an
    /// IDistributedCache (Set, SetString and their async forms) is written into the cache object; read back by its key in
    /// the same request, it is the request's data, deserialized too (learn.microsoft.com dotnet/api/
    /// microsoft.extensions.caching.memory.cacheextensions.set, .imemorycache.createentry, .icacheentry.value,
    /// microsoft.extensions.caching.distributed.idistributedcache.set, .distributedcacheextensions.setstring).
    [Fact]
    public void Json_a_request_puts_into_a_cache_and_reads_back_is_request_data() => Expect(Types + """
        public class DraftController : ControllerBase
        {
            private readonly Microsoft.Extensions.Caching.Memory.IMemoryCache _memory;
            private readonly Microsoft.Extensions.Caching.Distributed.IDistributedCache _shared;
            private readonly SqlConnection _db = new();
            public DraftController(Microsoft.Extensions.Caching.Memory.IMemoryCache memory, Microsoft.Extensions.Caching.Distributed.IDistributedCache shared)
            {
                _memory = memory;
                _shared = shared;
            }
            public IActionResult Remember(string draft)
            {
                Microsoft.Extensions.Caching.Memory.CacheExtensions.Set(_memory, "draft", draft);
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(Microsoft.Extensions.Caching.Memory.CacheExtensions.Get<string>(_memory, "draft")!)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
                return Ok();
            }
            public IActionResult Entry(string draft)
            {
                using (var entry = _memory.CreateEntry("draft")) { entry.Value = draft; }
                _memory.TryGetValue("draft", out var held);
                var f = JsonConvert.DeserializeObject<Filter>((string)held!)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
                return Ok();
            }
            public async Task<IActionResult> Share(string draft)
            {
                await Microsoft.Extensions.Caching.Distributed.DistributedCacheExtensions.SetStringAsync(_shared, "draft", draft);
                var f = JsonConvert.DeserializeObject<Filter>((await Microsoft.Extensions.Caching.Distributed.DistributedCacheExtensions.GetStringAsync(_shared, "draft"))!)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
                return Ok();
            }
            public IActionResult Bytes(string draft)
            {
                _shared.Set("draft", System.Text.Encoding.UTF8.GetBytes(draft), new Microsoft.Extensions.Caching.Distributed.DistributedCacheEntryOptions());
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(System.Text.Encoding.UTF8.GetString(_shared.Get("draft")!))!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
                return Ok();
            }
        }
        """);

    /// What another request put into a cache is stored data for this one (request-scoped heap, decision R-6): read back by
    /// a key, its JSON deserializes into stored data (R-E39).
    [Fact]
    public void Json_another_request_put_into_a_cache_is_stored_data() => Expect(Types + """
        public class DraftController : ControllerBase
        {
            private readonly Microsoft.Extensions.Caching.Memory.IMemoryCache _memory;
            private readonly SqlConnection _db = new();
            public DraftController(Microsoft.Extensions.Caching.Memory.IMemoryCache memory) => _memory = memory;
            public IActionResult Save(string name, string draft)
            {
                Microsoft.Extensions.Caching.Memory.CacheExtensions.Set(_memory, name, draft);
                return Ok();
            }
            public IActionResult Load(string name)
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(Microsoft.Extensions.Caching.Memory.CacheExtensions.Get<string>(_memory, name)!)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'");
                return Ok();
            }
        }
        """);

    /// Fix round 1 of Task 34, M3: the JSON and XML parsers read the text they are given (learn.microsoft.com dotnet/api/
    /// system.text.json.jsondocument.parse, .jsondocument.rootelement, .jsonelement.getproperty,
    /// system.text.json.nodes.jsonnode.parse, .jsonnode.item, system.xml.serialization.xmlserializer.deserialize,
    /// system.io.stringreader.-ctor; newtonsoft.com/json/help JObject.Parse, JToken.Parse,
    /// JsonConvert.DeserializeAnonymousType), with R-E39's key-only rule.
    [Fact]
    public void Parsers_of_request_text_give_request_data_and_of_cached_text_stored_data() => Expect(Types + """
        public class ParseController : ControllerBase
        {
            private readonly Dictionary<string, string> _cache = new();
            private readonly SqlConnection _db = new();
            public IActionResult Run(string text, string key)
            {
                _db.Execute("SELECT 1 WHERE r = '" + System.Text.Json.JsonDocument.Parse(text).RootElement.GetProperty("r").GetString() + "'"); /*sink*/
                _db.Execute("SELECT 2 WHERE r = '" + System.Text.Json.Nodes.JsonNode.Parse(text)!["r"]!.GetValue<string>() + "'"); /*sink*/
                _db.Execute("SELECT 3 WHERE r = '" + JObject.Parse(text)["r"] + "'"); /*sink*/
                _db.Execute("SELECT 4 WHERE r = '" + JToken.Parse(text)["r"] + "'"); /*sink*/
                var x = (Filter)new System.Xml.Serialization.XmlSerializer(typeof(Filter)).Deserialize(new StringReader(text))!;
                _db.Execute("SELECT 5 WHERE r = '" + x.Region + "'"); /*sink*/
                var a = JsonConvert.DeserializeAnonymousType(text, new { Region = "" })!;
                _db.Execute("SELECT 6 WHERE r = '" + a.Region + "'"); /*sink*/
                _db.Execute("SELECT 7 WHERE r = '" + System.Text.Json.JsonDocument.Parse(_cache[key]).RootElement.GetProperty("r").GetString() + "'");
                _db.Execute("SELECT 8 WHERE r = '" + System.Text.Json.Nodes.JsonNode.Parse(_cache[key])!["r"]!.GetValue<string>() + "'");
                _db.Execute("SELECT 9 WHERE r = '" + JObject.Parse(_cache[key])["r"] + "'");
                var y = (Filter)new System.Xml.Serialization.XmlSerializer(typeof(Filter)).Deserialize(new StringReader(_cache[key]))!;
                _db.Execute("SELECT 10 WHERE r = '" + y.Region + "'");
                var b = JsonConvert.DeserializeAnonymousType(_cache[key], new { Region = "" })!;
                _db.Execute("SELECT 11 WHERE r = '" + b.Region + "'");
                return Ok();
            }
        }
        """);

    /// Final review I1: the same drop when the request data reaches a helper's parameters (the seed path) rather than
    /// returning from it (the substitution path): text found by a request key and deserialized in a helper, and a key given
    /// to a helper that looks it up and hands the text to another that deserializes it.
    private const string Archive = """
        public static class Archive
        {
            public static void Report(string text, SqlConnection db)
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(text)!;
                db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'");
            }
            public static void ReportRaw(string text, SqlConnection db) => db.Execute("SELECT * FROM notes WHERE t = '" + text + "'"); /*sink*/
            public static void Fetch(Dictionary<string, string> store, string key, SqlConnection db) => Report(store[key], db);
            public static void FetchRaw(Dictionary<string, string> store, string key, SqlConnection db) => ReportRaw(store[key], db);
            public static void Mix(Dictionary<string, string> store, string key, string extra, SqlConnection db) => Mixed(store[key] + extra, db);
            public static void Mixed(string text, SqlConnection db)
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(text)!;
                db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
            }
        }
        """;

    [Fact]
    public void Cached_json_found_by_a_request_key_and_deserialized_in_a_helper_is_stored_data() => Expect(Types + Archive + """
        public class ArchiveController : ControllerBase
        {
            private readonly Dictionary<string, string> _store = new();
            private readonly SqlConnection _db = new();
            public IActionResult Inline(string key)
            {
                Archive.Report(_store[key], _db);
                return Ok();
            }
            public IActionResult Handed(string key)
            {
                Archive.Fetch(_store, key, _db);
                return Ok();
            }
            public IActionResult RawText(string key)
            {
                Archive.FetchRaw(_store, key, _db);
                return Ok();
            }
            public IActionResult WithMore(string key, string extra)
            {
                Archive.Mix(_store, key, extra, _db);
                return Ok();
            }
        }
        """);

    [Fact]
    public void Cached_json_a_helper_stores_by_a_request_key_and_another_deserializes_is_stored_data() => Expect(Types + """
        public class Shelf { public string Text = ""; }
        public class Tray { public string Text = ""; }
        public class ShelfController : ControllerBase
        {
            private readonly Dictionary<string, string> _store = new();
            private readonly Shelf _shelf = new();
            private readonly Tray _raw = new();
            private readonly SqlConnection _db = new();
            public IActionResult Keep(string key)
            {
                Remember(key);
                Use();
                RememberRaw(key);
                UseRaw();
                return Ok();
            }
            private void Remember(string key) => _shelf.Text = _store[key];
            private void Use()
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(_shelf.Text)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'");
            }
            private void RememberRaw(string key) => _raw.Text = key;
            private void UseRaw()
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(_raw.Text)!;
                _db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + "'"); /*sink*/
            }
        }
        """);

    /// Final review re-check RC1: a sink reached both deserialized and raw, where the raw path joins the helper's summary
    /// only in a later analysis of its cycle (the action is in the cycle and seeds the helper first). The sink's lookup-key
    /// marks then meet, and the seeds must run again: the raw text found by a request key is request data.
    private const string Ledger = """
        public class LedgerController : ControllerBase
        {
            private readonly Dictionary<string, string> _store = new();
            private readonly SqlConnection _db = new();
            public IActionResult Book(string key)
            {
                Ledger.Post(_store[key], _db, 0);
                return Ok();
            }
        }
        public static class Ledger
        {
            public static void Post(string text, SqlConnection db, int hops)
            {
                var tail = Relay(text, db, hops);
                var f = System.Text.Json.JsonSerializer.Deserialize<Filter>(text)!;
                db.Execute("SELECT * FROM sales WHERE region = '" + f.Region + tail + "'"); /*sink*/
            }
            public static string Relay(string text, SqlConnection db, int hops)
            {
                CALLBACK
                return text;
            }
        }
        """;

    [Fact]
    public void Raw_cached_text_joining_a_cycles_summary_late_is_still_reported() =>
        Expect(Types + Ledger.Replace("CALLBACK", "if (hops > 50) new LedgerController().Book(text);"));

    [Fact]
    public void Raw_cached_text_beside_a_deserialized_path_is_reported() => Expect(Types + Ledger.Replace("CALLBACK", ""));

    private static void Expect(string code) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code));
}
