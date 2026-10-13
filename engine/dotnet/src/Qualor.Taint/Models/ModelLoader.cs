using System.Globalization;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Qualor.Taint;

/// Reads models/csharp (format v1, models/README.md): sources.yml and propagators.yml (shared) and one
/// `<name>.yml` per rule `csharp.<name>`. Strict: an unknown or missing key, a wrong value or a malformed member name
/// throws ModelException with the file and the line of the offending node. The YAML representation model (not a
/// deserializer into classes) is used so that every error, the semantic ones too, carries its line.
public static class ModelLoader
{
    public const string SourcesFile = "sources.yml";
    public const string PropagatorsFile = "propagators.yml";
    public const string RulePrefix = "csharp.";

    /// The values of propagators.yml's `unmodelled-external`.
    public static readonly IReadOnlyList<string> UnmodelledPolicies = new[] { "string-or-collection-return", "none" };

    /// Loads the models of `modelsDir` (the directory holding sources.yml, i.e. models/csharp).
    public static ModelSet Load(string modelsDir)
    {
        var sourcesFile = Path.Combine(modelsDir, SourcesFile);
        var sources = ReadSources(Doc.Open(sourcesFile));
        var propagatorsFile = Path.Combine(modelsDir, PropagatorsFile);
        var (propagators, unmodelled) = ReadPropagators(Doc.Open(propagatorsFile));

        string[] files;
        try
        {
            files = Directory.GetFiles(modelsDir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new ModelException(modelsDir, 1, "cannot list the models: " + e.Message, e);
        }
        Array.Sort(files, StringComparer.Ordinal);
        var rules = new List<RuleModel>();
        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            if (name is SourcesFile or PropagatorsFile) continue;
            if (name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)) throw new ModelException(file, 1, "a model file ends in .yml");
            if (!name.EndsWith(".yml", StringComparison.Ordinal)) continue;
            rules.Add(ReadRule(Doc.Open(file), RulePrefix + name[..^4]));
        }
        return new ModelSet(sources, propagators, unmodelled, rules);
    }

    private static SourceModel ReadSources(Doc doc)
    {
        var top = doc.Fields(doc.Root, "controllers", "razor-pages", "bound-properties", "minimal-api", "binding-attributes",
            "not-source-attributes", "parameter-types", "members");

        var c = doc.Fields(top.Required("controllers"), "bases", "base-name-suffixes", "name-suffixes", "class-attributes",
            "not-class-attributes", "not-method-attributes", "public-methods-only");
        var controllers = new ControllerSources(doc.Types(c.Required("bases")), doc.Names(c.Required("base-name-suffixes")),
            doc.Names(c.Required("name-suffixes")), doc.Types(c.Required("class-attributes")), doc.Types(c.Required("not-class-attributes")),
            doc.Types(c.Required("not-method-attributes")), doc.Bool(c.Required("public-methods-only")));

        var r = doc.Fields(top.Required("razor-pages"), "bases", "handler-prefixes", "public-methods-only");
        var razor = new RazorPageSources(doc.Types(r.Required("bases")), doc.Names(r.Required("handler-prefixes")), doc.Bool(r.Required("public-methods-only")));

        var b = doc.Fields(top.Required("bound-properties"), "property-attributes", "class-attributes");
        var bound = new BoundPropertySources(doc.Types(b.Required("property-attributes")), doc.Types(b.Required("class-attributes")));

        var m = doc.Fields(top.Required("minimal-api"), "map-methods", "source-types");
        var mapMethods = doc.Sequence(m.Required("map-methods")).Select(n => doc.Pattern(n, MemberKind.Method)).ToList();
        if (mapMethods.Any(p => p.Kind != MemberKind.Method)) throw doc.Error(m.Required("map-methods"), "map-methods are methods");
        var minimal = new MinimalApiSources(mapMethods, doc.Types(m.Required("source-types"), arrays: true));

        var t = doc.Fields(top.Required("parameter-types"), "scalars", "scalar-collections", "not-scalar-elements", "enums-are-scalar",
            "not-source-types", "interfaces-are-services", "source-interfaces");
        var types = new ParameterTypes(doc.Types(t.Required("scalars")), doc.Types(t.Required("scalar-collections")),
            doc.Types(t.Required("not-scalar-elements")), doc.Bool(t.Required("enums-are-scalar")), doc.Types(t.Required("not-source-types")),
            doc.Bool(t.Required("interfaces-are-services")), doc.Types(t.Required("source-interfaces")));

        var members = doc.Sequence(top.Required("members")).Select(n => doc.Member(n, new[] { "method", "property-get" }).Pattern).ToList();

        return new SourceModel(controllers, razor, bound, minimal, doc.Types(top.Required("binding-attributes")),
            doc.Types(top.Required("not-source-attributes")), types, members);
    }

    private static (IReadOnlyList<PropagatorModel>, string) ReadPropagators(Doc doc)
    {
        var top = doc.Fields(doc.Root, "propagators", "unmodelled-external");
        var list = new List<PropagatorModel>();
        foreach (var node in doc.Sequence(top.Required("propagators")))
        {
            var (pattern, f) = doc.Member(node, new[] { "method", "property-get" }, "from", "to");
            var from = f.Optional("from") is { } fromNode
                ? doc.Positions(fromNode, "from", "this", "args")
                : pattern.Kind switch { MemberKind.Constructor => new[] { "args" }, MemberKind.PropertyGet => new[] { "this" }, _ => new[] { "this", "args" } };
            var to = f.Optional("to") is { } toNode ? doc.Positions(toNode, "to", "return", "this", "out") : new[] { "return" };
            list.Add(new PropagatorModel(pattern, from, to));
        }
        var policyNode = top.Required("unmodelled-external");
        var policy = doc.String(policyNode);
        if (!UnmodelledPolicies.Contains(policy)) throw doc.Error(policyNode, $"unmodelled-external must be one of {string.Join(", ", UnmodelledPolicies)}");
        return (list, policy);
    }

    private static RuleModel ReadRule(Doc doc, string expectedId)
    {
        var top = doc.Fields(doc.Root, "rule", "kind", "sinks", "sanitizers", "guards", "misuse");
        var idNode = top.Required("rule");
        var id = doc.String(idNode);
        if (id != expectedId) throw doc.Error(idNode, $"rule must be {expectedId} (the file's name)");
        var kindNode = top.Required("kind");
        var kind = doc.String(kindNode) switch
        {
            "taint" => RuleKind.Taint,
            "misuse" => RuleKind.Misuse,
            _ => throw doc.Error(kindNode, "kind must be taint or misuse"),
        };

        var sinks = new List<SinkModel>();
        var sinksNode = kind == RuleKind.Taint ? top.Required("sinks") : top.Optional("sinks");
        if (sinksNode != null)
        {
            foreach (var node in doc.Sequence(sinksNode))
            {
                var (pattern, f) = doc.Member(node, new[] { "method", "property-set" }, "args", "param-types");
                var argsNode = f.Optional("args");
                IReadOnlyList<int> args;
                if (pattern.Kind == MemberKind.PropertySet)
                {
                    if (argsNode != null) throw doc.Error(argsNode, "a property-set sink has no args (its assigned value is the sink)");
                    args = Array.Empty<int>();
                }
                else
                {
                    if (argsNode == null) throw doc.Error(node, "a method sink needs args (parameter ordinals)");
                    var ordinals = doc.Sequence(argsNode).Select(n => doc.Ordinal(n, "args")).ToList();
                    if (ordinals.Count == 0 || ordinals.Distinct().Count() != ordinals.Count) throw doc.Error(argsNode, "args must be distinct parameter ordinals, at least one");
                    args = ordinals;
                }
                var paramTypes = f.Optional("param-types") is { } pt ? doc.Types(pt, arrays: true) : Array.Empty<string>();
                sinks.Add(new SinkModel(pattern, args) { ParamTypes = paramTypes });
            }
            if (kind == RuleKind.Taint && sinks.Count == 0) throw doc.Error(sinksNode, "a taint rule needs at least one sink");
        }

        var sanitizers = top.Optional("sanitizers") is { } sn
            ? doc.Sequence(sn).Select(n => doc.Member(n, new[] { "method", "property-get" }).Pattern).ToList()
            : new List<MemberPattern>();

        var guards = new List<GuardModel>();
        if (top.Optional("guards") is { } gn)
        {
            foreach (var node in doc.Sequence(gn))
            {
                var (pattern, f) = doc.Member(node, new[] { "method" }, "arg", "clean-when");
                if (pattern.Kind != MemberKind.Method) throw doc.Error(node, "a guard is a method");
                guards.Add(new GuardModel(pattern, doc.Ordinal(f.Required("arg"), "arg"), doc.Bool(f.Required("clean-when"))));
            }
        }

        var misuse = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (top.Optional("misuse") is { } mn)
        {
            if (kind != RuleKind.Misuse) throw doc.Error(mn, "misuse: belongs to a rule of kind misuse");
            if (mn is not YamlMappingNode map) throw doc.Error(mn, "misuse must be a mapping");
            foreach (var (k, v) in map.Children) misuse[doc.String(k)] = Doc.Plain(v);
        }
        return new RuleModel(id, kind, sinks, sanitizers, guards, misuse);
    }

    /// One YAML file: its root mapping and the checks, each throwing ModelException at the node's line.
    private sealed class Doc
    {
        private static readonly Regex Identifier = new(@"^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant);
        private static readonly Regex TypeName = new(@"^[A-Za-z_][A-Za-z0-9_]*(`[0-9]+)?([.+][A-Za-z_][A-Za-z0-9_]*(`[0-9]+)?)*$", RegexOptions.CultureInvariant);

        private Doc(string file, YamlNode root)
        {
            File = file;
            Root = root;
        }

        public string File { get; }

        public YamlNode Root { get; }

        public static Doc Open(string file)
        {
            string text;
            try
            {
                text = System.IO.File.ReadAllText(file);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                throw new ModelException(file, 1, "cannot read: " + e.Message, e);
            }
            var stream = new YamlStream();
            try
            {
                stream.Load(new StringReader(text));
            }
            catch (YamlException e)
            {
                throw new ModelException(file, Line(e.Start), Unmarked(e.Message), e);
            }
            if (stream.Documents.Count != 1) throw new ModelException(file, 1, "a model file holds one YAML document");
            var root = stream.Documents[0].RootNode;
            if (root is not YamlMappingNode) throw new ModelException(file, Line(root.Start), "the file must be a mapping");
            return new Doc(file, root);
        }

        public ModelException Error(YamlNode node, string message) => new(File, Line(node.Start), message);

        public Fields Fields(YamlNode node, params string[] allowed)
        {
            if (node is not YamlMappingNode map) throw Error(node, "expected a mapping with " + string.Join(", ", allowed));
            var fields = new Dictionary<string, YamlNode>(StringComparer.Ordinal);
            foreach (var (k, v) in map.Children)
            {
                var key = String(k);
                if (Array.IndexOf(allowed, key) < 0) throw Error(k, $"unknown key {key} (expected {string.Join(", ", allowed)})");
                if (!fields.TryAdd(key, v)) throw Error(k, $"duplicate key {key}");
            }
            return new Fields(this, map, fields);
        }

        /// A mapping that names exactly one member under one of `memberKeys`, plus `otherKeys`.
        public (MemberPattern Pattern, Fields Fields) Member(YamlNode node, string[] memberKeys, params string[] otherKeys)
        {
            var f = Fields(node, memberKeys.Concat(otherKeys).ToArray());
            var present = memberKeys.Where(k => f.Optional(k) != null).ToList();
            if (present.Count != 1) throw Error(node, $"exactly one of {string.Join(", ", memberKeys)}");
            var kind = present[0] switch
            {
                "property-get" => MemberKind.PropertyGet,
                "property-set" => MemberKind.PropertySet,
                _ => MemberKind.Method,
            };
            return (Pattern(f.Required(present[0]), kind), f);
        }

        /// `Type.Member`, `Type.Prefix*`, `Type.*` or (for a method) `Type..ctor`.
        public MemberPattern Pattern(YamlNode node, MemberKind kind)
        {
            var text = String(node);
            if (text.EndsWith("..ctor", StringComparison.Ordinal))
            {
                if (kind != MemberKind.Method) throw Error(node, $"{text}: a .ctor is a method, not a property");
                return new MemberPattern(CheckType(node, text[..^6], arrays: false), ".ctor", false, MemberKind.Constructor);
            }
            var dot = text.LastIndexOf('.');
            if (dot <= 0 || dot == text.Length - 1) throw Error(node, $"{text}: a member is written Type.Member");
            var name = text[(dot + 1)..];
            var prefix = name.EndsWith('*');
            var stem = prefix ? name[..^1] : name;
            if (stem.Contains('*') || text[..dot].Contains('*')) throw Error(node, $"{text}: '*' only at the end of a member name");
            if (!(prefix && stem.Length == 0) && !Identifier.IsMatch(stem)) throw Error(node, $"{text}: not a member name");
            return new MemberPattern(CheckType(node, text[..dot], arrays: false), stem, prefix, kind);
        }

        public IReadOnlyList<string> Types(YamlNode node, bool arrays = false) =>
            Sequence(node).Select(n => CheckType(n, String(n), arrays)).ToList();

        public IReadOnlyList<string> Names(YamlNode node) =>
            Sequence(node).Select(n => Identifier.IsMatch(String(n)) ? String(n) : throw Error(n, $"{String(n)}: not a name")).ToList();

        /// A list of `from`/`to` positions: the words allowed or parameter ordinals.
        public IReadOnlyList<string> Positions(YamlNode node, string key, params string[] words)
        {
            var list = Sequence(node).Select(n =>
            {
                var s = String(n);
                if (Array.IndexOf(words, s) >= 0) return s;
                return n is YamlScalarNode { Style: ScalarStyle.Plain } && int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var ordinal)
                    ? ordinal.ToString(CultureInfo.InvariantCulture)
                    : throw Error(n, $"{key}: {s}: expected {string.Join(", ", words)} or a parameter ordinal");
            }).ToList();
            if (list.Count == 0) throw Error(node, $"{key} must not be empty");
            return list;
        }

        public IReadOnlyList<YamlNode> Sequence(YamlNode node) =>
            node is YamlSequenceNode seq ? seq.Children.ToList() : throw Error(node, "expected a list");

        public string String(YamlNode node) =>
            node is YamlScalarNode { Value: { Length: > 0 } v } ? v : throw Error(node, "expected a non-empty value");

        public bool Bool(YamlNode node) => String(node) switch
        {
            "true" => true,
            "false" => false,
            var s => throw Error(node, $"{KeyHint(node)}{s}: expected true or false"),
        };

        public int Ordinal(YamlNode node, string key) =>
            node is YamlScalarNode { Style: ScalarStyle.Plain, Value: { } v }
            && int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                ? n
                : throw Error(node, $"{key}: {(node as YamlScalarNode)?.Value} is not a parameter ordinal (0, 1, ...)");

        private string CheckType(YamlNode node, string text, bool arrays)
        {
            var element = arrays && text.EndsWith("[]", StringComparison.Ordinal) ? text[..^2] : text;
            return TypeName.IsMatch(element) ? text : throw Error(node, $"{text}: not a type's metadata name");
        }

        private string KeyHint(YamlNode node) =>
            Root.AllNodes.OfType<YamlMappingNode>().SelectMany(m => m.Children).FirstOrDefault(c => ReferenceEquals(c.Value, node)).Key is YamlScalarNode k
                ? k.Value + ": " : "";

        /// A YAML value as plain objects: a string (null for `~`, `null` or nothing), a list or a dictionary.
        public static object? Plain(YamlNode node) => node switch
        {
            YamlScalarNode { Style: ScalarStyle.Plain, Value: null or "" or "~" or "null" } => null,
            YamlScalarNode s => s.Value,
            YamlSequenceNode seq => seq.Children.Select(Plain).ToList(),
            YamlMappingNode map => map.Children.ToDictionary(c => ((YamlScalarNode)c.Key).Value ?? "", c => Plain(c.Value), StringComparer.Ordinal),
            _ => null,
        };

        private static int Line(Mark mark) => (int)Math.Clamp(mark.Line, 1, int.MaxValue);

        /// YamlDotNet's message without its "(Line: .., Col: .., Idx: ..) - (...): " prefix; the line is ours.
        private static string Unmarked(string message)
        {
            var i = message.IndexOf("): ", StringComparison.Ordinal);
            return message.StartsWith("(Line", StringComparison.Ordinal) && i >= 0 ? message[(i + 3)..] : message;
        }
    }

    private sealed class Fields
    {
        private readonly Doc _doc;
        private readonly YamlMappingNode _map;
        private readonly Dictionary<string, YamlNode> _fields;

        public Fields(Doc doc, YamlMappingNode map, Dictionary<string, YamlNode> fields)
        {
            _doc = doc;
            _map = map;
            _fields = fields;
        }

        public YamlNode? Optional(string key) => _fields.TryGetValue(key, out var v) ? v : null;

        public YamlNode Required(string key) => Optional(key) ?? throw _doc.Error(_map, $"missing key {key}");
    }
}
