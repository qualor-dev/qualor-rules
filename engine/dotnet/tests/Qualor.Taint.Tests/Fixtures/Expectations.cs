using YamlDotNet.RepresentationModel;

namespace Qualor.Taint.Tests.Fixtures;

/// A line of an OpenGrep fixture named in expectations.yml. File is the fixture file's name (optional in the
/// file: the rule's main fixture, `<name>.cs` of `csharp.<name>`).
public sealed record ExpectedLine(string Rule, string File, int Line, string Reason);

/// engine/dotnet/expectations.yml: which todo lines the engine must find or keep quiet, and which fixture lines cannot
/// compile in any form (excluded from the engine comparison).
public sealed record Expectations(IReadOnlyList<ExpectedLine> MustFind, IReadOnlyList<ExpectedLine> MustStayQuiet, IReadOnlyList<ExpectedLine> Uncompilable)
{
    public static readonly Expectations None = new(Array.Empty<ExpectedLine>(), Array.Empty<ExpectedLine>(), Array.Empty<ExpectedLine>());

    /// Lines that compile but whose annotation rests on an uncompilable line (`excluded:`); not compared either.
    public IReadOnlyList<ExpectedLine> Excluded { get; init; } = Array.Empty<ExpectedLine>();

    public static Expectations Load(string path)
    {
        var yaml = new YamlStream();
        using (var reader = new StreamReader(path)) yaml.Load(reader);
        var root = (YamlMappingNode)yaml.Documents[0].RootNode;
        return new Expectations(Entries(root, "must-find", "why"), Entries(root, "must-stay-quiet", "why"), Entries(root, "uncompilable", "reason"))
        {
            Excluded = Entries(root, "excluded", "reason"),
        };
    }

    private static IReadOnlyList<ExpectedLine> Entries(YamlMappingNode root, string key, string reasonKey)
    {
        var result = new List<ExpectedLine>();
        if (!root.Children.TryGetValue(new YamlScalarNode(key), out var node) || node is not YamlSequenceNode seq) return result;
        foreach (var item in seq.Children.Cast<YamlMappingNode>())
        {
            string Get(string k) => item.Children.TryGetValue(new YamlScalarNode(k), out var v) ? ((YamlScalarNode)v).Value ?? "" : "";
            var rule = Get("rule");
            var file = Get("file");
            if (file.Length == 0 && rule.StartsWith("csharp.", StringComparison.Ordinal)) file = rule["csharp.".Length..] + ".cs";
            result.Add(new ExpectedLine(rule, file, int.Parse(Get("line")), Get(reasonKey)));
        }
        return result;
    }
}
