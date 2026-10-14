using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint.Cli.Output;

/// SARIF 2.1.0 for one analysis run: tool qualor-taint with one rule per model, a result per finding (mapped locations,
/// the path as codeFlows[0].threadFlows[0], the other sources as relatedLocations; no partialFingerprints, Qualor
/// computes its own), the run's AnalysisStats in runs[0].properties and the invocation's success. A result's confidence
/// (R-9) is `properties.confidence` ("high" or "medium"); a medium result's level is "warning" (a high one keeps the
/// rule's level, "error"), and each step of its path that is not a plain flow names its kind (`properties.kind`).
public static class SarifWriter
{
    public const string Schema = "https://json.schemastore.org/sarif-2.1.0.json";
    public const string SrcRoot = "%SRCROOT%";

    /// Finding paths as SARIF uris: relative to Root (with '/') when under it, else absolute (file URI); the latter are
    /// collected in Outside, for a note.
    public sealed class PathMapper
    {
        private readonly string? _root;
        public PathMapper(string? root) => _root = root == null ? null : Normalize(root).TrimEnd('/');
        public SortedSet<string> Outside { get; } = new(StringComparer.Ordinal);

        public (string Uri, bool Relative) Map(string path)
        {
            var p = Normalize(path);
            if (_root != null)
            {
                var windows = _root.Length >= 2 && _root[1] == ':';
                var cmp = windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                if (p.Length > _root.Length && p.StartsWith(_root, cmp) && p[_root.Length] == '/')
                    return (Escape(p[(_root.Length + 1)..]), true);
                Outside.Add(p);
            }
            return (p.Length >= 2 && p[1] == ':' ? "file:///" + Escape(p) : p.StartsWith('/') ? "file://" + Escape(p) : Escape(p), false);
        }

        private static string Normalize(string path) => path.Replace('\\', '/');

        private static string Escape(string path) =>
            string.Join('/', path.Split('/').Select(s => s.Length == 2 && s[1] == ':' ? s : Uri.EscapeDataString(s)));
    }

    public static void Write(Stream stream, ModelSet models, AnalysisResult result, string? version, string? root, IReadOnlyList<string> inputErrors)
    {
        using var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        var mapper = new PathMapper(root);
        var ruleIds = models.Rules.Select(r => r.RuleId).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var kinds = models.Rules.ToDictionary(r => r.RuleId, r => r.Kind);

        w.WriteStartObject();
        w.WriteString("$schema", Schema);
        w.WriteString("version", "2.1.0");
        w.WriteStartArray("runs");
        w.WriteStartObject();

        w.WriteStartObject("tool");
        w.WriteStartObject("driver");
        w.WriteString("name", "qualor-taint");
        if (!string.IsNullOrEmpty(version)) w.WriteString("semanticVersion", version);
        w.WriteStartArray("rules");
        foreach (var id in ruleIds)
        {
            w.WriteStartObject();
            w.WriteString("id", id);
            w.WriteString("name", id[(id.IndexOf('.') + 1)..]);
            w.WriteStartObject("shortDescription");
            w.WriteString("text", kinds[id] == RuleKind.Taint ? $"{id}: request data reaches a sink" : $"{id}: insecure configuration");
            w.WriteEndObject();
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteEndObject();
        w.WriteEndObject();

        if (root != null)
        {
            w.WriteStartObject("originalUriBaseIds");
            w.WriteStartObject(SrcRoot);
            w.WriteString("uri", RootUri(root));
            w.WriteEndObject();
            w.WriteEndObject();
        }

        w.WriteStartArray("results");
        foreach (var f in result.Findings)
        {
            w.WriteStartObject();
            w.WriteString("ruleId", f.RuleId);
            w.WriteNumber("ruleIndex", ruleIds.IndexOf(f.RuleId));
            w.WriteString("level", f.Confidence == Confidence.Medium ? "warning" : "error");
            w.WriteStartObject("message");
            var name = f.RuleId[(f.RuleId.IndexOf('.') + 1)..];
            // A sink's own message (Task 29: a DataTable filter, a request-chosen type) names what was reached.
            w.WriteString("text", f.Message != null
                ? $"{f.RuleId}: {f.Message}"
                : kinds.TryGetValue(f.RuleId, out var k) && k == RuleKind.Misuse
                ? $"{f.RuleId}: insecure configuration ({name})"
                : $"{f.RuleId}: request data reaches the {name} sink");
            w.WriteEndObject();
            w.WriteStartArray("locations");
            WriteLocation(w, mapper, f.SinkSpan, null, null);
            w.WriteEndArray();
            if (f.Path.Count > 0)
            {
                w.WriteStartArray("codeFlows");
                w.WriteStartObject();
                w.WriteStartArray("threadFlows");
                w.WriteStartObject();
                w.WriteStartArray("locations");
                foreach (var step in f.Path)
                {
                    // a threadFlowLocation: the location sits under its "location" property
                    w.WriteStartObject();
                    w.WriteStartObject("location");
                    WriteLocationBody(w, mapper, step.Span, null, step.Message);
                    w.WriteEndObject();
                    if (step.Kind.Name() is { } kind)
                    {
                        w.WriteStartObject("properties");
                        w.WriteString("kind", kind);
                        w.WriteEndObject();
                    }
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteEndObject();
                w.WriteEndArray();
                w.WriteEndObject();
                w.WriteEndArray();
            }
            if (f.OtherSources.Count > 0)
            {
                w.WriteStartArray("relatedLocations");
                var n = 1;
                foreach (var s in f.OtherSources) WriteLocation(w, mapper, s.GetMappedLineSpan(), n++, "other request data reaching the same sink");
                w.WriteEndArray();
            }
            w.WriteStartObject("properties");
            w.WriteString("confidence", f.Confidence == Confidence.Medium ? "medium" : "high");
            w.WriteEndObject();
            w.WriteEndObject();
        }
        w.WriteEndArray();

        w.WriteStartArray("invocations");
        w.WriteStartObject();
        w.WriteBoolean("executionSuccessful", result.Complete);
        var notes = new List<(string Level, string Text)>();
        if (!result.Complete) notes.Add(("error", "analysis incomplete: " + result.IncompleteReason));
        foreach (var e in inputErrors) notes.Add(("warning", "input: " + e));
        if (mapper.Outside.Count > 0)
            notes.Add(("note", $"{mapper.Outside.Count} file(s) outside --root are reported with absolute paths, first: {mapper.Outside.First()}"));
        if (notes.Count > 0)
        {
            w.WriteStartArray("toolExecutionNotifications");
            foreach (var (level, text) in notes)
            {
                w.WriteStartObject();
                w.WriteString("level", level);
                w.WriteStartObject("message");
                w.WriteString("text", text);
                w.WriteEndObject();
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        w.WriteEndObject();
        w.WriteEndArray();

        var stats = result.Stats;
        w.WriteStartObject("properties");
        w.WriteStartObject("analysisStats");
        w.WriteNumber("projects", stats.Projects);
        w.WriteNumber("methods", stats.Methods);
        w.WriteNumber("failedMethods", stats.FailedMethods);
        w.WriteStartArray("firstErrors");
        foreach (var e in stats.FirstErrors) w.WriteStringValue(e);
        w.WriteEndArray();
        w.WriteNumber("sccs", stats.Sccs);
        w.WriteNumber("unmodelledExternalCalls", stats.UnmodelledExternalCalls);
        w.WriteNumber("elapsedSeconds", Math.Round(stats.Elapsed.TotalSeconds, 3));
        w.WriteNumber("peakMemoryBytes", stats.PeakMemoryBytes);
        w.WriteNumber("entryPoints", stats.EntryPoints);
        w.WriteNumber("viewEdges", stats.ViewEdges);
        w.WriteNumber("unresolvedViews", stats.UnresolvedViews);
        w.WriteNumber("uncompiledViews", stats.UncompiledViews);
        w.WriteNumber("compiledByEngineViews", stats.CompiledByEngineViews);
        w.WriteNumber("engineViewErrors", stats.EngineViewErrors);
        w.WriteNumber("dispatchByRegistrations", stats.DispatchByRegistrations);
        w.WriteNumber("dispatchNarrowed", stats.DispatchNarrowed);
        w.WriteNumber("dispatchByScanning", stats.DispatchByScanning);
        w.WriteNumber("dispatchByHierarchy", stats.DispatchByHierarchy);
        w.WriteNumber("openProjects", stats.OpenProjects);
        w.WriteNumber("openTypes", stats.OpenTypes);
        w.WriteNumber("highFindings", stats.HighFindings);
        w.WriteNumber("mediumFindings", stats.MediumFindings);
        w.WriteEndObject();
        w.WriteEndObject();

        w.WriteEndObject();
        w.WriteEndArray();
        w.WriteEndObject();
    }

    private static string RootUri(string root)
    {
        var p = root.Replace('\\', '/').TrimEnd('/') + "/";
        return new PathMapper(null).Map(p).Uri;
    }

    private static void WriteLocation(Utf8JsonWriter w, PathMapper mapper, FileLinePositionSpan span, int? id, string? message)
    {
        w.WriteStartObject();
        WriteLocationBody(w, mapper, span, id, message);
        w.WriteEndObject();
    }

    private static void WriteLocationBody(Utf8JsonWriter w, PathMapper mapper, FileLinePositionSpan span, int? id, string? message)
    {
        if (id != null) w.WriteNumber("id", id.Value);
        w.WriteStartObject("physicalLocation");
        w.WriteStartObject("artifactLocation");
        var (uri, relative) = mapper.Map(span.Path);
        w.WriteString("uri", uri);
        if (relative) w.WriteString("uriBaseId", SrcRoot);
        w.WriteEndObject();
        w.WriteStartObject("region");
        w.WriteNumber("startLine", span.StartLinePosition.Line + 1);
        w.WriteNumber("startColumn", span.StartLinePosition.Character + 1);
        w.WriteNumber("endLine", span.EndLinePosition.Line + 1);
        w.WriteNumber("endColumn", span.EndLinePosition.Character + 1);
        w.WriteEndObject();
        w.WriteEndObject();
        if (message != null)
        {
            w.WriteStartObject("message");
            w.WriteString("text", message);
            w.WriteEndObject();
        }
    }
}
