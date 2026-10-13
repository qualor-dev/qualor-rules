namespace Qualor.Taint.Tests.Fixtures;

/// An OpenGrep test annotation (`// ruleid: <rule>` and the like). Kind is ruleid, ok, todoruleid or todook; Line is the
/// line AFTER the comment (the annotated line); File is the file name (not the path) the comment is in.
public sealed record Annotation(string File, int Line, string Kind, string RuleId)
{
    public static readonly IReadOnlyList<string> Kinds = new[] { "ruleid", "ok", "todoruleid", "todook" };

    /// The annotations of one file's text: every line that, after trimming, is `// <kind>: <rule id>`.
    public static IReadOnlyList<Annotation> Parse(string file, string text)
    {
        var result = new List<Annotation>();
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith("//", StringComparison.Ordinal)) continue;
            var body = line[2..].Trim();
            var colon = body.IndexOf(':');
            if (colon <= 0) continue;
            var kind = body[..colon].Trim();
            if (!Kinds.Contains(kind)) continue;
            var rule = body[(colon + 1)..].Trim();
            if (rule.Length == 0 || rule.Any(char.IsWhiteSpace)) continue;
            result.Add(new Annotation(file, i + 2, kind, rule));
        }
        return result;
    }
}
