using System.Text;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// The shipped models (the shared ones and the rules) with one probe rule `csharp.probe` written from YAML, so a capability
/// is tested apart from the shipped rule models (only the probe rule's findings are read); and the lines a snippet
/// reports for the probe rule.
public abstract class ProbeModels : TempDirs
{
    protected const string Rule = "csharp.probe";

    protected ModelSet Probe(string ruleYaml)
    {
        var dir = TempDir();
        // Every shipped model (propagators.yml's `only-for:` names shipped rules); the tests read the probe rule's findings.
        foreach (var file in Directory.GetFiles(ModelLoaderTests.ShippedModels(), "*.yml"))
            File.Copy(file, Path.Combine(dir, Path.GetFileName(file)));
        File.WriteAllText(Path.Combine(dir, "probe.yml"), "rule: csharp.probe\nkind: taint\n" + ruleYaml, new UTF8Encoding(false));
        return ModelLoader.Load(dir);
    }

    /// The 1-based lines of the snippet the engine reports the probe rule on, in order.
    protected static IReadOnlyList<int> Findings(ModelSet models, string code)
    {
        var result = new TaintEngine(models, Snippet.Options).Analyze(Snippet.Compile(code), CancellationToken.None);
        Assert.True(result.Stats.FailedMethods == 0, "failed bodies: " + string.Join("; ", result.Stats.FirstErrors));
        return result.Findings.Where(f => f.RuleId == Rule && Path.GetFileName(f.Sink.SourceTree!.FilePath) == "Snippet.cs")
            .Select(f => f.Sink.GetLineSpan().StartLinePosition.Line + 1).OrderBy(l => l).ToList();
    }

    protected static void Expect(ModelSet models, string code) => Assert.Equal(Snippet.Marked(code), Findings(models, code));
}
