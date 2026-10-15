using Qualor.Taint.Tests.Fixtures;
using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests;

/// Final review Minor 1: two analyses of the same code, each over its own compilation (new symbols, new syntax trees, so
/// every identity-hashed dictionary is ordered anew), report the same findings with the same paths, confidences and
/// other sources: summary effects are visited in a canonical order and equally good paths are chosen canonically
/// (Trail.Better's fingerprint), so what a user sees does not change between scans of unchanged code.
public sealed class DeterminismTests
{
    [Theory]
    [InlineData("sql-injection")]
    [InlineData("path-traversal")]
    [InlineData("xss")]
    public void Two_runs_report_the_same_paths(string name)
    {
        var path = OpenGrepFixtureCompileTests.PathOf(name);
        Assert.Equal(Shown(path), Shown(path));
    }

    private static List<string> Shown(string fixturePath)
    {
        var compiled = FixtureRunner.Compile(fixturePath);
        var result = new TaintEngine(Snippet.Models, Snippet.Options).Analyze(compiled.Solution, CancellationToken.None);
        Assert.True(result.Complete, result.IncompleteReason);
        return result.Findings.Select(f =>
        {
            var steps = string.Join(" | ", f.Path.Select(s => $"{Path.GetFileName(s.Span.Path)}:{s.Span.StartLinePosition.Line + 1}:{s.Span.StartLinePosition.Character + 1} {s.Message} {s.Kind}"));
            var others = string.Join(",", f.OtherSources.Select(o => $"{Path.GetFileName(o.SourceTree?.FilePath)}:{o.SourceSpan.Start}"));
            return $"{f.RuleId} {Path.GetFileName(f.SinkSpan.Path)}:{f.SinkSpan.StartLinePosition.Line + 1} {f.Confidence} [{steps}] ({others})";
        }).ToList();
    }
}
