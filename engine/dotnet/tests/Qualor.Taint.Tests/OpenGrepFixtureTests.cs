using Microsoft.CodeAnalysis;
using Qualor.Taint.Tests.Fixtures;

namespace Qualor.Taint.Tests;

/// What the OpenGrep fixtures need to compile: FixtureReferences, the harness's implicit usings, the shims in
/// engine/dotnet/fixtures/shims and the `uncompilable:` lines of engine/dotnet/expectations.yml.
public class OpenGrepFixtureCompileTests
{
    private static readonly string ExpectationsFile = Path.Combine(Repo.EngineDir, "expectations.yml");

    public static IEnumerable<object[]> Fixtures() => FixtureRunner.AllFixturePaths().Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    internal static string PathOf(string name) => FixtureRunner.AllFixturePaths().Single(p => Path.GetFileNameWithoutExtension(p) == name);

    private static IEnumerable<string> FixtureFiles() =>
        FixtureRunner.AllFixturePaths().SelectMany(FixtureRunner.FilesOf).Where(f => !f.EndsWith(".shim.cs", StringComparison.Ordinal));

    [Fact]
    public void There_are_twelve_fixtures() => Assert.Equal(12, FixtureRunner.AllFixturePaths().Count);

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Fixture_compiles_without_errors(string name)
    {
        var compiled = FixtureRunner.Compile(PathOf(name), Expectations.Load(ExpectationsFile));
        Assert.True(compiled.CompileErrors.Count == 0,
            name + ": " + compiled.CompileErrors.Count + " compile errors" + Environment.NewLine +
            string.Join(Environment.NewLine, compiled.CompileErrors.Take(40).Select(e => e.ToString())));
    }

    [Fact]
    public void Every_uncompilable_line_really_has_a_compile_error()
    {
        var expectations = Expectations.Load(ExpectationsFile);
        var stale = new List<string>();
        foreach (var group in expectations.Uncompilable.GroupBy(u => u.File))
        {
            var path = FixtureRunner.AllFixturePaths().Single(p => Path.GetFileName(p) == group.Key);
            var errorLines = FixtureRunner.Compile(path).CompileErrors
                .Where(e => e.Location.IsInSource && Path.GetFileName(e.Location.SourceTree!.FilePath) == group.Key)
                .Select(e => e.Location.GetLineSpan().StartLinePosition.Line + 1).ToHashSet();
            stale.AddRange(group.Where(u => !errorLines.Contains(u.Line)).Select(u => u.File + ":" + u.Line));
        }
        Assert.True(stale.Count == 0, "uncompilable entries without a compile error (remove them): " + string.Join(", ", stale));
    }

    [Fact]
    public void Expectation_entries_point_at_annotated_lines()
    {
        var expectations = Expectations.Load(ExpectationsFile);
        var annotations = FixtureFiles().SelectMany(f => Annotation.Parse(Path.GetFileName(f), File.ReadAllText(f))).ToList();
        bool Has(ExpectedLine e, params string[] kinds) => annotations.Any(a => a.File == e.File && a.Line == e.Line && a.RuleId == e.Rule && kinds.Contains(a.Kind));

        Assert.All(expectations.MustFind, e => Assert.True(Has(e, "todoruleid"), "must-find " + e.File + ":" + e.Line + " is no todoruleid line"));
        Assert.All(expectations.MustStayQuiet, e => Assert.True(Has(e, "todook"), "must-stay-quiet " + e.File + ":" + e.Line + " is no todook line"));
        Assert.All(expectations.ReportedTodoOk, e => Assert.True(Has(e, "todook"), "reported-todook " + e.File + ":" + e.Line + " is no todook line"));
        Assert.All(expectations.Excluded, e => Assert.True(Has(e, "ruleid", "ok", "todoruleid", "todook"), "excluded " + e.File + ":" + e.Line + " is not annotated"));
    }

    [Fact]
    public void Annotations_precede_a_line_of_code()
    {
        var bad = new List<string>();
        foreach (var file in FixtureFiles())
        {
            var text = File.ReadAllText(file);
            var lines = text.Split('\n');
            foreach (var a in Annotation.Parse(Path.GetFileName(file), text))
            {
                var target = a.Line <= lines.Length ? lines[a.Line - 1].Trim() : "";
                if (target.Length == 0 || target.StartsWith("//", StringComparison.Ordinal)) bad.Add(a.File + ":" + (a.Line - 1));
            }
        }
        Assert.True(bad.Count == 0, "annotations not followed by a line of code: " + string.Join(", ", bad));
    }

    [Fact]
    public void The_annotation_counts_match_the_fixtures()
    {
        // 479 ruleid, 397 ok, 86 todoruleid and 50 todook comments in the twelve fixtures and their two companions.
        var annotations = FixtureFiles().SelectMany(f => Annotation.Parse(Path.GetFileName(f), File.ReadAllText(f))).ToList();
        Assert.Equal(479, annotations.Count(a => a.Kind == "ruleid"));
        Assert.Equal(397, annotations.Count(a => a.Kind == "ok"));
        Assert.Equal(86, annotations.Count(a => a.Kind == "todoruleid"));
        Assert.Equal(50, annotations.Count(a => a.Kind == "todook"));
    }
}

/// The OpenGrep fixtures against the engine: for every rule with a model (the theory data grows with models/csharp)
/// no ruleid line is Missing, no ok line is Unexpected, and every must-find entry of expectations.yml is found.
public class OpenGrepFixtureTests
{
    private static readonly Lazy<ModelSet> Models = new(() => ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")));

    public static IEnumerable<object[]> Rules() =>
        Models.Value.Rules.Select(r => new object[] { r.RuleId["csharp.".Length..] });

    /// Ruling R-E7 ended with Task 11 (guards and allow-lists): no rule may keep a pending Missing or Unexpected line.
    /// The list stays for a line a later task has to leave open, with its reason and the task that closes it; a listed
    /// line the engine gets right fails the test too (remove the entry).
    private static readonly (string Rule, string File, int Line, string Kind, string Why)[] Pending =
        Array.Empty<(string, string, int, string, string)>();

    /// The engine runs to completion (no internal error, no iteration cap) on every fixture, modelled or not.
    [Theory]
    [MemberData(nameof(OpenGrepFixtureCompileTests.Fixtures), MemberType = typeof(OpenGrepFixtureCompileTests))]
    public void Engine_completes_on_the_fixture(string name)
    {
        var compiled = FixtureRunner.Compile(OpenGrepFixtureCompileTests.PathOf(name), Expectations.Load(Path.Combine(Repo.EngineDir, "expectations.yml")));
        var result = new TaintEngine(Models.Value, new TaintEngineOptions(TimeSpan.FromMinutes(10), 4L << 30)).Analyze(compiled.Solution, CancellationToken.None);
        Assert.True(result.Complete && result.Stats.FailedMethods == 0,
            name + ": " + result.IncompleteReason + "; failed bodies: " + string.Join("; ", result.Stats.FirstErrors));
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void Fixture_matches(string name)
    {
        var expectations = Expectations.Load(Path.Combine(Repo.EngineDir, "expectations.yml"));
        var rule = "csharp." + name;
        var result = FixtureRunner.Run(OpenGrepFixtureCompileTests.PathOf(name), Models.Value, expectations: expectations);

        Assert.Empty(result.CompileErrors);
        var pending = Pending.Where(p => p.Rule == rule).ToList();
        bool IsPending(Annotation a, string kind) => pending.Any(p => p.Kind == kind && p.File == a.File && p.Line == a.Line);
        var missing = result.Missing.Where(a => !IsPending(a, "missing")).Select(a => a.File + ":" + a.Line).ToList();
        var unexpected = result.Unexpected.Where(a => !IsPending(a, "unexpected")).Select(a => a.File + ":" + a.Line).ToList();
        var stale = pending.Where(p => !(p.Kind == "missing" ? result.Missing : result.Unexpected).Any(a => a.File == p.File && a.Line == p.Line))
            .Select(p => p.Kind + " " + p.File + ":" + p.Line).ToList();
        Assert.True(missing.Count == 0 && unexpected.Count == 0 && stale.Count == 0,
            $"{rule}: Missing [{string.Join(", ", missing)}]; Unexpected [{string.Join(", ", unexpected)}]; pending entries now right (remove) [{string.Join(", ", stale)}]");
        foreach (var e in expectations.MustFind.Where(e => e.Rule == rule))
            Assert.Contains(result.TodoFound, a => a.File == e.File && a.Line == e.Line);
        foreach (var e in expectations.MustStayQuiet.Where(e => e.Rule == rule))
            Assert.DoesNotContain(result.TodoOkReported, a => a.File == e.File && a.Line == e.Line);
        // A ratchet both ways: every todoruleid line the engine finds is pinned in must-find (so a regression is seen),
        // and the todook lines it reports are exactly reported-todook (the false positives it shares with OpenGrep).
        var unpinned = result.TodoFound
            .Where(a => !expectations.MustFind.Any(e => e.Rule == rule && e.File == a.File && e.Line == a.Line))
            .Select(a => a.File + ":" + a.Line).ToList();
        Assert.True(unpinned.Count == 0, $"{rule}: todoruleid lines found but not in must-find (add them) [{string.Join(", ", unpinned)}]");
        var reported = result.TodoOkReported.Select(a => a.File + ":" + a.Line).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var pinned = expectations.ReportedTodoOk.Where(e => e.Rule == rule).Select(e => e.File + ":" + e.Line).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Assert.True(reported.SequenceEqual(pinned),
            $"{rule}: todook lines reported [{string.Join(", ", reported)}] differ from reported-todook [{string.Join(", ", pinned)}]");
    }
}
