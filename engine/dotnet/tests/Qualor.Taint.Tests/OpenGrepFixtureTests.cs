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

/// The engine of the comparison test. Null until the engine exists (Task 7 sets Analyze to run TaintEngine over the
/// LoadedSolution and return its findings as (rule id, file, line)); the comparison theory is skipped meanwhile.
public static class FixtureEngine
{
    public static Func<LoadedSolution, IReadOnlyList<(string RuleId, string File, int Line)>>? Analyze => null;
}

/// A theory that is skipped while there is no engine to run.
public sealed class EngineTheoryAttribute : TheoryAttribute
{
    public EngineTheoryAttribute()
    {
        if (FixtureEngine.Analyze == null) Skip = "the taint engine arrives with Task 7 (FixtureEngine.Analyze is null)";
    }
}

/// The OpenGrep fixtures against the engine: for every rule with a model (the theory data grows with models/csharp)
/// no ruleid line is Missing, no ok line is Unexpected, and every must-find entry of expectations.yml is found.
public class OpenGrepFixtureTests
{
    // Ruling R-E7: until Task 11 adds guards and allow-lists, Unexpected may hold ok lines whose safety rests on an
    // allow-list or a guard; Task 7 lists them in its report and filters them here. From Task 11 on: none.
    public static IEnumerable<object[]> Rules() =>
        ModelLoader.Load(Path.Combine(Repo.Root, "models", "csharp")).Rules
            .Select(r => new object[] { r.RuleId["csharp.".Length..] });

    [EngineTheory]
    [MemberData(nameof(Rules))]
    public void Fixture_matches(string name)
    {
        var expectations = Expectations.Load(Path.Combine(Repo.EngineDir, "expectations.yml"));
        var rule = "csharp." + name;
        var result = FixtureRunner.Run(OpenGrepFixtureCompileTests.PathOf(name), FixtureEngine.Analyze!, expectations);

        Assert.Empty(result.CompileErrors);
        Assert.Empty(result.Missing);
        Assert.Empty(result.Unexpected);
        foreach (var e in expectations.MustFind.Where(e => e.Rule == rule))
            Assert.Contains(result.TodoFound, a => a.File == e.File && a.Line == e.Line);
        foreach (var e in expectations.MustStayQuiet.Where(e => e.Rule == rule))
            Assert.DoesNotContain(result.TodoOkReported, a => a.File == e.File && a.Line == e.Line);
    }
}
