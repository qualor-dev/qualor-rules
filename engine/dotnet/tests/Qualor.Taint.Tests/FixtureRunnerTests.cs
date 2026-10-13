using Qualor.Taint.Tests.Fixtures;

namespace Qualor.Taint.Tests;

/// The annotation parser and FixtureRunner's comparison, with a fake engine (a delegate returning given findings).
public class FixtureRunnerTests : TempDirs
{
    private const string Demo = "csharp.demo";

    // The annotations are on lines 5, 7, 9 and 11 and refer to lines 6, 8, 10 and 12.
    private const string Source = """
        public class C
        {
            public void M(string a)
            {
                // ruleid: csharp.demo
                var x = a;
                // ok: csharp.demo
                var y = "";
                // todoruleid: csharp.demo
                var z = a;
                // todook: csharp.demo
                var w = "";
            }
        }
        """;

    private string Fixture(string source = Source, string name = "demo")
    {
        var path = Path.Combine(TempDir(), name + ".cs");
        File.WriteAllText(path, source);
        return path;
    }

    private static Func<LoadedSolution, IReadOnlyList<(string RuleId, string File, int Line)>> Reports(params (string, string, int)[] findings) =>
        _ => findings;

    [Fact]
    public void Parse_reads_the_four_kinds_and_refers_to_the_next_line()
    {
        var text = "// header\r\n// ruleid: csharp.a\r\nx();\r\n  // ok: csharp.b\r\ny();\r\n// todoruleid: csharp.c\r\n// todook: csharp.d\r\nz();\r\n// note: not an annotation\r\n// ruleid: two words\r\n";
        var annotations = Annotation.Parse("f.cs", text);
        Assert.Equal(new[]
        {
            new Annotation("f.cs", 3, "ruleid", "csharp.a"),
            new Annotation("f.cs", 5, "ok", "csharp.b"),
            new Annotation("f.cs", 7, "todoruleid", "csharp.c"),
            new Annotation("f.cs", 8, "todook", "csharp.d"),
        }, annotations);
    }

    [Fact]
    public void Parse_ignores_annotations_inside_code_lines()
    {
        Assert.Empty(Annotation.Parse("f.cs", "var s = \"// ruleid: csharp.a\";\nx();\n"));
    }

    [Fact]
    public void Nothing_reported_leaves_ruleid_missing_and_nothing_else()
    {
        var result = FixtureRunner.Run(Fixture(), Reports());
        Assert.Empty(result.CompileErrors);
        Assert.Equal(new[] { new Annotation("demo.cs", 6, "ruleid", Demo) }, result.Missing);
        Assert.Empty(result.Unexpected);
        Assert.Empty(result.TodoFound);
        Assert.Empty(result.TodoOkReported);
        Assert.Empty(result.Unannotated);
    }

    [Fact]
    public void Everything_reported_is_found_unexpected_and_todo()
    {
        var result = FixtureRunner.Run(Fixture(), Reports((Demo, "demo.cs", 6), (Demo, "demo.cs", 8), (Demo, "demo.cs", 10), (Demo, "demo.cs", 12)));
        Assert.Empty(result.Missing);
        Assert.Equal(new[] { new Annotation("demo.cs", 8, "ok", Demo) }, result.Unexpected);
        Assert.Equal(new[] { new Annotation("demo.cs", 10, "todoruleid", Demo) }, result.TodoFound);
        Assert.Equal(new[] { new Annotation("demo.cs", 12, "todook", Demo) }, result.TodoOkReported);
    }

    [Fact]
    public void An_exact_match_has_no_missing_and_no_unexpected()
    {
        var result = FixtureRunner.Run(Fixture(), Reports((Demo, "demo.cs", 6)));
        Assert.Empty(result.Missing);
        Assert.Empty(result.Unexpected);
        Assert.Empty(result.TodoFound);
    }

    [Fact]
    public void A_finding_on_an_unannotated_line_is_listed_apart_and_other_rules_are_ignored()
    {
        var result = FixtureRunner.Run(Fixture(), Reports((Demo, "demo.cs", 6), (Demo, "demo.cs", 4), ("csharp.other", "demo.cs", 8)));
        Assert.Empty(result.Missing);
        Assert.Empty(result.Unexpected);
        Assert.Equal(new[] { new Annotation("demo.cs", 4, "finding", Demo) }, result.Unannotated);
    }

    [Fact]
    public void A_finding_in_another_file_does_not_count()
    {
        var result = FixtureRunner.Run(Fixture(), Reports((Demo, "other.cs", 6)));
        Assert.Single(result.Missing);
    }

    [Fact]
    public void The_finding_path_may_be_a_full_path()
    {
        var path = Fixture();
        var result = FixtureRunner.Run(path, Reports((Demo, path, 6)));
        Assert.Empty(result.Missing);
    }

    [Fact]
    public void The_analyzer_gets_the_compiled_fixture()
    {
        LoadedSolution? seen = null;
        FixtureRunner.Run(Fixture(), solution => { seen = solution; return Array.Empty<(string, string, int)>(); });
        var project = Assert.Single(seen!.Projects);
        Assert.Contains(project.Compilation.SyntaxTrees, t => Path.GetFileName(t.FilePath) == "demo.cs");
        Assert.Empty(project.Errors);
    }

    [Fact]
    public void Compile_errors_are_reported_and_an_uncompilable_line_is_excluded_from_both()
    {
        var source = Source.Replace("var x = a;", "var x = undeclared;");
        var path = Fixture(source);
        var broken = FixtureRunner.Run(path, Reports());
        Assert.Single(broken.CompileErrors);

        var expectations = new Expectations(Array.Empty<ExpectedLine>(), Array.Empty<ExpectedLine>(), new[] { new ExpectedLine(Demo, "demo.cs", 6, "test") });
        var excluded = FixtureRunner.Run(path, Reports(), expectations);
        Assert.Empty(excluded.CompileErrors);
        Assert.Empty(excluded.Missing);
    }

    [Fact]
    public void Top_level_statements_compile_as_an_executable_with_the_implicit_usings()
    {
        var path = Fixture("var list = new List<string>();\n// ruleid: csharp.demo\nConsole.WriteLine(list.Count);\nclass T { }\n");
        var result = FixtureRunner.Run(path, Reports((Demo, "demo.cs", 3)));
        Assert.Empty(result.CompileErrors);
        Assert.Empty(result.Missing);
    }

    [Fact]
    public void A_companion_file_is_compiled_and_annotated_with_the_fixture()
    {
        var dir = TempDir();
        var path = Path.Combine(dir, "demo.cs");
        File.WriteAllText(path, "public class A { public int F() => B.G(); }\n");
        File.WriteAllText(Path.Combine(dir, "demo.more.cs"), "public static class B\n{\n    // ruleid: csharp.demo\n    public static int G() => 1;\n}\n");
        var result = FixtureRunner.Run(path, Reports());
        Assert.Empty(result.CompileErrors);
        Assert.Equal(new[] { new Annotation("demo.more.cs", 4, "ruleid", Demo) }, result.Missing);
    }

    [Fact]
    public void Expectations_load_from_yaml()
    {
        var file = Path.Combine(TempDir(), "e.yml");
        File.WriteAllText(file, "must-find:\n  - { rule: csharp.sql-injection, line: 12, why: \"w\" }\nmust-stay-quiet: []\nuncompilable:\n  - { rule: csharp.xss, file: xss.cs, line: 3, reason: \"r\" }\nexcluded:\n  - { rule: csharp.xss, file: xss.cs, line: 4, reason: \"x\" }\n");
        var e = Expectations.Load(file);
        Assert.Equal(new ExpectedLine("csharp.sql-injection", "sql-injection.cs", 12, "w"), Assert.Single(e.MustFind));
        Assert.Empty(e.MustStayQuiet);
        Assert.Equal(new ExpectedLine("csharp.xss", "xss.cs", 3, "r"), Assert.Single(e.Uncompilable));
        Assert.Equal(4, Assert.Single(e.Excluded).Line);
    }
}
