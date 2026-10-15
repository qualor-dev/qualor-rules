using System.Text;

namespace Qualor.Taint.Tests.Intraprocedural;

/// Ruling R-E10: a body whose analysis throws is skipped and counted; the run is incomplete only above 1 % of the bodies.
public sealed class EngineFailureTests
{
    private static AnalysisResult Run(int methods)
    {
        var code = new StringBuilder("public class C\n{\n");
        code.Append("    public void Bad([FromQuery] string q, SqlConnection c) => c.Execute(q);\n");
        for (var i = 0; i < methods - 1; i++) code.Append($"    public void M{i}([FromQuery] string q, SqlConnection c) => c.Execute(q);\n");
        code.Append("}\n");
        var engine = new TaintEngine(Snippet.Models, Snippet.Options)
        {
            BeforeBody = m => { if (m?.Name == "Bad") throw new InvalidOperationException("injected"); },
        };
        return engine.Analyze(Snippet.Compile(code.ToString()), CancellationToken.None);
    }

    [Fact]
    public void One_failed_body_in_a_hundred_and_twenty_is_skipped_and_the_run_stays_complete()
    {
        var result = Run(120);
        Assert.Equal((true, 1, 119, 119), (result.Complete, result.Stats.FailedMethods, result.Stats.Methods, result.Findings.Count));
        Assert.Null(result.Stats.IncompleteKind);
    }

    [Fact]
    public void One_failed_body_in_two_makes_the_run_incomplete()
    {
        var result = Run(2);
        Assert.Equal((false, "1 of 2 bodies failed (more than 1 %); first: Snippet.cs:3: InvalidOperationException: injected", "failed"),
            (result.Complete, result.IncompleteReason, result.Stats.IncompleteKind));
    }
}
