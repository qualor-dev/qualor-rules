using System.Text;

namespace Qualor.Taint.Tests;

public sealed class ModelLoaderTests : TempDirs
{
    /// The repository's models/csharp, found upwards from the test assembly.
    internal static string ShippedModels()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "models", "csharp");
            if (File.Exists(Path.Combine(candidate, "sources.yml"))) return candidate;
        }
        throw new InvalidOperationException("models/csharp not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Loads_the_shared_models_and_the_sql_injection_model()
    {
        var set = ModelLoader.Load(ShippedModels());

        var sql = Assert.Single(set.Rules, r => r.RuleId == "csharp.sql-injection");
        Assert.Equal(RuleKind.Taint, sql.Kind);
        Assert.Contains(sql.Sinks, s => s.Member == new MemberPattern("Microsoft.Data.SqlClient.SqlCommand", ".ctor", false, MemberKind.Constructor)
            && s.Args.SequenceEqual(new[] { 0 }));
        Assert.Contains(sql.Sinks, s => s.Member == new MemberPattern("System.Data.Common.DbCommand", "CommandText", false, MemberKind.PropertySet));
        Assert.Contains(sql.Sinks, s => s.Member == new MemberPattern("Microsoft.EntityFrameworkCore.RelationalQueryableExtensions", "FromSqlRaw", false, MemberKind.Method)
            && s.Args.SequenceEqual(new[] { 1 }));
        Assert.Contains(sql.Sinks, s => s.Member == new MemberPattern("Dapper.SqlMapper", "Query", true, MemberKind.Method)
            && s.ParamTypes.SequenceEqual(new[] { "System.String" }));
        Assert.Contains(sql.Sanitizers, m => m == new MemberPattern("System.Int32", "Parse", false, MemberKind.Method));
        Assert.Empty(sql.Guards);

        Assert.Contains("Microsoft.AspNetCore.Mvc.FromQueryAttribute", set.Sources.BindingAttributes);
        Assert.Contains("Microsoft.AspNetCore.Mvc.FromServicesAttribute", set.Sources.NotSourceAttributes);
        Assert.Contains("Microsoft.AspNetCore.Mvc.ControllerBase", set.Sources.Controllers.Bases);
        Assert.Contains("OnGet", set.Sources.RazorPages.HandlerPrefixes);
        Assert.Contains("System.Guid", set.Sources.ParameterTypes.Scalars);
        Assert.Contains(set.Sources.Members, m => m == new MemberPattern("Microsoft.AspNetCore.Http.HttpRequest", "Query", false, MemberKind.PropertyGet));
        Assert.Contains(set.Sources.MinimalApi.MapMethods, m => m.MemberName == "MapGet");

        var append = Assert.Single(set.Propagators, p => p.Member == new MemberPattern("System.Text.StringBuilder", "Append", true, MemberKind.Method));
        Assert.Equal(new[] { "args" }, append.From);
        Assert.Equal(new[] { "this", "return" }, append.To);
        var concat = Assert.Single(set.Propagators, p => p.Member.TypeName == "System.String" && p.Member.MemberName == "Concat");
        Assert.Equal(new[] { "this", "args" }, concat.From);   // the default for a method
        Assert.Equal(new[] { "return" }, concat.To);
        Assert.Equal("string-or-collection-return", set.UnmodelledExternal);
    }

    [Fact]
    public void A_guard_and_a_misuse_model_are_read()
    {
        var dir = WriteModels(("open-redirect.yml", """
            rule: csharp.open-redirect
            kind: taint
            sinks:
              - method: Microsoft.AspNetCore.Mvc.ControllerBase.Redirect
                args: [0]
            guards:
              - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl
                arg: 0
                clean-when: true
            """), ("xxe.yml", """
            rule: csharp.xxe
            kind: misuse
            misuse:
              test-code: ['tests/', '*Tests.cs']
              calls:
                - method: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize*
                - property-get: System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
              enum-values:
                - type: Newtonsoft.Json.TypeNameHandling
                  safe: [None]
              values:
                - property-set: System.Xml.XmlReaderSettings.XmlResolver
                  created: [System.Xml.XmlUrlResolver]
                  with: { property: DtdProcessing, values: [Parse] }
                  at: object
                - property-set: System.Xml.XmlTextReader.XmlResolver
                  created: [System.Xml.XmlUrlResolver]
                  without: { property: DtdProcessing, values: [Prohibit, Ignore] }
                - method: System.Net.Security.SslStream..ctor
                  args: [2]
                  accepts-all: true
              accepts-all-methods: System.Net.Security.SslPolicyErrors
            """));

        var set = ModelLoader.Load(dir);

        var redirect = set.Rules.Single(r => r.RuleId == "csharp.open-redirect");
        var guard = Assert.Single(redirect.Guards);
        Assert.Equal(new GuardModel(new MemberPattern("Microsoft.AspNetCore.Mvc.IUrlHelper", "IsLocalUrl", false, MemberKind.Method), 0, true), guard);
        Assert.Null(redirect.Misuse);
        var xxe = set.Rules.Single(r => r.RuleId == "csharp.xxe");
        Assert.Equal(RuleKind.Misuse, xxe.Kind);
        var m = xxe.Misuse!;
        Assert.Equal(new[] { "tests/", "*Tests.cs" }, m.TestCode);
        Assert.Equal(new[]
        {
            new MemberPattern("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "Deserialize", true, MemberKind.Method),
            new MemberPattern("System.Net.Http.HttpClientHandler", "DangerousAcceptAnyServerCertificateValidator", false, MemberKind.PropertyGet),
        }, m.Calls);
        var e = Assert.Single(m.EnumValues);
        Assert.Equal("Newtonsoft.Json.TypeNameHandling", e.Type);
        Assert.Equal(new[] { "None" }, e.Safe);
        Assert.Equal(3, m.Values.Count);
        Assert.Equal(new MemberPattern("System.Xml.XmlReaderSettings", "XmlResolver", false, MemberKind.PropertySet), m.Values[0].Member);
        Assert.Equal(new[] { "System.Xml.XmlUrlResolver" }, m.Values[0].Created);
        Assert.Equal("DtdProcessing", m.Values[0].With!.Property);
        Assert.Equal(new[] { "Parse" }, m.Values[0].With!.Values);
        Assert.True(m.Values[0].AtObject);
        Assert.Null(m.Values[0].Without);
        Assert.Equal(new[] { "Prohibit", "Ignore" }, m.Values[1].Without!.Values);
        Assert.False(m.Values[1].AtObject);
        Assert.Equal(new MemberPattern("System.Net.Security.SslStream", ".ctor", false, MemberKind.Constructor), m.Values[2].Member);
        Assert.Equal(new[] { 2 }, m.Values[2].Args);
        Assert.True(m.Values[2].AcceptsAll);
        Assert.Empty(m.Values[2].Created);
        Assert.Equal("System.Net.Security.SslPolicyErrors", m.AcceptsAllMethods);
    }

    [Theory]
    [InlineData("misuse:\n  calls: []\n", 4, "test-code")]                                                            // test-code missing
    [InlineData("misuse:\n  test-code: []\n  colour: x\n", 5, "colour")]                                             // unknown key
    [InlineData("misuse:\n  test-code: []\n  calls:\n    - property-set: A.B\n", 6, "unknown key property-set")]     // a setter is no call
    [InlineData("misuse:\n  test-code: []\n  enum-values:\n    - type: A\n", 6, "safe")]                             // safe missing
    [InlineData("misuse:\n  test-code: []\n  values:\n    - property-set: A.B\n", 6, "created or accepts-all")]      // no value kind
    [InlineData("misuse:\n  test-code: []\n  values:\n    - property-set: A.B\n      created: [C]\n      accepts-all: true\n", 6, "created or accepts-all")]
    [InlineData("misuse:\n  test-code: []\n  values:\n    - method: A.B\n      created: [C]\n", 6, "args")]          // a method without args
    [InlineData("misuse:\n  test-code: []\n  values:\n    - method: A.B\n      args: [0]\n      created: [C]\n      with: { property: P, values: [V] }\n", 9, "property-set")]
    [InlineData("misuse:\n  test-code: []\n  values:\n    - property-set: A.B\n      created: [C]\n      at: here\n", 8, "at")]
    [InlineData("misuse:\n  test-code: []\n  values:\n    - property-set: A.B\n      created: [C]\n      with: { property: P }\n", 8, "values")]
    [InlineData("misuse:\n  test-code: ['']\n", 4, "non-empty")]
    [InlineData("misuse:\n  test-code: []\n  accepts-all-methods: [A]\n", 5, "non-empty value")]
    [InlineData("misuse: {}\n", 3, "test-code")]
    public void An_invalid_misuse_model_throws_with_its_line(string misuse, int line, string fragment)
    {
        var dir = WriteModels(("xxe.yml", "rule: csharp.xxe\nkind: misuse\n" + misuse));

        var e = Assert.Throws<ModelException>(() => ModelLoader.Load(dir));

        Assert.Equal(line, e.Line);
        Assert.Contains(fragment, e.Message);
    }

    [Fact]
    public void A_conditional_sink_is_read()
    {
        var dir = WriteModels(("command-injection.yml", """
            rule: csharp.command-injection
            kind: taint
            sinks:
              - method: System.Diagnostics.Process.Start
                args: [1]
                when:
                  - arg: 0
                    matches: '^(sh|bash)$'
                  - literal-text: '-c'
                  - after: '^-c$'
                    next: true
              - method: System.Collections.ObjectModel.Collection`1.Add
                args: [0]
                when:
                  - receiver: System.Diagnostics.ProcessStartInfo.ArgumentList
                  - property: FileName
                    of: 1
                    matches: 'sh'
              - method: A.Write
                args: [0]
                when:
                  - outside: A.Open
                    until: A.Close
            """));

        var rule = ModelLoader.Load(dir).Rules.Single(r => r.RuleId == "csharp.command-injection");

        var start = rule.Sinks[0].When;
        Assert.Equal(new[] { SinkConditionKind.Argument, SinkConditionKind.LiteralText, SinkConditionKind.After }, start.Select(c => c.Kind));
        Assert.Equal(0, start[0].Arg);
        Assert.Matches(start[0].Pattern!, "bash");
        Assert.True(start[2].Next);
        var add = rule.Sinks[1].When;
        Assert.Equal(new MemberPattern("System.Diagnostics.ProcessStartInfo", "ArgumentList", false, MemberKind.PropertyGet), add[0].Member);
        Assert.Equal(("FileName", 1), (add[1].Property, add[1].Arg));
        var write = rule.Sinks[2].When.Single();
        Assert.Equal(SinkConditionKind.Outside, write.Kind);
        Assert.Equal(new MemberPattern("A", "Open", false, MemberKind.Method), write.Member);
        Assert.Equal(new MemberPattern("A", "Close", false, MemberKind.Method), write.Until);
    }

    [Theory]
    [InlineData("  - method: A.B\n    args: [0]\n    when: []\n", 6, "when")]                                       // empty
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - arg: 0\n", 7, "matches")]                       // missing matches
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - arg: 0\n        matches: '('\n", 8, "regular expression")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - arg: 0\n        literal-text: x\n", 7, "exactly one")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - literal-text: x\n        next: true\n", 8, "next")]
    [InlineData("  - property-set: A.B\n    when:\n      - after: x\n", 6, "method sink")]
    [InlineData("  - method: A..ctor\n    args: [0]\n    when:\n      - receiver: A.B\n", 7, "receiver")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - receiver: A.B*\n", 7, "'*'")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - property: 1x\n        matches: x\n", 7, "not a name")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - outside: A.C\n", 7, "until")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - outside: A.C*\n        until: A.D\n", 7, "'*'")]
    [InlineData("  - method: A.B\n    args: [0]\n    when:\n      - arg: 0\n        matches: x\n        until: A.D\n", 9, "until")]
    public void An_invalid_condition_throws_with_its_line(string sink, int line, string fragment)
    {
        var dir = WriteModels(("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n" + sink));

        var e = Assert.Throws<ModelException>(() => ModelLoader.Load(dir));

        Assert.Equal(line, e.Line);
        Assert.Contains(fragment, e.Message);
    }

    [Theory]
    [InlineData("  - method: Dapper.SqlMapper.Query*\n    args: [1]\n    flavour: x\n", 6, "flavour")]       // unknown key
    [InlineData("  - method: Dapper.SqlMapper.Query*\n    args: [x]\n", 5, "args")]                         // not an ordinal
    [InlineData("  - method: Dapper.SqlMapper.Query*\n    args: [-1]\n", 5, "args")]                        // negative
    [InlineData("  - method: Dapper.SqlMapper.Query*\n    args: []\n", 5, "args")]                          // empty
    [InlineData("  - method: Dapper.SqlMapper.Query*\n", 4, "args")]                                        // missing
    [InlineData("  - method: Dapper.SqlMapper.Qu*ery\n    args: [1]\n", 4, "*")]                            // '*' not at the end
    [InlineData("  - method: SqlMapper\n    args: [1]\n", 4, "Type.Member")]                                // no type
    [InlineData("  - property-set: Dapper.SqlMapper..ctor\n", 4, ".ctor")]                                  // a constructor setter
    [InlineData("  - property-set: System.Data.Common.DbCommand.CommandText\n    args: [0]\n", 5, "args")]  // args on a setter
    [InlineData("  - method: A.B\n    property-set: A.C\n    args: [0]\n", 4, "exactly one")]               // two members
    public void An_invalid_rule_model_throws_with_its_file_and_line(string sink, int line, string fragment)
    {
        var dir = WriteModels(("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n" + sink));

        var e = Assert.Throws<ModelException>(() => ModelLoader.Load(dir));

        Assert.Equal(Path.Combine(dir, "sql-injection.yml"), e.File);
        Assert.Equal(line, e.Line);
        Assert.Contains(fragment, e.Message);
        Assert.StartsWith(e.File + ":" + line + ": ", e.Message);
    }

    [Theory]
    [InlineData("sql-injection.yml", "rule: csharp.sqli\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\n", 1, "csharp.sql-injection")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks: []\n", 3, "sink")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taintt\nsinks:\n  - method: A.B\n    args: [0]\n", 2, "kind")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nmisuse: {}\nsinks:\n  - method: A.B\n    args: [0]\n", 3, "misuse")]
    [InlineData("xxe.yml", "rule: csharp.xxe\nkind: misuse\n", 1, "misuse")]                                             // misuse: missing
    // Task 29: a misuse rule may have a taint form (sinks), but no guards, and no sanitizers or sources without sinks.
    [InlineData("xxe.yml", "rule: csharp.xxe\nkind: misuse\nmisuse:\n  test-code: []\nsinks:\n  - method: A.B\n    args: [0]\nguards: []\n", 8, "guards")]
    [InlineData("xxe.yml", "rule: csharp.xxe\nkind: misuse\nmisuse:\n  test-code: []\nsanitizers:\n  - method: A.B\n", 6, "sinks")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsources: []\nsinks:\n  - method: A.B\n    args: [0]\n", 3, "sources")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsources:\n  - property-set: A.B\nsinks:\n  - method: A.B\n    args: [0]\n", 4, "property-set")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\nsanitizers:\n  - property-get: A.Item\n    key: x\n    key-is: A.C\n", 7, "key or key-is")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\nsanitizers:\n  - method: A.C\n    key: x\n", 7, "receiver-type")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\n    when:\n      - property: P\n        matches: x\n        unless: y\n", 7, "matches or unless")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\n    when:\n      - property: P..Q\n        unless: y\n", 7, "not a name")]
    [InlineData("propagators.yml", "propagators:\n  - method: A.B\n    only-for: [sql]\nunmodelled-external: none\n", 3, "rule id")]
    [InlineData("propagators.yml", "propagators:\n  - method: A.B\n    only-for: [csharp.sql-injection, csharp.unsafe-deserialisation]\nunmodelled-external: none\n", 3, "csharp.unsafe-deserialisation is no rule")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\nsanitizers:\n  - property-get: A.Item\n    receiver-type: A\n    key: x\n", 8, "receiver-type")]
    [InlineData("propagators.yml", "propagators:\n  - method: A.B\n    from: [this]\n    param-types: [System.IO.Stream]\nunmodelled-external: none\n", 4, "ordinals")]
    [InlineData("propagators.yml", "propagators:\n  - method: A.B\n    param-types: [System.IO.Stream]\nunmodelled-external: none\n", 3, "ordinals")]
    [InlineData("propagators.yml", "propagators: []\nunmodelled-external: none\nknown-text:\n  - { member: A.B*, text: x }\n", 4, "'*'")]
    [InlineData("propagators.yml", "propagators: []\nunmodelled-external: none\nknown-text:\n  - { member: A.B, text: x }\n  - { member: A.B, text: y }\n", 5, "duplicate")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nkind: taint\nsinks:\n  - method: A.B\n    args: [0]\nguards:\n  - method: A.C\n    arg: 0\n    clean-when: maybe\n", 9, "clean-when")]
    [InlineData("sql-injection.yml", "rule: csharp.sql-injection\nrule: csharp.sql-injection\n", 2, "")]  // duplicate key
    [InlineData("sql-injection.yml", "rule: [unclosed\n", 2, "")]                                           // not YAML
    [InlineData("propagators.yml", "propagators:\n  - method: System.String.Concat\n    to: [nowhere]\nunmodelled-external: string-or-collection-return\n", 3, "to")]
    [InlineData("propagators.yml", "propagators: []\nunmodelled-external: everything\n", 2, "unmodelled-external")]
    [InlineData("sources.yml", "controllers: {}\n", 1, "")]                                                 // keys missing
    public void Invalid_files_throw_with_their_line(string name, string text, int line, string fragment)
    {
        var dir = WriteModels((name, text));

        var e = Assert.Throws<ModelException>(() => ModelLoader.Load(dir));

        Assert.Equal(Path.Combine(dir, name), e.File);
        Assert.Equal(line, e.Line);
        Assert.Contains(fragment, e.Message);
    }

    /// Task 29: a rule's own sources (`sources:`, with `receiver:`), a sink's `message:`, keyed sanitizers (`key:`,
    /// `key-is:`), a property path and `unless:` in a condition, a misuse rule's taint form, `only-for:` and `known-text:`.
    [Fact]
    public void The_task_29_keys_are_read()
    {
        var dir = WriteModels(
            ("sql-injection.yml", """
                rule: csharp.sql-injection
                kind: taint
                sources:
                  - property-get: A.Host
                  - property-get: B.Value
                    receiver: A.Base
                sinks:
                  - method: T.Select
                    args: [0]
                    message: "a filter"
                    when:
                      - property: StartInfo.FileName
                        unless: '^x$'
                sanitizers:
                  - property-get: H.Item
                    key: '(?i)^host$'
                  - property-get: H.Item
                    key-is: N.Host
                  - method: D.TryGetValue
                    receiver-type: H
                    key: '^host$'
                """),
            ("xxe.yml", "rule: csharp.xxe\nkind: misuse\nmisuse:\n  test-code: []\nsinks:\n  - method: S..ctor\n    args: [0]\n"),
            ("propagators.yml", "propagators:\n  - method: System.Type.GetType\n    from: [0]\n    only-for: [csharp.xxe]\nunmodelled-external: none\nknown-text:\n  - { member: System.Uri.SchemeDelimiter, text: \"://\" }\n"));

        var models = ModelLoader.Load(dir);

        var sql = models.Rules.Single(r => r.RuleId == "csharp.sql-injection");
        Assert.Equal(new[] { "A.Host", "B.Value" }, sql.Sources.Select(s => s.Member.ToString()));
        Assert.Null(sql.Sources[0].Receiver);
        Assert.Equal("A.Base", sql.Sources[1].Receiver!.ToString());
        var sink = Assert.Single(sql.Sinks);
        Assert.Equal("a filter", sink.Message);
        var condition = Assert.Single(sink.When);
        Assert.Equal("StartInfo.FileName", condition.Property);
        Assert.True(condition.Negated);
        Assert.Equal(3, sql.KeySanitizers.Count);
        Assert.Null(sql.KeySanitizers[0].ReceiverType);
        Assert.Equal(MemberKind.Method, sql.KeySanitizers[2].Member.Kind);
        Assert.Equal("H", sql.KeySanitizers[2].ReceiverType);
        Assert.Equal("(?i)^host$", sql.KeySanitizers[0].Matches!.ToString());
        Assert.Equal("N.Host", sql.KeySanitizers[1].Is!.ToString());
        Assert.Empty(sql.Sanitizers);
        var xxe = models.Rules.Single(r => r.RuleId == "csharp.xxe");
        Assert.Equal(RuleKind.Misuse, xxe.Kind);
        Assert.Equal(MemberKind.Constructor, Assert.Single(xxe.Sinks).Member.Kind);
        Assert.Equal(new[] { "csharp.xxe" }, Assert.Single(models.Propagators).OnlyFor);
        Assert.Equal("://", models.KnownTexts["System.Uri.SchemeDelimiter"]);
    }

    [Fact]
    public void A_missing_shared_file_is_an_error()
    {
        var dir = WriteModels();
        File.Delete(Path.Combine(dir, "propagators.yml"));
        var e = Assert.Throws<ModelException>(() => ModelLoader.Load(dir));
        Assert.Equal(Path.Combine(dir, "propagators.yml"), e.File);
    }

    /// A copy of the shipped models with the given files written over (or added).
    private string WriteModels(params (string Name, string Text)[] files)
    {
        var dir = TempDir();
        foreach (var f in Directory.GetFiles(ShippedModels(), "*.yml")) File.Copy(f, Path.Combine(dir, Path.GetFileName(f)));
        foreach (var (name, text) in files) File.WriteAllText(Path.Combine(dir, name), text, new UTF8Encoding(false));
        return dir;
    }
}
