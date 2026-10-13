using Basic.Reference.Assemblies;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint.Tests;

/// SymbolMatch on real symbols: small compilations against the .NET 8 reference assemblies, with stubs (written here)
/// standing in for the library types the models name.
public sealed class SymbolMatchTests
{
    private const string Stubs = """
        using System.Collections.Generic;
        using System.Data;
        using System.Data.Common;
        namespace Microsoft.Data.SqlClient
        {
            public sealed class SqlCommand : DbCommand
            {
                public SqlCommand() { }
                public SqlCommand(string cmdText) { }
                public override string CommandText { get; set; } = "";
                public override int CommandTimeout { get; set; }
                public override CommandType CommandType { get; set; }
                public override bool DesignTimeVisible { get; set; }
                public override UpdateRowSource UpdatedRowSource { get; set; }
                protected override DbConnection? DbConnection { get; set; }
                protected override DbParameterCollection DbParameterCollection => throw null!;
                protected override DbTransaction? DbTransaction { get; set; }
                public override void Cancel() { }
                public override int ExecuteNonQuery() => 0;
                public override object? ExecuteScalar() => null;
                public override void Prepare() { }
                protected override DbParameter CreateDbParameter() => throw null!;
                protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => throw null!;
            }
            public class SqlCommandBuilderLike { public SqlCommandBuilderLike(string text) { } }
        }
        namespace Npgsql
        {
            public sealed class NpgsqlCommand { public NpgsqlCommand(string? cmdText) { } }
            public sealed class NpgsqlDataSource : DbDataSource
            {
                public override string ConnectionString => "";
                protected override DbConnection CreateDbConnection() => throw null!;
                public new NpgsqlCommand CreateCommand(string? commandText = null) => new NpgsqlCommand(commandText);
            }
        }
        namespace Dapper
        {
            public static class SqlMapper
            {
                public static IEnumerable<T> Query<T>(this IDbConnection cnn, string sql, object? param = null) => throw null!;
                public static T QueryFirstOrDefault<T>(this IDbConnection cnn, string sql, object? param = null) => throw null!;
            }
        }
        namespace Lib
        {
            public class Bag : IDictionary<string, string>
            {
                private readonly Dictionary<string, string> _d = new();
                public string this[string key] { get => _d[key]; set => _d[key] = value; }
                public ICollection<string> Keys => _d.Keys;
                public ICollection<string> Values => _d.Values;
                public int Count => _d.Count;
                public bool IsReadOnly => false;
                public void Add(string key, string value) => _d.Add(key, value);
                public void Add(KeyValuePair<string, string> item) => _d.Add(item.Key, item.Value);
                public void Clear() => _d.Clear();
                public bool Contains(KeyValuePair<string, string> item) => _d.ContainsKey(item.Key);
                public bool ContainsKey(string key) => _d.ContainsKey(key);
                public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex) { }
                public IEnumerator<KeyValuePair<string, string>> GetEnumerator() => _d.GetEnumerator();
                public bool Remove(string key) => _d.Remove(key);
                public bool Remove(KeyValuePair<string, string> item) => _d.Remove(item.Key);
                bool IDictionary<string, string>.TryGetValue(string key, out string value) => _d.TryGetValue(key, out value!);
                System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => _d.GetEnumerator();
                public bool TryAdd(string key, string value) => _d.TryAdd(key, value);
            }
            public class Unrelated { public bool TryGetValue(string key, out string value) { value = key; return true; } }
        }
        """;

    private const string Code = """
        using System.Collections.Generic;
        using System.Data;
        using System.Data.Common;
        using System.Text;
        using Dapper;
        using Microsoft.Data.SqlClient;
        using Npgsql;
        public record User(string Name);
        public static class Use
        {
            public static void Run(string q, IDbConnection conn, DbCommand db, IDbCommand idb, NpgsqlDataSource ds, IDictionary<string, string> map, Lib.Bag bag, Lib.Unrelated other)
            {
                var cmd = new SqlCommand();
                cmd.CommandText = q;
                db.CommandText = q;
                idb.CommandText = q;
                var init = new SqlCommand { CommandText = q };
                var read = cmd.CommandText;
                var withText = new SqlCommand(q);
                var like = new Microsoft.Data.SqlClient.SqlCommandBuilderLike(q);
                var users = conn.Query<User>(q);
                var first = conn.QueryFirstOrDefault<User>(q);
                var users2 = SqlMapper.Query<User>(conn, q);
                var fromSource = ds.CreateCommand(q);
                map.TryGetValue("k", out var v1);
                new Dictionary<string, string>().TryGetValue("k", out var v2);
                ((IDictionary<string, string>)bag).TryGetValue("k", out var v3);
                other.TryGetValue("k", out var v4);
                var sb = new StringBuilder().Append(q).Append(1).AppendLine(q);
                var s = sb.ToString() + 1.ToString();
            }
        }
        """;

    private static readonly Lazy<(CSharpCompilation Compilation, SemanticModel Model, SyntaxNode Root)> Compiled = new(() =>
    {
        var compilation = CSharpCompilation.Create("SymbolMatchTests",
            new[] { CSharpSyntaxTree.ParseText(Stubs, new CSharpParseOptions(LanguageVersion.CSharp12)), CSharpSyntaxTree.ParseText(Code, new CSharpParseOptions(LanguageVersion.CSharp12)) },
            Net80.References.All, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        var tree = compilation.SyntaxTrees[1];
        return (compilation, compilation.GetSemanticModel(tree), tree.GetRoot());
    });

    [Fact]
    public void The_compilation_has_no_errors()
    {
        Assert.Empty(Compiled.Value.Compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));
    }

    private static MemberPattern P(string member, MemberKind kind)
    {
        if (kind == MemberKind.Constructor) return new MemberPattern(member[..member.IndexOf("..ctor", StringComparison.Ordinal)], ".ctor", false, kind);
        var dot = member.LastIndexOf('.');
        var name = member[(dot + 1)..];
        return new MemberPattern(member[..dot], name.TrimEnd('*'), name.EndsWith('*'), kind);
    }

    /// The symbol of the left side of the n-th assignment `<text> = ...` whose left side reads `text`.
    private static ISymbol Assigned(string text, int nth = 0) =>
        Compiled.Value.Root.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(a => a.Left.ToString() == text)
            .Select(a => Compiled.Value.Model.GetSymbolInfo(a.Left).Symbol!).ElementAt(nth);

    /// The method symbol of the n-th invocation or object creation whose text starts with `start`, as GetSymbolInfo gives it.
    private static IMethodSymbol Called(string start, int nth = 0) =>
        Compiled.Value.Root.DescendantNodes().Where(n => n is InvocationExpressionSyntax or BaseObjectCreationExpressionSyntax && n.ToString().StartsWith(start, StringComparison.Ordinal))
            .Select(n => (IMethodSymbol)Compiled.Value.Model.GetSymbolInfo(n).Symbol!).ElementAt(nth);

    /// The same, as IOperation gives it (an extension method in its static form).
    private static IMethodSymbol Operation(string start) =>
        Compiled.Value.Root.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(n => n.ToString().StartsWith(start, StringComparison.Ordinal))
            .Select(n => ((IInvocationOperation)Compiled.Value.Model.GetOperation(n)!).TargetMethod).First();

    [Fact]
    public void The_DbCommand_CommandText_setter_matches_on_an_SqlCommand_through_the_override()
    {
        var pattern = P("System.Data.Common.DbCommand.CommandText", MemberKind.PropertySet);
        var onSqlCommand = Assigned("cmd.CommandText");
        Assert.Equal("Microsoft.Data.SqlClient.SqlCommand", onSqlCommand.ContainingType.ToDisplayString());   // the override itself

        Assert.True(SymbolMatch.Matches(pattern, onSqlCommand));
        Assert.True(SymbolMatch.Matches(pattern, ((IPropertySymbol)onSqlCommand).SetMethod!));
        Assert.True(SymbolMatch.Matches(pattern, Assigned("db.CommandText")));
        Assert.True(SymbolMatch.Matches(pattern, Assigned("CommandText")));                                  // object initializer
        Assert.False(SymbolMatch.Matches(pattern, Assigned("idb.CommandText")));                             // IDbCommand is no DbCommand
        Assert.False(SymbolMatch.Matches(pattern, ((IPropertySymbol)onSqlCommand).GetMethod!));               // a read is no set
        Assert.False(SymbolMatch.Matches(P("System.Data.Common.DbCommand.CommandText", MemberKind.PropertyGet), ((IPropertySymbol)onSqlCommand).SetMethod!));
        Assert.True(SymbolMatch.Matches(P("System.Data.Common.DbCommand.CommandText", MemberKind.PropertyGet), ((IPropertySymbol)onSqlCommand).GetMethod!));
        Assert.False(SymbolMatch.Matches(P("System.Data.Common.DbCommand.CommandText", MemberKind.Method), onSqlCommand));
        // A derived type's pattern does not match the base member (the receiver may be any command).
        Assert.False(SymbolMatch.Matches(P("Microsoft.Data.SqlClient.SqlCommand.CommandText", MemberKind.PropertySet), Assigned("db.CommandText")));
    }

    [Fact]
    public void An_interface_pattern_matches_its_implementations()
    {
        var pattern = P("System.Data.IDbCommand.CommandText", MemberKind.PropertySet);
        Assert.True(SymbolMatch.Matches(pattern, Assigned("idb.CommandText")));
        Assert.True(SymbolMatch.Matches(pattern, Assigned("cmd.CommandText")));   // SqlCommand → DbCommand → IDbCommand
        Assert.True(SymbolMatch.Matches(pattern, Assigned("db.CommandText")));

        var tryGet = P("System.Collections.Generic.IDictionary`2.TryGetValue", MemberKind.Method);
        Assert.True(SymbolMatch.Matches(tryGet, Called("map.TryGetValue")));
        Assert.True(SymbolMatch.Matches(tryGet, Called("new Dictionary<string, string>().TryGetValue")));   // Dictionary<,> implements it
        var explicitImpl = ((INamedTypeSymbol)Compiled.Value.Compilation.GetTypeByMetadataName("Lib.Bag")!).GetMembers()
            .OfType<IMethodSymbol>().Single(m => m.Name.EndsWith(".TryGetValue", StringComparison.Ordinal));
        Assert.True(SymbolMatch.Matches(tryGet, explicitImpl));                                             // an explicit implementation
        Assert.False(SymbolMatch.Matches(tryGet, Called("other.TryGetValue")));                              // same name, no IDictionary
        var tryAdd = ((INamedTypeSymbol)Compiled.Value.Compilation.GetTypeByMetadataName("Lib.Bag")!).GetMembers("TryAdd").Single();
        Assert.False(SymbolMatch.Matches(P("System.Collections.Generic.IDictionary`2.TryAdd", MemberKind.Method), tryAdd)); // IDictionary has no TryAdd
    }

    [Fact]
    public void Dapper_Query_star_matches_Query_of_T_and_an_exact_name_does_not_match_a_longer_one()
    {
        var queryStar = P("Dapper.SqlMapper.Query*", MemberKind.Method);
        var reduced = Called("conn.Query<User>");
        Assert.NotNull(reduced.ReducedFrom);                                     // the extension method as GetSymbolInfo gives it
        Assert.True(SymbolMatch.Matches(queryStar, reduced));
        Assert.True(SymbolMatch.Matches(queryStar, Operation("conn.Query<User>")));   // ... and as IOperation does
        Assert.True(SymbolMatch.Matches(queryStar, Called("SqlMapper.Query<User>")));
        Assert.True(SymbolMatch.Matches(P("Dapper.SqlMapper.Query", MemberKind.Method), reduced));

        var firstOrDefault = Called("conn.QueryFirstOrDefault");
        Assert.False(SymbolMatch.Matches(P("Dapper.SqlMapper.QueryFirst", MemberKind.Method), firstOrDefault));
        Assert.True(SymbolMatch.Matches(P("Dapper.SqlMapper.QueryFirst*", MemberKind.Method), firstOrDefault));
        Assert.True(SymbolMatch.Matches(queryStar, firstOrDefault));
        Assert.False(SymbolMatch.Matches(P("Dapper.SqlMapper.Execute*", MemberKind.Method), firstOrDefault));
        Assert.False(SymbolMatch.Matches(P("Dapper.Other.Query*", MemberKind.Method), reduced));
    }

    [Fact]
    public void A_constructor_pattern_matches_its_own_type_only()
    {
        var ctor = P("Microsoft.Data.SqlClient.SqlCommand..ctor", MemberKind.Constructor);
        Assert.True(SymbolMatch.Matches(ctor, Called("new SqlCommand(q)")));
        Assert.True(SymbolMatch.Matches(ctor, Called("new SqlCommand()")));
        Assert.True(SymbolMatch.Matches(P("Microsoft.Data.SqlClient.SqlCommand..ctor", MemberKind.Constructor), Called("new SqlCommand {")));
        Assert.False(SymbolMatch.Matches(ctor, Called("new Microsoft.Data.SqlClient.SqlCommandBuilderLike")));   // name prefix is no match
        Assert.False(SymbolMatch.Matches(P("System.Data.Common.DbCommand..ctor", MemberKind.Constructor), Called("new SqlCommand(q)")));
        Assert.False(SymbolMatch.Matches(P("Microsoft.Data.SqlClient.SqlCommand.*", MemberKind.Method), Called("new SqlCommand(q)")));
    }

    [Fact]
    public void A_base_type_pattern_matches_a_member_a_derived_type_hides_with_new()
    {
        var create = P("System.Data.Common.DbDataSource.CreateCommand", MemberKind.Method);
        var hiding = Called("ds.CreateCommand");
        Assert.Equal("Npgsql.NpgsqlDataSource", hiding.ContainingType.ToDisplayString());
        Assert.True(SymbolMatch.Matches(create, hiding));
    }

    [Fact]
    public void Prefix_and_any_member_patterns_and_overrides_of_object_members()
    {
        Assert.True(SymbolMatch.Matches(P("System.Text.StringBuilder.Append*", MemberKind.Method), Called("new StringBuilder().Append(q).Append(1).AppendLine")));
        Assert.True(SymbolMatch.Matches(P("System.Text.StringBuilder.*", MemberKind.Method), Called("new StringBuilder().Append(q).Append(1).AppendLine")));
        Assert.True(SymbolMatch.Matches(P("System.Object.ToString", MemberKind.Method), Called("sb.ToString")));   // StringBuilder overrides it
        Assert.True(SymbolMatch.Matches(P("System.Object.ToString", MemberKind.Method), Called("1.ToString")));
        Assert.False(SymbolMatch.Matches(P("System.Text.StringBuilder.ToString", MemberKind.Method), Called("1.ToString")));
    }

    [Fact]
    public void Metadata_names_of_types()
    {
        var c = Compiled.Value.Compilation;
        Assert.Equal("System.Collections.Generic.IDictionary`2", SymbolMatch.MetadataName(c.GetTypeByMetadataName("System.Collections.Generic.IDictionary`2")!));
        Assert.Equal("System.Collections.Generic.Dictionary`2+KeyCollection", SymbolMatch.MetadataName(c.GetTypeByMetadataName("System.Collections.Generic.Dictionary`2+KeyCollection")!));
        Assert.Equal("System.String[]", SymbolMatch.MetadataName(c.CreateArrayTypeSymbol(c.GetSpecialType(SpecialType.System_String))));
        Assert.Equal("User", SymbolMatch.MetadataName(c.GetTypeByMetadataName("User")!));
        var listOfInt = c.GetTypeByMetadataName("System.Collections.Generic.List`1")!.Construct(c.GetSpecialType(SpecialType.System_Int32));
        Assert.Equal("System.Collections.Generic.List`1", SymbolMatch.MetadataName(listOfInt));   // the definition's name
    }
}
