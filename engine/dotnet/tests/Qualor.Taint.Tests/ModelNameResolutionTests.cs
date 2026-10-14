using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Qualor.Taint.Tests.Fixtures;
using YamlDotNet.RepresentationModel;

namespace Qualor.Taint.Tests;

/// Every type and member the models in models/csharp name resolves against FixtureReferences.All (a misspelt name
/// fails here). The names that cannot resolve are listed under `unresolved-model-names:` in expectations.yml with
/// the reason; the list must match exactly, so a name that starts to resolve (or a new misspelling) fails too.
public class ModelNameResolutionTests
{
    private static readonly string ModelsDir = Path.Combine(Repo.Root, "models", "csharp");

    [Fact]
    public void Model_names_resolve_against_the_fixture_references()
    {
        var models = ModelLoader.Load(ModelsDir);
        var compilation = CSharpCompilation.Create("ModelNames", references: FixtureReferences.All);

        var unresolved = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var (name, _) in TypeNames(models))
            if (Resolve(compilation, name) == null) unresolved.Add(name);
        foreach (var (pattern, _) in Members(models))
        {
            var type = Resolve(compilation, pattern.TypeName);
            if (type == null) continue; // reported as a type
            if (!HasMember(compilation, type, pattern)) unresolved.Add(pattern.ToString() + " [" + pattern.Kind + "]");
        }

        var allowed = AllowedUnresolved();
        var unexpected = unresolved.Except(allowed.Keys).ToList();
        var stale = allowed.Keys.Except(unresolved).ToList();
        Assert.True(unexpected.Count == 0 && stale.Count == 0,
            "unresolved model names not allowed in expectations.yml:" + Environment.NewLine + string.Join(Environment.NewLine, unexpected) +
            Environment.NewLine + "allowed names that resolve now (remove them):" + Environment.NewLine + string.Join(Environment.NewLine, stale));
    }

    [Fact]
    public void A_misspelt_name_is_found()
    {
        var compilation = CSharpCompilation.Create("ModelNames", references: FixtureReferences.All);
        Assert.NotNull(Resolve(compilation, "System.Data.Common.DbCommand"));
        Assert.Null(Resolve(compilation, "System.Data.Common.DbComand"));
        var command = Resolve(compilation, "System.Data.Common.DbCommand")!;
        Assert.True(HasMember(compilation, command, new MemberPattern("System.Data.Common.DbCommand", "CommandText", false, MemberKind.PropertySet)));
        Assert.False(HasMember(compilation, command, new MemberPattern("System.Data.Common.DbCommand", "CommandTxt", false, MemberKind.PropertySet)));
        Assert.True(HasMember(compilation, command, new MemberPattern("System.Data.Common.DbCommand", "Execute", true, MemberKind.Method)));
        Assert.False(HasMember(compilation, command, new MemberPattern("System.Data.Common.DbCommand", "Zzz", true, MemberKind.Method)));
        Assert.True(HasMember(compilation, command, new MemberPattern("System.Data.Common.DbCommand", ".ctor", false, MemberKind.Constructor)));
    }

    // GetTypeByMetadataName gives null for a name two references both define (Npgsql bundles System.Text.EncodingExtensions
    // next to System.Memory), so the first of all definitions is taken.
    private static INamedTypeSymbol? Resolve(Compilation compilation, string name)
    {
        if (name.EndsWith("[]", StringComparison.Ordinal)) name = name[..^2];
        return compilation.GetTypesByMetadataName(name).FirstOrDefault();
    }

    private static bool HasMember(Compilation compilation, INamedTypeSymbol type, MemberPattern p)
    {
        var types = new List<INamedTypeSymbol> { type };
        for (var b = type.BaseType; b != null; b = b.BaseType) types.Add(b);
        types.AddRange(type.AllInterfaces);
        if (type.TypeKind == TypeKind.Interface) types.Add(compilation.GetSpecialType(SpecialType.System_Object));
        bool Named(string name, string metadataName) => p.Prefix ? name.StartsWith(p.MemberName, StringComparison.Ordinal) || metadataName.StartsWith(p.MemberName, StringComparison.Ordinal) : name == p.MemberName || metadataName == p.MemberName;
        foreach (var t in types)
        {
            foreach (var m in t.GetMembers())
            {
                switch (p.Kind)
                {
                    case MemberKind.Constructor when m is IMethodSymbol { MethodKind: MethodKind.Constructor }: return true;
                    case MemberKind.Method when m is IMethodSymbol { MethodKind: not (MethodKind.Constructor or MethodKind.PropertyGet or MethodKind.PropertySet or MethodKind.StaticConstructor) } ms && Named(ms.Name, ms.MetadataName): return true;
                    case MemberKind.PropertyGet when m is IPropertySymbol { GetMethod: not null } ps && Named(ps.Name, ps.MetadataName): return true;
                    case MemberKind.PropertySet when m is IPropertySymbol { SetMethod: not null } ps && Named(ps.Name, ps.MetadataName): return true;
                }
            }
        }
        return false;
    }

    private static IEnumerable<(string Name, string Where)> TypeNames(ModelSet m)
    {
        var s = m.Sources;
        foreach (var n in s.Controllers.Bases.Concat(s.Controllers.ClassAttributes).Concat(s.Controllers.NotClassAttributes).Concat(s.Controllers.NotMethodAttributes)) yield return (n, "controllers");
        foreach (var n in s.RazorPages.Bases) yield return (n, "razor-pages");
        foreach (var n in s.BoundProperties.PropertyAttributes.Concat(s.BoundProperties.ClassAttributes)) yield return (n, "bound-properties");
        foreach (var n in s.MinimalApi.SourceTypes) yield return (n, "minimal-api");
        foreach (var n in s.BindingAttributes.Concat(s.NotSourceAttributes)) yield return (n, "attributes");
        var pt = s.ParameterTypes;
        foreach (var n in pt.Scalars.Concat(pt.ScalarCollections).Concat(pt.NotScalarElements).Concat(pt.NotSourceTypes).Concat(pt.SourceInterfaces)) yield return (n, "parameter-types");
        foreach (var (p, w) in Members(m)) yield return (p.TypeName, w);
        foreach (var rule in m.Rules)
            foreach (var sink in rule.Sinks)
                foreach (var n in sink.ParamTypes) yield return (n, rule.RuleId + " param-types");
    }

    private static IEnumerable<(MemberPattern Pattern, string Where)> Members(ModelSet m)
    {
        foreach (var p in m.Sources.MinimalApi.MapMethods) yield return (p, "minimal-api");
        foreach (var p in m.Sources.Members) yield return (p, "sources");
        foreach (var p in m.Propagators) yield return (p.Member, "propagators");
        foreach (var rule in m.Rules)
        {
            foreach (var s in rule.Sinks) yield return (s.Member, rule.RuleId + " sinks");
            foreach (var c in rule.Sinks.SelectMany(s => s.When).Where(c => c.Member != null)) yield return (c.Member!, rule.RuleId + " when receiver");
            foreach (var s in rule.Sanitizers) yield return (s, rule.RuleId + " sanitizers");
            foreach (var g in rule.Guards) yield return (g.Member, rule.RuleId + " guards");
        }
    }

    private static Dictionary<string, string> AllowedUnresolved()
    {
        var yaml = new YamlStream();
        using (var reader = new StreamReader(Path.Combine(Repo.EngineDir, "expectations.yml"))) yaml.Load(reader);
        var root = (YamlMappingNode)yaml.Documents[0].RootNode;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!root.Children.TryGetValue(new YamlScalarNode("unresolved-model-names"), out var node)) return result;
        foreach (var item in ((YamlSequenceNode)node).Children.Cast<YamlMappingNode>())
            result[((YamlScalarNode)item.Children[new YamlScalarNode("name")]).Value!] = ((YamlScalarNode)item.Children[new YamlScalarNode("reason")]).Value!;
        return result;
    }
}
