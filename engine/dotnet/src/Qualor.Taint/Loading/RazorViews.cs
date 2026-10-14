using System.Text;
using Microsoft.AspNetCore.Mvc.Razor.Extensions;
using Microsoft.AspNetCore.Razor.Language;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Razor;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// Task 30 (decision R-11): the Razor views of a project that no build compiled (ASP.NET Core 2.x compiles its views at
/// run time, nopCommerce copies its plugins' views and compiles them at run time) are compiled here, with the Razor
/// language API and its MVC extensions, into C# that joins the project's compilation like the Razor source generator's.
///
/// - The views are the project's recorded `razor-view=` files (CompilationInput.RazorViews) under its directory, but the
///   `_ViewImports.cshtml` files, which are imports, not views.
/// - A view has a generated class when a tree of the compilation maps a `#line` to its file, or names its project-relative
///   path (`/Views/Home/Index.cshtml`) in a `RazorCompiledItem`, `RazorCompiledItemMetadata("Identifier", …)` or
///   `RazorSourceChecksum` attribute (as EntryPoints identifies a view). Such views are left alone.
/// - The others are compiled only when the project references ASP.NET Core MVC's Razor views
///   (`Microsoft.AspNetCore.Mvc.Razor.RazorPage`): a `.cshtml` elsewhere is no MVC view.
/// - The Razor language version follows the referenced ASP.NET Core (2.0, 2.1, 3.0, 5.0, else the latest this API knows);
///   the code is MVC's (RazorExtensions), with the project's C# language version, `_ViewImports.cshtml` up the view's
///   folders (MVC's import feature), the project's tag helpers (`@addTagHelper`, discovered once per project in its own
///   compilation and references) and `#line` directives into the `.cshtml`, so findings are reported there.
///   `_ViewStart.cshtml` is a view of its own, as the build compiles it.
/// - Nothing here throws: a view that cannot be read or generated, or whose generated code has Razor or C# errors, is
///   counted (ProjectCompilation.EngineViewErrors); its code joins the compilation as far as it was generated.
internal static class RazorViews
{
    private const string RazorPage = "Microsoft.AspNetCore.Mvc.Razor.RazorPage";

    /// A view compiled here: its recorded path, its generated tree, and its Razor errors.
    internal sealed record View(string Path, SyntaxTree Tree, IReadOnlyList<string> RazorErrors);

    /// The views compiled here and those that could not be (path: reason).
    internal sealed record Batch(IReadOnlyList<View> Views, IReadOnlyList<string> Failed)
    {
        public static readonly Batch None = new(Array.Empty<View>(), Array.Empty<string>());
    }

    public static Batch Compile(CompilationInput input, CSharpCompilation compilation, CSharpParseOptions parseOptions, CancellationToken ct)
    {
        if (input.RazorViews.Count == 0) return Batch.None;
        var projectDir = System.IO.Path.GetDirectoryName(input.ProjectPath);
        if (string.IsNullOrEmpty(projectDir)) return Batch.None;
        var dirKey = SolutionLoader.PathKey(projectDir).TrimEnd('/') + "/";

        var candidates = new List<(string Path, string Identifier)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var failed = new List<string>();
        foreach (var view in input.RazorViews)
        {
            var key = SolutionLoader.PathKey(view);
            if (!seen.Add(key) || IsImports(view)) continue;
            if (!key.StartsWith(dirKey, StringComparison.Ordinal) && !key.StartsWith(dirKey, StringComparison.OrdinalIgnoreCase))
            {
                failed.Add($"{view}: outside the project directory {projectDir}");
                continue;
            }
            candidates.Add((view, "/" + view.Replace('\\', '/')[(projectDir.Replace('\\', '/').TrimEnd('/').Length + 1)..]));
        }
        if (candidates.Count == 0) return new Batch(Array.Empty<View>(), failed);
        if (compilation.GetTypeByMetadataName(RazorPage) == null) return Batch.None;

        var compiled = CompiledViews(compilation, ct);
        candidates.RemoveAll(c => compiled.Paths.Contains(SolutionLoader.PathKey(c.Path)) || compiled.Identifiers.Contains(c.Identifier));
        if (candidates.Count == 0) return new Batch(Array.Empty<View>(), failed);

        RazorProjectEngine engine;
        try
        {
            engine = CreateEngine(projectDir, compilation, parseOptions);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            failed.AddRange(candidates.Select(c => $"{c.Path}: the Razor compiler could not be set up: {e.GetType().Name}: {e.Message}"));
            return new Batch(Array.Empty<View>(), failed);
        }

        var views = new List<View>();
        foreach (var (path, _) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var item = engine.FileSystem.GetItem(path, FileKinds.Legacy);
                if (!item.Exists)
                {
                    failed.Add($"{path}: cannot be read");
                    continue;
                }
                var document = engine.Process(item).GetCSharpDocument();
                var errors = document.Diagnostics.Where(d => d.Severity == RazorDiagnosticSeverity.Error).Select(d => d.ToString()).ToList();
                var text = SourceText.From(document.GeneratedCode, Encoding.UTF8, SourceHashAlgorithm.Sha256);
                views.Add(new View(path, CSharpSyntaxTree.ParseText(text, parseOptions, path + ".g.cs", ct), errors));
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                failed.Add($"{path}: {e.GetType().Name}: {e.Message}");
            }
        }
        return new Batch(views, failed);
    }

    private static bool IsImports(string path) =>
        System.IO.Path.GetFileName(path.Replace('\\', '/')).Equals("_ViewImports.cshtml", StringComparison.OrdinalIgnoreCase);

    /// The views the compilation already has a generated class for: the `.cshtml` files its `#line` directives map to (by
    /// PathKey), and the project-relative paths its Razor attributes name (case-insensitive, as MVC looks views up).
    private static (HashSet<string> Paths, HashSet<string> Identifiers) CompiledViews(CSharpCompilation compilation, CancellationToken ct)
    {
        var paths = new HashSet<string>(StringComparer.Ordinal);
        var identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var tree in compilation.SyntaxTrees)
        {
            ct.ThrowIfCancellationRequested();
            var root = tree.GetRoot(ct);
            if (root.ContainsDirectives)
                foreach (var mapping in tree.GetLineMappings(ct))
                    if (mapping.MappedSpan.HasMappedPath && mapping.MappedSpan.Path.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase))
                        paths.Add(SolutionLoader.PathKey(mapping.MappedSpan.Path));
            // Assembly attributes and the attributes of (nested) type declarations, never member bodies.
            foreach (var list in root.DescendantNodes(n => n is CompilationUnitSyntax or BaseNamespaceDeclarationSyntax or TypeDeclarationSyntax or AttributeListSyntax)
                         .OfType<AttributeListSyntax>())
                foreach (var attribute in list.Attributes)
                    if (Identifier(attribute) is { } id) identifiers.Add(id);
        }
        return (paths, identifiers);
    }

    /// The view path a Razor attribute names: RazorCompiledItem(typeof(T), kind, path), RazorSourceChecksum(algorithm,
    /// checksum, path), RazorCompiledItemMetadata("Identifier", path).
    private static string? Identifier(AttributeSyntax attribute)
    {
        var name = attribute.Name switch
        {
            QualifiedNameSyntax q => q.Right.Identifier.ValueText,
            AliasQualifiedNameSyntax a => a.Name.Identifier.ValueText,
            SimpleNameSyntax s => s.Identifier.ValueText,
            _ => "",
        };
        if (name.EndsWith("Attribute", StringComparison.Ordinal)) name = name[..^"Attribute".Length];
        var args = attribute.ArgumentList?.Arguments;
        if (args is not { Count: 2 or 3 } a2) return null;
        string? Literal(int i) => a2[i].Expression is LiteralExpressionSyntax { Token.Value: string s } ? s : null;
        return name switch
        {
            "RazorCompiledItem" or "RazorSourceChecksum" when a2.Count == 3 => Literal(2),
            "RazorCompiledItemMetadata" when a2.Count == 2 && Literal(0) == "Identifier" => Literal(1),
            _ => null,
        };
    }

    private static RazorProjectEngine CreateEngine(string projectDir, CSharpCompilation compilation, CSharpParseOptions parseOptions)
    {
        var version = LanguageVersionOf(compilation);
        var configuration = RazorConfiguration.Create(version, "MVC-" + version, Array.Empty<RazorExtension>());
        return RazorProjectEngine.Create(configuration, RazorProjectFileSystem.Create(projectDir), builder =>
        {
            RazorExtensions.Register(builder);
            if (!builder.Features.OfType<DefaultTagHelperDescriptorProvider>().Any()) builder.Features.Add(new DefaultTagHelperDescriptorProvider());
            if (!builder.Features.OfType<ViewComponentTagHelperDescriptorProvider>().Any()) builder.Features.Add(new ViewComponentTagHelperDescriptorProvider());
            foreach (var feature in builder.Features.OfType<ITagHelperFeature>().ToList()) builder.Features.Remove(feature);
            builder.Features.Add(new ProjectTagHelpers(compilation));
            builder.SetCSharpLanguageVersion(parseOptions.LanguageVersion);
        });
    }

    /// The Razor language version of the ASP.NET Core the project references (its Microsoft.AspNetCore.Mvc.Razor).
    private static RazorLanguageVersion LanguageVersionOf(CSharpCompilation compilation)
    {
        var mvc = compilation.ReferencedAssemblyNames.FirstOrDefault(a => a.Name == "Microsoft.AspNetCore.Mvc.Razor");
        if (mvc == null) return RazorLanguageVersion.Latest;
        return (mvc.Version.Major, mvc.Version.Minor) switch
        {
            (1, _) => RazorLanguageVersion.Version_1_1,
            (2, 0) => RazorLanguageVersion.Version_2_0,
            (2, _) => RazorLanguageVersion.Version_2_1,
            (3, _) => RazorLanguageVersion.Version_3_0,
            (5, _) => RazorLanguageVersion.Version_5_0,
            _ => RazorLanguageVersion.Latest,
        };
    }

    /// The project's tag helpers, discovered once (the Razor engine asks for them for every view) in the project's own
    /// compilation and its references; none when discovery fails (the views still compile, tag helpers as markup).
    private sealed class ProjectTagHelpers(Compilation compilation) : RazorEngineFeatureBase, ITagHelperFeature
    {
        private IReadOnlyList<TagHelperDescriptor>? _descriptors;

        public IReadOnlyList<TagHelperDescriptor> GetDescriptors()
        {
            if (_descriptors != null) return _descriptors;
            var results = new List<TagHelperDescriptor>();
            try
            {
                var context = TagHelperDescriptorProviderContext.Create(results);
                context.SetCompilation(compilation);
                foreach (var provider in Engine.Features.OfType<ITagHelperDescriptorProvider>().OrderBy(p => p.Order)) provider.Execute(context);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                results.Clear();
            }
            return _descriptors = results;
        }
    }
}
