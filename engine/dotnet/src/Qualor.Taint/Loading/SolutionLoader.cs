using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// Rebuilds one CSharpCompilation per recorded project and target framework. Project references become source
/// compilations (whole solution); every other reference is metadata. Nothing here throws on a bad project: missing
/// files, unresolved references and cycles become errors of the project they affect, and its compilation is
/// built from what is there.
public static class SolutionLoader
{
    /// A recorded source or reference file that cannot be read.
    public const string MissingFileId = "QT0001";
    /// A project reference with no recorded input (the referenced project was not built in the session).
    public const string MissingProjectReferenceId = "QT0002";
    /// A project reference that closes a cycle; the reference is dropped.
    public const string ReferenceCycleId = "QT0003";
    /// A second input for the same project and target framework; the first one (by input file name) is used.
    public const string DuplicateInputId = "QT0004";

    private static readonly DiagnosticDescriptor MissingFile = Descriptor(MissingFileId, "Recorded file not readable");
    private static readonly DiagnosticDescriptor MissingProjectReference = Descriptor(MissingProjectReferenceId, "Project reference without input");
    private static readonly DiagnosticDescriptor ReferenceCycle = Descriptor(ReferenceCycleId, "Project reference cycle");
    private static readonly DiagnosticDescriptor DuplicateInput = Descriptor(DuplicateInputId, "Duplicate compilation input");

    /// Topological order over ProjectReferences (by ProjectPath+TFM; a referenced project with several TFMs: the one
    /// whose TFM is the referencing TFM, else the highest compatible, else the first); project references become
    /// CompilationReferences; generated *.cs under GeneratedDir are added as syntax trees; a cycle or a missing
    /// referenced input falls back to the metadata reference recorded for it (if any) and records an error.
    /// The fallback is the reference's `project-reference-assembly` (ruling R-E4): when it can be read it is used and
    /// no error is recorded; otherwise the reference is dropped with an error. Per-project I/O and path failures are
    /// errors of that project (QT0001), never exceptions.
    public static LoadedSolution Load(IReadOnlyList<CompilationInput> inputs, CancellationToken ct)
    {
        var nodes = new List<Node>();
        var byKey = new Dictionary<(string Path, string Tfm), Node>();
        var byPath = new Dictionary<string, List<Node>>(StringComparer.Ordinal);
        var duplicates = new List<(Node Kept, CompilationInput Dropped)>();
        foreach (var input in inputs)
        {
            var path = PathKey(input.ProjectPath);
            var key = (path, input.TargetFramework.ToLowerInvariant());
            if (byKey.TryGetValue(key, out var existing))
            {
                duplicates.Add((existing, input));
                continue;
            }
            var node = new Node(input, nodes.Count);
            nodes.Add(node);
            byKey[key] = node;
            if (!byPath.TryGetValue(path, out var list)) byPath[path] = list = new List<Node>();
            list.Add(node);
        }
        foreach (var (kept, dropped) in duplicates)
            kept.LoadErrors.Add(Diagnostic.Create(DuplicateInput, Location.None,
                $"{dropped.InputFile} records {dropped.ProjectPath} ({dropped.TargetFramework}) again; {kept.Input.InputFile} is used"));

        foreach (var node in nodes)
        {
            var references = node.Input.ProjectReferences;
            var assemblies = node.Input.ProjectReferenceAssemblies;
            for (var n = 0; n < references.Count; n++)
            {
                var reference = references[n];
                var assembly = assemblies.Count == references.Count && assemblies[n].Length > 0 ? assemblies[n] : null;
                var target = byPath.TryGetValue(PathKey(reference), out var candidates)
                    ? Frameworks.Select(candidates, node.Input.TargetFramework, c => c.Input.TargetFramework)
                    : null;
                if (target is null || ReferenceEquals(target, node)) node.Unresolved.Add((reference, assembly));
                else if (node.DependencyAssemblies.TryAdd(target, assembly))
                {
                    node.Dependencies.Add(target);
                    target.Dependents.Add(node);
                }
            }
        }

        // Kahn's algorithm, ties broken by input order so the result is deterministic. When only cycles remain,
        // the first remaining node is compiled without its not-yet-compiled references.
        var remaining = nodes.ToDictionary(n => n, n => n.Dependencies.Count);
        var ready = new SortedSet<int>(nodes.Where(n => n.Dependencies.Count == 0).Select(n => n.Index));
        var result = new List<ProjectCompilation>(nodes.Count);
        var cache = new ReferenceCache();
        while (remaining.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            Node next;
            if (ready.Count > 0)
            {
                next = nodes[ready.Min];
                ready.Remove(next.Index);
            }
            else
            {
                next = remaining.Keys.MinBy(n => n.Index)!;
            }
            remaining.Remove(next);
            result.Add(Compile(next, cache, ct));
            foreach (var dependent in next.Dependents)
            {
                if (!remaining.TryGetValue(dependent, out var count)) continue;
                remaining[dependent] = --count;
                if (count == 0) ready.Add(dependent.Index);
            }
        }
        return new LoadedSolution(result);
    }

    private static ProjectCompilation Compile(Node node, ReferenceCache cache, CancellationToken ct)
    {
        var input = node.Input;
        var errors = new List<Diagnostic>(node.LoadErrors);
        var parseOptions = new CSharpParseOptions(input.LanguageVersion, preprocessorSymbols: input.Defines)
            .WithFeatures(Features(input));
        var fallbacks = new List<string>();

        var trees = new List<SyntaxTree>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in input.Sources)
        {
            if (seen.Add(PathKey(source))) AddTree(source);
        }
        if (input.GeneratedDir is { } generatedDir)
        {
            string[] generated;
            try
            {
                generated = Directory.GetFiles(generatedDir, "*.cs", SearchOption.AllDirectories);
            }
            catch (DirectoryNotFoundException)
            {
                generated = Array.Empty<string>();   // no source generator wrote anything
            }
            catch (Exception e) when (IsFileFailure(e))
            {
                errors.Add(Diagnostic.Create(MissingFile, Location.None, $"generated-dir {generatedDir} cannot be listed: {e.Message}"));
                generated = Array.Empty<string>();
            }
            Array.Sort(generated, StringComparer.Ordinal);
            foreach (var file in generated)
            {
                if (seen.Add(PathKey(file))) AddTree(file);   // a generated file also recorded as source= is added once
            }
        }

        var references = new List<MetadataReference>();
        foreach (var path in input.References.Distinct(StringComparer.Ordinal))
        {
            if (cache.Get(path) is { } reference) references.Add(reference);
            else errors.Add(Diagnostic.Create(MissingFile, Location.None, $"reference {path} cannot be read"));
        }
        foreach (var dependency in node.Dependencies)
        {
            if (dependency.Compilation is { } compilation) references.Add(compilation.ToMetadataReference());
            else if (!AddFallback(node.DependencyAssemblies[dependency], out var why))
                errors.Add(Diagnostic.Create(ReferenceCycle, Location.None,
                    $"project reference {dependency.Input.ProjectPath} ({dependency.Input.TargetFramework}) closes a cycle and was dropped; {why}"));
        }
        foreach (var (reference, assembly) in node.Unresolved)
        {
            if (!AddFallback(assembly, out var why))
                errors.Add(Diagnostic.Create(MissingProjectReference, Location.None, $"project reference {reference} has no recorded input; {why}"));
        }

        var options = new CSharpCompilationOptions(input.OutputKind,
                nullableContextOptions: input.Nullable, allowUnsafe: input.AllowUnsafe, concurrentBuild: true)
            .WithAssemblyIdentityComparer(DesktopAssemblyIdentityComparer.Default);
        // csc's /main (MSBuild's StartupObject): the entry point of an application with more than one Main (CS0017
        // otherwise); a library has none (csc refuses /main for one: CS2017).
        if (input.StartupObject != null && input.OutputKind is OutputKind.ConsoleApplication or OutputKind.WindowsApplication)
            options = options.WithMainTypeName(input.StartupObject);
        var result = CSharpCompilation.Create(input.AssemblyName, trees, references, options);
        // Task 30 (R-11): the recorded views without a generated class, compiled by the engine. Their errors (Razor's and
        // the compiler's in their code) are theirs, not the build's: counted apart, never fatal.
        var views = RazorViews.Compile(input, result, parseOptions, ct);
        if (views.Views.Count > 0) result = result.AddSyntaxTrees(views.Views.Select(v => v.Tree));
        node.Compilation = result;
        var viewOf = views.Views.ToDictionary(v => v.Tree, v => v.Path);
        var viewErrors = views.Failed.ToList();
        var failedViews = new HashSet<string>(StringComparer.Ordinal);
        foreach (var v in views.Views)
            if (v.RazorErrors.Count > 0 && failedViews.Add(v.Path)) viewErrors.Add($"{v.Path}: {v.RazorErrors[0]}");
        foreach (var d in result.GetDiagnostics(ct).Where(d => d.Severity == DiagnosticSeverity.Error))
        {
            if (d.Location.SourceTree is { } tree && viewOf.TryGetValue(tree, out var view))
            {
                if (failedViews.Add(view)) viewErrors.Add($"{view}: {d.Id} {d.GetMessage(System.Globalization.CultureInfo.InvariantCulture)}");
            }
            else errors.Add(d);
        }
        return new ProjectCompilation(input, result, errors)
        {
            FallbackAssemblies = fallbacks,
            EngineViews = views.Views.Select(v => v.Path).ToList(),
            EngineViewErrors = viewErrors,
        };

        // The referenced project's recorded assembly as a metadata reference, in place of its compilation.
        bool AddFallback(string? assembly, out string why)
        {
            why = "";
            if (assembly is null)
            {
                why = "no assembly is recorded for it, its types are missing";
                return false;
            }
            if (cache.Get(assembly) is not { } fallback)
            {
                why = $"its recorded assembly {assembly} cannot be read, its types are missing";
                return false;
            }
            if (!references.Contains(fallback)) references.Add(fallback);
            fallbacks.Add(assembly);
            return true;
        }

        void AddTree(string path)
        {
            SourceText text;
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                text = SourceText.From(stream, encoding: null, checksumAlgorithm: SourceHashAlgorithm.Sha256);
            }
            catch (Exception e) when (IsFileFailure(e) || e is InvalidDataException)
            {
                errors.Add(Diagnostic.Create(MissingFile, Location.None, $"source {path} cannot be read: {e.Message}"));
                return;
            }
            trees.Add(CSharpSyntaxTree.ParseText(text, parseOptions, path, ct));
        }
    }

    /// csc's /features: each Features entry `key[=value]` (value "true" when absent), then InterceptorsNamespaces
    /// under both keys the compiler reads (ruling R-E6); later entries win.
    internal static Dictionary<string, string> Features(CompilationInput input)
    {
        var features = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in input.Features)
        {
            var eq = entry.IndexOf('=');
            if (eq == 0) continue;
            if (eq < 0) features[entry] = "true";
            else features[entry[..eq]] = entry[(eq + 1)..];
        }
        if (input.InterceptorsNamespaces.Count > 0)
        {
            var namespaces = string.Join(';', input.InterceptorsNamespaces);
            features["InterceptorsNamespaces"] = namespaces;
            features["InterceptorsPreviewNamespaces"] = namespaces;
        }
        return features;
    }

    /// What a recorded path can throw: I/O and access failures, and a malformed path (a NUL character, a bad format).
    internal static bool IsFileFailure(Exception e) =>
        e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException;

    private static DiagnosticDescriptor Descriptor(string id, string title) =>
        new(id, title, "{0}", "Qualor.Taint.Loading", DiagnosticSeverity.Error, isEnabledByDefault: true);

    /// A recorded path as a lookup key: separators unified, `.` and `..` resolved, and case folded for Windows
    /// paths (drive letter or UNC), on any host, since the inputs may have been recorded on another OS.
    internal static string PathKey(string path)
    {
        var windows = path.Length >= 2 && (path[1] == ':' || path.StartsWith(@"\\", StringComparison.Ordinal));
        var unified = path.Replace('\\', '/');
        var parts = new List<string>();
        foreach (var part in unified.Split('/'))
        {
            if (part == "." || (part.Length == 0 && parts.Count > 0)) continue;
            if (part == ".." && parts.Count > 1) parts.RemoveAt(parts.Count - 1);
            else parts.Add(part);
        }
        var key = string.Join('/', parts);
        return windows ? key.ToLowerInvariant() : key;
    }

    private sealed class Node(CompilationInput input, int index)
    {
        public CompilationInput Input { get; } = input;
        public int Index { get; } = index;
        public List<Node> Dependencies { get; } = new();
        public List<Node> Dependents { get; } = new();
        public Dictionary<Node, string?> DependencyAssemblies { get; } = new();
        public List<(string Project, string? Assembly)> Unresolved { get; } = new();
        public List<Diagnostic> LoadErrors { get; } = new();
        public CSharpCompilation? Compilation { get; set; }
    }
}

/// Metadata references shared by path across the projects of one load, so Roslyn reads each assembly once.
internal sealed class ReferenceCache
{
    private readonly Dictionary<string, MetadataReference?> _references = new(StringComparer.Ordinal);

    /// The reference for a recorded path, or null when the file cannot be read.
    public MetadataReference? Get(string path)
    {
        if (_references.TryGetValue(path, out var reference)) return reference;
        try
        {
            reference = File.Exists(path) ? MetadataReference.CreateFromFile(path) : null;
        }
        catch (Exception e) when (SolutionLoader.IsFileFailure(e) || e is BadImageFormatException)
        {
            reference = null;
        }
        _references[path] = reference;
        return reference;
    }
}

/// Target framework monikers, as far as choosing which build of a multi-targeting project to reference.
internal static class Frameworks
{
    private enum Family { NetFramework, NetStandard, NetCore }

    private sealed record Moniker(Family Family, Version Version, string Platform);

    /// The candidate whose TFM equals the wanted one, else the highest compatible one, else the first.
    public static T? Select<T>(IReadOnlyList<T> candidates, string wanted, Func<T, string> tfm) where T : class
    {
        if (candidates.Count == 0) return null;
        var exact = candidates.FirstOrDefault(c => string.Equals(tfm(c), wanted, StringComparison.OrdinalIgnoreCase));
        if (exact is not null) return exact;
        var want = Parse(wanted);
        if (want is not null)
        {
            var best = candidates
                .Select(c => (Candidate: c, Moniker: Parse(tfm(c))))
                .Where(c => c.Moniker is not null && Compatible(want, c.Moniker))
                .OrderByDescending(c => c.Moniker!.Family == want.Family)
                .ThenByDescending(c => c.Moniker!.Platform.Length > 0)
                .ThenByDescending(c => c.Moniker!.Version)
                .Select(c => c.Candidate)
                .FirstOrDefault();
            if (best is not null) return best;
        }
        return candidates[0];
    }

    private static bool Compatible(Moniker want, Moniker have)
    {
        if (have.Platform.Length > 0 && have.Platform != want.Platform) return false;
        return (want.Family, have.Family) switch
        {
            (Family.NetCore, Family.NetCore) => have.Version <= want.Version,
            (Family.NetCore, Family.NetStandard) => have.Version <= (want.Version.Major >= 3 ? new Version(2, 1) : new Version(2, 0)),
            (Family.NetStandard, Family.NetStandard) => have.Version <= want.Version,
            (Family.NetFramework, Family.NetFramework) => have.Version <= want.Version,
            (Family.NetFramework, Family.NetStandard) => want.Version >= new Version(4, 6, 1) && have.Version <= new Version(2, 0),
            _ => false,
        };
    }

    /// net8.0, net8.0-windows10.0.19041, netcoreapp3.1, netstandard2.0, net48, net472; null for anything else.
    private static Moniker? Parse(string tfm)
    {
        var lower = tfm.ToLowerInvariant();
        var dash = lower.IndexOf('-');
        var platform = dash < 0 ? "" : new string(lower[(dash + 1)..].TakeWhile(char.IsLetter).ToArray());
        var core = dash < 0 ? lower : lower[..dash];
        if (core.StartsWith("netstandard", StringComparison.Ordinal))
            return Version.TryParse(core["netstandard".Length..], out var v) ? new Moniker(Family.NetStandard, v, platform) : null;
        if (core.StartsWith("netcoreapp", StringComparison.Ordinal))
            return Version.TryParse(core["netcoreapp".Length..], out var v) ? new Moniker(Family.NetCore, v, platform) : null;
        if (!core.StartsWith("net", StringComparison.Ordinal)) return null;
        var rest = core[3..];
        if (rest.Contains('.'))
            return Version.TryParse(rest, out var v) && v.Major >= 5 ? new Moniker(Family.NetCore, v, platform) : null;
        if (rest.Length is >= 2 and <= 3 && rest.All(char.IsAsciiDigit))   // net48 = 4.8, net472 = 4.7.2
            return new Moniker(Family.NetFramework, new Version(string.Join('.', rest.ToCharArray())), platform);
        return null;
    }
}
