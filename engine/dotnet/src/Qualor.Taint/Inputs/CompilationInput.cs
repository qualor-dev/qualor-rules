using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint;

/// One project and target framework as Qualor's build hook recorded it (compilation input format v1:
/// `.qualor/dotnet/compilations/<hash>.txt`). Paths are kept exactly as recorded, never normalised.
public sealed record CompilationInput(
    string ProjectPath, string TargetFramework, string AssemblyName, OutputKind OutputKind,
    LanguageVersion LanguageVersion, NullableContextOptions Nullable, IReadOnlyList<string> Defines,
    bool AllowUnsafe, string? GeneratedDir, IReadOnlyList<string> Sources,
    IReadOnlyList<string> References, IReadOnlyList<string> ProjectReferences, string InputFile)
{
    /// The built assembly of each project reference (`project-reference-assembly=`, ruling R-E4), paired by position
    /// with ProjectReferences; the loader's fallback when a referenced project has no input or closes a cycle. Empty
    /// when none were recorded or their count did not match.
    public IReadOnlyList<string> ProjectReferenceAssemblies { get; init; } = Array.Empty<string>();

    /// MSBuild's Features (`features=`, ruling R-E6): each entry `key` or `key=value`, for the parse options.
    public IReadOnlyList<string> Features { get; init; } = Array.Empty<string>();

    /// MSBuild's InterceptorsNamespaces (`interceptors-namespaces=`, ruling R-E6), set by the SDK for generators that
    /// write interceptors (configuration binder, request delegate generator).
    public IReadOnlyList<string> InterceptorsNamespaces { get; init; } = Array.Empty<string>();
}
