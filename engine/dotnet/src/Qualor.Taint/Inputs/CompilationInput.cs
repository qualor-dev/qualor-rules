using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint;

/// One project and target framework as Qualor's build hook recorded it (compilation input format v1:
/// `.qualor/dotnet/compilations/<hash>.txt`). Paths are kept exactly as recorded, never normalised.
public sealed record CompilationInput(
    string ProjectPath, string TargetFramework, string AssemblyName, OutputKind OutputKind,
    LanguageVersion LanguageVersion, NullableContextOptions Nullable, IReadOnlyList<string> Defines,
    bool AllowUnsafe, string? GeneratedDir, IReadOnlyList<string> Sources,
    IReadOnlyList<string> References, IReadOnlyList<string> ProjectReferences, string InputFile);
