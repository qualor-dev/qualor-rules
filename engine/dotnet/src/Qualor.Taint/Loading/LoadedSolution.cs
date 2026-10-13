using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint;

/// A rebuilt project: its input, its compilation, and every error found while loading it (missing files,
/// unresolved project references, cycles) followed by the compiler's own errors. A project with errors is
/// still analysed as far as its compilation allows.
public sealed record ProjectCompilation(CompilationInput Input, CSharpCompilation Compilation, IReadOnlyList<Diagnostic> Errors)
{
    /// The recorded assemblies that stand in for project references without an input or dropped from a cycle, one
    /// per such reference (ruling R-E6: reported by `rebuild`).
    public IReadOnlyList<string> FallbackAssemblies { get; init; } = Array.Empty<string>();
}

/// The whole solution's compilations, referenced projects before the projects that reference them.
public sealed record LoadedSolution(IReadOnlyList<ProjectCompilation> Projects);
