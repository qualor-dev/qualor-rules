using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint;

/// A rebuilt project: its input, its compilation, and every error found while loading it (missing files,
/// unresolved project references, cycles) followed by the compiler's own errors. A project with errors is
/// still analysed as far as its compilation allows.
public sealed record ProjectCompilation(CompilationInput Input, CSharpCompilation Compilation, IReadOnlyList<Diagnostic> Errors);

/// The whole solution's compilations, referenced projects before the projects that reference them.
public sealed record LoadedSolution(IReadOnlyList<ProjectCompilation> Projects);
