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

    /// The recorded views no build compiled that the engine compiled into this compilation (Task 30, R-11: RazorViews).
    public IReadOnlyList<string> EngineViews { get; init; } = Array.Empty<string>();

    /// One line per view the engine could not compile cleanly (`<path>: <first error>`): not read or not generated, outside
    /// the project directory and not compiled by the build, or with Razor or compiler errors in its code (which is analysed
    /// as far as it goes); and one line for the project (`<project>: tag helper discovery failed: …`) when its tag helpers
    /// could not be discovered (its views then render them as markup). Never in Errors.
    public IReadOnlyList<string> EngineViewErrors { get; init; } = Array.Empty<string>();

    /// The recorded sources (and the generated-file directory) that could not be read (QT0001): a project with a source
    /// not loaded, or with no syntax tree at all, is analysed without part of its code (ruling R-E42: the run is
    /// incomplete).
    public int SourcesNotLoaded { get; init; }

    /// The metadata references that could not be read and the project references dropped with no assembly to stand for
    /// them (their types are missing; ruling R-E42: counted and warned, the run stays complete).
    public int UnresolvedReferences { get; init; }

    /// Whether part of the project's code could not be loaded (ruling R-E42).
    public bool SourcesMissing => SourcesNotLoaded > 0 || !Compilation.SyntaxTrees.Any();
}

/// The whole solution's compilations, referenced projects before the projects that reference them.
public sealed record LoadedSolution(IReadOnlyList<ProjectCompilation> Projects);
