using Microsoft.CodeAnalysis;

namespace Qualor.Taint.Tests.Fixtures;

/// The metadata references the OpenGrep fixtures compile against: the .NET 8 and ASP.NET Core 8 reference assemblies
/// and the test-only packages of this project (Microsoft.Data.SqlClient, Npgsql, Dapper, ...). The list is written
/// by the project's own build (target QualorWriteFixtureReferences, from the compile-time ReferencePath items, so the
/// references are the reference assemblies a project of these packages would compile against, not the host runtime's
/// implementation assemblies) and read from `fixture-references.txt` next to the test assembly.
public static class FixtureReferences
{
    private static readonly Lazy<IReadOnlyList<MetadataReference>> AllLazy = new(Load);

    public static IReadOnlyList<MetadataReference> All => AllLazy.Value;

    private static IReadOnlyList<MetadataReference> Load()
    {
        var list = Path.Combine(AppContext.BaseDirectory, "fixture-references.txt");
        return File.ReadAllLines(list)
            .Where(l => l.Length > 0)
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
            .ToList();
    }
}
