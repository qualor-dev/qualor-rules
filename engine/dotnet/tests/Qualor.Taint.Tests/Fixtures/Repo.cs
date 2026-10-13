namespace Qualor.Taint.Tests.Fixtures;

/// The qualor-rules checkout the tests run from: the directory above `engine/dotnet`.
public static class Repo
{
    public static readonly string Root = Find();

    public static string EngineDir => Path.Combine(Root, "engine", "dotnet");

    private static string Find()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "engine", "dotnet", "Qualor.Taint.sln"))) return dir.FullName;
        throw new InvalidOperationException("qualor-rules root (engine/dotnet/Qualor.Taint.sln) not found above " + AppContext.BaseDirectory);
    }
}
