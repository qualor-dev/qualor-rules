namespace Qualor.Taint.Tests;

/// Temporary directories for one test class instance (xUnit creates one per test), removed on dispose.
public abstract class TempDirs : IDisposable
{
    private readonly List<string> _dirs = new();

    /// A fresh directory whose name holds a space and non-ASCII characters (Review Focus 5).
    protected string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "qualor-taint-tests", "My Dir Ünï " + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        foreach (var dir in _dirs)
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        GC.SuppressFinalize(this);
    }
}
