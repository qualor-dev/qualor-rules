using System.Collections.Concurrent;

namespace Qualor.Taint;

/// The test-code paths a misuse rule skips (`test-code:`, the OpenGrep rule's `paths: exclude`; COVERAGE.md "Test
/// code"), matched as OpenGrep matches them from the scanned directory: a glob ending in '/' names a directory at any
/// depth, any other glob a file or directory name at any depth; '*' stands for any characters, case matters.
internal static class TestCode
{
    private static readonly char[] Separators = { '/', '\\' };
    private static readonly ConcurrentDictionary<string, string?> RepositoryRoots = new(StringComparer.Ordinal);

    /// Whether a path (relative to the scanned directory, either separator) is test code under `globs`.
    public static bool Matches(string relativePath, IReadOnlyList<string> globs)
    {
        if (globs.Count == 0) return false;
        var segments = relativePath.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
        foreach (var glob in globs)
        {
            var directory = glob.EndsWith('/');
            var pattern = directory ? glob[..^1] : glob;
            var last = directory ? segments.Length - 1 : segments.Length;
            for (var i = 0; i < last; i++)
                if (Glob(pattern, segments[i])) return true;
        }
        return false;
    }

    /// The path relative to `root` (the scanned directory); without a root, relative to the nearest directory above
    /// the file that holds `.git` (a directory or a worktree's file). A path outside the root, or with no repository
    /// above it, is returned as it is.
    public static string Relative(string path, string? root)
    {
        root ??= RepositoryRoot(path);
        if (root == null) return path;
        try
        {
            var relative = Path.GetRelativePath(root, path);
            return relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative) ? path : relative;
        }
        catch (ArgumentException)
        {
            return path;
        }
    }

    private static string? RepositoryRoot(string path)
    {
        string? dir;
        try
        {
            if (!Path.IsPathRooted(path)) return null;
            dir = Path.GetDirectoryName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
        return dir == null ? null : RepositoryRoots.GetOrAdd(dir, FindRepository);
    }

    private static string? FindRepository(string dir)
    {
        try
        {
            for (var d = new DirectoryInfo(dir); d != null; d = d.Parent)
            {
                var git = Path.Combine(d.FullName, ".git");
                if (Directory.Exists(git) || File.Exists(git)) return d.FullName;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
        }
        return null;
    }

    /// A glob with '*' (any characters) over one path segment, case-sensitive.
    private static bool Glob(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (p < pattern.Length && pattern[p] == text[t])
            {
                p++;
                t++;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
