using Qualor.Taint.Tests.Intraprocedural;

namespace Qualor.Taint.Tests.Capabilities;

/// Task 34, firm core 24.12: Microsoft.Extensions.FileProviders (learn.microsoft.com aspnet/core/fundamentals/
/// file-providers; dotnet/api/microsoft.extensions.fileproviders.ifileprovider, .ifileinfo, .idirectorycontents,
/// .physicalfileprovider, .notfoundfileinfo). The IFileInfo a provider gives for a path holds that path (its PhysicalPath
/// and its Name: a file that is not found is a NotFoundFileInfo whose Name is the path as given); a directory's contents
/// are the entries under the path given. PhysicalFileProvider "scopes all paths to a directory and its children. This
/// scoping prevents access to the file system outside of the specified directory": the PhysicalPath it gives cannot leave
/// its root (or is null), so it is clean for path traversal; the Name is not (ruling R-E37 refined).
public sealed class FileProviderTests
{
    private const string PathRule = "csharp.path-traversal";

    private const string Header = """
        using Microsoft.Extensions.FileProviders;
        """;

    [Fact]
    public void A_file_found_by_a_request_path_through_an_unknown_provider_carries_that_path() => Expect(Header + """
        public class MediaController : ControllerBase
        {
            private readonly IFileProvider _files;
            public MediaController(IFileProvider files) => _files = files;
            public void Remove(string path)
            {
                var info = _files.GetFileInfo(path);
                Directory.Delete(info.PhysicalPath!, true); /*sink*/
                System.IO.File.Delete(_files.GetFileInfo("cache/" + path).PhysicalPath!); /*sink*/
                foreach (var entry in _files.GetDirectoryContents(path))
                    System.IO.File.Delete(entry.PhysicalPath!); /*sink*/
            }
        }
        """, PathRule);

    [Fact]
    public void A_file_found_through_a_project_provider_wrapper_carries_the_path() => Expect(Header + """
        public class CacheStore
        {
            private readonly IFileProvider _files;
            public CacheStore(IFileProvider files) => _files = files;
            public IFileInfo Find(string subpath) => _files.GetFileInfo(subpath.Replace(':', '_'));
            public bool Drop(string path)
            {
                var info = Find(path);
                if (!Directory.Exists(info.PhysicalPath)) return false;
                Directory.Delete(info.PhysicalPath!, true); /*sink*/
                return true;
            }
        }
        public class MediaController : ControllerBase
        {
            private readonly CacheStore _store;
            public MediaController(CacheStore store) => _store = store;
            public bool Remove(string path) => _store.Drop(path);
        }
        """, PathRule);

    [Fact]
    public void A_physical_provider_keeps_the_physical_path_under_its_root_but_not_the_name() => Expect(Header + """
        public class MirrorProvider : PhysicalFileProvider
        {
            public MirrorProvider(string root) : base(root) { }
            public new IFileInfo GetFileInfo(string subpath) => base.GetFileInfo(subpath.Replace(':', '_'));
        }
        public class MediaController : ControllerBase
        {
            private readonly PhysicalFileProvider _physical = new("/srv/media");
            private readonly MirrorProvider _mirror = new("/srv/cache");
            private readonly IFileProvider _any;
            public MediaController(IFileProvider any) => _any = any;
            public void Remove(string path)
            {
                Directory.Delete(_physical.GetFileInfo(path).PhysicalPath!, true);
                Directory.Delete(_mirror.GetFileInfo(path).PhysicalPath!, true);
                foreach (var entry in _physical.GetDirectoryContents(path))
                    System.IO.File.Delete(entry.PhysicalPath!);
                // A file that is not found (outside the root, rooted, absent) is a NotFoundFileInfo whose Name is the path
                // as given (ruling R-E37 refined): Name keeps the request data, PhysicalPath does not.
                System.IO.File.Delete("/srv/trash/" + _any.GetFileInfo(path).Name); /*sink*/
                System.IO.File.Delete("/srv/trash/" + _physical.GetFileInfo(path).Name); /*sink*/
                var info = _physical.GetFileInfo(path);
                Directory.Delete(info.PhysicalPath!, true);
                System.IO.File.Move(info.PhysicalPath!, "/srv/trash/" + info.Name); /*sink*/
                System.IO.File.Delete(_any.GetFileInfo("fixed/readme.txt").PhysicalPath!);
            }
        }
        """, PathRule);

    [Fact]
    public void A_contained_file_name_is_still_request_text_for_the_other_rules() => Expect(Header + """
        public class MediaController : ControllerBase
        {
            private readonly PhysicalFileProvider _physical = new("/srv/media");
            public void Tag(string path, SqlConnection db)
            {
                var info = _physical.GetFileInfo(path);
                new SqlCommand("UPDATE media SET seen = 1 WHERE name = '" + info.Name + "'", db).ExecuteNonQuery(); /*sink*/
            }
        }
        """, "csharp.sql-injection");

    /// Fix round 2 of Task 34, RR-I2: what a PhysicalFileProvider gives keeps its request data as a whole; its PhysicalPath
    /// is clean only where the engine still knows it exactly (in place, through a local). Passed to a project method or
    /// kept in a field, the file's members are read from the whole value: the Name is still found, and so is the
    /// PhysicalPath (the documented cost of R-E37: an over-report, never a miss).
    [Fact]
    public void A_physical_file_passed_on_or_kept_reads_from_its_whole_value() => Expect(Header + """
        public static class Shelf
        {
            public static void Discard(IFileInfo file) => System.IO.File.Delete("/var/bin/" + file.Name); /*sink*/
            public static void Erase(IFileInfo file) => System.IO.File.Delete(file.PhysicalPath!); /*sink*/
        }
        public class AssetsController : ControllerBase
        {
            private readonly PhysicalFileProvider _assets = new("/var/assets");
            private IFileInfo? _pending;
            public void Stage(string asset)
            {
                _pending = _assets.GetFileInfo(asset);
                var here = _assets.GetFileInfo(asset);
                System.IO.File.Delete(here.PhysicalPath!);
                Shelf.Discard(here);
                Shelf.Erase(here);
                Commit();
            }
            private void Commit()
            {
                System.IO.File.Copy(_pending!.PhysicalPath!, "/var/done/" + _pending.Name); /*sink*/
            }
        }
        """, PathRule);

    private static void Expect(string code, string rule) => Assert.Equal(Snippet.Marked(code), Snippet.Findings(code, rule));
}
