using Gallery.Imaging;
using Gallery.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Gallery.Endpoints;

public static class AvatarEndpoints
{
    public static void UseAvatars(this IEndpointRouteBuilder routes)
    {
        // PUT binds the import from the body; the downloader and the options come from the container.
        routes.MapPut("/avatars/{user}", Import);
        // DELETE does not bind the body: this parameter is no request data by the binding rules.
        routes.MapDelete("/avatars/{user}", async (string user, AvatarImport import, IDownloader downloader) =>
            Results.Bytes(await downloader.FetchQuery(import.SourceUrl)));
    }

    private static async Task<IResult> Import(string user, AvatarImport import, IDownloader downloader, GalleryOptions options)
    {
        var fallback = await downloader.FetchPlaceholder(options.PlaceholderUrl);
        var bytes = await downloader.Fetch(import.SourceUrl);
        return Results.Bytes(bytes.Length > 0 ? bytes : fallback, "image/png");
    }
}
