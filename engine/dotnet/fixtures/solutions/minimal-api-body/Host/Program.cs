using Gallery.Endpoints;
using Gallery.Imaging;
using Gallery.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Gallery.Host;

public static class Composition
{
    public static WebApplication Create(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton(new GalleryOptions());
        builder.Services.AddHttpClient<IDownloader, Downloader>();
        var app = builder.Build();
        app.UseAvatars();
        return app;
    }
}
