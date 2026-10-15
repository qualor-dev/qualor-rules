namespace Gallery.Model;

// A user's request to import an avatar from an address of their choosing.
public sealed record AvatarImport(string SourceUrl, string Caption);

// Settings of the gallery, provided by the container.
public sealed class GalleryOptions
{
    public string PlaceholderUrl { get; set; } = "https://img.gallery.test/placeholder.png";
}
