namespace Gallery.Imaging;

public interface IDownloader
{
    Task<byte[]> Fetch(string address);

    Task<byte[]> FetchPlaceholder(string address);

    Task<byte[]> FetchQuery(string address);
}

// Downloads image bytes from an address.
public sealed class Downloader : IDownloader
{
    private readonly HttpClient _client;

    public Downloader(HttpClient client) => _client = client;

    public Task<byte[]> Fetch(string address) =>
        // ruleid: csharp.ssrf
        _client.GetByteArrayAsync(address);

    public Task<byte[]> FetchPlaceholder(string address) =>
        // ok: csharp.ssrf
        _client.GetByteArrayAsync(address);

    public Task<byte[]> FetchQuery(string address) =>
        // ok: csharp.ssrf
        _client.GetByteArrayAsync(address);
}
