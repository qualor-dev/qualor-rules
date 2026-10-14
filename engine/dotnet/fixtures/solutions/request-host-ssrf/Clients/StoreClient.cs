using Microsoft.AspNetCore.Http;

namespace Shop.Clients;

// A client that calls the store back on the address the request was made to.
public class StoreClient
{
    private readonly HttpClient _http;

    public StoreClient(HttpClient http) => _http = http;

    public async Task<string> WarmUp(string host)
    {
        // ruleid: csharp.ssrf
        return await _http.GetStringAsync($"https://{host}/health");
    }

    public async Task<string> Callback(HostString host, PathString pathBase)
    {
        // ruleid: csharp.ssrf
        _http.BaseAddress = new Uri("https://" + host + pathBase + "/");
        return await _http.GetStringAsync("api/ping");
    }

    // The host only goes into the path of a fixed service.
    public async Task<string> Report(string host)
    {
        // ok: csharp.ssrf
        return await _http.GetStringAsync("https://status.contoso.test/sites/" + Uri.EscapeDataString(host));
    }

    public async Task<string> Status(string site)
    {
        // ok: csharp.ssrf
        return await _http.GetStringAsync(Uri.UriSchemeHttps + Uri.SchemeDelimiter + "status.contoso.test/" + site);
    }
}
