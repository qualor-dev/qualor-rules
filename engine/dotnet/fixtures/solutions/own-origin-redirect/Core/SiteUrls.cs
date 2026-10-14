using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Shop.Core;

// The site's own addresses, read from the current request.
public class SiteUrls
{
    private readonly IHttpContextAccessor _accessor;

    public SiteUrls(IHttpContextAccessor accessor) => _accessor = accessor;

    private HttpRequest Request => _accessor.HttpContext!.Request;

    // scheme://host of the request, from the Host header.
    public string Origin() =>
        $"{(Request.IsHttps ? Uri.UriSchemeHttps : Uri.UriSchemeHttp)}{Uri.SchemeDelimiter}{Request.Headers[HeaderNames.Host]}";

    // The host alone: what follows it decides where a browser goes.
    public string Host() => Request.Headers.Host.ToString();

    public string ReturnUrl() => Request.Query["returnUrl"].ToString();
}
