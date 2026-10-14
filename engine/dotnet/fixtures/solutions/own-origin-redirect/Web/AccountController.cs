using Microsoft.AspNetCore.Mvc;
using Shop.Core;

namespace Shop.Web;

public class AccountController : Controller
{
    private readonly SiteUrls _urls;

    public AccountController(SiteUrls urls) => _urls = urls;

    public IActionResult Secure()
    {
        // ok: csharp.open-redirect
        return Redirect(_urls.Origin() + Request.PathBase + Request.Path + Request.QueryString);
    }

    public IActionResult Home()
    {
        // ok: csharp.open-redirect
        return Redirect(Request.PathBase + "/home");
    }

    public IActionResult Same()
    {
        // ok: csharp.open-redirect
        return Redirect($"{Request.Scheme}://{Request.Headers.Host}{Request.Path}");
    }

    public IActionResult Back()
    {
        // ruleid: csharp.open-redirect
        return Redirect(_urls.ReturnUrl());
    }

    public IActionResult Path()
    {
        // ruleid: csharp.open-redirect
        return Redirect(_urls.Host() + Request.Path);
    }
}
