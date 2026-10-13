// Microsoft.AspNetCore.Mvc and Microsoft.AspNetCore.Http come from a global using in another file
// of the project (global using Microsoft.AspNetCore.Mvc;), so this file names no namespace.
public class ShortcutController : Controller
{
    public IActionResult Follow(string destination)
    {
        // ruleid: csharp.open-redirect
        return new RedirectResult(destination);
    }

    public IActionResult FollowLocal(string destination)
    {
        // ok: csharp.open-redirect
        return new LocalRedirectResult(destination);
    }
}
