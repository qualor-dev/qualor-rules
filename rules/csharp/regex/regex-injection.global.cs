// The regular-expression namespace comes from a global using in another file of the project,
// so this file names only Regex.
using Microsoft.AspNetCore.Mvc;

public class TagFilterController : Controller
{
    public IActionResult Filter(string tagPattern, string tag)
    {
        // ruleid: csharp.regex-injection
        var filter = new Regex(tagPattern);
        // ruleid: csharp.regex-injection
        var matches = Regex.IsMatch("release-2026", tagPattern);
        // ruleid: csharp.regex-injection
        var spelled = new System.Text.RegularExpressions.Regex(tagPattern);
        // ruleid: csharp.regex-injection
        var spelledStatic = System.Text.RegularExpressions.Regex.Split("a-b", tagPattern);
        // ok: csharp.regex-injection
        var plain = Regex.IsMatch(tag, "^[a-z0-9-]+$");
        return Ok(filter.IsMatch(tag) && matches && plain);
    }
}
