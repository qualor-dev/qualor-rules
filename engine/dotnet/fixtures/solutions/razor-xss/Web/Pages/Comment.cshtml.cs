using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorXss.Web.Pages;

/// A Razor Page whose bound property the page renders (Comment.cshtml).
public class CommentModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string Text { get; set; }

    public void OnGet()
    {
    }
}
