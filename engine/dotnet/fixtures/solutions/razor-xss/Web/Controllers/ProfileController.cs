using Microsoft.AspNetCore.Mvc;
using RazorXss.Models;

namespace RazorXss.Web.Controllers;

/// An MVC controller passing request data to a view through its model (Views/Profile/Show.cshtml).
public class ProfileController : Controller
{
    public IActionResult Show([FromQuery] string q)
    {
        var model = new UserProfile { Name = "Ada" };
        model.Bio = q;
        return View(model);
    }
}
