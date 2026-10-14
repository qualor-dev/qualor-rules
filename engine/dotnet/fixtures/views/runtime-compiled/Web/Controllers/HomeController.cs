using Microsoft.AspNetCore.Mvc;
using RuntimeViews.Models;

namespace RuntimeViews.Controllers;

/// An MVC controller rendering views no build compiled (Views/Home/*.cshtml).
public class HomeController : Controller
{
    public IActionResult Show(string q)
    {
        var model = new ProfileModel { Name = "Ada" };
        model.Bio = q;
        return View(model);
    }

    public IActionResult Broken(string q) => View(new ProfileModel { Bio = q });

    public IActionResult Unclosed(string q) => View(new ProfileModel { Bio = q });
}
