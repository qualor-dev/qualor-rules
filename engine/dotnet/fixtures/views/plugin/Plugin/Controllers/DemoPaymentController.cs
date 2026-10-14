using Microsoft.AspNetCore.Mvc;
using Shop.Plugin.Payments.Demo.Models;

namespace Shop.Plugin.Payments.Demo.Controllers;

/// A plugin's controller: it names its view by the path the application copies it to.
public class DemoPaymentController : Controller
{
    public IActionResult Configure([FromQuery] string note)
    {
        var model = new ConfigureModel { Title = "Demo" };
        model.Note = note;
        return View("~/Plugins/Payments.Demo/Views/Configure.cshtml", model);
    }
}
