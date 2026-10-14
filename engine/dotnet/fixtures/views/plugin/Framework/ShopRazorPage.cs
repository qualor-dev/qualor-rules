using Microsoft.AspNetCore.Mvc.Razor;

namespace Shop.Framework;

/// The application's base class for its views (`@inherits` in a plugin's _ViewImports.cshtml), with a text helper.
public abstract class ShopRazorPage<TModel> : RazorPage<TModel>
{
    public string Label(string text) => text.Trim();
}
