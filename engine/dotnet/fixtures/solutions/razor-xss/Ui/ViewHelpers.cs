using Microsoft.AspNetCore.Html;

namespace RazorXss.Ui;

/// Helpers the views call to render HTML (a shared UI library).
public static class ViewHelpers
{
    public static IHtmlContent Highlight(string text) =>
        // ruleid: csharp.xss
        new HtmlString("<mark>" + text + "</mark>");

    public static IHtmlContent Separator() =>
        // ok: csharp.xss
        new HtmlString("<hr />");
}
