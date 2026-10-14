using Microsoft.AspNetCore.Mvc;
using RuntimeViews.Areas.Admin.Models;

namespace RuntimeViews.Areas.Admin;

/// An area controller: its views import the area's namespace through Areas/Admin/Views/_ViewImports.cshtml.
[Area("Admin")]
public class NotesController : Controller
{
    public IActionResult Edit([FromForm] string text) => View(new NoteModel { Text = text });
}
