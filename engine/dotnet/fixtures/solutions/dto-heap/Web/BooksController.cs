using Library.Contracts;
using Library.Services;
using Microsoft.AspNetCore.Mvc;

namespace Library.Web;

[ApiController]
[Route("api/books")]
public class BooksController : ControllerBase
{
    private readonly BookSearch _search = new();

    [HttpPost("by-title")]
    public IActionResult ByTitle([FromBody] SearchRequest request) => Ok(_search.ByTitle(request));

    [HttpPost("by-page-size")]
    public IActionResult ByPageSize([FromBody] SearchRequest request) => Ok(_search.ByPageSize(request));

    [HttpPost("fixed")]
    public IActionResult Fixed([FromBody] SearchRequest request) => Ok(_search.Fixed(request));
}
