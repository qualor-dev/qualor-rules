using Audit.Common;
using Microsoft.AspNetCore.Mvc;

namespace Audit.Api;

[ApiController]
[Route("api/entries")]
public class EntriesController : AppControllerBase
{
    [HttpGet("tenant")]
    public IActionResult ForTenant() => Ok(RunCount("SELECT COUNT(*) FROM Entries WHERE Tenant = '" + CurrentTenant() + "'"));

    [HttpGet("search")]
    public IActionResult Search(string text) => Ok(RunCount("SELECT COUNT(*) FROM Entries WHERE Text = '" + text + "'"));

    [HttpGet("all")]
    public IActionResult All() => Ok(RunFixed());
}
