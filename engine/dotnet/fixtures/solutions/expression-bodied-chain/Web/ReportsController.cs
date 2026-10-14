using Microsoft.AspNetCore.Mvc;
using Reports.Core;

namespace Reports.Web;

[ApiController]
[Route("api/reports")]
public class ReportsController : ControllerBase
{
    private readonly ReportRunner _runner = new();

    private string Term => Request.Query["term"].ToString();

    private ReportQuery Build() => new(Term);

    [HttpGet("run")]
    public IActionResult Run() => Ok(_runner.Run(Build()));

    [HttpGet("wrapped")]
    public IActionResult Wrapped(string clause) => Ok(_runner.RunWrapped(clause));

    [HttpGet("safe")]
    public IActionResult Safe() => Ok(_runner.RunSafe(new ReportQuery("monthly")));
}
