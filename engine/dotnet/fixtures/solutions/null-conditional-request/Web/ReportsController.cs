using Microsoft.AspNetCore.Mvc;
using Reports.Data;

namespace Reports.Web;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    private readonly ReportRepository _reports;

    public ReportsController(ReportRepository reports) => _reports = reports;

    [HttpGet("tenant")]
    public IActionResult Tenant() => Ok(_reports.CountForTenant());

    [HttpGet("region")]
    public IActionResult Region() => Ok(_reports.CountForRegion());

    [HttpGet("top")]
    public IActionResult Top() => Ok(_reports.Top());
}
