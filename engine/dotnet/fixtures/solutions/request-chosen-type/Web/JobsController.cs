using Microsoft.AspNetCore.Mvc;
using Scheduler.Import;

namespace Scheduler.Web;

[ApiController]
[Route("jobs")]
public class JobsController : ControllerBase
{
    [HttpPost]
    public IActionResult Enqueue() => Accepted(JobReader.Read(Request.Body));

    [HttpPost("wrapped")]
    public IActionResult Wrapped([FromQuery] string payload) => Accepted(JobReader.ReadWrapped(Request.Body, payload));

    [HttpPost("envelope")]
    public IActionResult Envelope() => Accepted(JobReader.ReadEnvelope(Request.Body));
}
