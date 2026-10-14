using Fleet.Tools;
using Microsoft.AspNetCore.Mvc;

namespace Fleet.Web;

[ApiController]
[Route("maintenance")]
public class MaintenanceController : ControllerBase
{
    private readonly AgentConsole _console = new();

    [HttpGet("reachable/{machine}")]
    public async Task<IActionResult> Reachable(string machine) => Ok(await _console.Reachable(machine));

    [HttpPost("rotate")]
    public IActionResult Rotate([FromForm] string logName)
    {
        _console.Rotate(logName);
        return NoContent();
    }

    [HttpPost("notes")]
    public IActionResult Notes([FromBody] string note)
    {
        _console.Archive(note);
        _console.Sort(note);
        return NoContent();
    }
}
