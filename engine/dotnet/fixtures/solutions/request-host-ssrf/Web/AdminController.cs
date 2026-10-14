using Microsoft.AspNetCore.Mvc;
using Shop.Clients;

namespace Shop.Web;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    private readonly StoreClient _client;

    public AdminController(StoreClient client) => _client = client;

    [HttpPost("warm-up")]
    public async Task<IActionResult> WarmUp() => Ok(await _client.WarmUp(Request.Host.Value!));

    [HttpPost("callback")]
    public async Task<IActionResult> Callback() => Ok(await _client.Callback(Request.Host, Request.PathBase));

    [HttpGet("report")]
    public async Task<IActionResult> Report() => Ok(await _client.Report(Request.Host.Host));

    [HttpGet("status")]
    public async Task<IActionResult> Status() => Ok(await _client.Status(Request.Host.Value!));
}
