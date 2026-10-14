using Helpdesk.Core;
using Microsoft.AspNetCore.Mvc;

namespace Helpdesk.Web;

[ApiController]
[Route("api/tickets")]
public class TicketsController : ControllerBase
{
    private readonly TicketStore _store = new();

    [HttpGet("find")]
    public IActionResult Find(string reference) => Ok(_store.Find(new Ticket(reference)));

    [HttpGet("explicit")]
    public IActionResult FindExplicit(string reference) => Ok(_store.FindExplicit(new Ticket(reference)));

    [HttpGet("safe")]
    public IActionResult FindSafe(string reference) => Ok(_store.FindSafe(new Ticket(reference)));
}
