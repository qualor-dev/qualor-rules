using Microsoft.AspNetCore.Mvc;
using Shop.Domain;

namespace Shop.Web;

[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orders;

    public OrdersController(IOrderService orders) => _orders = orders;

    [HttpGet("by-customer")]
    public IActionResult ByCustomer(string customer) => Ok(_orders.CountByCustomer(customer));

    [HttpGet("by-status")]
    public IActionResult ByStatus(string status) => Ok(_orders.CountByStatus(status));

    [HttpGet("all")]
    public IActionResult All(string note) => Ok(_orders.CountAll(note));
}
