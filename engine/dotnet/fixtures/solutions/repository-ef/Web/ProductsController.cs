using Catalog.Data;
using Microsoft.AspNetCore.Mvc;

namespace Catalog.Web;

[ApiController]
[Route("api/products")]
public class ProductsController : ControllerBase
{
    private readonly IProductRepository _repository;

    public ProductsController(IProductRepository repository) => _repository = repository;

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string name) => Ok(_repository.SearchByName(name));

    [HttpGet("category")]
    public IActionResult Category([FromQuery] string category) => Ok(_repository.ByCategory(category));

    [HttpGet("newest")]
    public IActionResult Newest([FromQuery] string unused) => Ok(_repository.Newest(unused));
}
