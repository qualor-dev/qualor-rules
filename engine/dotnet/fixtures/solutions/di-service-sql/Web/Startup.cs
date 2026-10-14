using Microsoft.Extensions.DependencyInjection;
using Shop.Domain;
using Shop.Infrastructure;

namespace Shop.Web;

public static class Startup
{
    public static void Register(IServiceCollection services)
    {
        services.AddScoped<IOrderService>(_ => new OrderService("Server=.;Database=Shop"));
        services.AddControllers();
    }
}
