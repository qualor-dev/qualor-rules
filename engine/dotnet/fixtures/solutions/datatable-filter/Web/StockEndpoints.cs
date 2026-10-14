using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Warehouse.Data;

namespace Warehouse.Web;

public sealed record StockQuery(string Site, string Prefix);

// Minimal API endpoints over the stock table: the query string and a JSON body.
public static class StockEndpoints
{
    public static void MapStock(this IEndpointRouteBuilder routes, StockTable stock)
    {
        routes.MapGet("/stock/{site}", (string site) => stock.ForSite(site).Count);
        routes.MapPost("/stock/search", ([FromBody] StockQuery query) => stock.Available(query.Site, query.Prefix));
        routes.MapGet("/stock/empty", (string orderBy) => stock.Empty(orderBy));
        routes.MapGet("/stock/total", (string bin) => stock.Total(bin));
    }
}
