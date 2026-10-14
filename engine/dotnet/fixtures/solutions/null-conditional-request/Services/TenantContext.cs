using Microsoft.AspNetCore.Http;

namespace Reports.Services;

// The current tenant, from the request when there is one.
public class TenantContext
{
    private readonly IHttpContextAccessor _accessor;

    public TenantContext(IHttpContextAccessor accessor) => _accessor = accessor;

    public string Tenant() => _accessor.HttpContext?.Request.Headers["X-Tenant"];

    public string Region() => _accessor.HttpContext?.Request?.Query["region"].ToString();

    public int PageSize() => _accessor.HttpContext?.Request.Query.Count ?? 0;
}
