using Microsoft.Data.SqlClient;
using Reports.Services;

namespace Reports.Data;

public class ReportRepository
{
    private readonly string _connectionString;
    private readonly TenantContext _tenant;

    public ReportRepository(string connectionString, TenantContext tenant)
    {
        _connectionString = connectionString;
        _tenant = tenant;
    }

    public int CountForTenant()
    {
        using var connection = new SqlConnection(_connectionString);
        // ruleid: csharp.sql-injection
        using var command = new SqlCommand("SELECT COUNT(*) FROM Reports WHERE Tenant = '" + _tenant.Tenant() + "'", connection);
        return (int)command.ExecuteScalar();
    }

    public int CountForRegion()
    {
        using var connection = new SqlConnection(_connectionString);
        // ruleid: csharp.sql-injection
        using var command = new SqlCommand($"SELECT COUNT(*) FROM Reports WHERE Region = '{_tenant.Region()}'", connection);
        return (int)command.ExecuteScalar();
    }

    public int Top()
    {
        using var connection = new SqlConnection(_connectionString);
        // ok: csharp.sql-injection
        using var command = new SqlCommand("SELECT TOP " + _tenant.PageSize() + " Id FROM Reports", connection);
        return (int)command.ExecuteScalar();
    }
}
