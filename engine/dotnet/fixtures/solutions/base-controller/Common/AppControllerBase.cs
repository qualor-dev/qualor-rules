using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace Audit.Common;

// A shared base class in another project: its helpers read the request or run SQL for every controller.
public abstract class AppControllerBase : ControllerBase
{
    protected string CurrentTenant() => Request.Query["tenant"].ToString();

    protected string CurrentCulture() => "en-US";

    protected int RunCount(string sql)
    {
        using var connection = new SqlConnection("Server=.;Database=Audit");
        // ruleid: csharp.sql-injection
        using var command = new SqlCommand(sql, connection);
        return (int)command.ExecuteScalar();
    }

    protected int RunFixed()
    {
        using var connection = new SqlConnection("Server=.;Database=Audit");
        // ok: csharp.sql-injection
        using var command = new SqlCommand("SELECT COUNT(*) FROM Entries", connection);
        return (int)command.ExecuteScalar();
    }
}
