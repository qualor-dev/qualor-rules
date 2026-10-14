using Microsoft.Data.SqlClient;
using Shop.Domain;

namespace Shop.Infrastructure;

public class OrderService : IOrderService
{
    private readonly string _connectionString;

    public OrderService(string connectionString) => _connectionString = connectionString;

    public int CountByCustomer(string customer)
    {
        using var connection = new SqlConnection(_connectionString);
        var sql = "SELECT COUNT(*) FROM Orders WHERE Customer = '" + customer + "'";
        // ruleid: csharp.sql-injection
        using var command = new SqlCommand(sql, connection);
        return (int)command.ExecuteScalar();
    }

    public int CountByStatus(string status)
    {
        using var connection = new SqlConnection(_connectionString);
        // ok: csharp.sql-injection
        using var command = new SqlCommand("SELECT COUNT(*) FROM Orders WHERE Status = @status", connection);
        command.Parameters.AddWithValue("@status", status);
        return (int)command.ExecuteScalar();
    }

    // The parameter is request data in the controller, but it never reaches the SQL text.
    public int CountAll(string note)
    {
        using var connection = new SqlConnection(_connectionString);
        var sql = "SELECT COUNT(*) FROM Orders";
        // ok: csharp.sql-injection
        using var command = new SqlCommand(sql, connection);
        return (int)command.ExecuteScalar();
    }
}
