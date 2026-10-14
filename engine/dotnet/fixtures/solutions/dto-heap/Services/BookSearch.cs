using Library.Contracts;
using Microsoft.Data.SqlClient;

namespace Library.Services;

public class BookSearch
{
    private readonly SqlConnection _connection = new("Server=.;Database=Library");

    public int ByTitle(SearchRequest request)
    {
        var sql = "SELECT COUNT(*) FROM Books WHERE Title = '" + request.Title + "'";
        // ruleid: csharp.sql-injection
        return new SqlCommand(sql, _connection).ExecuteNonQuery();
    }

    public int ByPageSize(SearchRequest request)
    {
        var sql = "SELECT TOP " + request.PageSize + " * FROM Books";
        // ok: csharp.sql-injection
        return new SqlCommand(sql, _connection).ExecuteNonQuery();
    }

    public int Fixed(SearchRequest request)
    {
        // ok: csharp.sql-injection
        return new SqlCommand("SELECT COUNT(*) FROM Books WHERE Author = 'Anon'", _connection).ExecuteNonQuery();
    }
}
