using Microsoft.Data.SqlClient;

namespace Reports.Core;

public class ReportQuery
{
    private readonly string _term;

    public ReportQuery(string term) => _term = term;

    public string Term => _term;

    public string Filter => "Name = '" + Term + "'";

    public string Text => "SELECT * FROM Reports WHERE " + Filter;

    public string SafeText => "SELECT * FROM Reports WHERE Name = 'monthly'";

    public static string Wrap(string clause) => "(" + clause + ")";
}

public class ReportRunner
{
    private readonly SqlConnection _connection = new("Server=.;Database=Reports");

    public int Run(ReportQuery query)
    {
        // ruleid: csharp.sql-injection
        return new SqlCommand(query.Text, _connection).ExecuteNonQuery();
    }

    public int RunWrapped(string clause)
    {
        // ruleid: csharp.sql-injection
        return new SqlCommand("SELECT * FROM Reports WHERE " + ReportQuery.Wrap(clause), _connection).ExecuteNonQuery();
    }

    public int RunSafe(ReportQuery query)
    {
        // ok: csharp.sql-injection
        return new SqlCommand(query.SafeText, _connection).ExecuteNonQuery();
    }
}
