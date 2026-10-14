using Microsoft.Data.SqlClient;

namespace Helpdesk.Core;

public class Ticket
{
    public Ticket(string reference) => Reference = reference;

    public string Reference { get; }

    public override string ToString() => Reference;
}

public class TicketStore
{
    private readonly SqlConnection _connection = new("Server=.;Database=Helpdesk");

    public int Find(Ticket ticket)
    {
        // ruleid: csharp.sql-injection
        return new SqlCommand($"SELECT * FROM Tickets WHERE Reference = '{ticket}'", _connection).ExecuteNonQuery();
    }

    public int FindExplicit(Ticket ticket)
    {
        // ruleid: csharp.sql-injection
        return new SqlCommand($"SELECT * FROM Tickets WHERE Reference = '{ticket.ToString()}'", _connection).ExecuteNonQuery();
    }

    public int FindSafe(Ticket ticket)
    {
        // ok: csharp.sql-injection
        return new SqlCommand($"SELECT * FROM Tickets WHERE Id = {ticket.GetHashCode()}", _connection).ExecuteNonQuery();
    }
}
