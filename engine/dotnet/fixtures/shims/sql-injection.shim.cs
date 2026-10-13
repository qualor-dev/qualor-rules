// Shim for the engine harness: sql-injection

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

public class SavedReports
{
    public SavedReport Find(string name) => null;
}

public class SavedReport
{
    public string Query { get; set; }
}

public class Product { }

public class Shipment { }

// Base classes of other libraries (a game engine, an event listener) that are not controllers.
public class GameBehaviour { }

public class ListenerBase { }
