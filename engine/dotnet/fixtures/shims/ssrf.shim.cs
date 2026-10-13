// Shim for the engine harness: ssrf
global using System.Web;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

public interface IMediator
{
    Task Send(string key);
}

public interface IRepository
{
    Task<string> GetAsync(string key);
    Task DeleteAsync(string key);
    Task<Webhook> GetInstanceAsync(string id);
    Webhook GetInstance(string id);
    Task<T> FindAsync<T>(string id);
    Task<string> BuildUrlAsync(string id);
}
