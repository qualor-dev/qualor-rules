// Shim for the engine harness: xss
// The fixture has no `using Microsoft.AspNetCore.Html;` on purpose (OpenGrep tests the short and the qualified
// HtmlString apart); a project would bring the namespace in from a GlobalUsings.cs.
global using Microsoft.AspNetCore.Html;
global using System.Web;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

public class ChatMessage
{
    public string Content { get; set; }
}
