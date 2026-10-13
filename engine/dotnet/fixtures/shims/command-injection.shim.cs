// Shim for the engine harness: command-injection
// The fixture has no `using System.Diagnostics;` on purpose (OpenGrep tests the short and the qualified names
// apart); a project would bring the namespaces in from a GlobalUsings.cs, which these two lines stand for.
global using System.Diagnostics;
global using Microsoft.Net.Http.Headers;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

// A scheduler of the project: it runs nothing itself, so its arguments are no command line.
public class JobScheduler
{
    public void Start(string name) { }
    public void Start(string fileName, string arguments) { }
}

// Project classes that only look like ProcessStartInfo.
public class DownloadOptions
{
    public string FileName { get; set; }
}

public class TaskOptions
{
    public string FileName { get; set; }
    public string Arguments { get; set; }
}
