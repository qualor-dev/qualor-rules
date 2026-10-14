using System.Diagnostics;

namespace Fleet.Tools;

// A build agent that keeps an interactive shell open and types maintenance commands into it
// (learn.microsoft.com: Process.StandardInput, ProcessStartInfo.RedirectStandardInput; cmd, about_pwsh).
public sealed class AgentConsole
{
    public async Task<int> Reachable(string machine)
    {
        var info = new ProcessStartInfo
        {
            FileName = Environment.OSVersion.Platform == PlatformID.Win32NT ? "cmd.exe" : "bash",
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        using var console = new Process { StartInfo = info };
        console.Start();
        // ruleid: csharp.command-injection
        await console.StandardInput.WriteLineAsync($"ping -c 1 {machine}");
        // ok: csharp.command-injection
        await console.StandardInput.WriteLineAsync("exit");
        await console.WaitForExitAsync();
        return console.ExitCode;
    }

    public void Rotate(string logName)
    {
        var console = new Process();
        console.StartInfo.FileName = "pwsh";
        console.StartInfo.Arguments = "-NoLogo -Command -";
        console.StartInfo.RedirectStandardInput = true;
        console.Start();
        using (var input = console.StandardInput)
        {
            // ruleid: csharp.command-injection
            input.Write("Move-Item ./logs/current.log ./logs/" + logName);
        }
    }

    // The started program reads the text as data, not as commands.
    public void Archive(string note)
    {
        var console = Process.Start("bash", "-c \"gzip > /var/archive/note.gz\"");
        // ok: csharp.command-injection
        console.StandardInput.WriteLine(note);
    }

    public void Sort(string names)
    {
        var info = new ProcessStartInfo("sort") { RedirectStandardInput = true };
        var sorter = new Process();
        sorter.StartInfo = info;
        sorter.Start();
        // ok: csharp.command-injection
        sorter.StandardInput.WriteLine(names);
    }
}
