using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint.Cli;

/// `Qualor.Taint.Cli rebuild --inputs <dir> --json <file>`: rebuilds the recorded compilations and writes, per
/// project and target framework, its source count, the project references served by their recorded assembly and the
/// errors. Exit code 0 whatever the projects' errors;
/// 2 when the arguments are invalid.
public static class Program
{
    private const int FirstErrors = 10;

    private const string Usage = "usage: Qualor.Taint.Cli rebuild --inputs <dir> --json <file>";

    public static int Main(string[] args) => Run(args, Console.Error);

    public static int Run(string[] args, TextWriter log)
    {
        if (args.Length == 0 || args[0] != "rebuild") return Invalid(log, "unknown or missing command");
        string? inputs = null, json = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (i + 1 >= args.Length) return Invalid(log, $"{args[i]} needs a value or is not an option");
            switch (args[i])
            {
                case "--inputs": inputs = args[++i]; break;
                case "--json": json = args[++i]; break;
                default: return Invalid(log, $"unknown option {args[i]}");
            }
        }
        if (inputs is null || json is null) return Invalid(log, "--inputs and --json are required");
        if (!Directory.Exists(inputs)) return Invalid(log, $"inputs directory {inputs} does not exist");

        var read = InputReader.Read(inputs, out var inputErrors);
        foreach (var error in inputErrors) log.WriteLine($"input: {error}");
        var solution = SolutionLoader.Load(read, CancellationToken.None);
        WriteJson(json, solution, inputErrors);
        foreach (var p in solution.Projects)
            log.WriteLine($"{p.Input.ProjectPath} ({p.Input.TargetFramework}): {p.Errors.Count} error(s)");
        return 0;
    }

    private static int Invalid(TextWriter log, string message)
    {
        log.WriteLine(message);
        log.WriteLine(Usage);
        return 2;
    }

    private static void WriteJson(string path, LoadedSolution solution, IReadOnlyList<string> inputErrors)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (dir is not null) Directory.CreateDirectory(dir);
        using var stream = File.Create(path);
        using var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        w.WriteStartObject();
        w.WriteStartArray("projects");
        foreach (var p in solution.Projects)
        {
            w.WriteStartObject();
            w.WriteString("project", p.Input.ProjectPath);
            w.WriteString("tfm", p.Input.TargetFramework);
            w.WriteNumber("sources", p.Input.Sources.Count);
            w.WriteNumber("trees", p.Compilation.SyntaxTrees.Count());
            w.WriteNumber("fallbacks", p.FallbackAssemblies.Count);
            w.WriteStartArray("fallbackAssemblies");
            foreach (var assembly in p.FallbackAssemblies) w.WriteStringValue(assembly);
            w.WriteEndArray();
            w.WriteNumber("errors", p.Errors.Count);
            w.WriteStartArray("firstErrors");
            foreach (var d in p.Errors.Take(FirstErrors)) w.WriteStringValue(Format(d));
            w.WriteEndArray();
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteStartArray("inputErrors");
        foreach (var error in inputErrors) w.WriteStringValue(error);
        w.WriteEndArray();
        w.WriteEndObject();
    }

    /// "CS0246 /src/App/P.cs(3,11): The type or namespace name 'Missing' could not be found ..."
    private static string Format(Diagnostic d)
    {
        var message = d.GetMessage(CultureInfo.InvariantCulture);
        if (!d.Location.IsInSource) return $"{d.Id} {message}";
        var span = d.Location.GetLineSpan();
        var b = new StringBuilder();
        b.Append(d.Id).Append(' ').Append(span.Path)
            .Append('(').Append(span.StartLinePosition.Line + 1).Append(',').Append(span.StartLinePosition.Character + 1).Append("): ")
            .Append(message);
        return b.ToString();
    }
}
