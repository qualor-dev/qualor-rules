using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Qualor.Taint.Cli.Output;

namespace Qualor.Taint.Cli;

/// `Qualor.Taint.Cli rebuild --inputs <dir> --json <file>`: rebuilds the recorded compilations and writes, per
/// project and target framework, its source count, the project references served by their recorded assembly and the
/// errors. Exit code 0 whatever the projects' errors;
/// 2 when the arguments are invalid.
public static class Program
{
    private const int FirstErrors = 10;

    private const string Usage =
        "usage: Qualor.Taint.Cli rebuild --inputs <dir> --json <file>\n" +
        "       Qualor.Taint.Cli analyze --inputs <dir> --models <dir> --sarif <file> [--root <dir>] [--time-limit <seconds>] [--memory-limit <MB>] [--version <pack version>]";

    public const int DefaultTimeLimitSeconds = 600;
    public const int DefaultMemoryLimitMb = 4096;

    /// Test hook: called after the arguments are accepted, before the command runs (an exception thrown here is a crash).
    internal static Action? BeforeCommand { get; set; }

    public static int Main(string[] args) => Run(args, Console.Error);

    public static int Run(string[] args, TextWriter log)
    {
        try
        {
            if (args.Length == 0 || args[0] is not ("rebuild" or "analyze")) return Invalid(log, "unknown or missing command");
            var options = ParseOptions(args, out var problem);
            if (problem != null) return Invalid(log, problem);
            BeforeCommand?.Invoke();
            return args[0] == "rebuild" ? Rebuild(options, log) : Analyze(options, log);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            log.WriteLine($"crash: {e}");
            return 1;
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args, out string? problem)
    {
        problem = null;
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        var known = args[0] == "analyze"
            ? new[] { "--inputs", "--models", "--sarif", "--root", "--time-limit", "--memory-limit", "--version" }
            : new[] { "--inputs", "--json" };
        for (var i = 1; i < args.Length; i++)
        {
            if (i + 1 >= args.Length) { problem = $"{args[i]} needs a value or is not an option"; break; }
            if (!known.Contains(args[i])) { problem = $"unknown option {args[i]}"; break; }
            options[args[i]] = args[i + 1];
            i++;
        }
        return options;
    }

    /// `analyze`: 0 complete, 3 incomplete (budget, iteration cap, failed methods above 1 %; the SARIF is still written),
    /// 2 invalid arguments, models or output path, 1 crash.
    private static int Analyze(Dictionary<string, string> options, TextWriter log)
    {
        options.TryGetValue("--inputs", out var inputs);
        options.TryGetValue("--models", out var models);
        options.TryGetValue("--sarif", out var sarif);
        if (inputs is null || models is null || sarif is null) return Invalid(log, "--inputs, --models and --sarif are required");
        if (!Directory.Exists(inputs)) return Invalid(log, $"inputs directory {inputs} does not exist");
        if (!Directory.Exists(models)) return Invalid(log, $"models directory {models} does not exist");
        options.TryGetValue("--root", out var root);
        if (root is not null && !Directory.Exists(root)) return Invalid(log, $"root directory {root} does not exist");

        var timeLimit = TimeSpan.FromSeconds(DefaultTimeLimitSeconds);
        if (options.TryGetValue("--time-limit", out var t))
        {
            if (!double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) || !(seconds >= 0) || seconds > 1e9)
                return Invalid(log, $"--time-limit '{t}' is not a number of seconds");
            timeLimit = TimeSpan.FromSeconds(seconds);
        }
        long memoryMb = DefaultMemoryLimitMb;
        if (options.TryGetValue("--memory-limit", out var m) &&
            (!long.TryParse(m, NumberStyles.None, CultureInfo.InvariantCulture, out memoryMb) || memoryMb > (long.MaxValue >> 20)))
            return Invalid(log, $"--memory-limit '{m}' is not a number of megabytes");

        ModelSet modelSet;
        try { modelSet = ModelLoader.Load(models); }
        catch (ModelException e) { log.WriteLine($"invalid models: {e.Message}"); return 2; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            log.WriteLine($"cannot read the models: {e.Message}");
            return 2;
        }

        // Open the output first: an unwritable path is a usage error, found before the analysis runs.
        FileStream output;
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(sarif));
            if (dir is not null) Directory.CreateDirectory(dir);
            output = new FileStream(sarif, FileMode.Create, FileAccess.Write, FileShare.Read);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            log.WriteLine($"cannot write the SARIF file {sarif}: {e.Message}");
            return 2;
        }

        using (output)
        {
            var read = InputReader.Read(inputs, out var inputErrors);
            foreach (var error in inputErrors) log.WriteLine($"input: {error}");
            var solution = SolutionLoader.Load(read, CancellationToken.None);
            var engine = new TaintEngine(modelSet, new TaintEngineOptions(timeLimit, memoryMb << 20) { SourceRoot = root });
            var result = engine.Analyze(solution, CancellationToken.None);
            // Ruling R-E42: every project the solution could not load or compile cleanly, on stderr as in the SARIF.
            foreach (var problem in result.Stats.ProjectProblems) log.WriteLine($"project: {problem}");
            options.TryGetValue("--version", out var version);
            SarifWriter.Write(output, modelSet, result, version ?? PackVersion(models), root, inputErrors);
            log.WriteLine($"{result.Findings.Count} finding(s); {(result.Complete ? "complete" : "incomplete: " + result.IncompleteReason)}");
            return result.Complete ? 0 : 3;
        }
    }

    /// The pack version from `<models>/../manifest.json` (a `version` string), when the pack manifest is there.
    private static string? PackVersion(string models)
    {
        try
        {
            var manifest = Path.Combine(Path.GetFullPath(models), "..", "manifest.json");
            if (!File.Exists(manifest)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest, Encoding.UTF8));
            return doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }

    private static int Rebuild(Dictionary<string, string> options, TextWriter log)
    {
        options.TryGetValue("--inputs", out var inputs);
        options.TryGetValue("--json", out var json);
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
            w.WriteNumber("engineViews", p.EngineViews.Count);
            w.WriteStartArray("engineViewErrors");
            foreach (var e in p.EngineViewErrors) w.WriteStringValue(e);
            w.WriteEndArray();
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
    private static string Format(Diagnostic d) => SolutionLoader.Format(d);
}
