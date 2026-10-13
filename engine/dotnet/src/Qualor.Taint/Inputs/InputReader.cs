using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Qualor.Taint;

/// Reads the compilation input files (format v1) Qualor's build hook writes, one per project and target
/// framework: UTF-8, one `key=value` entry per line (split on the first `=`), list keys repeated, unknown keys
/// ignored. Values, paths included, are kept byte for byte: spaces, non-ASCII characters and either separator.
public static class InputReader
{
    public const string Header = "qualor-compilation=1";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// Every *.txt under dir that starts with "qualor-compilation=1"; malformed files are returned in errors, never thrown.
    public static IReadOnlyList<CompilationInput> Read(string dir, out IReadOnlyList<string> errors)
    {
        var inputs = new List<CompilationInput>();
        var problems = new List<string>();
        errors = problems;
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            problems.Add($"{dir}: cannot list the compilation inputs: {e.Message}");
            return inputs;
        }
        Array.Sort(files, StringComparer.Ordinal);
        foreach (var file in files)
        {
            try
            {
                inputs.Add(Parse(file, File.ReadAllBytes(file)));
            }
            catch (FormatException e)
            {
                problems.Add($"{file}: {e.Message}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                problems.Add($"{file}: cannot read: {e.Message}");
            }
        }
        return inputs;
    }

    private static CompilationInput Parse(string file, byte[] bytes)
    {
        var start = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        string text;
        try
        {
            text = StrictUtf8.GetString(bytes, start, bytes.Length - start);
        }
        catch (DecoderFallbackException)
        {
            throw new FormatException("not valid UTF-8");
        }

        var lines = text.Split('\n');
        if (lines[0].TrimEnd('\r') != Header)
            throw new FormatException($"does not start with {Header}");

        var scalars = new Dictionary<string, string>(StringComparer.Ordinal);
        var sources = new List<string>();
        var references = new List<string>();
        var projectReferences = new List<string>();
        for (var n = 1; n < lines.Length; n++)
        {
            var line = lines[n].TrimEnd('\r');
            if (line.Length == 0) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) throw new FormatException($"line {n + 1} is not a key=value entry");
            var key = line[..eq];
            var value = line[(eq + 1)..];
            switch (key)
            {
                case "source": if (value.Length > 0) sources.Add(value); break;
                case "reference": if (value.Length > 0) references.Add(value); break;
                case "project-reference": if (value.Length > 0) projectReferences.Add(value); break;
                default: scalars[key] = value; break;
            }
        }

        string Get(string key) => scalars.TryGetValue(key, out var v) ? v : "";

        var project = Get("project");
        if (project.Length == 0) throw new FormatException("has no project entry");
        var assembly = Get("assembly");
        if (assembly.Length == 0) assembly = FileNameWithoutExtension(project);
        var generated = Get("generated-dir");

        return new CompilationInput(
            ProjectPath: project,
            TargetFramework: Get("tfm"),
            AssemblyName: assembly,
            OutputKind: ParseOutputKind(Get("output-kind")),
            LanguageVersion: ParseLanguageVersion(Get("lang-version")),
            Nullable: ParseNullable(Get("nullable")),
            Defines: Get("defines").Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            AllowUnsafe: ParseBool("allow-unsafe", Get("allow-unsafe")),
            GeneratedDir: generated.Length == 0 ? null : generated,
            Sources: sources,
            References: references,
            ProjectReferences: projectReferences,
            InputFile: file);
    }

    /// MSBuild's OutputType: Exe and WinExe are applications, Library (or none) a library; others are not supported.
    private static OutputKind ParseOutputKind(string value) => value.ToLowerInvariant() switch
    {
        "exe" => OutputKind.ConsoleApplication,
        "winexe" => OutputKind.WindowsApplication,
        "library" or "" => OutputKind.DynamicallyLinkedLibrary,
        _ => throw new FormatException($"output-kind '{value}' is not supported (Exe, WinExe or Library)"),
    };

    private static LanguageVersion ParseLanguageVersion(string value)
    {
        if (value.Length == 0) return LanguageVersion.Default;
        if (LanguageVersionFacts.TryParse(value, out var version)) return version;
        throw new FormatException($"lang-version '{value}' is not a C# language version");
    }

    private static NullableContextOptions ParseNullable(string value) => value.ToLowerInvariant() switch
    {
        "" or "disable" => NullableContextOptions.Disable,
        "enable" => NullableContextOptions.Enable,
        "warnings" => NullableContextOptions.Warnings,
        "annotations" => NullableContextOptions.Annotations,
        _ => throw new FormatException($"nullable '{value}' is not one of enable, disable, warnings, annotations"),
    };

    private static bool ParseBool(string key, string value) => value.ToLowerInvariant() switch
    {
        "true" => true,
        "false" or "" => false,
        _ => throw new FormatException($"{key} '{value}' is not true or false"),
    };

    /// The file name without its extension, for paths recorded on Windows or Unix alike (on any host).
    internal static string FileNameWithoutExtension(string path)
    {
        var name = path[(path.LastIndexOfAny(new[] { '/', '\\' }) + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[..dot] : name;
    }
}
