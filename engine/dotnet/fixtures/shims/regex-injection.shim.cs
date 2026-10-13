// Shim for the engine harness: regex-injection
// regex-injection.global.cs names only Regex: a project's GlobalUsings.cs brings the namespace in.
global using System.Text.RegularExpressions;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

// What the Regex source generator writes for [GeneratedRegex] (the fixture declares the partial method only).
public partial class TextController
{
    private static partial Regex LettersRegex() => null;
}
