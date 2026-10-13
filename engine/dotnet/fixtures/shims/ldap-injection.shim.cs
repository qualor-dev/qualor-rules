// Shim for the engine harness: ldap-injection
// The fixture says System.DirectoryServices and Encoder come from a GlobalUsings.cs of the project.
// An alias beats the namespace imports of System.Text (its own Encoder), as the project's file would see it.
global using System.DirectoryServices;
global using Encoder = Microsoft.Security.Application.Encoder;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

namespace Microsoft.Security.Application
{
    // The AntiXSS encoder.
    public static class Encoder
    {
        public static string LdapFilterEncode(string value) => value;
        public static string LdapDistinguishedNameEncode(string value) => value;
    }
}

namespace Acme.Text
{
    // A project's own class named like the encoder; it escapes nothing.
    public static class Encoder
    {
        public static string LdapFilterEncode(string value) => value;
    }
}
