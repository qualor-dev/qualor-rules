// Shim for the engine harness: tls-verification-disabled
global using static Memoizer;

// A project helper that wraps a callback; its result stands for a certificate callback of either kind.
public sealed class Memoized
{
    public static implicit operator System.Net.Security.RemoteCertificateValidationCallback(Memoized m) => null;

    public static implicit operator System.Func<System.Net.Http.HttpRequestMessage, System.Security.Cryptography.X509Certificates.X509Certificate2, System.Security.Cryptography.X509Certificates.X509Chain, System.Net.Security.SslPolicyErrors, bool>(Memoized m) => null;
}

public static class Memoizer
{
    public static Memoized Memoize(System.Func<bool> callback) => null;
    public static void Pin(System.Security.Cryptography.X509Certificates.X509Certificate certificate) { }
}

// A widget of another library with callback properties.
public class Widget
{
    public System.Func<object, object, object, object, bool> Filter { get; set; }
    public System.Func<object, object, object, object, bool> ValidationCallback { get; set; }
}
