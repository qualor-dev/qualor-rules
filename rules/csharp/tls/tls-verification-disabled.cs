using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;

public class HttpHandlers
{
    // A lambda that returns true whatever it is given.
    public HttpClient Lambda()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        return new HttpClient(handler);
    }

    public HttpClient Initializer()
    {
        // ruleid: csharp.tls-verification-disabled
        return new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true });
    }

    public HttpClient BlockBody()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            Console.WriteLine("accepting " + cert?.Subject);
            return true;
        };
        return new HttpClient(handler);
    }

    public HttpClient Typed()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (HttpRequestMessage m, X509Certificate2? c, X509Chain? ch, SslPolicyErrors e) => true;
        return new HttpClient(handler);
    }

    public HttpClient AnonymousDelegate()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = delegate { return true; };
        return new HttpClient(handler);
    }

    // The helper Microsoft provides for this: its name says what it does.
    public HttpClient Dangerous()
    {
        var handler = new HttpClientHandler();
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return new HttpClient(handler);
    }

    public HttpClient DangerousQualified()
    {
        // ruleid: csharp.tls-verification-disabled
        return new HttpClient(new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = (s, c, ch, e) => true } });
    }

    public HttpClient DangerousInitializer()
    {
        return new HttpClient(new HttpClientHandler
        {
            // ruleid: csharp.tls-verification-disabled
            ServerCertificateCustomValidationCallback = System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        });
    }

    // A method group whose method accepts everything.
    public HttpClient MethodGroup()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = AcceptAnything;
        return new HttpClient(handler);
    }

    // ruleid: csharp.tls-verification-disabled
    private static bool AcceptAnything(HttpRequestMessage message, X509Certificate2? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        return true;
    }

    // ruleid: csharp.tls-verification-disabled
    private static bool AcceptExpression(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;

    // ruleid: csharp.tls-verification-disabled
    private static bool AcceptAndLog(object sender, X509Certificate cert, X509Chain chain, System.Net.Security.SslPolicyErrors errors)
    {
        Console.WriteLine(errors);
        return true;
    }

    // The callbacks that look at what they are given.
    public HttpClient Checks()
    {
        var handler = new HttpClientHandler();
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == SslPolicyErrors.None;
        return new HttpClient(handler);
    }

    public HttpClient Pinned(string thumbprint)
    {
        var handler = new HttpClientHandler();
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => cert != null && cert.Thumbprint == thumbprint;
        return new HttpClient(handler);
    }

    public HttpClient Branching()
    {
        var handler = new HttpClientHandler();
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }
            return false;
        };
        return new HttpClient(handler);
    }

    public HttpClient Throws()
    {
        var handler = new HttpClientHandler();
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            if (errors != SslPolicyErrors.None)
            {
                throw new InvalidOperationException("bad certificate");
            }
            return true;
        };
        return new HttpClient(handler);
    }

    public HttpClient LogsOnly()
    {
        var handler = new HttpClientHandler();
        // A condition that only logs checks nothing.
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            if (errors != SslPolicyErrors.None)
            {
                Console.WriteLine(errors);
            }
            return true;
        };
        return new HttpClient(handler);
    }

    public HttpClient Default()
    {
        // ok: csharp.tls-verification-disabled
        return new HttpClient(new HttpClientHandler());
    }

    public HttpClient Reset(HttpClientHandler handler)
    {
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = null;
        return new HttpClient(handler);
    }

    // A method that checks the errors.
    private static bool Strict(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        // ok: csharp.tls-verification-disabled
        return errors == SslPolicyErrors.None;
    }

    private static bool StrictBranches(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors != SslPolicyErrors.None)
        {
            return false;
        }
        // ok: csharp.tls-verification-disabled
        return true;
    }

    private static bool ThrowsOnErrors(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors != SslPolicyErrors.None)
        {
            throw new InvalidOperationException("bad certificate");
        }
        // ok: csharp.tls-verification-disabled
        return true;
    }

    private static bool TwoReturns(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        var known = Pinned(cert);
        return known;
        // ok: csharp.tls-verification-disabled
        return true;
    }

    private static bool WithTry(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        try
        {
            Pin(cert);
        }
        catch (Exception)
        {
            return false;
        }
        // ok: csharp.tls-verification-disabled
        return true;
    }

    // A lambda nested in the value is not the callback.
    public HttpClient Wrapped(HttpClientHandler handler)
    {
        // ok: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = Memoize(() => true);
        return new HttpClient(handler);
    }

    // Other callbacks that return true have nothing to do with certificates.
    public void LookAlikes(Widget widget)
    {
        // ok: csharp.tls-verification-disabled
        widget.Filter = (a, b, c, d) => true;
        // ok: csharp.tls-verification-disabled
        widget.ValidationCallback = (a, b, c, d) => true;
    }
}

public class ServicePoints
{
    public void Lambda()
    {
        // ruleid: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
    }

    public void Subscribe()
    {
        // ruleid: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;
    }

    public void Anonymous()
    {
        // ruleid: csharp.tls-verification-disabled
        System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }

    public void Typed()
    {
        // ruleid: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
    }

    public void ExplicitDelegate()
    {
        // ruleid: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback((s, c, ch, e) => true);
    }

    public void Delegate()
    {
        // ruleid: csharp.tls-verification-disabled
        var callback = new RemoteCertificateValidationCallback((s, c, ch, e) => true);
    }

    public void MethodGroup()
    {
        // The method AcceptEverything below is the finding.
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptEverything);
    }

    // ruleid: csharp.tls-verification-disabled
    private static bool AcceptEverything(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        return true;
    }

    public void Checks()
    {
        // ok: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => sslPolicyErrors == SslPolicyErrors.None;
        // ok: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback((s, c, ch, e) => e == SslPolicyErrors.None);
        // ok: csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = null;
    }
}

public class Streams
{
    public SslStream StreamLambda(System.IO.Stream inner)
    {
        // ruleid: csharp.tls-verification-disabled
        return new SslStream(inner, false, (sender, cert, chain, errors) => true);
    }

    public SslStream StreamWithSelection(System.IO.Stream inner)
    {
        // ruleid: csharp.tls-verification-disabled
        return new SslStream(inner, false, (sender, cert, chain, errors) => true, null);
    }

    public SslStream StreamBlock(System.IO.Stream inner)
    {
        // ruleid: csharp.tls-verification-disabled
        return new SslStream(inner, false, delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e)
        {
            Console.WriteLine(e);
            return true;
        });
    }

    public SslStream StreamMethodGroup(System.IO.Stream inner)
    {
        // The method AcceptAll below is the finding.
        return new SslStream(inner, false, new RemoteCertificateValidationCallback(AcceptAll));
    }

    // ruleid: csharp.tls-verification-disabled
    private static bool AcceptAll(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors) => true;

    public SslClientAuthenticationOptions Options()
    {
        // ruleid: csharp.tls-verification-disabled
        return new SslClientAuthenticationOptions { TargetHost = "example.com", RemoteCertificateValidationCallback = (s, c, ch, e) => true };
    }

    public void OptionsAssigned(SslClientAuthenticationOptions options)
    {
        // ruleid: csharp.tls-verification-disabled
        options.RemoteCertificateValidationCallback = delegate { return true; };
    }

    public void WebSocket(ClientWebSocket socket)
    {
        // ruleid: csharp.tls-verification-disabled
        socket.Options.RemoteCertificateValidationCallback = (s, c, ch, e) => true;
    }

    public SslStream Checked(System.IO.Stream inner)
    {
        // ok: csharp.tls-verification-disabled
        return new SslStream(inner, false, (sender, cert, chain, errors) => errors == SslPolicyErrors.None);
    }

    public SslStream WrappedLambda(System.IO.Stream inner)
    {
        // ok: csharp.tls-verification-disabled
        return new SslStream(inner, false, Memoize(() => true));
    }

    public SslStream Branching(System.IO.Stream inner)
    {
        // ok: csharp.tls-verification-disabled
        return new SslStream(inner, false, (sender, cert, chain, errors) =>
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }
            return false;
        });
    }

    public SslStream Default(System.IO.Stream inner)
    {
        // ok: csharp.tls-verification-disabled
        return new SslStream(inner);
    }

    public SslStream Selection(System.IO.Stream inner, X509Certificate local)
    {
        // ok: csharp.tls-verification-disabled
        return new SslStream(inner, false, (sender, cert, chain, errors) => errors == SslPolicyErrors.None, (sender, host, certs, remote, issuers) => local);
    }

    public SslClientAuthenticationOptions OptionsDefault()
    {
        // ok: csharp.tls-verification-disabled
        return new SslClientAuthenticationOptions { TargetHost = "example.com" };
    }
}

public class Limits
{
    public HttpClient FromVariable()
    {
        Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> trustAll = (m, c, ch, e) => true;
        var handler = new HttpClientHandler();
        // The callback is a variable; only its definition shows it accepts everything.
        // todoruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = trustAll;
        return new HttpClient(handler);
    }

    public HttpClient IgnoresOneError()
    {
        var handler = new HttpClientHandler();
        // Accepting every certificate whose only problem is the host name is not looked at.
        // todoruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.RemoteCertificateNameMismatch;
        return new HttpClient(handler);
    }

    public HttpClient TryCatch()
    {
        var handler = new HttpClientHandler();
        // A swallowing try block checks nothing.
        // ruleid: csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) =>
        {
            try
            {
                Console.WriteLine(c?.Subject);
            }
            catch (Exception)
            {
            }
            return true;
        };
        return new HttpClient(handler);
    }

    public HttpClient OnlyForTests(HttpClientHandler handler, bool development)
    {
        // The setting is conditional on a flag: reported all the same.
        if (development)
        {
            // todook: csharp.tls-verification-disabled
            handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        }
        return new HttpClient(handler);
    }
}
