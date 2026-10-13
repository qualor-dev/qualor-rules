// Shim for the engine harness: open-redirect
// open-redirect.global.cs names no namespace: a project's GlobalUsings.cs brings Microsoft.AspNetCore.Mvc in.
global using Microsoft.AspNetCore.Mvc;
global using System.Web;
global using System.Text.Encodings.Web;
global using Duende.IdentityServer.Services;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

// A document archive of the project.
public class ArchiveDocument
{
    public string DownloadLink { get; set; }
}

public interface IArchive
{
    Task<ArchiveDocument> GetDocumentAsync(string slug);
    Task<ArchiveDocument> LoadMirror(string slug);
    ArchiveDocument FindDocument(string slug);
    Task<string> LoadCanonicalAsync(string target);
    Task<string> ShortenAsync(string target);
}

// The object of a project's own navigator.
public class Navigation
{
    public void Redirect(string page) { }
}

namespace Duende.IdentityServer.Services
{
    public class AuthorizationRequest
    {
        public Client Client { get; set; }
    }

    public class Client
    {
        public string ClientName { get; set; }
    }

    public class AuthenticationRequest { }

    public interface IIdentityServerInteractionService
    {
        Task<AuthorizationRequest> GetAuthorizationContextAsync(string returnUrl);
        Task<AuthenticationRequest> GetAuthenticationContextAsync(string returnUrl);
        bool IsValidReturnUrl(string returnUrl);
    }
}
