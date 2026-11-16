using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Settings for signing users in to one Microsoft Entra ID tenant with the OpenID Connect
    /// authorization code flow and PKCE. The client calls <see cref="Validate"/> when it is
    /// created, so a bad value stops the app at startup instead of failing at sign-in.
    /// </summary>
    public sealed class AuthSettings
    {
        private static readonly string[] MultiTenantAliases = { "common", "organizations", "consumers" };
        private static readonly char[] PathSeparator = { '/' };

        /// <summary>Application (client) ID of the app registration.</summary>
        public string ClientId { get; set; }

        /// <summary>Tenant authority, for example https://login.microsoftonline.com/{tenant-id}.</summary>
        public string Authority { get; set; }

        /// <summary>Redirect URI registered on the app registration. HTTPS is required outside localhost.</summary>
        public Uri RedirectUri { get; set; }

        /// <summary>Sign-in scopes. Must include "openid". Request only what the app uses.</summary>
        public IReadOnlyCollection<string> Scopes { get; set; } = new[] { "openid", "profile" };

        /// <summary>
        /// Preferred client credential: a certificate with its private key, loaded from a secure
        /// store such as Azure Key Vault.
        /// </summary>
        public X509Certificate2 ClientCertificate { get; set; }

        /// <summary>
        /// Fallback client credential. Load it from a secure store, never from source control or a
        /// plain config file, and rotate it before it expires.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>How long a sign-in attempt stays valid between the redirect and the callback.</summary>
        public TimeSpan FlowLifetime { get; set; } = TimeSpan.FromMinutes(15);

        /// <summary>Allowed clock difference between this server and Entra ID when checking token lifetimes.</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>The tenant's OpenID Connect discovery document.</summary>
        internal string MetadataAddress => Authority.TrimEnd('/') + "/v2.0/.well-known/openid-configuration";

        /// <summary>Throws <see cref="InvalidOperationException"/> naming every invalid setting.</summary>
        public void Validate()
        {
            var errors = new List<string>();

            if (!Guid.TryParse(ClientId, out _))
            {
                errors.Add("ClientId must be the application (client) ID, a GUID.");
            }

            ValidateAuthority(errors);
            ValidateRedirectUri(errors);
            ValidateScopes(errors);
            ValidateCredential(errors);

            if (FlowLifetime < TimeSpan.FromMinutes(1) || FlowLifetime > TimeSpan.FromMinutes(30))
            {
                errors.Add("FlowLifetime must be between 1 and 30 minutes.");
            }

            if (ClockSkew < TimeSpan.Zero || ClockSkew > TimeSpan.FromMinutes(5))
            {
                errors.Add("ClockSkew must be between 0 and 5 minutes.");
            }

            if (errors.Count > 0)
            {
                throw new InvalidOperationException("Invalid authentication settings: " + string.Join(" ", errors));
            }
        }

        private void ValidateAuthority(List<string> errors)
        {
            if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authority) || authority.Scheme != Uri.UriSchemeHttps)
            {
                errors.Add("Authority must be an absolute HTTPS URI.");
                return;
            }

            var segments = authority.AbsolutePath.Split(PathSeparator, StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length != 1 || authority.Query.Length > 0 || authority.Fragment.Length > 0 || authority.UserInfo.Length > 0)
            {
                errors.Add("Authority must look like https://login.microsoftonline.com/{tenant-id}, with no version suffix, query or fragment.");
                return;
            }

            if (MultiTenantAliases.Contains(segments[0], StringComparer.OrdinalIgnoreCase))
            {
                errors.Add("Authority must name one tenant. common, organizations and consumers are multi-tenant and need issuer checks against a tenant allowlist, which this client doesn't implement.");
            }
        }

        private void ValidateRedirectUri(List<string> errors)
        {
            if (RedirectUri == null || !RedirectUri.IsAbsoluteUri)
            {
                errors.Add("RedirectUri must be an absolute URI.");
                return;
            }

            var isHttps = RedirectUri.Scheme == Uri.UriSchemeHttps;
            var isLocalHttp = RedirectUri.Scheme == Uri.UriSchemeHttp && RedirectUri.IsLoopback;
            if (!isHttps && !isLocalHttp)
            {
                errors.Add("RedirectUri must use HTTPS; plain HTTP is allowed only on localhost.");
            }

            if (RedirectUri.Fragment.Length > 0)
            {
                errors.Add("RedirectUri must not contain a fragment.");
            }
        }

        private void ValidateScopes(List<string> errors)
        {
            if (Scopes == null || !Scopes.Contains("openid", StringComparer.Ordinal))
            {
                errors.Add("Scopes must include \"openid\"; without it Entra ID returns no ID token.");
            }
            else if (Scopes.Any(scope => string.IsNullOrWhiteSpace(scope) || scope.Any(char.IsWhiteSpace)))
            {
                errors.Add("Each scope must be one non-empty value without spaces.");
            }
        }

        private void ValidateCredential(List<string> errors)
        {
            var hasCertificate = ClientCertificate != null;
            var hasSecret = !string.IsNullOrEmpty(ClientSecret);
            if (hasCertificate == hasSecret)
            {
                errors.Add("Configure exactly one client credential: ClientCertificate (preferred) or ClientSecret.");
            }
            else if (hasCertificate && !ClientCertificate.HasPrivateKey)
            {
                errors.Add("ClientCertificate must include its private key.");
            }
            else if (hasCertificate && ClientCertificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            {
                errors.Add("ClientCertificate has expired.");
            }
        }
    }
}