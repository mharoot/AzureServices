using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Text.RegularExpressions;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Strongly-typed, validated Entra ID settings. Everything environment-specific
    /// (redirect URIs, tenant, secret) comes from configuration, so dev/test/prod differ
    /// only by Web.config transforms and never by branching on the app pool name.
    /// </summary>
    public sealed class AuthSettings
    {
        public const string ClientIdKey = "AZURE_CLIENT_ID";
        public const string TenantIdKey = "AZURE_TENANT_ID";
        public const string ClientSecretKey = "AZURE_CLIENT_SECRET";
        public const string RedirectUriKey = "AZURE_REDIRECT_URI";
        public const string PostLoginUriKey = "AZURE_POST_LOGIN_URI";

        // Single-tenant only: the issuer check in IdTokenValidator relies on a concrete tenant.
        private static readonly Regex TenantPattern = new Regex(@"^[A-Za-z0-9][A-Za-z0-9.\-]*$", RegexOptions.Compiled);
        private static readonly string[] MultiTenantAliases = { "common", "organizations", "consumers" };

        public AuthSettings(string clientId, string tenantId, string clientSecret, string redirectUri, string postLoginUri)
        {
            ClientId = Require(clientId, ClientIdKey);
            TenantId = Require(tenantId, TenantIdKey);
            ClientSecret = Require(clientSecret, ClientSecretKey);

            if (!TenantPattern.IsMatch(TenantId) ||
                Array.IndexOf(MultiTenantAliases, TenantId.ToLowerInvariant()) >= 0)
            {
                throw new ConfigurationErrorsException(
                    TenantIdKey + " must be a specific tenant GUID or domain (not common/organizations/consumers).");
            }

            RedirectUri = ParseSecureUri(redirectUri, RedirectUriKey);
            PostLoginRedirectUri = ParseSecureUri(postLoginUri, PostLoginUriKey);

            // Defence in depth: we only ever send the browser back to our own host after login.
            if (!string.Equals(RedirectUri.Host, PostLoginRedirectUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                throw new ConfigurationErrorsException(
                    PostLoginUriKey + " must be on the same host as " + RedirectUriKey + ".");
            }
        }

        public string ClientId { get; }
        public string TenantId { get; }
        public string ClientSecret { get; }

        /// <summary>Must exactly match a Web redirect URI registered on the Entra app registration.</summary>
        public Uri RedirectUri { get; }

        /// <summary>Where the user lands after a successful sign-in.</summary>
        public Uri PostLoginRedirectUri { get; }

        public IReadOnlyList<string> Scopes { get; } = new[] { "openid", "profile", "email" };

        public string Authority => "https://login.microsoftonline.com/" + TenantId;

        public string MetadataAddress => Authority + "/v2.0/.well-known/openid-configuration";

        public static AuthSettings FromConfiguration() => FromAppSettings(ConfigurationManager.AppSettings);

        public static AuthSettings FromAppSettings(NameValueCollection settings)
        {
            if (settings == null) throw new ArgumentNullException(nameof(settings));
            return new AuthSettings(
                settings[ClientIdKey],
                settings[TenantIdKey],
                settings[ClientSecretKey],
                settings[RedirectUriKey],
                settings[PostLoginUriKey]);
        }

        private static string Require(string value, string key)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                // Never include the value itself in the message (it may be the client secret).
                throw new ConfigurationErrorsException("Required app setting '" + key + "' is missing or empty.");
            }
            return value.Trim();
        }

        private static Uri ParseSecureUri(string value, string key)
        {
            Require(value, key);
            Uri uri;
            if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out uri))
            {
                throw new ConfigurationErrorsException("App setting '" + key + "' must be an absolute URI.");
            }

            var isHttps = uri.Scheme == Uri.UriSchemeHttps;
            var isLoopbackHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
            if (!isHttps && !isLoopbackHttp)
            {
                throw new ConfigurationErrorsException("App setting '" + key + "' must use https (http is only allowed for localhost).");
            }
            return uri;
        }
    }
}
