using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace WEBNAME.Auth
{
    /// <summary>
    /// MSAL.NET-backed client. Register ONE instance for the process lifetime: the
    /// confidential client application is designed to be a singleton (it owns an HTTP stack
    /// and metadata cache), unlike the original code which rebuilt it on every request.
    /// </summary>
    public sealed class MsalOidcClient : IOidcClient
    {
        private readonly AuthSettings _settings;
        private readonly IConfidentialClientApplication _app;

        public MsalOidcClient(AuthSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _app = ConfidentialClientApplicationBuilder.Create(settings.ClientId)
                .WithClientSecret(settings.ClientSecret)
                .WithRedirectUri(settings.RedirectUri.AbsoluteUri)
                .WithAuthority(settings.Authority)
                .Build();
        }

        public Uri BuildAuthorizationUri(AuthFlowState flow)
        {
            if (flow == null) throw new ArgumentNullException(nameof(flow));

            var query = string.Join("&", new[]
            {
                "client_id=" + Uri.EscapeDataString(_settings.ClientId),
                "response_type=code",
                "redirect_uri=" + Uri.EscapeDataString(_settings.RedirectUri.AbsoluteUri),
                "response_mode=query",
                "scope=" + Uri.EscapeDataString(string.Join(" ", _settings.Scopes)),
                "state=" + Uri.EscapeDataString(flow.State),
                "nonce=" + Uri.EscapeDataString(flow.Nonce),
                "code_challenge=" + Uri.EscapeDataString(flow.CodeChallenge),
                "code_challenge_method=S256"
            });

            return new Uri(_settings.Authority + "/oauth2/v2.0/authorize?" + query);
        }

        public async Task<string> RedeemAuthorizationCodeAsync(string code, string codeVerifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(code)) throw new ArgumentException("Authorization code is required.", nameof(code));
            if (string.IsNullOrEmpty(codeVerifier)) throw new ArgumentException("PKCE verifier is required.", nameof(codeVerifier));

            var result = await _app
                .AcquireTokenByAuthorizationCode(_settings.Scopes, code)
                .WithPkceCodeVerifier(codeVerifier)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            // We only need the ID token to establish our own session. MSAL keeps an in-memory
            // token cache per account on a long-lived app object, which would grow forever.
            if (result.Account != null)
            {
                try { await _app.RemoveAsync(result.Account).ConfigureAwait(false); }
                catch (MsalException) { /* best effort; never fail a sign-in over cache cleanup */ }
            }

            if (string.IsNullOrEmpty(result.IdToken))
            {
                throw new InvalidOperationException("Entra ID did not return an ID token.");
            }
            return result.IdToken;
        }
    }
}
