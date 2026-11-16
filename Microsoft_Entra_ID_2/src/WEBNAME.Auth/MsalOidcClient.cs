using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using MsalLogLevel = Microsoft.Identity.Client.LogLevel;

namespace WEBNAME.Auth
{
    /// <summary>Signs users in with the OpenID Connect authorization code flow and PKCE.</summary>
    public interface IOidcClient
    {
        /// <summary>Builds the Entra ID sign-in URL for a new attempt. Redirect the browser to it.</summary>
        Task<Uri> BuildAuthorizationUriAsync(AuthFlowState flow, CancellationToken cancellationToken);

        /// <summary>
        /// Checks the callback, redeems the code and validates the ID token. Remove the stored
        /// flow from the cookie or session before calling, whatever the outcome, so it can't be
        /// used twice. Throws <see cref="OidcSignInException"/> when sign-in must not go ahead;
        /// other exceptions mean the tenant's discovery document couldn't be fetched.
        /// </summary>
        Task<OidcUser> CompleteSignInAsync(AuthorizationResponse response, AuthFlowState storedFlow, CancellationToken cancellationToken);
    }

    /// <summary>The query values Entra ID sends back to the redirect URI.</summary>
    public sealed class AuthorizationResponse
    {
        /// <summary>Wraps the callback's code, state, error and error_description values.</summary>
        public AuthorizationResponse(string code, string state, string error, string errorDescription)
        {
            Code = code;
            State = state;
            Error = error;
            ErrorDescription = errorDescription;
        }

        /// <summary>The authorization code.</summary>
        public string Code { get; }

        /// <summary>The state value echoed back by Entra ID.</summary>
        public string State { get; }

        /// <summary>The OAuth error code, such as access_denied, when sign-in failed.</summary>
        public string Error { get; }

        /// <summary>Entra ID's error description. Log it; never show it to users.</summary>
        public string ErrorDescription { get; }
    }

    /// <summary>
    /// A user whose ID token passed validation. Key accounts on <see cref="TenantId"/> plus
    /// <see cref="ObjectId"/>. Never use <see cref="UserName"/> or an email claim to find an
    /// account or grant access: users and admins can change them.
    /// </summary>
    public sealed class OidcUser
    {
        internal OidcUser(ClaimsIdentity identity)
        {
            Identity = identity;
            TenantId = identity.FindFirst("tid")?.Value;
            ObjectId = identity.FindFirst("oid")?.Value;
            DisplayName = identity.FindFirst("name")?.Value;
            UserName = identity.FindFirst("preferred_username")?.Value;
        }

        /// <summary>The tid claim: the user's tenant.</summary>
        public string TenantId { get; }

        /// <summary>The oid claim: the user's immutable ID in the tenant.</summary>
        public string ObjectId { get; }

        /// <summary>The name claim. For display only.</summary>
        public string DisplayName { get; }

        /// <summary>The preferred_username claim. Mutable and unverified; for display only.</summary>
        public string UserName { get; }

        /// <summary>All validated claims, for building the app's session (roles are in "roles").</summary>
        public ClaimsIdentity Identity { get; }
    }

    /// <summary>Why a sign-in was refused.</summary>
    public enum OidcSignInFailure
    {
        /// <summary>The state was missing or didn't match: a possible CSRF attempt, or the attempt cookie was lost.</summary>
        InvalidState,

        /// <summary>The attempt took longer than <see cref="AuthSettings.FlowLifetime"/>.</summary>
        Expired,

        /// <summary>Entra ID returned an error, for example because the user cancelled.</summary>
        AuthorizationError,

        /// <summary>The callback had no authorization code.</summary>
        MissingCode,

        /// <summary>The token endpoint refused the code, or couldn't be reached.</summary>
        CodeRedemptionFailed,

        /// <summary>The ID token failed validation.</summary>
        InvalidIdToken,
    }

    /// <summary>
    /// Sign-in was refused. Show the user a generic error with a link to start again, and log
    /// <see cref="Failure"/>. Don't show the message to users.
    /// </summary>
    public sealed class OidcSignInException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public OidcSignInException(OidcSignInFailure failure, string message, Exception innerException = null)
            : base(message, innerException)
        {
            Failure = failure;
        }

        /// <summary>Why sign-in was refused.</summary>
        public OidcSignInFailure Failure { get; }
    }

    /// <summary>
    /// Microsoft Entra ID sign-in built on MSAL.NET (code redemption) and Microsoft.IdentityModel
    /// (ID token validation). Register one instance for the life of the app (a singleton): it is
    /// thread-safe and holds the MSAL application and the cached discovery document and keys.
    /// </summary>
    public sealed class MsalOidcClient : IOidcClient
    {
        private readonly AuthSettings _settings;
        private readonly string[] _scopes;
        private readonly IConfidentialClientApplication _app;
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly EntraIdTokenValidator _idTokenValidator;
        private readonly ILogger _logger;

        /// <summary>Creates the client. Throws <see cref="InvalidOperationException"/> if the settings are invalid.</summary>
        public MsalOidcClient(AuthSettings settings, ILogger<MsalOidcClient> logger)
            : this(settings, CreateConfigurationManager(settings), null, logger)
        {
        }

        /// <summary>
        /// Creates the client with your own discovery configuration manager and MSAL HTTP client
        /// factory, for tests or to share them across the app.
        /// </summary>
        public MsalOidcClient(
            AuthSettings settings,
            IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
            IMsalHttpClientFactory httpClientFactory,
            ILogger<MsalOidcClient> logger)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            settings.Validate();
            _settings = settings;
            _scopes = settings.Scopes.ToArray();
            _configurationManager = configurationManager ?? throw new ArgumentNullException(nameof(configurationManager));
            _logger = (ILogger)logger ?? NullLogger.Instance;
            _idTokenValidator = new EntraIdTokenValidator(configurationManager, settings.ClientId, settings.ClockSkew);

            var builder = ConfidentialClientApplicationBuilder.Create(settings.ClientId)
                .WithAuthority(new Uri(settings.Authority))
                .WithRedirectUri(settings.RedirectUri.AbsoluteUri)
                .WithLogging(ForwardMsalLog, MsalLogLevel.Warning, enablePiiLogging: false, enableDefaultPlatformLogging: false);

            if (settings.ClientCertificate != null)
            {
                builder = builder.WithCertificate(settings.ClientCertificate);
            }
            else
            {
                builder = builder.WithClientSecret(settings.ClientSecret);
                _logger.LogWarning("Entra ID sign-in is using a client secret. Use a certificate or a managed identity credential in production.");
            }

            if (httpClientFactory != null)
            {
                builder = builder.WithHttpClientFactory(httpClientFactory);
            }

            _app = builder.Build();

            // Sign-in needs only the ID token, so the user token cache keeps nothing: it starts empty
            // and is cleared again in the same locked cache operation that wrote the tokens. MSAL
            // expects web apps to handle the user cache explicitly like this rather than let one
            // in-memory cache grow with every user.
            _app.UserTokenCache.SetBeforeAccess(KeepNoTokens);
            _app.UserTokenCache.SetAfterAccess(KeepNoTokens);
        }

        /// <inheritdoc />
        public async Task<Uri> BuildAuthorizationUriAsync(AuthFlowState flow, CancellationToken cancellationToken)
        {
            if (flow == null)
            {
                throw new ArgumentNullException(nameof(flow));
            }

            // The endpoint comes from the tenant's discovery document (OpenID Connect Discovery 1.0).
            var configuration = await _configurationManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            if (!Uri.TryCreate(configuration.AuthorizationEndpoint, UriKind.Absolute, out var endpoint)
                || endpoint.Scheme != Uri.UriSchemeHttps
                || endpoint.Query.Length > 0)
            {
                throw new InvalidOperationException("The discovery document has no valid HTTPS authorization endpoint.");
            }

            var parameters = new[]
            {
                new KeyValuePair<string, string>("client_id", _settings.ClientId),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("redirect_uri", _settings.RedirectUri.AbsoluteUri),
                new KeyValuePair<string, string>("response_mode", "query"),
                new KeyValuePair<string, string>("scope", string.Join(" ", _scopes)),
                new KeyValuePair<string, string>("state", flow.State),
                new KeyValuePair<string, string>("nonce", flow.Nonce),
                new KeyValuePair<string, string>("code_challenge", flow.CodeChallenge),
                new KeyValuePair<string, string>("code_challenge_method", "S256"),
            };

            var query = string.Join("&", parameters.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
            return new Uri(endpoint.AbsoluteUri + "?" + query);
        }

        /// <inheritdoc />
        public async Task<OidcUser> CompleteSignInAsync(AuthorizationResponse response, AuthFlowState storedFlow, CancellationToken cancellationToken)
        {
            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            // CSRF protection (RFC 6749 section 10.12, RFC 9700 section 4.7): nothing in the
            // callback is trusted until its state matches the value stored for this browser.
            if (storedFlow == null || !SecureCompare.FixedTimeEquals(response.State, storedFlow.State))
            {
                throw Refuse(OidcSignInFailure.InvalidState, "The state is missing or doesn't match this sign-in attempt.");
            }

            if (storedFlow.IsExpired(DateTimeOffset.UtcNow, _settings.FlowLifetime))
            {
                throw Refuse(OidcSignInFailure.Expired, "The sign-in attempt expired.");
            }

            if (!string.IsNullOrEmpty(response.Error))
            {
                // Callback values are attacker-controlled: log them sanitized, never echo them to users.
                _logger.LogWarning(
                    "Entra ID returned authorization error {Error}: {ErrorDescription}",
                    ForLog(response.Error, 64),
                    ForLog(response.ErrorDescription, 512));
                throw Refuse(OidcSignInFailure.AuthorizationError, "Entra ID returned an authorization error.");
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                throw Refuse(OidcSignInFailure.MissingCode, "The callback contained no authorization code.");
            }

            var result = await RedeemCodeAsync(response.Code, storedFlow.CodeVerifier, cancellationToken).ConfigureAwait(false);

            try
            {
                var identity = await _idTokenValidator.ValidateAsync(result.IdToken, storedFlow.Nonce, cancellationToken).ConfigureAwait(false);
                return new OidcUser(identity);
            }
            catch (IdTokenValidationException ex)
            {
                throw Refuse(OidcSignInFailure.InvalidIdToken, ex.Message, ex, result.CorrelationId.ToString());
            }
        }

        private async Task<AuthenticationResult> RedeemCodeAsync(string code, string codeVerifier, CancellationToken cancellationToken)
        {
            try
            {
                // The PKCE verifier proves this server started the flow (RFC 7636), so an
                // intercepted or injected code is useless on its own.
                return await _app.AcquireTokenByAuthorizationCode(_scopes, code)
                    .WithPkceCodeVerifier(codeVerifier)
                    .ExecuteAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (MsalException ex)
            {
                // invalid_grant usually means the code expired, was already used, or the verifier
                // didn't match. The user should start a new sign-in.
                throw Refuse(OidcSignInFailure.CodeRedemptionFailed, "The authorization code couldn't be redeemed (" + ex.ErrorCode + ").", ex, ex.CorrelationId);
            }
        }

        private static void KeepNoTokens(TokenCacheNotificationArgs args)
        {
            args.TokenCache.DeserializeMsalV3(null, shouldClearExistingCache: true);
        }

        private OidcSignInException Refuse(OidcSignInFailure failure, string reason, Exception innerException = null, string correlationId = null)
        {
            _logger.LogWarning(
                innerException,
                "Sign-in refused ({Failure}): {Reason} Entra ID correlation ID: {CorrelationId}",
                failure,
                reason,
                correlationId ?? "none");
            return new OidcSignInException(failure, reason, innerException);
        }

        private void ForwardMsalLog(MsalLogLevel level, string message, bool containsPii)
        {
            // PII logging is off, so MSAL scrubs its messages; drop anything still flagged as PII.
            if (containsPii)
            {
                return;
            }

            switch (level)
            {
                case MsalLogLevel.Error:
                    _logger.LogError("MSAL: {MsalMessage}", message);
                    break;
                case MsalLogLevel.Warning:
                    _logger.LogWarning("MSAL: {MsalMessage}", message);
                    break;
                default:
                    _logger.LogDebug("MSAL: {MsalMessage}", message);
                    break;
            }
        }

        // Replaces control characters and Unicode line breaks and truncates, so attacker-controlled
        // values can't forge or flood log entries (CWE-117).
        private static string ForLog(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(Math.Min(value.Length, maxLength));
            foreach (var c in value)
            {
                if (builder.Length == maxLength)
                {
                    break;
                }

                builder.Append(char.IsControl(c) || c == '\u2028' || c == '\u2029' ? ' ' : c);
            }

            return builder.ToString();
        }

        private static ConfigurationManager<OpenIdConnectConfiguration> CreateConfigurationManager(AuthSettings settings)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings));
            }

            settings.Validate();

            // Caches the discovery document and signing keys and refreshes them periodically, so
            // Entra ID key rotation needs no redeploy.
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                settings.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
        }
    }
}