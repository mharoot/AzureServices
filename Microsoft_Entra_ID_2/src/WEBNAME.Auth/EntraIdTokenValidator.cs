using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Validates an Entra ID token as OpenID Connect Core 1.0 section 3.1.3.7 requires: signature
    /// with the tenant's published keys (RS256 only), issuer, audience, lifetime, required claims
    /// and nonce. Thread-safe; share one instance with the client.
    /// </summary>
    public sealed class EntraIdTokenValidator
    {
        // oid + tid identify the user; OIDC requires sub, iat and (when sent) nonce.
        private static readonly string[] RequiredClaims = { "sub", "oid", "tid", "iat", "nonce" };

        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly string _clientId;
        private readonly TimeSpan _clockSkew;
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        /// <summary>Creates a validator that reads issuer and signing keys from the tenant's discovery document.</summary>
        public EntraIdTokenValidator(IConfigurationManager<OpenIdConnectConfiguration> configurationManager, string clientId, TimeSpan clockSkew)
        {
            _configurationManager = configurationManager ?? throw new ArgumentNullException(nameof(configurationManager));
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentException("The client ID is required.", nameof(clientId));
            }

            _clientId = clientId;
            _clockSkew = clockSkew;
        }

        /// <summary>
        /// Returns the token's claims, or throws <see cref="IdTokenValidationException"/> if any
        /// check fails.
        /// </summary>
        public async Task<ClaimsIdentity> ValidateAsync(string idToken, string expectedNonce, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(expectedNonce))
            {
                throw new ArgumentException("The expected nonce is required.", nameof(expectedNonce));
            }

            if (string.IsNullOrEmpty(idToken))
            {
                throw new IdTokenValidationException("The token response contained no ID token.");
            }

            var result = await ValidateWithCurrentKeysAsync(idToken, cancellationToken).ConfigureAwait(false);
            if (!result.IsValid)
            {
                if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                {
                    // The token names a key the cached discovery document doesn't have, as happens after
                    // Entra ID rotates keys. Ask for a refresh (rate-limited by the configuration
                    // manager) so the next sign-in can validate; this one fails, as in ASP.NET Core.
                    _configurationManager.RequestRefresh();
                }

                // IdentityModel hides token contents in these exception messages unless
                // IdentityModelEventSource.ShowPII is on. Keep it off in production.
                throw new IdTokenValidationException("The ID token failed signature, issuer, audience or lifetime validation.", result.Exception);
            }

            var token = (JsonWebToken)result.SecurityToken;

            // Steps 3 and 4: Entra ID tokens have exactly one audience, this client (checked above).
            // A second audience, or an azp naming another client, means the token wasn't issued for this sign-in.
            if (token.Audiences.Count() != 1)
            {
                throw new IdTokenValidationException("The ID token must have exactly one audience.");
            }

            if (token.TryGetPayloadValue("azp", out string authorizedParty) && !string.Equals(authorizedParty, _clientId, StringComparison.Ordinal))
            {
                throw new IdTokenValidationException("The ID token was issued to another client.");
            }

            foreach (var claimType in RequiredClaims)
            {
                if (!token.TryGetClaim(claimType, out var claim) || string.IsNullOrWhiteSpace(claim.Value))
                {
                    throw new IdTokenValidationException("The ID token is missing the required claim '" + claimType + "'.");
                }
            }

            // Step 11: the nonce must match the one sent in this sign-in attempt, so an ID token
            // captured from another sign-in can't be replayed.
            if (!SecureCompare.FixedTimeEquals(token.GetClaim("nonce").Value, expectedNonce))
            {
                throw new IdTokenValidationException("The ID token nonce doesn't match this sign-in attempt.");
            }

            return result.ClaimsIdentity;
        }

        private async Task<TokenValidationResult> ValidateWithCurrentKeysAsync(string idToken, CancellationToken cancellationToken)
        {
            var configuration = await _configurationManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(configuration.Issuer) || configuration.Issuer.IndexOf("{tenantid}", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                throw new InvalidOperationException("The discovery document must name one tenant's issuer. Multi-tenant authorities aren't supported.");
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = configuration.Issuer,
                ValidAudience = _clientId,
                IssuerSigningKeys = configuration.SigningKeys,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ClockSkew = _clockSkew,
                NameClaimType = "name",
                RoleClaimType = "roles",
            };

            return await _handler.ValidateTokenAsync(idToken, parameters).ConfigureAwait(false);
        }
    }

    /// <summary>An ID token failed validation. Treat the sign-in as failed.</summary>
    public sealed class IdTokenValidationException : Exception
    {
        /// <summary>Creates the exception. The message must not contain token contents.</summary>
        public IdTokenValidationException(string message, Exception innerException = null)
            : base(message, innerException)
        {
        }
    }
}