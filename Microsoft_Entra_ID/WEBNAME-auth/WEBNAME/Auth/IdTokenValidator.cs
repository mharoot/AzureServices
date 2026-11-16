using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WEBNAME.Auth
{
    public interface IIdTokenValidator
    {
        /// <exception cref="SecurityTokenException">The token is invalid for any reason.</exception>
        Task<ClaimsPrincipal> ValidateAsync(string idToken, string expectedNonce, CancellationToken cancellationToken);
    }

    /// <summary>
    /// Fully validates the ID token (signature, issuer, audience, lifetime, nonce). The original
    /// code only called ReadJwtToken, which parses a JWT without verifying anything.
    /// </summary>
    public sealed class IdTokenValidator : IIdTokenValidator
    {
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
        private readonly string _clientId;
        private readonly TimeSpan _clockSkew;

        public IdTokenValidator(
            IConfigurationManager<OpenIdConnectConfiguration> configManager,
            string clientId,
            TimeSpan? clockSkew = null)
        {
            _configManager = configManager ?? throw new ArgumentNullException(nameof(configManager));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("Client id is required.", nameof(clientId));
            _clientId = clientId;
            _clockSkew = clockSkew ?? TimeSpan.FromMinutes(2);
        }

        /// <summary>Production factory: signing keys are fetched from the tenant's OIDC metadata and cached/refreshed.</summary>
        public static IdTokenValidator Create(AuthSettings settings)
        {
            var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                settings.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
            return new IdTokenValidator(manager, settings.ClientId);
        }

        public async Task<ClaimsPrincipal> ValidateAsync(string idToken, string expectedNonce, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(idToken)) throw new SecurityTokenException("ID token is missing.");
            if (string.IsNullOrEmpty(expectedNonce)) throw new ArgumentException("Expected nonce is required.", nameof(expectedNonce));

            var config = await _configManager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.Issuer,
                ValidateAudience = true,
                ValidAudience = _clientId,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = _clockSkew,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
            };

            // Keep raw claim names ("email", "oid", "tid") instead of the legacy long URIs.
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

            ClaimsPrincipal principal;
            try
            {
                SecurityToken validated;
                principal = handler.ValidateToken(idToken, parameters, out validated);
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                // Probably a signing-key rollover: ask for fresh metadata before the next attempt.
                _configManager.RequestRefresh();
                throw;
            }
            catch (ArgumentException ex)
            {
                throw new SecurityTokenException("ID token is malformed.", ex);
            }

            var nonce = principal.FindFirst("nonce")?.Value;
            if (!CryptoUtil.ConstantTimeEquals(nonce, expectedNonce))
            {
                throw new SecurityTokenException("ID token nonce does not match this sign-in attempt.");
            }

            return principal;
        }
    }
}
