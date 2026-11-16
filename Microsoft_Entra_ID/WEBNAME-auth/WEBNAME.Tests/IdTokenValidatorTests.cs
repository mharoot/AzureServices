using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using WEBNAME.Auth;
using Xunit;

namespace WEBNAME.Tests
{
    public sealed class IdTokenValidatorTests : IDisposable
    {
        private const string Issuer = "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0";
        private const string Nonce = "nonce-nonce-nonce-1234";

        private readonly RSA _signingRsa = RSA.Create(2048);
        private readonly RSA _otherRsa = RSA.Create(2048);
        private readonly RsaSecurityKey _signingKey;
        private readonly FakeConfigManager _config;
        private readonly IdTokenValidator _validator;

        public IdTokenValidatorTests()
        {
            _signingKey = new RsaSecurityKey(_signingRsa) { KeyId = "kid-1" };
            var oidc = new OpenIdConnectConfiguration { Issuer = Issuer };
            oidc.SigningKeys.Add(_signingKey);
            _config = new FakeConfigManager(oidc);
            _validator = new IdTokenValidator(_config, TestData.ClientId);
        }

        public void Dispose()
        {
            _signingRsa.Dispose();
            _otherRsa.Dispose();
        }

        [Fact]
        public async Task Accepts_a_valid_token_and_keeps_raw_claim_names()
        {
            var token = CreateToken(extraClaims: new[] { new Claim("email", "a@b.com"), new Claim("oid", "oid-1") });

            var principal = await _validator.ValidateAsync(token, Nonce, CancellationToken.None);

            Assert.Equal("a@b.com", principal.FindFirst("email")?.Value);
            Assert.Equal("oid-1", principal.FindFirst("oid")?.Value);
        }

        [Fact]
        public async Task Rejects_wrong_nonce()
        {
            var token = CreateToken();
            await Assert.ThrowsAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, "a-different-nonce-1234", CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_token_without_nonce()
        {
            var token = CreateToken(nonce: null);
            await Assert.ThrowsAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_wrong_audience()
        {
            var token = CreateToken(audience: "someone-elses-client-id");
            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_wrong_issuer()
        {
            var token = CreateToken(issuer: "https://login.microsoftonline.com/other-tenant/v2.0");
            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_expired_token()
        {
            var token = CreateToken(notBefore: DateTime.UtcNow.AddHours(-2), expires: DateTime.UtcNow.AddHours(-1));
            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_token_signed_with_an_unknown_key()
        {
            var attacker = new RsaSecurityKey(_otherRsa) { KeyId = "kid-1" }; // same kid, different key
            var token = CreateToken(signingKey: attacker);

            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Rejects_unsigned_token()
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = new JwtSecurityToken(Issuer, TestData.ClientId,
                new[] { new Claim("nonce", Nonce) }, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(30));
            var unsigned = handler.WriteToken(jwt);

            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(unsigned, Nonce, CancellationToken.None));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not-a-jwt")]
        [InlineData("a.b.c")]
        public async Task Rejects_missing_or_malformed_token(string token)
        {
            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
        }

        [Fact]
        public async Task Unknown_signing_key_triggers_a_metadata_refresh()
        {
            var attacker = new RsaSecurityKey(_otherRsa) { KeyId = "rolled-key" };
            var token = CreateToken(signingKey: attacker);

            await Assert.ThrowsAnyAsync<SecurityTokenException>(
                () => _validator.ValidateAsync(token, Nonce, CancellationToken.None));
            Assert.True(_config.RefreshRequested);
        }

        private string CreateToken(
            string issuer = Issuer,
            string audience = TestData.ClientId,
            string nonce = Nonce,
            DateTime? notBefore = null,
            DateTime? expires = null,
            SecurityKey signingKey = null,
            IEnumerable<Claim> extraClaims = null)
        {
            var claims = new List<Claim>();
            if (nonce != null) claims.Add(new Claim("nonce", nonce));
            if (extraClaims != null) claims.AddRange(extraClaims);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Subject = new ClaimsIdentity(claims),
                NotBefore = notBefore ?? DateTime.UtcNow.AddMinutes(-1),
                Expires = expires ?? DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(signingKey ?? _signingKey, SecurityAlgorithms.RsaSha256)
            };
            return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
        }

        private sealed class FakeConfigManager : IConfigurationManager<OpenIdConnectConfiguration>
        {
            private readonly OpenIdConnectConfiguration _config;
            public bool RefreshRequested;

            public FakeConfigManager(OpenIdConnectConfiguration config) { _config = config; }

            public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) =>
                Task.FromResult(_config);

            public void RequestRefresh() { RefreshRequested = true; }
        }
    }
}
