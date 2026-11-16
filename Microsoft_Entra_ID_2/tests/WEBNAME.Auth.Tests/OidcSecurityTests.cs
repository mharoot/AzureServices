using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace WEBNAME.Auth.Tests
{
    /// <summary>
    /// Security tests for the sign-in flow. Entra ID is simulated: a local RSA key signs the test
    /// ID tokens and a fake HTTP handler plays the token endpoint, so no network is needed.
    /// </summary>
    public sealed class OidcSecurityTests
    {
        private const string TenantId = "11111111-1111-1111-1111-111111111111";
        private const string ClientId = "22222222-2222-2222-2222-222222222222";
        private const string ObjectId = "33333333-3333-3333-3333-333333333333";
        private const string OtherClientId = "44444444-4444-4444-4444-444444444444";
        private const string Authority = "https://login.microsoftonline.com/" + TenantId;
        private const string Issuer = Authority + "/v2.0";
        private const string AuthorizationEndpoint = Authority + "/oauth2/v2.0/authorize";
        private const string Nonce = "nonce-sent-with-this-sign-in";

        private static readonly RsaSecurityKey TenantKey = NewRsaKey("tenant-key");
        private static readonly RsaSecurityKey OtherKey = NewRsaKey("other-key");

        private readonly IConfigurationManager<OpenIdConnectConfiguration> _discovery =
            new StaticConfigurationManager<OpenIdConnectConfiguration>(Discovery(TenantKey));

        // ---------- PKCE and the per-attempt flow state ----------

        [Fact]
        public void S256Challenge_MatchesRfc7636TestVector()
        {
            // RFC 7636 Appendix B.
            Assert.Equal(
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                AuthFlowState.ComputeS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        }

        [Fact]
        public void NewFlow_HasFreshUrlSafeValues()
        {
            var first = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var second = AuthFlowState.Create(DateTimeOffset.UtcNow);

            Assert.Matches("^[A-Za-z0-9_-]{43}$", first.State);
            Assert.Matches("^[A-Za-z0-9_-]{43}$", first.Nonce);
            Assert.Matches("^[A-Za-z0-9_-]{43}$", first.CodeVerifier);
            Assert.NotEqual(first.State, second.State);
            Assert.NotEqual(first.Nonce, second.Nonce);
            Assert.NotEqual(first.CodeVerifier, second.CodeVerifier);
            Assert.Equal(AuthFlowState.ComputeS256Challenge(first.CodeVerifier), first.CodeChallenge);
        }

        [Fact]
        public void StoredFlow_WithMalformedValues_IsRejected()
        {
            var valid = AuthFlowState.Create(DateTimeOffset.UtcNow);

            Assert.Throws<ArgumentException>(() => new AuthFlowState("too-short", valid.Nonce, valid.CodeVerifier, valid.CreatedUtc));
            Assert.Throws<ArgumentException>(() => new AuthFlowState(valid.State, null, valid.CodeVerifier, valid.CreatedUtc));
            Assert.Throws<ArgumentException>(() => new AuthFlowState(valid.State, valid.Nonce, valid.CodeVerifier + "+/=", valid.CreatedUtc));
        }

        [Fact]
        public void Flow_ExpiresAfterItsLifetime_AndRejectsFutureTimestamps()
        {
            var now = DateTimeOffset.UtcNow;
            var lifetime = TimeSpan.FromMinutes(15);
            var flow = AuthFlowState.Create(now);

            Assert.False(flow.IsExpired(now.AddMinutes(14), lifetime));
            Assert.True(flow.IsExpired(now.AddMinutes(15), lifetime));
            Assert.True(AuthFlowState.Create(now.AddMinutes(10)).IsExpired(now, lifetime));
        }

        // ---------- Settings checked at startup ----------

        [Fact]
        public void Settings_RejectMultiTenantAuthority()
        {
            var settings = NewSettings();
            settings.Authority = "https://login.microsoftonline.com/common";

            Assert.Throws<InvalidOperationException>(() => settings.Validate());
        }

        [Fact]
        public void Settings_RequireHttpsRedirect_ExceptOnLocalhost()
        {
            var settings = NewSettings();
            settings.RedirectUri = new Uri("http://app.example.com/signin-oidc");
            Assert.Throws<InvalidOperationException>(() => settings.Validate());

            settings.RedirectUri = new Uri("http://localhost:5000/signin-oidc");
            settings.Validate();
        }

        [Fact]
        public void Settings_RequireOpenIdScope()
        {
            var settings = NewSettings();
            settings.Scopes = new[] { "profile", "email" };

            Assert.Throws<InvalidOperationException>(() => settings.Validate());
        }

        [Fact]
        public void Settings_RequireExactlyOneCredential()
        {
            var none = NewSettings();
            none.ClientSecret = null;
            Assert.Throws<InvalidOperationException>(() => none.Validate());

            using (var certificate = NewCertificate())
            {
                var both = NewSettings();
                both.ClientCertificate = certificate;
                Assert.Throws<InvalidOperationException>(() => both.Validate());
            }
        }

        [Fact]
        public void Client_AcceptsCertificateCredential()
        {
            using (var certificate = NewCertificate())
            {
                var settings = NewSettings();
                settings.ClientSecret = null;
                settings.ClientCertificate = certificate;

                Assert.NotNull(new MsalOidcClient(settings, _discovery, new FakeEntra(), null));
            }
        }

        // ---------- ID token validation (OpenID Connect Core 1.0, section 3.1.3.7) ----------

        [Fact]
        public async Task ValidIdToken_IsAccepted()
        {
            var identity = await Validator().ValidateAsync(CreateIdToken(Nonce), Nonce, CancellationToken.None);

            Assert.Equal(ObjectId, identity.FindFirst("oid").Value);
            Assert.Equal(TenantId, identity.FindFirst("tid").Value);
        }

        [Fact]
        public Task IdToken_WithAnotherSignInsNonce_IsRejected() =>
            AssertRejectedAsync(CreateIdToken("nonce-from-another-sign-in"));

        [Fact]
        public Task IdToken_ForAnotherClient_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.Audience = OtherClientId));

        [Fact]
        public Task IdToken_WithExtraAudience_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d =>
            {
                d.Audience = null;
                d.Claims["aud"] = new[] { ClientId, "api://another-app" };
            }));

        [Fact]
        public Task IdToken_AuthorizedForAnotherParty_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.Claims["azp"] = OtherClientId));

        [Fact]
        public Task IdToken_FromAnotherTenant_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.Issuer = "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"));

        [Fact]
        public Task ExpiredIdToken_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d =>
            {
                d.IssuedAt = DateTime.UtcNow.AddHours(-2);
                d.NotBefore = DateTime.UtcNow.AddHours(-2);
                d.Expires = DateTime.UtcNow.AddHours(-1);
            }));

        [Fact]
        public Task IdToken_SignedWithUnknownKey_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.SigningCredentials = new SigningCredentials(OtherKey, SecurityAlgorithms.RsaSha256)));

        [Fact]
        public Task UnsignedIdToken_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.SigningCredentials = null));

        [Fact]
        public Task IdToken_SignedWithSharedSecret_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('k', 64))), SecurityAlgorithms.HmacSha256)));

        [Fact]
        public Task IdToken_WithoutObjectId_IsRejected() =>
            AssertRejectedAsync(CreateIdToken(Nonce, d => d.Claims.Remove("oid")));

        [Fact]
        public async Task UnknownSigningKey_RequestsRefresh_SoTheNextSignInValidates()
        {
            var discovery = new RotatingDiscovery(Discovery(TenantKey), Discovery(OtherKey));
            var validator = new EntraIdTokenValidator(discovery, ClientId, TimeSpan.FromMinutes(2));
            var token = CreateIdToken(Nonce, d => d.SigningCredentials = new SigningCredentials(OtherKey, SecurityAlgorithms.RsaSha256));

            await Assert.ThrowsAsync<IdTokenValidationException>(() => validator.ValidateAsync(token, Nonce, CancellationToken.None));
            var identity = await validator.ValidateAsync(token, Nonce, CancellationToken.None);

            Assert.Equal(1, discovery.Refreshes);
            Assert.Equal(ObjectId, identity.FindFirst("oid").Value);
        }

        // ---------- The full flow through MsalOidcClient ----------

        [Fact]
        public async Task AuthorizationUri_UsesDiscoveryEndpointWithPkceStateAndNonce()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);

            var uri = await NewClient(new FakeEntra()).BuildAuthorizationUriAsync(flow, CancellationToken.None);

            Assert.StartsWith(AuthorizationEndpoint + "?", uri.AbsoluteUri);
            var query = ParseQuery(uri.Query);
            Assert.Equal(ClientId, query["client_id"]);
            Assert.Equal("code", query["response_type"]);
            Assert.Equal("openid profile", query["scope"]);
            Assert.Equal(flow.State, query["state"]);
            Assert.Equal(flow.Nonce, query["nonce"]);
            Assert.Equal(flow.CodeChallenge, query["code_challenge"]);
            Assert.Equal("S256", query["code_challenge_method"]);
            Assert.False(query.ContainsKey("code_verifier"));
        }

        [Fact]
        public async Task CompleteSignIn_RedeemsCodeWithVerifier_AndReturnsValidatedUser()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var entra = new FakeEntra { IssuedIdToken = CreateIdToken(flow.Nonce) };

            var user = await NewClient(entra).CompleteSignInAsync(Callback(flow), flow, CancellationToken.None);

            Assert.Equal(TenantId, user.TenantId);
            Assert.Equal(ObjectId, user.ObjectId);
            var body = entra.TokenRequests.Single();
            Assert.Contains("grant_type=authorization_code", body);
            Assert.Contains("code=test-authorization-code", body);
            Assert.Contains("code_verifier=" + flow.CodeVerifier, body);
        }

        [Fact]
        public async Task CompleteSignIn_LeavesNoTokensInMsalCache()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var client = NewClient(new FakeEntra { IssuedIdToken = CreateIdToken(flow.Nonce) });

            await client.CompleteSignInAsync(Callback(flow), flow, CancellationToken.None);

            // White-box check: read MSAL's user token cache through the client's private field.
            var app = (IConfidentialClientApplication)typeof(MsalOidcClient)
                .GetField("_app", BindingFlags.NonPublic | BindingFlags.Instance)
                .GetValue(client);
            var cache = Encoding.UTF8.GetString(((ITokenCacheSerializer)app.UserTokenCache).SerializeMsalV3());
            Assert.DoesNotContain("test-access-token", cache);
            Assert.DoesNotContain("test-refresh-token", cache);
        }

        [Fact]
        public async Task CompleteSignIn_WithForgedOrMissingState_IsRefusedBeforeCallingEntra()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var entra = new FakeEntra { IssuedIdToken = CreateIdToken(flow.Nonce) };
            var client = NewClient(entra);
            var forged = new AuthorizationResponse("test-authorization-code", AuthFlowState.Create(DateTimeOffset.UtcNow).State, null, null);

            await AssertRefusedAsync(OidcSignInFailure.InvalidState, () => client.CompleteSignInAsync(forged, flow, CancellationToken.None));
            await AssertRefusedAsync(OidcSignInFailure.InvalidState, () => client.CompleteSignInAsync(Callback(flow), null, CancellationToken.None));
            Assert.Empty(entra.TokenRequests);
        }

        [Fact]
        public Task CompleteSignIn_WithExpiredFlow_IsRefused()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow.AddHours(-1));

            return AssertRefusedAsync(OidcSignInFailure.Expired, () => NewClient(new FakeEntra()).CompleteSignInAsync(Callback(flow), flow, CancellationToken.None));
        }

        [Fact]
        public Task CompleteSignIn_WithAuthorizationError_IsRefused()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var denied = new AuthorizationResponse(null, flow.State, "access_denied", "AADSTS65004: User declined to consent.\r\nForged log line");

            return AssertRefusedAsync(OidcSignInFailure.AuthorizationError, () => NewClient(new FakeEntra()).CompleteSignInAsync(denied, flow, CancellationToken.None));
        }

        [Fact]
        public Task CompleteSignIn_WhenCodeRedemptionFails_IsRefused()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var entra = new FakeEntra { TokenError = "invalid_grant" };

            return AssertRefusedAsync(OidcSignInFailure.CodeRedemptionFailed, () => NewClient(entra).CompleteSignInAsync(Callback(flow), flow, CancellationToken.None));
        }

        [Fact]
        public Task CompleteSignIn_WhenIdTokenBelongsToAnotherSignIn_IsRefused()
        {
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var entra = new FakeEntra { IssuedIdToken = CreateIdToken(AuthFlowState.Create(DateTimeOffset.UtcNow).Nonce) };

            return AssertRefusedAsync(OidcSignInFailure.InvalidIdToken, () => NewClient(entra).CompleteSignInAsync(Callback(flow), flow, CancellationToken.None));
        }

        [Fact]
        public async Task CallbackValues_AreLoggedWithoutLineBreaks_AndTheSecretNeverIs()
        {
            var logger = new ListLogger();
            var flow = AuthFlowState.Create(DateTimeOffset.UtcNow);
            var client = new MsalOidcClient(NewSettings(), _discovery, new FakeEntra(), logger);
            var forged = new AuthorizationResponse(null, flow.State, "access_denied", "declined\r\n2026-11-16 INFO Admin signed in\u2028");

            await Assert.ThrowsAsync<OidcSignInException>(() => client.CompleteSignInAsync(forged, flow, CancellationToken.None));

            Assert.Contains(logger.Lines, line => line.Contains("declined  2026-11-16 INFO Admin signed in"));
            Assert.DoesNotContain(logger.Lines, line => line.IndexOfAny(new[] { '\r', '\n', '\u2028' }) >= 0);
            Assert.DoesNotContain(logger.Lines, line => line.Contains("test-only-secret"));
        }

        // ---------- Helpers ----------

        private async Task AssertRejectedAsync(string idToken)
        {
            await Assert.ThrowsAsync<IdTokenValidationException>(() => Validator().ValidateAsync(idToken, Nonce, CancellationToken.None));
        }

        private static async Task AssertRefusedAsync(OidcSignInFailure expected, Func<Task> signIn)
        {
            var refused = await Assert.ThrowsAsync<OidcSignInException>(signIn);
            Assert.Equal(expected, refused.Failure);
        }

        private EntraIdTokenValidator Validator() => new EntraIdTokenValidator(_discovery, ClientId, TimeSpan.FromMinutes(2));

        private MsalOidcClient NewClient(FakeEntra entra) => new MsalOidcClient(NewSettings(), _discovery, entra, null);

        private static AuthorizationResponse Callback(AuthFlowState flow) =>
            new AuthorizationResponse("test-authorization-code", flow.State, null, null);

        private static AuthSettings NewSettings() => new AuthSettings
        {
            ClientId = ClientId,
            Authority = Authority,
            RedirectUri = new Uri("https://app.example.com/signin-oidc"),
            ClientSecret = "test-only-secret",
        };

        private static RsaSecurityKey NewRsaKey(string keyId) => new RsaSecurityKey(RSA.Create(2048)) { KeyId = keyId };

        private static X509Certificate2 NewCertificate()
        {
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=sign-in-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            }
        }

        private static OpenIdConnectConfiguration Discovery(SecurityKey signingKey)
        {
            var configuration = new OpenIdConnectConfiguration { Issuer = Issuer, AuthorizationEndpoint = AuthorizationEndpoint };
            configuration.SigningKeys.Add(signingKey);
            return configuration;
        }

        private static string CreateIdToken(string nonce, Action<SecurityTokenDescriptor> change = null)
        {
            var now = DateTime.UtcNow;
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = ClientId,
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddHours(1),
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = "pairwise-subject-id",
                    ["oid"] = ObjectId,
                    ["tid"] = TenantId,
                    ["name"] = "Test User",
                    ["preferred_username"] = "test.user@contoso.example",
                    ["nonce"] = nonce,
                },
                SigningCredentials = new SigningCredentials(TenantKey, SecurityAlgorithms.RsaSha256),
            };
            change?.Invoke(descriptor);
            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        private static Dictionary<string, string> ParseQuery(string query) =>
            query.TrimStart('?').Split('&')
                .Select(pair => pair.Split(new[] { '=' }, 2))
                .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));

        /// <summary>Plays Entra ID's token endpoint, and instance discovery if MSAL asks for it.</summary>
        private sealed class FakeEntra : HttpMessageHandler, IMsalHttpClientFactory
        {
            private readonly HttpClient _client;

            public FakeEntra()
            {
                _client = new HttpClient(this);
            }

            public string IssuedIdToken { get; set; }

            public string TokenError { get; set; }

            public List<string> TokenRequests { get; } = new List<string>();

            public HttpClient GetHttpClient() => _client;

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var path = request.RequestUri.AbsolutePath;
                if (path.EndsWith("/discovery/instance", StringComparison.Ordinal))
                {
                    return Json(HttpStatusCode.OK,
                        "{\"tenant_discovery_endpoint\":\"" + Issuer + "/.well-known/openid-configuration\",\"api-version\":\"1.1\"," +
                        "\"metadata\":[{\"preferred_network\":\"login.microsoftonline.com\",\"preferred_cache\":\"login.windows.net\"," +
                        "\"aliases\":[\"login.microsoftonline.com\",\"login.windows.net\",\"login.microsoft.com\",\"sts.windows.net\"]}]}");
                }

                if (!path.EndsWith("/oauth2/v2.0/token", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }

                TokenRequests.Add(await request.Content.ReadAsStringAsync().ConfigureAwait(false));
                if (TokenError != null)
                {
                    return Json(HttpStatusCode.BadRequest,
                        "{\"error\":\"" + TokenError + "\",\"error_description\":\"AADSTS54005: The authorization code was already redeemed.\"," +
                        "\"error_codes\":[54005],\"correlation_id\":\"55555555-5555-5555-5555-555555555555\"}");
                }

                var clientInfo = Base64UrlEncoder.Encode("{\"uid\":\"" + ObjectId + "\",\"utid\":\"" + TenantId + "\"}");
                return Json(HttpStatusCode.OK,
                    "{\"token_type\":\"Bearer\",\"scope\":\"openid profile offline_access\",\"expires_in\":3600,\"ext_expires_in\":3600," +
                    "\"access_token\":\"test-access-token\",\"refresh_token\":\"test-refresh-token\"," +
                    "\"id_token\":\"" + IssuedIdToken + "\",\"client_info\":\"" + clientInfo + "\"}");
            }

            private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
                new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }

        /// <summary>Records formatted log lines.</summary>
        private sealed class ListLogger : ILogger<MsalOidcClient>
        {
            public List<string> Lines { get; } = new List<string>();

            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter) =>
                Lines.Add(formatter(state, exception));
        }

        /// <summary>Serves the old keys until a refresh is requested, like a cached discovery document during key rotation.</summary>
        private sealed class RotatingDiscovery : IConfigurationManager<OpenIdConnectConfiguration>
        {
            private readonly OpenIdConnectConfiguration _afterRotation;
            private OpenIdConnectConfiguration _current;

            public RotatingDiscovery(OpenIdConnectConfiguration beforeRotation, OpenIdConnectConfiguration afterRotation)
            {
                _current = beforeRotation;
                _afterRotation = afterRotation;
            }

            public int Refreshes { get; private set; }

            public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(_current);

            public void RequestRefresh()
            {
                Refreshes++;
                _current = _afterRotation;
            }
        }
    }
}