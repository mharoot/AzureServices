using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using WEBNAME.Auth;
using WEBNAME.Controllers;
using Xunit;

namespace WEBNAME.Tests
{
    public class SigninControllerTests
    {
        [Fact]
        public void Redirects_to_the_identity_provider_and_sets_a_flow_cookie()
        {
            /*
            Unit tests use a fake instead of the real client for these reasons:
              - A real login can’t be automated. Entra ID’s sign-in involves a browser, a password, possibly MFA, and a one-time authorization code. A test runner can’t do any of that.
              - Tests need to be fast and repeatable. A fake runs in microseconds and gives the same result every time. The real service would make tests slow, and they would fail when the network is down or Microsoft has an outage.
              - Tests need to be able to force failures. I can’t make Entra ID return an expired code or a 503 on demand, but the fake can throw any error I choose. That’s how I check the 401, 403 and 500 paths.
              - Tests shouldn’t need real credentials. A real client would need your client secret and tenant in the build pipeline.
              
            The tests prove that your controller logic behaves correctly: 
                it rejects a bad state, creates the session only on success, and never leaks error details. 
            
            They don’t prove that Microsoft accepts your app registration. 
            That needs a manual end-to-end run against your dev tenant, which is how the real client would be exercised.
            */
            var oidc = new FakeOidcClient();
            var controller = new SigninController(oidc) { Request = NewRequest("https://webname-dev.com/api/Signin") };

            var response = controller.Get();

            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.StartsWith("https://login.example/authorize", response.Headers.Location.AbsoluteUri);

            var setCookie = response.Headers.GetValues("Set-Cookie").Single();
            Assert.Contains(oidc.LastFlow.Serialize(), setCookie);
            Assert.Contains("HttpOnly", setCookie);
            Assert.Contains("Secure", setCookie);
            Assert.Contains("SameSite=Lax", setCookie);
            Assert.True(response.Headers.CacheControl.NoStore);
        }

        [Fact]
        public void Each_call_creates_a_fresh_flow()
        {
            var oidc = new FakeOidcClient();
            var controller = new SigninController(oidc) { Request = NewRequest("https://webname-dev.com/api/Signin") };

            controller.Get();
            var first = oidc.LastFlow;
            controller.Get();

            Assert.NotEqual(first.State, oidc.LastFlow.State);
        }

        private static HttpRequestMessage NewRequest(string url)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.SetConfiguration(new HttpConfiguration());
            return request;
        }
    }

    public class SigninRedirectCallbackControllerTests
    {
        private readonly FakeOidcClient _oidc = new FakeOidcClient();
        private readonly FakeValidator _validator = new FakeValidator();
        private readonly FakeSessionStore _session = new FakeSessionStore();
        private readonly FakeLogger _log = new FakeLogger();
        private readonly AuthFlowState _flow = AuthFlowState.Create();

        private SigninRedirectCallbackController NewController(bool withCookie = true, string cookieValue = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://webname-dev.com/api/SigninRedirectCallback");
            request.SetConfiguration(new HttpConfiguration());
            if (withCookie)
            {
                request.Headers.Add("Cookie", AuthFlowState.CookieName + "=" + (cookieValue ?? _flow.Serialize()));
            }

            return new SigninRedirectCallbackController(TestData.Settings(), _oidc, _validator, _session, _log)
            {
                Request = request
            };
        }

        private void GivenIdTokenClaims(params Claim[] claims) => _validator.Result = () => TestData.Principal(claims);

        [Fact]
        public async Task Happy_path_creates_session_and_redirects_to_configured_page()
        {
            GivenIdTokenClaims(
                new Claim("email", "jane@contoso.com"), new Claim("name", "Jane D"),
                new Claim("given_name", "Jane"), new Claim("family_name", "Doe"),
                new Claim("oid", "oid-123"), new Claim("tid", TestData.TenantId));

            var response = await NewController().Get("auth-code", _flow.State);

            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Equal("https://webname-dev.com/index.aspx", response.Headers.Location.AbsoluteUri);

            var user = Assert.Single(_session.Users);
            Assert.Equal("jane@contoso.com", user.Email);
            Assert.Equal("Jane D", user.Name);
            Assert.Equal("Jane Doe", user.DisplayName);
            Assert.Equal("oid-123", user.ObjectId);

            // PKCE verifier and nonce from the cookie reach the right collaborators.
            Assert.Equal("auth-code", _oidc.RedeemedCode);
            Assert.Equal(_flow.CodeVerifier, _oidc.RedeemedVerifier);
            Assert.Equal("raw.id.token", _validator.ReceivedToken);
            Assert.Equal(_flow.Nonce, _validator.ReceivedNonce);
        }

        [Fact]
        public async Task Every_outcome_expires_the_flow_cookie_and_disables_caching()
        {
            GivenIdTokenClaims(new Claim("email", "jane@contoso.com"));

            var ok = await NewController().Get("c", _flow.State);
            var bad = await NewController().Get(null, null);

            foreach (var r in new[] { ok, bad })
            {
                Assert.Contains("Max-Age=0", r.Headers.GetValues("Set-Cookie").Single());
                Assert.True(r.Headers.CacheControl.NoStore);
            }
        }

        [Fact]
        public async Task Falls_back_to_preferred_username_when_email_claim_is_absent()
        {
            GivenIdTokenClaims(new Claim("preferred_username", "jane@contoso.com"), new Claim("name", "Jane D"));

            await NewController().Get("c", _flow.State);

            var user = Assert.Single(_session.Users);
            Assert.Equal("jane@contoso.com", user.Email);
            Assert.Equal("Jane D", user.DisplayName); // no given/family -> name, not " "
        }

        [Fact]
        public async Task Display_name_falls_back_to_email_when_no_name_claims()
        {
            GivenIdTokenClaims(new Claim("email", "jane@contoso.com"));

            await NewController().Get("c", _flow.State);

            Assert.Equal("jane@contoso.com", Assert.Single(_session.Users).DisplayName);
        }

        [Fact]
        public async Task Token_without_any_email_is_forbidden_and_creates_no_session()
        {
            GivenIdTokenClaims(new Claim("name", "No Email"));

            var response = await NewController().Get("c", _flow.State);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(_session.Users);
        }

        [Theory]
        [InlineData(null, "state")]
        [InlineData("", "state")]
        [InlineData("code", null)]
        [InlineData("code", "")]
        public async Task Missing_code_or_state_is_a_bad_request(string code, string state)
        {
            var response = await NewController().Get(code, state);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0, _oidc.RedeemCalls);
        }

        [Fact]
        public async Task Missing_flow_cookie_is_rejected_before_redeeming_the_code()
        {
            var response = await NewController(withCookie: false).Get("code", _flow.State);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0, _oidc.RedeemCalls);
            Assert.Empty(_session.Users);
        }

        [Fact]
        public async Task State_mismatch_is_rejected_before_redeeming_the_code()
        {
            var response = await NewController().Get("code", AuthFlowState.Create().State);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0, _oidc.RedeemCalls);
            Assert.Empty(_session.Users);
        }

        [Fact]
        public async Task Tampered_cookie_is_rejected()
        {
            var response = await NewController(cookieValue: "garbage").Get("code", _flow.State);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0, _oidc.RedeemCalls);
        }

        [Fact]
        public async Task Provider_error_returns_401_and_logs_a_sanitized_description()
        {
            var response = await NewController().Get(
                error: "access_denied", error_description: "user\r\nINFO forged log line");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(0, _oidc.RedeemCalls);
            var line = Assert.Single(_log.Lines);
            Assert.DoesNotContain("\r", line);
            Assert.DoesNotContain("\n", line);
        }

        [Fact]
        public async Task Invalid_token_is_401_and_creates_no_session()
        {
            _validator.Result = () => throw new SecurityTokenException("bad signature");

            var response = await NewController().Get("code", _flow.State);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(_session.Users);
        }

        [Fact]
        public async Task Reused_or_expired_code_is_a_401()
        {
            _oidc.OnRedeem = () => throw new MsalServiceException("invalid_grant", "AADSTS70008: code expired");

            var response = await NewController().Get("code", _flow.State);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(_session.Users);
        }

        [Fact]
        public async Task Unexpected_errors_return_500_without_leaking_details()
        {
            _oidc.OnRedeem = () => throw new InvalidOperationException("secret connection string xyz");

            var response = await NewController().Get("code", _flow.State);
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.DoesNotContain("secret connection string", body);
            Assert.Contains("ref ", body); // support reference present
            Assert.Contains(_log.Lines, l => l.StartsWith("ERROR"));
        }

        [Fact]
        public async Task Session_failure_is_a_500_not_a_leaked_NullReferenceException()
        {
            GivenIdTokenClaims(new Claim("email", "jane@contoso.com"));
            var controller = new SigninRedirectCallbackController(
                TestData.Settings(), _oidc, _validator, new ThrowingSessionStore(), _log)
            {
                Request = NewController().Request
            };

            var response = await controller.Get("code", _flow.State);
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.DoesNotContain("NullReference", body);
        }

        [Fact]
        public void HttpSessionUserStore_fails_clearly_when_session_is_unavailable()
        {
            // No HttpContext in a unit test == the "session not enabled" situation.
            var ex = Assert.Throws<InvalidOperationException>(
                () => new HttpSessionUserStore().SignIn(new AuthenticatedUser()));
            Assert.Contains("session", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        private sealed class ThrowingSessionStore : IUserSessionStore
        {
            public void SignIn(AuthenticatedUser user) => throw new InvalidOperationException("session unavailable");
        }
    }

    public class MsalOidcClientTests
    {
        [Fact]
        public void Authorization_url_contains_state_nonce_pkce_and_exact_redirect_uri()
        {
            var settings = TestData.Settings();
            var client = new MsalOidcClient(settings);
            var flow = AuthFlowState.Create();

            var uri = client.BuildAuthorizationUri(flow);
            var query = uri.Query;

            Assert.StartsWith(settings.Authority + "/oauth2/v2.0/authorize", uri.AbsoluteUri);
            Assert.Contains("client_id=" + TestData.ClientId, query);
            Assert.Contains("response_type=code", query);
            Assert.Contains("state=" + flow.State, query);
            Assert.Contains("nonce=" + flow.Nonce, query);
            Assert.Contains("code_challenge=" + flow.CodeChallenge, query);
            Assert.Contains("code_challenge_method=S256", query);
            Assert.Contains("scope=openid%20profile%20email", query);
            Assert.Contains("redirect_uri=" + Uri.EscapeDataString(settings.RedirectUri.AbsoluteUri), query);
            Assert.DoesNotContain(flow.CodeVerifier, uri.AbsoluteUri); // verifier must never be sent on the front channel
            Assert.DoesNotContain("super-secret", uri.AbsoluteUri);
        }
    }
}
