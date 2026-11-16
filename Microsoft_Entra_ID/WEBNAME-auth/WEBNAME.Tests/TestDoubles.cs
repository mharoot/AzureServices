using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using WEBNAME.Auth;

namespace WEBNAME.Tests
{
    internal static class TestData
    {
        public const string ClientId = "11111111-1111-1111-1111-111111111111";
        public const string TenantId = "22222222-2222-2222-2222-222222222222";

        public static AuthSettings Settings() => new AuthSettings(
            ClientId, TenantId, "super-secret",
            "https://webname-dev.com/api/SigninRedirectCallback",
            "https://webname-dev.com/index.aspx");

        public static ClaimsPrincipal Principal(params Claim[] claims) =>
            new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    internal sealed class FakeOidcClient : IOidcClient
    {
        public AuthFlowState LastFlow;
        public string RedeemedCode;
        public string RedeemedVerifier;
        public int RedeemCalls;
        public Func<Task<string>> OnRedeem = () => Task.FromResult("raw.id.token");

        public Uri BuildAuthorizationUri(AuthFlowState flow)
        {
            LastFlow = flow;
            return new Uri("https://login.example/authorize?state=" + flow.State);
        }

        public Task<string> RedeemAuthorizationCodeAsync(string code, string codeVerifier, CancellationToken ct)
        {
            RedeemCalls++;
            RedeemedCode = code;
            RedeemedVerifier = codeVerifier;
            return OnRedeem();
        }
    }

    internal sealed class FakeValidator : IIdTokenValidator
    {
        public string ReceivedToken;
        public string ReceivedNonce;
        public Func<ClaimsPrincipal> Result = () => TestData.Principal();

        public Task<ClaimsPrincipal> ValidateAsync(string idToken, string expectedNonce, CancellationToken ct)
        {
            ReceivedToken = idToken;
            ReceivedNonce = expectedNonce;
            return Task.FromResult(Result());
        }
    }

    internal sealed class FakeSessionStore : IUserSessionStore
    {
        public readonly List<AuthenticatedUser> Users = new List<AuthenticatedUser>();
        public void SignIn(AuthenticatedUser user) => Users.Add(user);
    }

    internal sealed class FakeLogger : IAuthLogger
    {
        public readonly List<string> Lines = new List<string>();
        public void Info(string message) => Lines.Add("INFO " + message);
        public void Warn(string message) => Lines.Add("WARN " + message);
        public void Error(string message, Exception exception) => Lines.Add("ERROR " + message);
    }
}
