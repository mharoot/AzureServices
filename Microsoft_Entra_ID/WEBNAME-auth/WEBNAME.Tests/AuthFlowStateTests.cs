using System;
using WEBNAME.Auth;
using Xunit;

namespace WEBNAME.Tests
{
    public class AuthFlowStateTests
    {
        [Fact]
        public void Create_generates_unique_url_safe_values()
        {
            var a = AuthFlowState.Create();
            var b = AuthFlowState.Create();

            Assert.NotEqual(a.State, b.State);
            Assert.NotEqual(a.Nonce, b.Nonce);
            Assert.NotEqual(a.State, a.Nonce);
            Assert.Equal(43, a.CodeVerifier.Length);
            Assert.Matches("^[A-Za-z0-9_-]+$", a.State + a.Nonce + a.CodeVerifier);
        }

        [Fact]
        public void Code_challenge_matches_the_RFC7636_test_vector()
        {
            var flow = new AuthFlowState(
                "state-state-state-1", "nonce-nonce-nonce-1",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

            Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", flow.CodeChallenge);
        }

        [Fact]
        public void Serialize_then_TryParse_round_trips()
        {
            var original = AuthFlowState.Create();

            Assert.True(AuthFlowState.TryParse(original.Serialize(), out var parsed));
            Assert.Equal(original.State, parsed.State);
            Assert.Equal(original.Nonce, parsed.Nonce);
            Assert.Equal(original.CodeVerifier, parsed.CodeVerifier);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("only.two")]
        [InlineData("a.b.c.d")]
        [InlineData("short.short.short")]
        [InlineData("aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccc!ccccccccccccc")]
        public void TryParse_rejects_malformed_values(string value)
        {
            Assert.False(AuthFlowState.TryParse(value, out var flow));
            Assert.Null(flow);
        }

        [Fact]
        public void StateMatches_is_exact()
        {
            var flow = AuthFlowState.Create();

            Assert.True(flow.StateMatches(flow.State));
            Assert.False(flow.StateMatches(flow.State + "x"));
            Assert.False(flow.StateMatches(flow.State.Substring(1)));
            Assert.False(flow.StateMatches(flow.Nonce));
            Assert.False(flow.StateMatches(null));
            Assert.False(flow.StateMatches(""));
        }

        [Fact]
        public void Constructor_rejects_weak_values()
        {
            Assert.Throws<ArgumentException>(() => new AuthFlowState("short", "nonce-nonce-nonce-1", "verifier-verifier-1"));
            Assert.Throws<ArgumentException>(() => new AuthFlowState(null, "nonce-nonce-nonce-1", "verifier-verifier-1"));
        }

        [Fact]
        public void FlowCookie_has_required_security_attributes()
        {
            var flow = AuthFlowState.Create();

            var set = FlowCookie.BuildSetCookie(flow);
            Assert.StartsWith("__Host-oidc-flow=" + flow.Serialize(), set);
            Assert.Contains("Secure", set);
            Assert.Contains("HttpOnly", set);
            Assert.Contains("SameSite=Lax", set);
            Assert.Contains("Path=/", set);
            Assert.DoesNotContain("Domain=", set);

            Assert.Contains("Max-Age=0", FlowCookie.BuildExpire());
        }
    }
}
