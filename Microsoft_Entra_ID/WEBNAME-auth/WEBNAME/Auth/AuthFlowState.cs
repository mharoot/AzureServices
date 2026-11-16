using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Per-login-attempt secrets: <c>state</c> (CSRF), <c>nonce</c> (token replay) and the PKCE
    /// code verifier. Created when sign-in starts, kept in a short-lived HttpOnly cookie, and
    /// checked when Entra ID redirects back.
    /// </summary>
    public sealed class AuthFlowState
    {
        public const string CookieName = "__Host-oidc-flow";

        private static readonly Regex TokenPattern = new Regex(@"^[A-Za-z0-9_\-]{16,128}$", RegexOptions.Compiled);

        public AuthFlowState(string state, string nonce, string codeVerifier)
        {
            State = Validate(state, nameof(state));
            Nonce = Validate(nonce, nameof(nonce));
            CodeVerifier = Validate(codeVerifier, nameof(codeVerifier));
        }

        public string State { get; }
        public string Nonce { get; }
        public string CodeVerifier { get; }

        /// <summary>PKCE S256 challenge (RFC 7636 section 4.2).</summary>
        public string CodeChallenge
        {
            get
            {
                using (var sha = SHA256.Create())
                {
                    return Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(CodeVerifier)));
                }
            }
        }

        public static AuthFlowState Create() => new AuthFlowState(RandomToken(), RandomToken(), RandomToken());

        public string Serialize() => State + "." + Nonce + "." + CodeVerifier;

        public static bool TryParse(string value, out AuthFlowState flow)
        {
            flow = null;
            if (string.IsNullOrEmpty(value)) return false;

            var parts = value.Split('.');
            if (parts.Length != 3) return false;
            foreach (var part in parts)
            {
                if (!TokenPattern.IsMatch(part)) return false;
            }

            flow = new AuthFlowState(parts[0], parts[1], parts[2]);
            return true;
        }

        public bool StateMatches(string candidate) => CryptoUtil.ConstantTimeEquals(State, candidate);

        private static string Validate(string value, string name)
        {
            if (value == null || !TokenPattern.IsMatch(value))
            {
                throw new ArgumentException("Value must be 16-128 URL-safe characters.", name);
            }
            return value;
        }

        // 32 random bytes -> 43 base64url characters (also a valid PKCE verifier length).
        private static string RandomToken()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Base64Url(bytes);
        }

        private static string Base64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static class CryptoUtil
    {
        /// <summary>Compares two strings without short-circuiting on the first differing byte.</summary>
        public static bool ConstantTimeEquals(string a, string b)
        {
            if (a == null || b == null) return false;

            var x = Encoding.UTF8.GetBytes(a);
            var y = Encoding.UTF8.GetBytes(b);
            var diff = x.Length ^ y.Length;
            for (var i = 0; i < x.Length && i < y.Length; i++)
            {
                diff |= x[i] ^ y[i];
            }
            return diff == 0;
        }
    }
}
