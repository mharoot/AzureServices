using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace WEBNAME.Auth
{
    /// <summary>
    /// The one-time values for a single sign-in attempt: state (CSRF protection), nonce (ID token
    /// replay protection) and the PKCE code verifier (RFC 7636).
    /// </summary>
    /// <remarks>
    /// Keep it server-side, or in a cookie that is encrypted and signed (ASP.NET Core Data
    /// Protection, or MachineKey.Protect on .NET Framework), HttpOnly, Secure, SameSite=Lax and
    /// limited to the callback path. Delete it as soon as the callback arrives, whatever the
    /// outcome, so every value is used once. The code verifier must never reach the browser.
    /// </remarks>
    public sealed class AuthFlowState
    {
        // 32 random bytes carry 256 bits of entropy and encode to 43 base64url characters,
        // the minimum code verifier length in RFC 7636 section 4.1.
        private const int RandomBytes = 32;
        private const int MinLength = 43;
        private const int MaxLength = 128;
        private static readonly TimeSpan AllowedFutureSkew = TimeSpan.FromMinutes(2);

        /// <summary>Restores a stored attempt. Use <see cref="Create"/> to start a new one.</summary>
        public AuthFlowState(string state, string nonce, string codeVerifier, DateTimeOffset createdUtc)
        {
            State = RequireRandomValue(state, nameof(state));
            Nonce = RequireRandomValue(nonce, nameof(nonce));
            CodeVerifier = RequireRandomValue(codeVerifier, nameof(codeVerifier));
            CodeChallenge = ComputeS256Challenge(CodeVerifier);
            CreatedUtc = createdUtc;
        }

        /// <summary>Sent to Entra ID and compared, in constant time, with the value it returns.</summary>
        public string State { get; }

        /// <summary>Sent to Entra ID and required in the ID token.</summary>
        public string Nonce { get; }

        /// <summary>Secret proof that this server started the flow. Never send it to the browser.</summary>
        public string CodeVerifier { get; }

        /// <summary>S256 hash of the code verifier, sent in the authorization request.</summary>
        public string CodeChallenge { get; }

        /// <summary>When the attempt started.</summary>
        public DateTimeOffset CreatedUtc { get; }

        /// <summary>Starts a new attempt with values from a cryptographically secure random generator.</summary>
        public static AuthFlowState Create(DateTimeOffset utcNow)
        {
            return new AuthFlowState(NewRandomValue(), NewRandomValue(), NewRandomValue(), utcNow);
        }

        /// <summary>True when the attempt is older than <paramref name="lifetime"/>, or dated in the future.</summary>
        public bool IsExpired(DateTimeOffset utcNow, TimeSpan lifetime)
        {
            return utcNow - CreatedUtc >= lifetime || CreatedUtc - utcNow > AllowedFutureSkew;
        }

        /// <summary>BASE64URL(SHA256(ASCII(code_verifier))): the S256 method in RFC 7636 section 4.2.</summary>
        public static string ComputeS256Challenge(string codeVerifier)
        {
            if (codeVerifier == null)
            {
                throw new ArgumentNullException(nameof(codeVerifier));
            }

            using (var sha256 = SHA256.Create())
            {
                return Base64UrlEncode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));
            }
        }

        private static string NewRandomValue()
        {
            var bytes = new byte[RandomBytes];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(bytes);
            }

            return Base64UrlEncode(bytes);
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string RequireRandomValue(string value, string parameterName)
        {
            if (value == null || value.Length < MinLength || value.Length > MaxLength || !value.All(IsUnreserved))
            {
                throw new ArgumentException("Expected 43 to 128 characters from A-Z, a-z, 0-9, '-', '.', '_' and '~'.", parameterName);
            }

            return value;
        }

        // RFC 3986 unreserved characters: the code verifier alphabet in RFC 7636 section 4.1.
        private static bool IsUnreserved(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
        }
    }

    /// <summary>Compares secret strings in constant time, so response timing reveals nothing about them.</summary>
    internal static class SecureCompare
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool FixedTimeEquals(string left, string right)
        {
            if (left == null || right == null)
            {
                return false;
            }

            var a = Encoding.UTF8.GetBytes(left);
            var b = Encoding.UTF8.GetBytes(right);
#if NETCOREAPP2_1_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            if (a.Length != b.Length)
            {
                return false;
            }

            var difference = 0;
            for (var i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }

            return difference == 0;
#endif
        }
    }
}