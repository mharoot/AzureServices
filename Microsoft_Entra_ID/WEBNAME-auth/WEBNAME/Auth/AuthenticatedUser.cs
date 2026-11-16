using System;
using System.Security.Claims;

namespace WEBNAME.Auth
{
    /// <summary>The identity we keep for the signed-in user.</summary>
    public sealed class AuthenticatedUser
    {
        public string Email { get; private set; }
        public string Name { get; private set; }
        public string DisplayName { get; private set; }

        /// <summary>Entra object id ("oid"): the stable, unique user id. Email addresses can change; prefer this for authorization.</summary>
        public string ObjectId { get; private set; }
        public string TenantId { get; private set; }

        public static bool TryCreate(ClaimsPrincipal principal, out AuthenticatedUser user)
        {
            if (principal == null) throw new ArgumentNullException(nameof(principal));
            user = null;

            var email = Value(principal, "email") ?? Value(principal, "preferred_username");
            if (string.IsNullOrWhiteSpace(email)) return false;

            var name = Value(principal, "name");
            var given = Value(principal, "given_name");
            var family = Value(principal, "family_name");

            // given_name/family_name are optional claims in Entra; don't produce " " when absent.
            var display = (given + " " + family).Trim();
            if (display.Length == 0) display = name ?? email;

            user = new AuthenticatedUser
            {
                Email = email.Trim(),
                Name = name,
                DisplayName = display,
                ObjectId = Value(principal, "oid"),
                TenantId = Value(principal, "tid")
            };
            return true;
        }

        private static string Value(ClaimsPrincipal principal, string type)
        {
            var value = principal.FindFirst(type)?.Value;
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
    }
}
