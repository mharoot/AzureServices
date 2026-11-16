using System.Linq;
using System.Net.Http;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Builds/reads the flow cookie. Set-Cookie is written as a raw header because the Web API
    /// CookieHeaderValue type does not expose SameSite on all versions.
    ///
    /// - "__Host-" prefix: browser enforces Secure + Path=/ + no Domain (blocks subdomain injection).
    /// - SameSite=Lax (not Strict): the return from login.microsoftonline.com is a cross-site
    ///   top-level GET, which Strict would drop.
    /// </summary>
    public static class FlowCookie
    {
        private const string Attributes = "Path=/; Secure; HttpOnly; SameSite=Lax";

        public static string BuildSetCookie(AuthFlowState flow, int maxAgeSeconds = 600) =>
            AuthFlowState.CookieName + "=" + flow.Serialize() + "; Max-Age=" + maxAgeSeconds + "; " + Attributes;

        public static string BuildExpire() =>
            AuthFlowState.CookieName + "=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; " + Attributes;

        public static bool TryRead(HttpRequestMessage request, out AuthFlowState flow)
        {
            flow = null;
            var cookie = request.Headers.GetCookies(AuthFlowState.CookieName).FirstOrDefault();
            var value = cookie?[AuthFlowState.CookieName]?.Value;
            return AuthFlowState.TryParse(value, out flow);
        }
    }
}
