using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using WEBNAME.Auth;

namespace WEBNAME.Controllers
{
    /// <summary>
    /// GET /api/SigninRedirectCallback : Entra ID redirects here after login. Verifies the
    /// state cookie, redeems the code (with PKCE), fully validates the ID token, creates the
    /// session and redirects to the configured landing page.
    /// </summary>
    [AllowAnonymous]
    public class SigninRedirectCallbackController : ApiController
    {
        private readonly AuthSettings _settings;
        private readonly IOidcClient _oidc;
        private readonly IIdTokenValidator _validator;
        private readonly IUserSessionStore _session;
        private readonly IAuthLogger _log;

        public SigninRedirectCallbackController()
            : this(AuthServices.Settings, AuthServices.OidcClient, AuthServices.TokenValidator,
                   AuthServices.SessionStore, AuthServices.Logger)
        {
        }

        public SigninRedirectCallbackController(
            AuthSettings settings,
            IOidcClient oidc,
            IIdTokenValidator validator,
            IUserSessionStore session,
            IAuthLogger log)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _oidc = oidc ?? throw new ArgumentNullException(nameof(oidc));
            _validator = validator ?? throw new ArgumentNullException(nameof(validator));
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        [HttpGet]
        public async Task<HttpResponseMessage> Get(
            string code = null,
            string state = null,
            string error = null,
            string error_description = null,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var reference = Guid.NewGuid().ToString("N").Substring(0, 12);

            try
            {
                // The user cancelled or Entra ID refused (consent denied, MFA failed, ...).
                if (!string.IsNullOrEmpty(error))
                {
                    _log.Warn($"[{reference}] Entra ID returned error '{Sanitize(error)}': {Sanitize(error_description)}");
                    return Fail(HttpStatusCode.Unauthorized, "Sign-in was not completed.", reference);
                }

                if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                {
                    return Fail(HttpStatusCode.BadRequest, "Missing authorization code or state.", reference);
                }

                // CSRF / login-CSRF defence: the browser that finishes the login must be the one that started it.
                AuthFlowState flow;
                if (!FlowCookie.TryRead(Request, out flow) || !flow.StateMatches(state))
                {
                    _log.Warn($"[{reference}] State validation failed (missing/expired flow cookie or state mismatch).");
                    return Fail(HttpStatusCode.BadRequest, "Your sign-in session expired or is invalid. Please try again.", reference);
                }

                // NOTE: no ConfigureAwait(false) in this method. HttpContext.Current (needed for
                // session) is only restored on the ASP.NET sync context.
                var idToken = await _oidc.RedeemAuthorizationCodeAsync(code, flow.CodeVerifier, cancellationToken);
                var principal = await _validator.ValidateAsync(idToken, flow.Nonce, cancellationToken);

                AuthenticatedUser user;
                if (!AuthenticatedUser.TryCreate(principal, out user))
                {
                    _log.Warn($"[{reference}] ID token had neither 'email' nor 'preferred_username'.");
                    return Fail(HttpStatusCode.Forbidden, "Your account did not provide an email address.", reference);
                }

                _session.SignIn(user);
                _log.Info($"[{reference}] Sign-in succeeded for oid={user.ObjectId ?? "n/a"}.");

                var response = Request.CreateResponse(HttpStatusCode.Redirect);
                response.Headers.Location = _settings.PostLoginRedirectUri;
                return Complete(response);
            }
            catch (OperationCanceledException)
            {
                throw; // client disconnected; nothing to report
            }
            catch (SecurityTokenException ex)
            {
                _log.Warn($"[{reference}] ID token rejected: {ex.GetType().Name}: {Sanitize(ex.Message)}");
                return Fail(HttpStatusCode.Unauthorized, "Sign-in could not be verified.", reference);
            }
            catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_grant")
            {
                // Code already used / expired / PKCE mismatch: user-recoverable by signing in again.
                _log.Warn($"[{reference}] Authorization code rejected: {Sanitize(ex.Message)}");
                return Fail(HttpStatusCode.Unauthorized, "Sign-in expired. Please try again.", reference);
            }
            catch (MsalServiceException ex) when (ex.StatusCode >= 500)
            {
                _log.Error($"[{reference}] Entra ID unavailable (HTTP {ex.StatusCode}).", ex);
                return Fail(HttpStatusCode.ServiceUnavailable, "The sign-in service is temporarily unavailable.", reference);
            }
            catch (Exception ex)
            {
                // Includes misconfiguration (e.g. invalid_client / bad secret). Details go to the log, never to the browser.
                _log.Error($"[{reference}] Unexpected sign-in failure.", ex);
                return Fail(HttpStatusCode.InternalServerError, "Sign-in failed.", reference);
            }
        }

        private HttpResponseMessage Fail(HttpStatusCode status, string message, string reference) =>
            Complete(Request.CreateErrorResponse(status, message + " (ref " + reference + ")"));

        // Every outcome consumes the flow cookie (single use) and is uncacheable.
        private static HttpResponseMessage Complete(HttpResponseMessage response)
        {
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            response.Headers.TryAddWithoutValidation("Set-Cookie", FlowCookie.BuildExpire());
            return response;
        }

        // Query-string values are attacker-controlled: strip control chars (log forging) and cap length.
        private static string Sanitize(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            var cleaned = new string(value.Where(c => !char.IsControl(c)).ToArray());
            return cleaned.Length <= 200 ? cleaned : cleaned.Substring(0, 200) + "...";
        }
    }
}
