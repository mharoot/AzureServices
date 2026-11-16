using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web.Http;
using WEBNAME.Auth;

namespace WEBNAME.Controllers
{
    /// <summary>
    /// GET /api/Signin : starts sign-in. Generates state/nonce/PKCE, stores them in a
    /// short-lived cookie and redirects the browser to Entra ID. Point your "Sign in"
    /// link/button here.
    /// </summary>
    [AllowAnonymous]
    public class SigninController : ApiController
    {
        private readonly IOidcClient _oidc;

        public SigninController() : this(AuthServices.OidcClient)
        {
        }

        public SigninController(IOidcClient oidc)
        {
            _oidc = oidc ?? throw new ArgumentNullException(nameof(oidc));
        }

        [HttpGet]
        public HttpResponseMessage Get()
        {
            var flow = AuthFlowState.Create();

            var response = Request.CreateResponse(HttpStatusCode.Redirect);
            response.Headers.Location = _oidc.BuildAuthorizationUri(flow);
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            response.Headers.TryAddWithoutValidation("Set-Cookie", FlowCookie.BuildSetCookie(flow));
            return response;
        }
    }
}
