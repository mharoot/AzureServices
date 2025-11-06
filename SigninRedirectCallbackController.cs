
using Microsoft.Identity.Client;
using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace WEBNAME.Controllers
{

    // AuthController - will redirect to microsoft login, and then microsoft will redirect back to this controller, and this controller will set up the users email in the session and lastly redirect them to homepage.
    public class SigninRedirectCallbackController : ApiController
    {
        [HttpGet]
        public async Task<HttpResponseMessage> Get(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Missing authorization code.");
            }

            try
            {
                var clientId = ConfigurationManager.AppSettings["AZURE_CLIENT_ID"];
                var tenantId = ConfigurationManager.AppSettings["AZURE_TENANT_ID"];
                var clientSecret = ConfigurationManager.AppSettings["AZURE_CLIENT_SECRET"];

                // localhost gave me Clr4IntegratedAppPool, webname-dev gave me APP_POOL_ID: WEBNAMEDEV
                string appPool = Environment.GetEnvironmentVariable("APP_POOL_ID");

                var redirectUri = "https://webname-dev.com/api/SigninRedirectCallback"; // your callback page - needs to be added by kevin in the list of redirects that are allowed.

                if (appPool == "Clr4IntegratedAppPool")
                {
                    redirectUri = "https://localhost:44300/api/SigninRedirectCallback";
                }
                else if (appPool == "WEBNAMEDEV")
                {
                    redirectUri = "https://webname-dev.com/api/SigninRedirectCallback";
                }
                else if (appPool == "WEBNAMETEST")
                {
                    redirectUri = "https://webname-test.com/api/SigninRedirectCallback";
                }
                else
                {
                    redirectUri = "https://webname.com/api/SigninRedirectCallback";
                }

                var app = ConfidentialClientApplicationBuilder.Create(clientId)
                    .WithClientSecret(clientSecret)
                    .WithRedirectUri(redirectUri)
                    .WithAuthority($"https://login.microsoftonline.com/{tenantId}")
                    .Build();

                var result = await app.AcquireTokenByAuthorizationCode(
                    new[] { "openid", "profile", "email" }, code).ExecuteAsync();

                var idToken = result.IdToken;

                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(idToken);

                var email = token.Claims.FirstOrDefault(c => c.Type == "email")?.Value
                         ?? token.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;

                // Optionally store email in session or cookie here
                HttpContext.Current.Session["Email"] = email;
                HttpContext.Current.Session["Name"] = token.Claims.FirstOrDefault(c => c.Type == "name")?.Value;
                HttpContext.Current.Session["DisplayName"] = token.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value + " " + token.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value;

                var response = Request.CreateResponse(HttpStatusCode.Redirect);
                var redirectUri2 = "https://webname-dev.com/index.aspx";

                if (appPool == "Clr4IntegratedAppPool")
                {
                    redirectUri2 = "https://localhost:44300/index.aspx";
                }
                else if (appPool == "WEBNAMEDEV")
                {
                    redirectUri2 = "https://webname-dev.com/index.aspx";
                }
                else if (appPool == "WEBNAMETEST")
                {
                    redirectUri2 = "https://webname-test.com/index.aspx";
                }
                else
                {
                    redirectUri2 = "https://webname.com/index.aspx";
                }

                response.Headers.Location = new Uri(redirectUri2);
                return response;
            }
            catch (Exception ex)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex.Message);
            }
        }
    }
}
