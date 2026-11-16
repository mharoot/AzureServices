/*
This code example works with Microsoft Entra ID (formerly Azure Active Directory). It uses the official Microsoft Authentication Library (MSAL.NET) to handle the OAuth 2.0 / OpenID Connect authorization code flow.
Here is a breakdown of how it integrates with Entra ID and a few potential gotchas to watch out for in this specific implementation:

How it Connects to Microsoft Entra ID

• MSAL.NET Library: It imports Microsoft.Identity.Client and uses ConfidentialClientApplicationBuilder, which is the standard MSAL class for server-side web applications.
• Entra ID Endpoints: Setting .WithAuthority($"https://login.microsoftonline.com/{tenantId}") points the application directly to Microsoft Entra ID's v2.0 authentication endpoint for your specific tenant.
• Token Exchange: Calling AcquireTokenByAuthorizationCode exchanges the temporary code returned by Entra ID for an actual ID token (result.IdToken) containing the user's profile claims.

Important Caveats & Potential Issues in This Code

While the Entra ID authentication logic is valid, there are a few ASP.NET Framework quirks in this snippet that could cause runtime errors:
• Web API Session State: In standard ASP.NET Web API (ApiController), HttpContext.Current.Session is null by default. Unless you have explicitly enabled session state in your Global.asax (PostAuthenticateRequest), trying to set HttpContext.Current.Session["Email"] will throw a NullReferenceException.
• Missing state Parameter Validation: In a production OAuth 2.0 flow, you should pass and validate a state parameter alongside the code parameter to prevent Cross-Site Request Forgery (CSRF) attacks.
• Missing Claims: Depending on how your Entra ID tenant is configured, given_name and family_name might not always be included in the ID token by default unless configured in the app registration's Token configuration blade.
• Exact Redirect URI Match: The redirectUri built dynamically using APP_POOL_ID must match one of the Web Redirect URIs registered in the Entra ID portal character-for-character (including trailing slashes and http vs https).

*/
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
