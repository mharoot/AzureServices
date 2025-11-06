using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;



namespace WEBNAME.Controllers
{
    /*
      You must add the redirect uris to the approved list in Azure AD https://localhost:44300/api/SigninRedirectCallback, https://websitename-dev.com/api/SigninRedirectCallback
    */
    public class AuthController : ApiController
    {
        public object Response { get; private set; }

        // GET api/Auth
        public async Task<HttpResponseMessage> Get()
        {
            try
            {
                

                using (var client = new HttpClient())
                {
                    var clientId = ConfigurationManager.AppSettings["AZURE_CLIENT_ID"];
                    var tenantId = ConfigurationManager.AppSettings["AZURE_TENANT_ID"];
                    var clientSecret = ConfigurationManager.AppSettings["AZURE_CLIENT_SECRET"];

                    var tokenRequestBody = new Dictionary<string, string>
                    {
                        { "client_id", clientId },
                        { "scope", "https://graph.microsoft.com/.default" },
                        { "client_secret", clientSecret },
                        { "grant_type", "client_credentials" }
                    };

                    var tokenResponse = await client.PostAsync(
                        $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token",
                        new FormUrlEncodedContent(tokenRequestBody)
                    );



                    string tokenResponseStr = await tokenResponse.Content.ReadAsStringAsync();
                    JObject listData = JObject.Parse(tokenResponseStr);
                    JToken listDataValue = listData["access_token"];
                    string token = listDataValue.ToString();

                    // HttpContext.Current.Session["AccessToken"] doesn't work without configuring web config to do:
                    // <sessionState mode="InProc" cookieless="UseCookies" timeout="30" />
                    HttpContext.Current.Session["AccessToken"] = token; 

                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                    var response = await client.GetAsync("https://login.microsoftonline.com/e02a72f7-6b46-40ef-b706-e00bf8c058ba/oauth2/v2.0/authorize");
                    if (response.IsSuccessStatusCode)
                    {
                        // localhost gave me Clr4IntegratedAppPool, vaultweb-dev game me APP_POOL_ID: VAULTWEBDEV
                        string appPool = Environment.GetEnvironmentVariable("APP_POOL_ID");

                        var redirectUri = "https://websitename-dev.com/api/SigninRedirectCallback";

                        if (appPool == "Clr4IntegratedAppPool")
                        {
                            redirectUri = "https://localhost:44300/api/SigninRedirectCallback";
                        }
                        else if (appPool == "WEBSITENAMEDEV")
                        {
                            redirectUri = "https://websitename-dev.com/api/SigninRedirectCallback";
                        }
                        else if (appPool == "WEBSITENAMETEST")
                        {
                            redirectUri = "https://websitename-test.com/api/SigninRedirectCallback";
                        }
                        else
                        {
                            redirectUri = "https://websitename.com/api/SigninRedirectCallback";
                        }

                        var loginUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize?" +
                                       $"client_id={clientId}&response_type=code&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&response_mode=query&scope=openid%20profile%20email";

                        HttpContext.Current.Response.Redirect(loginUrl);

                        return response;
                    }
                }

            }
            catch (Exception ex)
            {

            }

            return new HttpResponseMessage();
        }

    }
}
