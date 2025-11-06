using Microsoft.Azure.Services.AppAuthentication;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Http;

namespace WebAppName.Controllers
{

    /**
        If your app is hosted in Azure App Service, enable Managed Identity.
        Then use AzureServiceTokenProvider to get a token for Key Vault.
    
        Managed Identity is a great choice, especially since your app is hosted in Azure App Service and you already have SSO configured.

        If you're not hosting your ASP.NET 4.6.1 app in Azure App Service, then Managed Identity is not available, and the approach using AzureServiceTokenProvider for Managed Identity won't work.
     */
    public class SharePointClientSecretController : ApiController
    {
        [HttpGet]
        public async Task<string> Get()
        {
            const string secretName = "SharePointClientSecret";
            const string keyVaultName = "hl-d-wus2-pgcdn-kv-01";

            // Use Managed Identity to get a token for Key Vault
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            string accessToken = await azureServiceTokenProvider.GetAccessTokenAsync("https://vault.azure.net");

            // Call Key Vault with the token
            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await httpClient.GetAsync($"https://{keyVaultName}.vault.azure.net/secrets/{secretName}?api-version=7.3");
                response.EnsureSuccessStatusCode();

                return await response.Content.ReadAsStringAsync();
            }
        }
    }
}
