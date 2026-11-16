using Microsoft.Identity.Client;
using System;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Http;

namespace WebAppName.Controllers
{

    /
    /*

      If you're not hosting your ASP.NET 4.6.1 app in Azure App Service, then Managed Identity is not available, and the approach using AzureServiceTokenProvider for Managed Identity won't work.
    
      Why Managed Identity Requires Azure Hosting
      Managed Identity is a feature of Azure resources like:
      
      App Service
      Azure Functions
      VMs
      Logic Apps
      
      It provides a secure identity only within Azure, which Azure AD can recognize and authorize. If you're running your app:
      
      Locally
      On-premises
      In a non-Azure cloud
      
      Then there's no Managed Identity context, and Azure AD will reject the token request.
      
      ✅ What You Can Do Instead
      If you're not using App Service, Use Client Credentials (Client ID + Secret or Certificate)
      
      To stay secure and compliant when you're not using Azure App Service and therefore can't use Managed Identity, you should follow these three key practices:

      ✅ 1. Use Azure AD App Registration with Client Credentials
      
      Register an application in Azure AD.
      Generate a Client ID and either:
      
      A Client Secret (simpler, but rotate regularly), or
      A Certificate (more secure and preferred for compliance).
      
      
      
      Use the OAuth 2.0 client credentials flow to authenticate your app to Azure services like Key Vault, Azure SQL, etc.
      
      ✅ 2. Secure Your Secrets
      
      Never store secrets in source control.
      Use one of the following secure storage options:
      
      Azure Key Vault (recommended even without Managed Identity — you can access it using client credentials).
      Environment variables (set securely on the host machine).
      Encrypted config files (e.g., using DPAPI or custom encryption).
      
      
      
      Make sure access to these secrets is tightly controlled and audited.
      
      ✅ 3. Rotate and Audit Secrets Regularly
      
      Set expiration dates for secrets.
      Rotate secrets on a schedule or when team members leave.
      Monitor access logs and set up alerts for suspicious activity.

      
    */
    public class SharePointClientSecret2Controller : ApiController
    {
        private static readonly string ClientId = ConfigurationManager.AppSettings["AZURE_CLIENT_ID"];
        private static readonly string ClientSecret = ConfigurationManager.AppSettings["AZURE_CLIENT_SECRET"];
        private static readonly string TenantId = ConfigurationManager.AppSettings["AZURE_TENANT_ID"];
        private static readonly string KeyVaultName = ConfigurationManager.AppSettings["AZURE_KEY_VAULT_NAME"];
        private static readonly string SecretName = "SharePointClientSecret";

        [HttpGet]
        public async Task<string> Get()
        {
            string accessToken = await GetAccessTokenAsync();

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await httpClient.GetAsync($"https://{KeyVaultName}.vault.azure.net/secrets/{SecretName}?api-version=7.3");

                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync();
            }
        }

        private async Task<string> GetAccessTokenAsync()
        {
            var app = ConfidentialClientApplicationBuilder.Create(ClientId)
                .WithClientSecret(ClientSecret)
                .WithAuthority(new Uri($"https://login.microsoftonline.com/{TenantId}"))
                .Build();

            var result = await app.AcquireTokenForClient(new[] { "https://vault.azure.net/.default" }).ExecuteAsync();
            return result.AccessToken;
        }
    }
}
