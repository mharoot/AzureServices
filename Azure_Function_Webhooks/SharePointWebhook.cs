
using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.Web;

namespace SharePointWebhookFunction
{

    /*
      Azure Function webhook starter.
      ----------------------------------------------------------------------------------------
      🔧 Next Steps
      ✅ 1. Register the Webhook in SharePoint
          Use PnP PowerShell or Microsoft Graph API to register your webhook pointing to the Azure Function URL.
          
      
      Example with PnP PowerShell:
      ----------------------------------------------------------------------------------------
      Connect-PnPOnline -Url "https://yourtenant.sharepoint.com/sites/yoursite" -Interactive

      Add-PnPWebhookSubscription -List "Documents" `
        -NotificationUrl "https://yourfunction.azurewebsites.net/api/SharePointWebhook" `
        -ExpirationDate (Get-Date).AddMonths(6)
        
      Note: Make sure your Azure Function is publicly accessible and responds to the validationtoken query parameter.

      ✅ 2. Process Metadata
        In the TODO section of your function, you can:
        
        Parse the JSON payload.
        Extract metadata like file name, path, user, timestamp.
        Store or forward it to Blob Storage, SQL, etc.

      ----------------------------------------------------------------------------------------
      
    */
    public class SharePointWebhook
    {
        private readonly ILogger _logger;

        public SharePointWebhook(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<SharePointWebhook>();
        }

        [Function("SharePointWebhook")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var query = HttpUtility.ParseQueryString(req.Url.Query);
            var validationToken = query["validationtoken"];

            if (!string.IsNullOrEmpty(validationToken))
            {
                var response = req.CreateResponse(HttpStatusCode.OK);
                await response.WriteStringAsync(validationToken);
                return response;
            }

            var payload = await req.ReadAsStringAsync();
            _logger.LogInformation("Received webhook payload: {Payload}", payload);

            // TODO: Add logic to parse and process SharePoint metadata here

            var successResponse = req.CreateResponse(HttpStatusCode.Accepted);
            await successResponse.WriteStringAsync("Webhook received and processed.");
            return successResponse;
        }
    }
}
