
using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.Web;
using System.Text.Json;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using WEBNAME.Models;

namespace SharePointWebhookFunction
{
    public class SharePointWebhook2
    {
        private readonly ILogger _logger;
        private readonly string _connectionString = Environment.GetEnvironmentVariable("SqlConnectionString");

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

            try
            {
                JObject listData = JObject.Parse(payload);
                var spdb = new SharePointDB("Headshots");
                var headshotsDB = new HeadshotsDB(listData, spdb, updateThumbnails: true, skipValue: "0", grabValue: "0", crossReferenceDelete: false);

                int result = await headshotsDB.StoreJObjectDataInDB();
                _logger.LogInformation("Headshots metadata processed. Records affected: {Result}", result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing webhook payload.");
            }

            var successResponse = req.CreateResponse(HttpStatusCode.Accepted);
            await successResponse.WriteStringAsync("Webhook received and processed.");
            return successResponse;
        }
    }
}
