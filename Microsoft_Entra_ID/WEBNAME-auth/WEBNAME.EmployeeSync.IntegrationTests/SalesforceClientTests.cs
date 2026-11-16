using System.Text.Json;
using Xunit;

namespace WEBNAME.EmployeeSync.IntegrationTests;

/// <summary>
/// The real SalesforceClient + real HttpClient talking over real HTTP to FakeSalesforce.
/// Covers auth, pagination, retry/backoff, token refresh, failover and secret hygiene.
/// </summary>
public class SalesforceClientTests : SyncTestBase
{
    private static async Task<List<JsonElement>> ReadAll(SalesforceClient client)
    {
        var rows = new List<JsonElement>();
        await foreach (var row in client.QueryAsync("SELECT Id FROM Employee__c")) rows.Add(row);
        return rows;
    }

    private static string[] Ids(IEnumerable<JsonElement> rows) =>
        rows.Select(r => r.GetProperty("Id").GetString()).ToArray();

    // ---------- auth & pagination ----------

    [Fact]
    public async Task Authenticates_once_follows_every_page_and_reuses_the_token()
    {
        Primary.Data.AddRange(MakeEmployees(5));
        Primary.PageSize = 2;

        var rows = await ReadAll(NewClient());

        Assert.Equal(Enumerable.Range(1, 5).Select(i => $"E{i:D4}"), Ids(rows)); // all rows, in order
        Assert.Equal(1, Primary.QueryRequests);      // first page
        Assert.Equal(2, Primary.NextPageRequests);   // pages 2 and 3 via nextRecordsUrl
        Assert.Equal(1, Primary.TokenRequests);      // one login, reused across pages
        Assert.Equal("Bearer token-1", Primary.LastAuthorization);
    }

    [Fact]
    public async Task Empty_result_returns_no_rows()
    {
        var rows = await ReadAll(NewClient());
        Assert.Empty(rows);
    }

    [Fact]
    public async Task Refreshes_an_expired_token_once_without_backing_off()
    {
        Primary.Data.AddRange(MakeEmployees(1));
        var client = NewClient();
        await ReadAll(client);

        Primary.CurrentToken = "token-2"; // token expires / is rotated server-side
        var rows = await ReadAll(client);

        Assert.Single(rows);
        Assert.Equal(2, Primary.TokenRequests);
        Assert.Empty(Delays); // a refresh is not a retry
    }

    // ---------- retry / backoff ----------

    [Fact]
    public async Task Retries_transient_errors_with_backoff_then_succeeds()
    {
        Primary.Data.AddRange(MakeEmployees(3));
        Primary.PageSize = 10;
        var calls = 0;
        Primary.Interceptor = _ => calls++ < 2 ? new Fault(503) : null;

        var rows = await ReadAll(NewClient());

        Assert.Equal(3, rows.Count);
        Assert.Equal(3, Primary.QueryRequests);    // 2 failures + 1 success
        Assert.Equal(2, Delays.Count);
        Assert.All(Delays, d => Assert.InRange(d, TimeSpan.Zero, TimeSpan.FromSeconds(30)));
        Assert.All(Delays, d => Assert.True(d > TimeSpan.Zero));
    }

    [Fact]
    public async Task Honours_the_Retry_After_header_on_429()
    {
        Primary.Data.AddRange(MakeEmployees(1));
        var calls = 0;
        Primary.Interceptor = _ => calls++ == 0 ? new Fault(429, RetryAfterSeconds: 7) : null;

        await ReadAll(NewClient());

        Assert.Equal(TimeSpan.FromSeconds(7), Assert.Single(Delays));
    }

    [Fact]
    public async Task Gives_up_after_the_retry_budget_is_spent()
    {
        Primary.Interceptor = _ => new Fault(503);

        await Assert.ThrowsAsync<SalesforceUnavailableException>(() => ReadAll(NewClient()));

        Assert.Equal(4, Primary.QueryRequests); // 1 attempt + MaxRetries(3)
        Assert.Equal(3, Delays.Count);
    }

    [Fact]
    public async Task Does_not_retry_permanent_errors()
    {
        Primary.Interceptor = _ => new Fault(400);

        await Assert.ThrowsAsync<SalesforceException>(() => ReadAll(NewClient()));

        Assert.Equal(1, Primary.QueryRequests);
        Assert.Empty(Delays);
    }

    // ---------- regional failover ----------

    [Fact]
    public async Task Fails_over_to_the_secondary_when_the_primary_is_down_and_sticks_to_it()
    {
        await using var secondary = await FakeSalesforce.StartAsync();
        secondary.Data.AddRange(MakeEmployees(3));
        Primary.Down = true;
        var client = NewClient(Primary, secondary);

        Assert.Equal(3, (await ReadAll(client)).Count);

        var primaryTokenCalls = Primary.TokenRequests;
        Assert.True(primaryTokenCalls >= 1); // primary was tried (and retried) first

        // Second query goes straight to the healthy endpoint instead of burning retries on the dead one.
        Assert.Equal(3, (await ReadAll(client)).Count);
        Assert.Equal(primaryTokenCalls, Primary.TokenRequests);
    }

    [Fact]
    public async Task Reports_unavailable_when_every_endpoint_is_down()
    {
        await using var secondary = await FakeSalesforce.StartAsync();
        Primary.Down = true;
        secondary.Down = true;

        await Assert.ThrowsAsync<SalesforceUnavailableException>(() => ReadAll(NewClient(Primary, secondary)));
    }

    // ---------- security / hygiene ----------

    [Fact]
    public async Task Bad_credentials_fail_fast_without_retrying_or_leaking_the_secret()
    {
        var client = new SalesforceClient(Http, new SalesforceOptions
        {
            InstanceUrls = new[] { Primary.BaseUrl },
            ClientId = FakeSalesforce.ClientId,
            ClientSecret = "wrong-secret-value",
            MaxRetries = 3
        }, ClientLog, RecordDelay);

        var ex = await Assert.ThrowsAsync<SalesforceAuthException>(() => ReadAll(client));

        Assert.Contains("invalid_client", ex.Message);
        Assert.DoesNotContain("wrong-secret-value", ex.Message);
        Assert.Equal(1, Primary.TokenRequests); // no retry: hammering a bad credential can lock the integration user
        Assert.Empty(Delays);
    }

    [Fact]
    public async Task Never_logs_the_client_secret_or_access_token()
    {
        Primary.Data.AddRange(MakeEmployees(2));
        var calls = 0;
        Primary.Interceptor = _ => calls++ == 0 ? new Fault(503) : null; // force a warning log line too

        await ReadAll(NewClient());

        Assert.NotEmpty(ClientLog.Lines);
        Assert.DoesNotContain(ClientLog.Lines, l => l.Contains(FakeSalesforce.ClientSecret));
        Assert.DoesNotContain(ClientLog.Lines, l => l.Contains("token-1"));
    }

    [Fact]
    public void Rejects_insecure_or_incomplete_configuration()
    {
        Assert.Throws<ArgumentException>(() => new SalesforceClient(Http, new SalesforceOptions
        {
            InstanceUrls = new[] { new Uri("http://example.my.salesforce.com") }, // http, not loopback
            ClientId = "id",
            ClientSecret = "secret"
        }));

        Assert.Throws<ArgumentException>(() => new SalesforceClient(Http, new SalesforceOptions
        {
            InstanceUrls = new[] { new Uri("https://example.my.salesforce.com") },
            ClientId = "id",
            ClientSecret = ""
        }));
    }
}
