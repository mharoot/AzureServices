using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WEBNAME.EmployeeSync.IntegrationTests;

public sealed record FakeRecord(string Id, string Name, string Email, string Department, DateTimeOffset Modified);

/// <summary>Scripted failure: status code and optional Retry-After seconds.</summary>
public sealed record Fault(int Status, int? RetryAfterSeconds = null);

/// <summary>
/// A real HTTP server (Kestrel on a random local port) that behaves like the parts of Salesforce we use:
/// OAuth client-credentials token endpoint, SOQL query with SystemModstamp filtering, paging through
/// nextRecordsUrl cursors, "+0000" style timestamps, 401 on stale tokens, and scriptable outages.
/// Because it is real HTTP, the production HttpClient code path (headers, status codes, timeouts,
/// JSON parsing) is exercised for real, which is what makes these integration tests rather than unit tests.
/// </summary>
public sealed class FakeSalesforce : IAsyncDisposable
{
    public const string ClientId = "test-client";
    public const string ClientSecret = "test-secret-DO-NOT-LOG";

    private static readonly Regex Watermark = new(@"SystemModstamp >= (\S+)", RegexOptions.Compiled);

    private readonly object _lock = new();
    private readonly Dictionary<string, List<FakeRecord>> _cursors = new();
    private WebApplication _app;

    public Uri BaseUrl { get; private set; }
    public List<FakeRecord> Data { get; } = new();
    public int PageSize { get; set; } = 2;
    public string CurrentToken { get; set; } = "token-1";

    /// <summary>When true every endpoint answers 503 (regional outage).</summary>
    public bool Down { get; set; }

    /// <summary>Return a Fault to short-circuit an authenticated query/page request; null lets it through.</summary>
    public Func<HttpContext, Fault> Interceptor { get; set; }

    // Observations the tests assert on.
    public int TokenRequests;
    public int QueryRequests;
    public int NextPageRequests;
    public string LastAuthorization;
    public List<string> Queries { get; } = new();

    public static bool IsNextPage(HttpContext ctx) =>
        ctx.Request.Path.Value!.Contains("/query/", StringComparison.Ordinal);

    public static async Task<FakeSalesforce> StartAsync()
    {
        var fake = new FakeSalesforce();

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0"); // port 0 = pick a free port
        var app = builder.Build();
        fake.MapEndpoints(app);

        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();

        fake._app = app;
        fake.BaseUrl = new Uri(address);
        return fake;
    }

    public async ValueTask DisposeAsync()
    {
        if (_app == null) return;
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    private void MapEndpoints(WebApplication app)
    {
        app.MapPost("/services/oauth2/token", async (HttpContext ctx) =>
        {
            Interlocked.Increment(ref TokenRequests);
            if (Down) return Results.StatusCode(503);

            var form = await ctx.Request.ReadFormAsync();
            var valid = form["grant_type"] == "client_credentials"
                        && form["client_id"] == ClientId
                        && form["client_secret"] == ClientSecret;
            if (!valid)
                return Results.Json(new { error = "invalid_client", error_description = "invalid client credentials" }, statusCode: 400);

            return Results.Json(new
            {
                access_token = CurrentToken,
                token_type = "Bearer",
                instance_url = BaseUrl.ToString().TrimEnd('/')
            });
        });

        app.MapGet("/services/data/{version}/query", (HttpContext ctx, string version) =>
        {
            Interlocked.Increment(ref QueryRequests);
            var blocked = Gate(ctx);
            if (blocked != null) return blocked;

            var soql = ctx.Request.Query["q"].ToString();
            lock (_lock) Queries.Add(soql);

            var rows = Filter(soql);
            var cursor = Guid.NewGuid().ToString("N");
            lock (_lock) _cursors[cursor] = rows;
            return Page(version, rows, cursor, 0);
        });

        app.MapGet("/services/data/{version}/query/{cursor}", (HttpContext ctx, string version, string cursor) =>
        {
            Interlocked.Increment(ref NextPageRequests);
            var blocked = Gate(ctx);
            if (blocked != null) return blocked;

            var dash = cursor.LastIndexOf('-');
            if (dash < 0 || !int.TryParse(cursor[(dash + 1)..], out var offset)) return Results.NotFound();

            List<FakeRecord> rows;
            lock (_lock)
            {
                if (!_cursors.TryGetValue(cursor[..dash], out rows)) return Results.NotFound();
            }
            return Page(version, rows, cursor[..dash], offset);
        });
    }

    // Down -> 503; stale/missing token -> 401; then any scripted fault.
    private IResult Gate(HttpContext ctx)
    {
        if (Down) return Results.StatusCode(503);

        LastAuthorization = ctx.Request.Headers.Authorization.ToString();
        if (LastAuthorization != "Bearer " + CurrentToken)
        {
            return Results.Json(new[] { new { message = "Session expired or invalid", errorCode = "INVALID_SESSION_ID" } }, statusCode: 401);
        }

        var fault = Interceptor?.Invoke(ctx);
        if (fault == null) return null;

        if (fault.RetryAfterSeconds.HasValue)
            ctx.Response.Headers["Retry-After"] = fault.RetryAfterSeconds.Value.ToString(CultureInfo.InvariantCulture);
        return Results.StatusCode(fault.Status);
    }

    private List<FakeRecord> Filter(string soql)
    {
        List<FakeRecord> snapshot;
        lock (_lock) snapshot = Data.ToList();

        var match = Watermark.Match(soql);
        if (match.Success)
        {
            var since = DateTimeOffset.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            snapshot = snapshot.Where(r => r.Modified >= since).ToList();
        }

        return snapshot.OrderBy(r => r.Modified).ThenBy(r => r.Id, StringComparer.Ordinal).ToList();
    }

    private IResult Page(string version, List<FakeRecord> rows, string cursor, int offset)
    {
        var slice = rows.Skip(offset).Take(PageSize).ToList();
        var hasMore = offset + PageSize < rows.Count;

        var body = new Dictionary<string, object>
        {
            ["totalSize"] = rows.Count,
            ["done"] = !hasMore,
            ["records"] = slice.Select(r => new Dictionary<string, object>
            {
                ["attributes"] = new { type = "Employee__c" },
                ["Id"] = r.Id,
                ["Name"] = r.Name,
                ["Email__c"] = r.Email,
                ["Department__c"] = r.Department,
                ["SystemModstamp"] = Stamp(r.Modified)
            }).ToList()
        };
        if (hasMore) body["nextRecordsUrl"] = $"/services/data/{version}/query/{cursor}-{offset + PageSize}";

        return Results.Json(body);
    }

    // Real Salesforce: 2024-05-01T12:30:15.123+0000 (offset without a colon).
    private static string Stamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff", CultureInfo.InvariantCulture) + "+0000";
}
