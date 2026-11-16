using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WEBNAME.EmployeeSync;

/// <summary>
/// Salesforce REST client: OAuth client-credentials, SOQL query pagination (nextRecordsUrl),
/// retry with exponential backoff + jitter (honouring Retry-After), one token refresh on 401,
/// and failover across configured endpoints.
///
/// Design notes
///  - Register ONE instance (HttpClient from IHttpClientFactory in production).
///  - Failover happens when a query STARTS. A nextRecordsUrl cursor belongs to one endpoint, so a
///    mid-stream failure surfaces to the caller, which resumes from its checkpoint (and fails over then).
///  - Secrets and tokens are never logged.
/// </summary>
public sealed class SalesforceClient
{
    private readonly HttpClient _http;
    private readonly SalesforceOptions _options;
    private readonly ILogger<SalesforceClient> _log;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly ConcurrentDictionary<Uri, string> _tokens = new();
    private int _preferred; // index into InstanceUrls; sticky after a failover

    private sealed record Page(List<JsonElement> Records, string NextPath);

    public SalesforceClient(
        HttpClient http,
        SalesforceOptions options,
        ILogger<SalesforceClient> logger = null,
        Func<TimeSpan, CancellationToken, Task> delay = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _log = logger ?? NullLogger<SalesforceClient>.Instance;
        _delay = delay ?? ((d, ct) => Task.Delay(d, ct));
    }

    /// <summary>Streams every record of a SOQL query, page by page, without loading all pages in memory.</summary>
    public async IAsyncEnumerable<JsonElement> QueryAsync(
        string soql,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(soql)) throw new ArgumentException("SOQL is required.", nameof(soql));

        var firstPath = $"/services/data/{_options.ApiVersion}/query?q={Uri.EscapeDataString(soql)}";
        var (page, instance) = await FirstPageWithFailoverAsync(firstPath, ct).ConfigureAwait(false);

        while (true)
        {
            foreach (var record in page.Records) yield return record;
            if (page.NextPath == null) yield break;
            page = await GetPageAsync(instance, page.NextPath, ct).ConfigureAwait(false);
        }
    }

    private async Task<(Page, Uri)> FirstPageWithFailoverAsync(string path, CancellationToken ct)
    {
        var count = _options.InstanceUrls.Count;
        var start = Volatile.Read(ref _preferred);
        Exception last = null;

        for (var i = 0; i < count; i++)
        {
            var index = (start + i) % count;
            var instance = _options.InstanceUrls[index];
            try
            {
                var page = await GetPageAsync(instance, path, ct).ConfigureAwait(false);
                if (i > 0)
                {
                    Volatile.Write(ref _preferred, index);
                    _log.LogWarning("Failed over to Salesforce endpoint {Host}.", instance.Host);
                }
                return (page, instance);
            }
            catch (SalesforceTransientException ex)
            {
                last = ex;
                _log.LogWarning("Salesforce endpoint {Host} unavailable: {Reason}", instance.Host, ex.Message);
            }
        }

        throw new SalesforceUnavailableException($"All {count} Salesforce endpoint(s) failed.", last);
    }

    private async Task<Page> GetPageAsync(Uri instance, string pathAndQuery, CancellationToken ct)
    {
        var refreshedToken = false;

        for (var attempt = 0; ; attempt++)
        {
            TimeSpan? retryAfter = null;
            string reason;

            try
            {
                var token = await GetTokenAsync(instance, ct).ConfigureAwait(false);
                using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(instance, pathAndQuery));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Headers.Add("Sforce-Query-Options", $"batchSize={_options.QueryBatchSize}");

                using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                    return await ParsePageAsync(response, ct).ConfigureAwait(false);

                if (response.StatusCode == HttpStatusCode.Unauthorized && !refreshedToken)
                {
                    // Expired/rotated token: refresh once. This does not consume a retry or back off.
                    refreshedToken = true;
                    _tokens.TryRemove(instance, out _);
                    attempt--;
                    continue;
                }

                if (!IsTransient(response.StatusCode))
                {
                    var body = await ReadTruncatedAsync(response, ct).ConfigureAwait(false);
                    throw new SalesforceException($"Salesforce returned HTTP {(int)response.StatusCode}: {body}");
                }

                retryAfter = ReadRetryAfter(response);
                reason = $"HTTP {(int)response.StatusCode}";
            }
            catch (SalesforceTransientException ex) { reason = ex.Message; }          // token endpoint was down
            catch (HttpRequestException ex) { reason = ex.GetType().Name + ": " + ex.Message; }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested) { reason = "request timed out"; }

            if (attempt >= _options.MaxRetries)
                throw new SalesforceTransientException($"Gave up after {attempt + 1} attempt(s): {reason}");

            var delay = retryAfter ?? Backoff(attempt);
            _log.LogWarning("Salesforce {Host} transient failure ({Reason}); retry {Attempt}/{Max} in {Delay}.",
                instance.Host, reason, attempt + 1, _options.MaxRetries, delay);
            await _delay(delay, ct).ConfigureAwait(false);
        }
    }

    private async Task<string> GetTokenAsync(Uri instance, CancellationToken ct)
    {
        if (_tokens.TryGetValue(instance, out var cached)) return cached;

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(instance, "/services/oauth2/token"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId,
                ["client_secret"] = _options.ClientSecret
            })
        };

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            if (IsTransient(response.StatusCode))
                throw new SalesforceTransientException($"Token endpoint returned HTTP {(int)response.StatusCode}.");

            // Only the OAuth error code (e.g. invalid_client) is surfaced, never request/response secrets.
            throw new SalesforceAuthException(
                $"Salesforce rejected the client credentials (HTTP {(int)response.StatusCode}, error '{await ReadOAuthErrorAsync(response, ct)}').");
        }

        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct)
            .ConfigureAwait(false);
        var token = doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() : null;
        if (string.IsNullOrEmpty(token))
            throw new SalesforceAuthException("Salesforce token response did not contain an access_token.");

        _tokens[instance] = token;
        return token;
    }

    private static async Task<Page> ParsePageAsync(HttpResponseMessage response, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        var root = doc.RootElement;

        var records = new List<JsonElement>();
        if (root.TryGetProperty("records", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            // Clone: elements must outlive the JsonDocument that is disposed here.
            foreach (var record in array.EnumerateArray()) records.Add(record.Clone());
        }

        string next = null;
        if (root.TryGetProperty("nextRecordsUrl", out var n) && n.ValueKind == JsonValueKind.String)
        {
            next = n.GetString();
            // The server controls this value and we attach a bearer token to it: only follow same-host API paths.
            if (next == null || !next.StartsWith("/services/data/", StringComparison.Ordinal))
                throw new SalesforceException("Salesforce returned an unexpected nextRecordsUrl.");
        }

        return new Page(records, next);
    }

    private static bool IsTransient(HttpStatusCode status) => (int)status is 408 or 429 or >= 500;

    private TimeSpan? ReadRetryAfter(HttpResponseMessage response)
    {
        var delta = response.Headers.RetryAfter?.Delta;
        if (delta == null || delta.Value <= TimeSpan.Zero) return null;
        return delta.Value > _options.MaxDelay ? _options.MaxDelay : delta.Value;
    }

    // Exponential backoff, capped, with 50-100% jitter so many workers do not retry in lockstep.
    private TimeSpan Backoff(int attempt)
    {
        var exponential = _options.BaseDelay.TotalMilliseconds * Math.Pow(2, attempt);
        var capped = Math.Min(exponential, _options.MaxDelay.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(capped * (0.5 + Random.Shared.NextDouble() / 2));
    }

    private static async Task<string> ReadTruncatedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return text.Length <= 300 ? text : text[..300] + "...";
    }

    private static async Task<string> ReadOAuthErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct)
                .ConfigureAwait(false);
            return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "unknown";
        }
        catch (JsonException) { return "unknown"; }
    }
}
