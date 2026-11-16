namespace WEBNAME.EmployeeSync;

public sealed class SalesforceOptions
{
    /// <summary>Ordered by preference: primary first, then failover endpoints.</summary>
    public IReadOnlyList<Uri> InstanceUrls { get; init; } = Array.Empty<Uri>();

    /// <summary>Connected App credentials (OAuth 2.0 client-credentials flow). Keep the secret in a vault, never in source.</summary>
    public string ClientId { get; init; }
    public string ClientSecret { get; init; }

    public string ApiVersion { get; init; } = "v62.0";

    /// <summary>Salesforce page size hint (Sforce-Query-Options: batchSize). Max 2000.</summary>
    public int QueryBatchSize { get; init; } = 2000;

    /// <summary>Retries per endpoint after the first attempt.</summary>
    public int MaxRetries { get; init; } = 4;
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromSeconds(30);

    public void Validate()
    {
        if (InstanceUrls == null || InstanceUrls.Count == 0)
            throw new ArgumentException("At least one Salesforce instance URL is required.");

        foreach (var url in InstanceUrls)
        {
            var ok = url.IsAbsoluteUri && (url.Scheme == Uri.UriSchemeHttps || url.IsLoopback);
            if (!ok) throw new ArgumentException("Salesforce instance URLs must be absolute https (http only for loopback test servers).");
        }

        if (string.IsNullOrWhiteSpace(ClientId) || string.IsNullOrWhiteSpace(ClientSecret))
            throw new ArgumentException("Salesforce ClientId and ClientSecret are required.");

        if (MaxRetries < 0) throw new ArgumentException("MaxRetries cannot be negative.");
    }
}
