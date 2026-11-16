namespace WEBNAME.EmployeeSync;

public sealed record Employee(string Id, string Name, string Email, string Department, DateTimeOffset LastModified);

public sealed record SyncResult(
    int Fetched,
    int Upserted,
    int DeadLettered,
    int Batches,
    DateTimeOffset? Watermark,
    TimeSpan Duration);

/// <summary>Permanent Salesforce failure (bad query, 4xx). Retrying will not help.</summary>
public class SalesforceException : Exception
{
    public SalesforceException(string message, Exception inner = null) : base(message, inner) { }
}

/// <summary>Temporary failure (429, 5xx, timeout, network). Safe to retry.</summary>
public sealed class SalesforceTransientException : SalesforceException
{
    public SalesforceTransientException(string message, Exception inner = null) : base(message, inner) { }
}

/// <summary>Every configured endpoint failed.</summary>
public sealed class SalesforceUnavailableException : SalesforceException
{
    public SalesforceUnavailableException(string message, Exception inner = null) : base(message, inner) { }
}

/// <summary>Credentials rejected. Not retried: repeating a bad login only risks locking the integration user.</summary>
public sealed class SalesforceAuthException : SalesforceException
{
    public SalesforceAuthException(string message) : base(message) { }
}
