#nullable enable
using Microsoft.Extensions.Logging;

namespace WEBNAME.EmployeeSync.IntegrationTests;

/// <summary>Captures log output so tests can assert on it (e.g. that secrets never appear).</summary>
public sealed class ListLogger<T> : ILogger<T>
{
    public List<string> Lines { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        lock (Lines) Lines.Add($"{logLevel}: {formatter(state, exception)} {exception}");
    }
}
#nullable disable

internal sealed class InMemorySink : IEmployeeSink
{
    public Dictionary<string, Employee> Store { get; } = new();
    public List<int> BatchSizes { get; } = new();

    /// <summary>Every call, including failed attempts.</summary>
    public int Calls;

    /// <summary>Decides, by 1-based call number, whether this call fails.</summary>
    public Func<int, bool> ShouldFail = _ => false;

    public Task UpsertBatchAsync(IReadOnlyList<Employee> batch, CancellationToken ct)
    {
        Calls++;
        if (ShouldFail(Calls)) throw new InvalidOperationException("sink unavailable");

        BatchSizes.Add(batch.Count);
        foreach (var employee in batch) Store[employee.Id] = employee; // upsert by Id
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryCheckpoint : ICheckpointStore
{
    public DateTimeOffset? Value;
    public Task<DateTimeOffset?> LoadAsync(CancellationToken ct) => Task.FromResult(Value);
    public Task SaveAsync(DateTimeOffset watermark, CancellationToken ct) { Value = watermark; return Task.CompletedTask; }
}

internal sealed class InMemoryDeadLetters : IDeadLetterStore
{
    public List<(string Record, string Reason)> Items { get; } = new();
    public Task AddAsync(string recordJson, string reason, CancellationToken ct)
    {
        Items.Add((recordJson, reason));
        return Task.CompletedTask;
    }
}

/// <summary>Starts a fresh fake Salesforce per test and offers helpers for building clients and data.</summary>
public abstract class SyncTestBase : IAsyncLifetime
{
    protected FakeSalesforce Primary;
    protected readonly List<TimeSpan> Delays = new();
    protected readonly ListLogger<SalesforceClient> ClientLog = new();
    protected readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    public virtual async Task InitializeAsync() => Primary = await FakeSalesforce.StartAsync();

    public virtual async Task DisposeAsync()
    {
        Http.Dispose();
        await Primary.DisposeAsync();
    }

    /// <summary>Records requested backoff delays instead of sleeping, so retry tests run instantly.</summary>
    protected Task RecordDelay(TimeSpan delay, CancellationToken ct)
    {
        lock (Delays) Delays.Add(delay);
        return Task.CompletedTask;
    }

    protected SalesforceClient NewClient(params FakeSalesforce[] servers)
    {
        var targets = servers.Length == 0 ? new[] { Primary } : servers;
        return new SalesforceClient(Http, new SalesforceOptions
        {
            InstanceUrls = targets.Select(s => s.BaseUrl).ToList(),
            ClientId = FakeSalesforce.ClientId,
            ClientSecret = FakeSalesforce.ClientSecret,
            MaxRetries = 3
        }, ClientLog, RecordDelay);
    }

    /// <summary>Employees E0001..E000n, each modified one second after the previous.</summary>
    protected static List<FakeRecord> MakeEmployees(int count, DateTimeOffset? start = null)
    {
        var first = start ?? new DateTimeOffset(2024, 5, 1, 8, 0, 0, TimeSpan.Zero);
        return Enumerable.Range(1, count)
            .Select(i => new FakeRecord($"E{i:D4}", $"Employee {i}", $"emp{i}@example.com", "Engineering", first.AddSeconds(i)))
            .ToList();
    }
}
