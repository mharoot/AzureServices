using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WEBNAME.EmployeeSync;

public sealed class EmployeeSyncOptions
{
    public int BatchSize { get; init; } = 1000;
    public int SinkMaxAttempts { get; init; } = 3;
    public TimeSpan SinkRetryDelay { get; init; } = TimeSpan.FromSeconds(1);
}

/// <summary>
/// Pulls employees from Salesforce incrementally and writes them to a sink in batches.
///
/// Guarantees
///  - At-least-once: the checkpoint only advances AFTER a batch is durably written, so a crash re-reads
///    (never skips) data. Idempotent upserts make the re-read harmless.
///  - Bad rows are dead-lettered; they do not stop the run.
///  - Any failure leaves the last good checkpoint in place. Re-running resumes from it.
///  - RunAsync(replayFrom) re-processes history from a chosen point (backfill / incident recovery).
/// </summary>
public sealed class EmployeeSyncService
{
    private readonly SalesforceClient _salesforce;
    private readonly IEmployeeSink _sink;
    private readonly ICheckpointStore _checkpoint;
    private readonly IDeadLetterStore _deadLetters;
    private readonly EmployeeSyncOptions _options;
    private readonly ILogger<EmployeeSyncService> _log;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public EmployeeSyncService(
        SalesforceClient salesforce,
        IEmployeeSink sink,
        ICheckpointStore checkpoint,
        IDeadLetterStore deadLetters,
        EmployeeSyncOptions options = null,
        ILogger<EmployeeSyncService> logger = null,
        Func<TimeSpan, CancellationToken, Task> delay = null)
    {
        _salesforce = salesforce ?? throw new ArgumentNullException(nameof(salesforce));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _checkpoint = checkpoint ?? throw new ArgumentNullException(nameof(checkpoint));
        _deadLetters = deadLetters ?? throw new ArgumentNullException(nameof(deadLetters));
        _options = options ?? new EmployeeSyncOptions();
        _log = logger ?? NullLogger<EmployeeSyncService>.Instance;
        _delay = delay ?? ((d, ct) => Task.Delay(d, ct));

        if (_options.BatchSize < 1) throw new ArgumentException("BatchSize must be at least 1.");
        if (_options.SinkMaxAttempts < 1) throw new ArgumentException("SinkMaxAttempts must be at least 1.");
    }

    public async Task<SyncResult> RunAsync(DateTimeOffset? replayFrom = null, CancellationToken ct = default)
    {
        var runId = Guid.NewGuid().ToString("N")[..8];
        using var scope = _log.BeginScope(new Dictionary<string, object> { ["RunId"] = runId });
        var stopwatch = Stopwatch.StartNew();

        var startFrom = replayFrom ?? await _checkpoint.LoadAsync(ct).ConfigureAwait(false);
        _log.LogInformation("Employee sync starting. Since={Since} Replay={Replay}", startFrom, replayFrom.HasValue);

        var batch = new List<Employee>(_options.BatchSize);
        int fetched = 0, upserted = 0, deadLettered = 0, batches = 0;
        var watermark = startFrom;

        async Task FlushAsync()
        {
            var snapshot = batch.ToArray(); // the sink never sees a list we keep mutating
            await UpsertWithRetryAsync(snapshot, batches + 1, ct).ConfigureAwait(false);

            upserted += snapshot.Length;
            batches++;

            var newest = snapshot.Max(e => e.LastModified);
            if (watermark == null || newest > watermark) watermark = newest;

            // Checkpoint strictly AFTER the durable write.
            await _checkpoint.SaveAsync(watermark.Value, ct).ConfigureAwait(false);
            batch.Clear();
            _log.LogInformation("Batch {Batch} committed ({Count} rows). Checkpoint={Watermark}", batches, snapshot.Length, watermark);
        }

        try
        {
            await foreach (var record in _salesforce.QueryAsync(EmployeeQuery.Build(startFrom), ct).ConfigureAwait(false))
            {
                fetched++;

                if (!EmployeeMapper.TryMap(record, out var employee, out var error))
                {
                    deadLettered++;
                    await _deadLetters.AddAsync(record.GetRawText(), error, ct).ConfigureAwait(false);
                    _log.LogWarning("Dead-lettered record: {Reason}", error);
                    continue;
                }

                batch.Add(employee);
                if (batch.Count >= _options.BatchSize) await FlushAsync().ConfigureAwait(false);
            }

            if (batch.Count > 0) await FlushAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex,
                "Employee sync FAILED after {Fetched} fetched / {Upserted} upserted in {Batches} batch(es). " +
                "Checkpoint={Watermark}. Safe to re-run: it resumes from the checkpoint.",
                fetched, upserted, batches, watermark);
            throw;
        }

        var result = new SyncResult(fetched, upserted, deadLettered, batches, watermark, stopwatch.Elapsed);
        _log.LogInformation(
            "Employee sync complete: fetched={Fetched} upserted={Upserted} deadLettered={DeadLettered} batches={Batches} duration={Duration}",
            result.Fetched, result.Upserted, result.DeadLettered, result.Batches, result.Duration);
        return result;
    }

    private async Task UpsertWithRetryAsync(IReadOnlyList<Employee> batch, int batchNumber, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await _sink.UpsertBatchAsync(batch, ct).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException && attempt < _options.SinkMaxAttempts)
            {
                _log.LogWarning(ex, "Sink write failed for batch {Batch} (attempt {Attempt}/{Max}); retrying.",
                    batchNumber, attempt, _options.SinkMaxAttempts);
                await _delay(_options.SinkRetryDelay, ct).ConfigureAwait(false);
            }
        }
    }
}
