using System.Globalization;
using System.Text.Json;

namespace WEBNAME.EmployeeSync;

/// <summary>Destination for employees (SQL, data lake, marketing platform). Must be idempotent: upsert by Id.</summary>
public interface IEmployeeSink
{
    Task UpsertBatchAsync(IReadOnlyList<Employee> batch, CancellationToken ct);
}

/// <summary>Remembers how far we got, so a crashed run resumes instead of restarting.</summary>
public interface ICheckpointStore
{
    Task<DateTimeOffset?> LoadAsync(CancellationToken ct);
    Task SaveAsync(DateTimeOffset watermark, CancellationToken ct);
}

/// <summary>Holds rows that failed validation so they can be inspected and fixed without blocking the feed.</summary>
public interface IDeadLetterStore
{
    Task AddAsync(string recordJson, string reason, CancellationToken ct);
}

/// <summary>
/// File checkpoint. Writes to a temp file then moves it over the real one, so a crash mid-write can
/// never leave a half-written checkpoint. A corrupt file fails loudly instead of silently re-syncing everything.
/// </summary>
public sealed class FileCheckpointStore : ICheckpointStore
{
    private readonly string _path;

    public FileCheckpointStore(string path) => _path = path ?? throw new ArgumentNullException(nameof(path));

    public async Task<DateTimeOffset?> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(_path)) return null;

        var text = (await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false)).Trim();
        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value))
            throw new InvalidDataException($"Checkpoint file '{_path}' is corrupt. Fix or delete it to force a full resync.");

        return value;
    }

    public async Task SaveAsync(DateTimeOffset watermark, CancellationToken ct)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(_path));
        Directory.CreateDirectory(directory!);

        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, watermark.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), ct).ConfigureAwait(false);
        File.Move(temp, _path, overwrite: true);
    }
}

/// <summary>Append-only JSON-lines dead-letter file.</summary>
public sealed class FileDeadLetterStore : IDeadLetterStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileDeadLetterStore(string path) => _path = path ?? throw new ArgumentNullException(nameof(path));

    public async Task AddAsync(string recordJson, string reason, CancellationToken ct)
    {
        var line = JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow, reason, record = recordJson });
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { await File.AppendAllTextAsync(_path, line + Environment.NewLine, ct).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }
}
