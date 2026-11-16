using System.Text.Json;
using Xunit;

namespace WEBNAME.EmployeeSync.IntegrationTests;

/// <summary>Real file system, real files (temp directory).</summary>
public sealed class FileStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "empsync-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task Checkpoint_survives_a_restart_and_leaves_no_temp_file()
    {
        var path = Path.Combine(_dir, "checkpoint.txt");
        var stamp = new DateTimeOffset(2024, 5, 1, 12, 30, 15, 123, TimeSpan.Zero);

        await new FileCheckpointStore(path).SaveAsync(stamp, default);
        var reloaded = await new FileCheckpointStore(path).LoadAsync(default); // "new process"

        Assert.Equal((DateTimeOffset?)stamp, reloaded);
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public async Task Missing_checkpoint_means_first_run()
    {
        Assert.Null(await new FileCheckpointStore(Path.Combine(_dir, "none.txt")).LoadAsync(default));
    }

    [Fact]
    public async Task Corrupt_checkpoint_fails_loudly_instead_of_silently_resyncing()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "checkpoint.txt");
        await File.WriteAllTextAsync(path, "garbage");

        await Assert.ThrowsAsync<InvalidDataException>(() => new FileCheckpointStore(path).LoadAsync(default));
    }

    [Fact]
    public async Task Dead_letters_are_appended_as_json_lines()
    {
        var path = Path.Combine(_dir, "dead.jsonl");
        Directory.CreateDirectory(_dir);
        var store = new FileDeadLetterStore(path);

        await store.AddAsync("{\"Id\":\"B1\"}", "invalid email", default);
        await store.AddAsync("{\"Id\":\"B2\"}", "missing name", default);

        var lines = await File.ReadAllLinesAsync(path);
        Assert.Equal(2, lines.Length);
        Assert.Equal("invalid email", JsonDocument.Parse(lines[0]).RootElement.GetProperty("reason").GetString());
    }
}

/// <summary>
/// Optional: talks to a REAL Salesforce SANDBOX to prove the credentials, Connected App setup and network
/// path work. Skipped automatically unless the environment variables below are set, and it refuses to run
/// against anything that does not look like a sandbox. Run only from the dev stage of the pipeline.
///   SF_INSTANCE_URL    e.g. https://yourco--dev.sandbox.my.salesforce.com   (must be a My Domain URL)
///   SF_CLIENT_ID / SF_CLIENT_SECRET   Connected App with the client-credentials flow enabled
/// </summary>
[Trait("Category", "LiveSalesforce")]
public class LiveSalesforceTests
{
    [SkippableFact]
    public async Task Real_sandbox_accepts_our_credentials_and_answers_a_query()
    {
        var url = Environment.GetEnvironmentVariable("SF_INSTANCE_URL");
        var id = Environment.GetEnvironmentVariable("SF_CLIENT_ID");
        var secret = Environment.GetEnvironmentVariable("SF_CLIENT_SECRET");

        Skip.If(string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(secret),
            "Set SF_INSTANCE_URL, SF_CLIENT_ID and SF_CLIENT_SECRET to run against a Salesforce sandbox.");
        Skip.IfNot(url.Contains(".sandbox.", StringComparison.OrdinalIgnoreCase),
            "Refusing to run live tests against a non-sandbox org.");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        var client = new SalesforceClient(http, new SalesforceOptions
        {
            InstanceUrls = new[] { new Uri(url) },
            ClientId = id,
            ClientSecret = secret
        });

        var rows = new List<JsonElement>();
        await foreach (var row in client.QueryAsync("SELECT Id FROM Organization LIMIT 1")) rows.Add(row);

        Assert.Single(rows); // every org has exactly one Organization row: proves auth + connectivity
    }
}
