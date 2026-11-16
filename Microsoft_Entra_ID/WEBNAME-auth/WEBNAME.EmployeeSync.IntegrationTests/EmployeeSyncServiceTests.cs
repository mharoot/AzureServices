using Xunit;

namespace WEBNAME.EmployeeSync.IntegrationTests;

/// <summary>
/// End-to-end sync behaviour: the real service, real client and real HTTP against FakeSalesforce,
/// with in-memory sink/checkpoint/dead-letter so failure modes can be scripted precisely.
/// </summary>
public class EmployeeSyncServiceTests : SyncTestBase
{
    private readonly InMemorySink _sink = new();
    private readonly InMemoryCheckpoint _checkpoint = new();
    private readonly InMemoryDeadLetters _dead = new();
    private readonly ListLogger<EmployeeSyncService> _log = new();

    private EmployeeSyncService NewService(SalesforceClient client = null, int batchSize = 10) =>
        new(client ?? NewClient(), _sink, _checkpoint, _dead,
            new EmployeeSyncOptions { BatchSize = batchSize, SinkMaxAttempts = 3 }, _log, RecordDelay);

    // ---------- happy path ----------

    [Fact]
    public async Task Full_sync_writes_everything_in_batches_and_checkpoints_the_newest_row()
    {
        var employees = MakeEmployees(25);
        Primary.Data.AddRange(employees);
        Primary.PageSize = 7; // pages and batches deliberately do not line up

        var result = await NewService(batchSize: 10).RunAsync();

        Assert.Equal(25, result.Fetched);
        Assert.Equal(25, result.Upserted);
        Assert.Equal(3, result.Batches);
        Assert.Equal(new[] { 10, 10, 5 }, _sink.BatchSizes);
        Assert.Equal(25, _sink.Store.Count);
        Assert.Equal((DateTimeOffset?)employees[^1].Modified, _checkpoint.Value);
    }

    [Fact]
    public async Task Maps_fields_and_parses_the_Salesforce_timestamp_format()
    {
        var modified = new DateTimeOffset(2024, 5, 1, 12, 30, 15, 123, TimeSpan.Zero);
        Primary.Data.Add(new FakeRecord("E1", "  Jane Doe ", "jane@example.com", "Engineering", modified));

        await NewService().RunAsync();

        var employee = _sink.Store["E1"];
        Assert.Equal("Jane Doe", employee.Name);
        Assert.Equal("jane@example.com", employee.Email);
        Assert.Equal("Engineering", employee.Department);
        Assert.Equal(modified, employee.LastModified); // "+0000" (no colon) parsed correctly
    }

    [Fact]
    public async Task No_changes_after_the_checkpoint_means_no_sink_calls_and_an_unchanged_checkpoint()
    {
        Primary.Data.AddRange(MakeEmployees(5));
        var future = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        _checkpoint.Value = future;

        var result = await NewService().RunAsync();

        Assert.Equal(0, result.Fetched);
        Assert.Equal(0, _sink.Calls);
        Assert.Equal((DateTimeOffset?)future, _checkpoint.Value);
    }

    // ---------- bad data ----------

    [Fact]
    public async Task Invalid_rows_are_dead_lettered_and_the_run_continues()
    {
        var t = new DateTimeOffset(2024, 5, 1, 8, 0, 0, TimeSpan.Zero);
        Primary.Data.AddRange(new[]
        {
            new FakeRecord("G1", "Good One", "g1@example.com", "Eng", t.AddSeconds(1)),
            new FakeRecord("B1", "No Email", null, "Eng", t.AddSeconds(2)),
            new FakeRecord("B2", "Bad Email", "not-an-email", "Eng", t.AddSeconds(3)),
            new FakeRecord("G2", "Good Two", "g2@example.com", "Eng", t.AddSeconds(4)),
        });

        var result = await NewService().RunAsync();

        Assert.Equal(4, result.Fetched);
        Assert.Equal(2, result.Upserted);
        Assert.Equal(2, result.DeadLettered);
        Assert.Equal(new[] { "G1", "G2" }, _sink.Store.Keys.OrderBy(k => k));
        Assert.Equal(2, _dead.Items.Count);
        Assert.All(_dead.Items, item => Assert.Contains("email", item.Reason, StringComparison.OrdinalIgnoreCase));
    }

    // ---------- recovery ----------

    [Fact]
    public async Task Sink_outage_keeps_the_last_good_checkpoint_and_a_rerun_recovers_everything()
    {
        var employees = MakeEmployees(25);
        Primary.Data.AddRange(employees);
        Primary.PageSize = 7;
        _sink.ShouldFail = call => call >= 2; // batch 1 succeeds, batch 2 fails on all 3 attempts

        await Assert.ThrowsAsync<InvalidOperationException>(() => NewService(batchSize: 10).RunAsync());

        Assert.Equal(4, _sink.Calls);                                   // 1 success + 3 failed attempts
        Assert.Equal(10, _sink.Store.Count);
        Assert.Equal((DateTimeOffset?)employees[9].Modified, _checkpoint.Value); // advanced only for committed rows
        Assert.Contains(_log.Lines, l => l.StartsWith("Error") && l.Contains("Safe to re-run"));

        // Sink is healthy again: re-run resumes from the checkpoint.
        _sink.ShouldFail = _ => false;
        var result = await NewService(batchSize: 10).RunAsync();

        Assert.Equal(EmployeeQuery.Build(employees[9].Modified), Primary.Queries.Last()); // resumed, not restarted
        Assert.Equal(25, _sink.Store.Count);                            // nothing lost, nothing duplicated
        Assert.Equal((DateTimeOffset?)employees[^1].Modified, _checkpoint.Value);
        Assert.Equal(16, result.Fetched);                               // 15 new rows + the boundary row (at-least-once)
    }

    [Fact]
    public async Task A_transient_sink_error_is_retried_without_failing_the_run()
    {
        Primary.Data.AddRange(MakeEmployees(25));
        _sink.ShouldFail = call => call == 2; // only the first attempt of batch 2 fails

        var result = await NewService(batchSize: 10).RunAsync();

        Assert.Equal(25, result.Upserted);
        Assert.Equal(4, _sink.Calls); // 3 batches + 1 retry
        Assert.Contains(TimeSpan.FromSeconds(1), Delays);
    }

    [Fact]
    public async Task A_Salesforce_outage_mid_stream_keeps_progress_and_the_next_run_finishes()
    {
        var employees = MakeEmployees(6);
        Primary.Data.AddRange(employees);
        Primary.PageSize = 2;
        Primary.Interceptor = ctx => FakeSalesforce.IsNextPage(ctx) ? new Fault(503) : null; // page 1 ok, then outage

        await Assert.ThrowsAsync<SalesforceTransientException>(() => NewService(batchSize: 2).RunAsync());

        Assert.Equal(2, _sink.Store.Count);
        Assert.Equal((DateTimeOffset?)employees[1].Modified, _checkpoint.Value);

        Primary.Interceptor = null; // Salesforce is back
        var result = await NewService(batchSize: 2).RunAsync();

        Assert.Equal(6, _sink.Store.Count);
        Assert.Equal((DateTimeOffset?)employees[5].Modified, _checkpoint.Value);
        Assert.Equal(5, result.Fetched); // resumed at the checkpoint row, not from the beginning
    }

    // ---------- incremental & replay ----------

    [Fact]
    public async Task Incremental_run_only_pulls_changes_since_the_checkpoint()
    {
        var employees = MakeEmployees(5);
        Primary.Data.AddRange(employees);
        await NewService().RunAsync();

        var newcomer = new FakeRecord("E9999", "New Hire", "new@example.com", "Sales", employees[^1].Modified.AddMinutes(10));
        Primary.Data.Add(newcomer);

        var result = await NewService().RunAsync();

        Assert.Equal(2, result.Fetched); // the boundary row + the new hire, not all 6
        Assert.True(_sink.Store.ContainsKey("E9999"));
        Assert.Equal((DateTimeOffset?)newcomer.Modified, _checkpoint.Value);
    }

    [Fact]
    public async Task Replay_reprocesses_history_idempotently()
    {
        var employees = MakeEmployees(10);
        Primary.Data.AddRange(employees);
        await NewService().RunAsync();

        var result = await NewService().RunAsync(replayFrom: employees[4].Modified);

        Assert.Equal(EmployeeQuery.Build(employees[4].Modified), Primary.Queries.Last());
        Assert.Equal(6, result.Fetched);        // rows 5..10 re-sent
        Assert.Equal(10, _sink.Store.Count);    // upserts: no duplicates
    }

    // ---------- failover through the whole pipeline ----------

    [Fact]
    public async Task Sync_completes_from_the_secondary_endpoint_when_the_primary_is_down()
    {
        await using var secondary = await FakeSalesforce.StartAsync();
        secondary.Data.AddRange(MakeEmployees(12));
        secondary.PageSize = 5;
        Primary.Down = true;

        var result = await NewService(NewClient(Primary, secondary)).RunAsync();

        Assert.Equal(12, result.Upserted);
        Assert.Equal(12, _sink.Store.Count);
    }
}
