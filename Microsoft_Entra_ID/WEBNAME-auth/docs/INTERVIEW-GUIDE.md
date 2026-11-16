# Interview guide: how this project maps to the role

## Be honest about what this is
Say it plainly: *"This is a reference project I built to practise the integration and operations patterns this role
uses. It runs against a simulated Salesforce, plus an optional live-sandbox test."* Interviewers respect that far more
than an overclaim, and every claim below is backed by code and tests you can open and walk through. Anything in the
"gaps" column, say you know it is the next step. Do not claim production experience you do not have.

You also have a second, real example from the same repo: the Entra ID sign-in (OAuth/OIDC, token validation, secrets,
unit tests, Selenium E2E). That is genuine back-end/security work and shows range.

## Responsibility -> evidence -> what to say

| Responsibility | Where it is in the repo | What to say |
|---|---|---|
| **APIs / integrations** (marketing <-> enterprise) | `SalesforceClient` (OAuth client-credentials, SOQL, REST paging); Entra callback controllers | "I integrate with a SaaS REST API behind an interface so the rest of the system never depends on vendor details, and I test it over real HTTP." |
| **Pagination** | `QueryAsync` streams `nextRecordsUrl` pages as `IAsyncEnumerable`; test `Authenticates_once_follows_every_page...` | "Streaming means memory stays flat for large result sets. I also only follow `nextRecordsUrl` if it stays on `/services/data/`, because I attach a bearer token to it." |
| **Batching** | `EmployeeSyncService` flushes every `BatchSize` rows; test with pages (7) and batches (10) deliberately misaligned | "Batch size is decoupled from page size, so each can be tuned independently." |
| **Replay and recovery** | Checkpoint saved only after the sink commits; `RunAsync(replayFrom)`; tests `Sink_outage_keeps...`, `A_Salesforce_outage_mid_stream...`, `Replay_reprocesses...` | "At-least-once delivery plus idempotent upserts. A crash re-reads but never skips. Replay is the same code path pointed at an earlier timestamp." |
| **Error handling** | Transient vs permanent vs auth exceptions; dead-letter store; no secrets in messages | "I classify failures: 429/5xx/timeouts retry with backoff; 4xx fail fast; bad credentials never retry because that can lock the integration user; bad rows are dead-lettered so one record cannot block the feed." |
| **Regional failover** | `FirstPageWithFailoverAsync`, sticky preference; tests for failover and all-down | "Failover at query start, because a pagination cursor belongs to one endpoint. Mid-stream failure fails the run and the checkpoint makes the retry cheap." |
| **Logging and monitoring** | Structured logs with RunId scope, counts, durations; test that secrets never appear in logs; runbook alert table | "Every run ends with one summary line; failures say whether it is safe to re-run." *(Gap: metrics/alerts not wired, see roadmap.)* |
| **Delivery** (source control, review, testing, change mgmt, dev/UAT/prod) | `.github/workflows/ci-cd.yml`, PR template | "Build once, promote the same artifact dev -> UAT -> prod; approvals via environments; PR template forces a rollback plan." *(Placeholders for the actual deploy steps.)* |
| **Operations** (incidents, durable fixes) | `docs/RUNBOOK.md`; the `>=` watermark decision; the token-refresh and failover design | "I write the runbook as I build, and fix causes rather than symptoms; the design notes in the code are the root-cause fixes for classic integration incidents." |
| **Testing** | 43 unit tests (auth) + ~25 integration tests (sync) + Selenium E2E + live sandbox test | "Unit for logic, integration over real HTTP for behaviour, E2E and live-sandbox for credentials and configuration." |

## Questions to be ready for (with the short answer)

1. **Why `>=` and not `>` on the watermark?** Rows can share a timestamp across a batch boundary; `>` would skip the
   unprocessed ones. `>=` re-sends the boundary row, and idempotent upserts make that harmless.
2. **At-least-once vs exactly-once?** True exactly-once across systems is impractical. At-least-once plus idempotent
   writes gives the same end state. Say that, and say upsert-by-key is what makes it safe.
3. **Why checkpoint after the write, not before?** If we crash between, we re-read (safe). The other order loses data.
4. **How do you avoid retry storms?** Exponential backoff with jitter, a retry cap, honour `Retry-After`, and no retry on
   permanent errors. Mention a circuit breaker as the next step (Polly).
5. **Failover design?** Ordered endpoints, sticky after failover, fail-back is a backlog item (timer or half-open probe).
6. **What if the sink is down for an hour?** Run fails after 3 attempts per batch, checkpoint holds, alert fires, re-run
   resumes. No data repair.
7. **Poison records?** Validate per row; dead-letter with a reason; continue; fix at source.
8. **How do you handle secrets?** Vault/env, never in code; errors and logs only show the OAuth error code; tested.
9. **How would you scale this up?** Bulk API 2.0 for large volumes, Change Data Capture / Platform Events instead of polling
   for near-real-time, queue between pull and write, parallelise by partition.
10. **What would you monitor?** Last-success age (lag), run duration, rows/run, dead-letter rate, retry count, failover events,
    API limit consumption. Alert on lag and on consecutive failures, not on single retries.
11. **What are the known weaknesses?** Deletes are not detected; failover is start-of-query only; no metrics yet. Saying this
    unprompted shows operational maturity.

## Roadmap: add these next (in this order)

1. **Serverless wrapper (about 1-2 hrs).** A timer-triggered Azure Function calling `EmployeeSyncService.RunAsync()` (this covers
   "serverless functions"). Sketch, untested:
   ```csharp
   public class EmployeeSyncFunction
   {
       private readonly EmployeeSyncService _sync;
       public EmployeeSyncFunction(EmployeeSyncService sync) => _sync = sync;

       [Function("EmployeeSync")]
       public Task Run([TimerTrigger("0 */15 * * * *")] TimerInfo timer, CancellationToken ct) => _sync.RunAsync(ct: ct);
   }
   ```
   Wire `SalesforceClient` via `IHttpClientFactory`, secrets from Key Vault references.
2. **A real sink (1-2 hrs).** SQL Server `MERGE` upsert in one transaction per batch, with `SqlException` transient-error retry.
   Add a test using a real SQL container (Testcontainers).
3. **Observability (1 hr).** Application Insights logger + custom metrics (rows, duration, lag, dead letters) and two alerts
   (no success in N minutes; 3 consecutive failures). Add a `/health` endpoint reporting last-success age.
4. **Internal dashboard (2-3 hrs).** A small page that shows last run, rows, lag, dead letters and a "re-run / replay from"
   button. This covers "internal dashboards", "front end" basics, and accessibility if you build it properly (labels, contrast, keyboard).
5. **API spec (30 min).** An OpenAPI document for a `POST /api/sync/replay?from=` endpoint, and a short README of the contract.
6. **Hardening.** Polly circuit breaker, fail-back timer, `queryAll` for deletions, structured metrics, CODEOWNERS and branch
   protection requiring one review plus a green pipeline.

## 5-minute demo script
1. `dotnet test` and show the green run (point at the test names; they read like a spec).
2. Open `Sink_outage_keeps_the_last_good_checkpoint...`: "I break the sink on batch 2, the run fails, the checkpoint stays at batch 1,
   I fix the sink and the re-run resumes; nothing lost or duplicated."
3. Open `Fails_over_to_the_secondary...`: "Primary returns 503; it retries, fails over, and sticks to the healthy endpoint."
4. Open `RUNBOOK.md`: "This is what on-call reads at 2 a.m."
5. Show the pipeline: "build once, promote the same artifact with approvals."
