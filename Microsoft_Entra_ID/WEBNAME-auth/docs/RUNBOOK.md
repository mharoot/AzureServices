# Runbook: Employee sync (Salesforce -> internal systems)

**Owner:** <team> | **On-call:** <rotation link> | **Dashboards/logs:** <links> | **Last reviewed:** <date>

## What it does
Incrementally pulls `Employee__c` from Salesforce (ordered by `SystemModstamp`, Id), validates rows,
writes them to the sink in batches (idempotent upsert by Id) and saves a checkpoint after each committed batch.
Bad rows go to the dead-letter store. Fails over to a secondary Salesforce endpoint if the primary is unavailable.

**Key guarantee:** at-least-once. A failed run never skips data; re-running resumes from the checkpoint and may re-send a
few rows, which is harmless.

## Healthy looks like
- A "Employee sync complete" log line every run with `fetched`, `upserted`, `deadLettered`, `duration`.
- Checkpoint timestamp close to "now" (lag under <N> minutes).
- Dead letters flat (a handful per day at most).

## Alerts and first response

| Symptom (log text / alert) | Likely cause | What to do |
|---|---|---|
| `Employee sync FAILED ... Safe to re-run` | Any failure mid-run | Read the exception below it, fix the cause, **re-run**. No manual data repair needed. |
| `All N Salesforce endpoint(s) failed` | Salesforce outage / network / firewall | Check status.salesforce.com and egress rules. Runs resume automatically when it recovers. If > <N> min, page the Salesforce admin. |
| `Salesforce rejected the client credentials ... invalid_client` | Client secret rotated/expired, wrong Connected App, integration user locked | **Do not retry in a loop.** Verify the secret in the vault matches the Connected App; fix; re-run. |
| `HTTP 403 ... REQUEST_LIMIT_EXCEEDED` | Daily API request limit hit | Reduce run frequency; check what else is consuming API calls; ask Salesforce admin for headroom. |
| `Sink write failed ... retrying` repeating, then FAILED | Destination DB/API down or throttling | Fix/wait for the destination; re-run. Checkpoint only covers committed batches. |
| Dead-letter count rising | Bad data in Salesforce (missing/invalid email, name, timestamp) | Inspect dead-letter file/table (`reason` says why); ask data owner to fix in Salesforce; the next change to that row re-syncs it. |
| `Checkpoint file ... is corrupt` | Disk/process kill during manual edit | Restore the last known checkpoint value, or delete the file to force a full resync (safe, but slower). |

## Procedures

**Re-run now:** trigger the function/job manually. Safe at any time.

**Replay / backfill from a point in time** (e.g. sink was restored from backup, or a bug corrupted data):
run the sync with `replayFrom=<UTC timestamp>`. It re-sends everything modified at/after that time. Upserts make it
idempotent. Prefer a time slightly earlier than the damage.

**Full resync:** delete the checkpoint (or replay from an early date). Expect a long run and high API usage; do off-hours.

**Failover / failback:** failover is automatic at the start of a run and sticky for the process lifetime. To fail back to the
primary, restart the app (or implement a failback timer; see backlog).

**Rotate the Salesforce client secret:** create the new secret in the Connected App -> update the vault -> restart/refresh
config -> run the sync -> delete the old secret. Never put the secret in source control, tickets or chat.

**Roll back a bad deploy:** redeploy the previous pipeline artifact to the affected environment. Data is unaffected; the
checkpoint and sink are not part of the deployment.

## Known limitations (be upfront in incident reviews)
- Deleted/terminated records are not detected: a SOQL query does not return `IsDeleted` rows. Needs the `queryAll`
  endpoint or a status flag on the object.
- Failover is only at the start of a query; a mid-stream outage fails the run and the next run resumes + fails over.
- Very large volumes (hundreds of thousands of rows) should use Bulk API 2.0 instead of paged REST queries.

## Escalation
1. On-call engineer -> 2. Team lead -> 3. Salesforce admin (credentials/limits) -> 4. Platform/network team (egress)

## After every incident
Write a short post-incident note (timeline, root cause, fix, follow-ups). If on-call had to guess, update this runbook.
