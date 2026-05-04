---
name: data-ingestion
description: Push SharpHound / AzureHound collection data into a BloodHound Enterprise deployment, monitor the ingest pipeline, and confirm the graph is updated. Use when the caller has fresh collection output to load, when the deployment's posture data is stale, or when the caller asks "ingest these files", "upload SharpHound output", "push collection data".
---

# Data ingestion

BHE's analysis is downstream of its data. Stale or partial data produces stale or partial findings. The ingest path turns SharpHound zips and AzureHound JSON into graph state — and it has predictable failure modes (file format mismatches, partial uploads, processing backlog) that this skill walks the agent through avoiding.

## Preconditions

- `bhe-bootstrap` has run.
- Collection files are reachable from the runtime (a path on disk, not a URL).

## Workflow

### 1. Validate the collection files

For each file:

- Confirm it's a regular file the runtime can read.
- Confirm the extension matches an accepted type — call `accepted_upload_types` once at the start and use the result as ground truth (BHE evolves the list).

Common shapes:

- `<computer>_BloodHound.zip` — SharpHound bundle.
- `<computer>_<timestamp>.json` — AzureHound output.

Reject obvious non-collection files (text reports, source archives) before opening a job. The API will reject them too, but the failure is more annoying than the rejection.

### 2. Open a job

Call `create_file_upload_job` once. The response carries the job id; capture it. One job covers many files — don't open a fresh job per file unless the caller wants the ingestion phases isolated.

### 3. Upload each file

For each file, call `upload_collection_file(job_id, path)`. Watch for:

- HTTP 4xx: the file format is wrong, the job is closed, or the deployment doesn't accept that type. Surface the error per file; don't abort the whole job for one bad file.
- Slow uploads: collection files can be hundreds of MB. The runtime's default timeout (30s) is too tight; pass an explicit timeout per file when uploading large bundles. (The agent doesn't have a timeout-override tool in v0.1; for now, split large files into chunks if upload fails — SharpHound supports `--SplitJsonOutput`.)

Track the per-file outcomes — successful uploads should report a non-zero size and a `status: uploaded`.

### 4. Close the job

Call `end_file_upload_job(job_id)`. This signals BHE to start ingesting the uploaded files. Until you close the job, files sit in pending state and aren't processed.

### 5. Monitor processing

Call `list_file_upload_jobs` periodically. The job's status transitions through Pending → Running → Complete (or Failed). Recommended cadence: poll every 30 seconds for the first 5 minutes, then every 2 minutes until the job reports a terminal state.

Don't hammer the endpoint — BHE rate-limits, and busy polling slows down everything else the agent might be doing in parallel.

### 6. Verify the graph absorbed the data

Once the job is Complete, call:

- `posture_snapshot` for each domain — the `captured_at` should be recent (post-ingest).
- `count_tag_members(tier_zero_tag_id)` — counts should reflect the new data.
- `domain_attack_paths(domain_sid)` — counts should reflect new findings if the analysis pass has run.

If the analysis pass hasn't run yet, the new graph state is loaded but findings haven't been recomputed. Either wait for the next scheduled cycle or trigger one explicitly via `start_attack_path_analysis`. Triggering eats CPU on the BHE side; coordinate with the operator before doing so.

### 7. Output

```
{
  "job_id": "...",
  "files": [
    { "name": "...", "size": ..., "status": "uploaded" | "rejected", "reason": "..." },
    ...
  ],
  "ingest_status": "Complete" | "Failed" | "Running",
  "graph_updated_at": "...",
  "tier_zero_delta": +2,
  "next_action": "wait for analysis cycle" | "run start_attack_path_analysis"
}
```

If any file failed, list the specific failures with their reasons — don't silently aggregate.

## Cost budget

- One `accepted_upload_types` call per session.
- One `create_file_upload_job` + one `end_file_upload_job` per ingest cycle.
- One upload per file (no retries on failure — failed uploads typically need operator action).
- Up to 10 `list_file_upload_jobs` poll calls before bailing on a stuck job.

## What NOT to do

- Don't auto-trigger `start_attack_path_analysis` after every ingest. It's CPU-intensive; let scheduled passes run, or coordinate explicitly.
- Don't upload partial collection runs. If the caller has SharpHound `--collectionmethod ACL` output but no `Group` or `Computer` results, the graph will be inconsistent.
- Don't try to recover failed uploads by replaying them mid-flight. Close the failed job, fix the root cause, open a new one.
- Don't attempt to delete or "fix up" graph state via Cypher to reflect what the upload should have produced. Re-collect and re-upload.
