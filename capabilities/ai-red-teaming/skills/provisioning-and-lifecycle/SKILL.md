---
name: provisioning-and-lifecycle
description: Provision a hosted target, pick the right endpoint per target type, tear down to stop billing, and interpret transient vs fatal errors. Load this whenever the user wants to provision/attack a bundled target (ml-extraction-*, *-mesh) or asks about environments, sandboxes, teardown, or billing.
allowed-tools: provision_environment teardown_environment list_environments generate_atlas_attack generate_evasion_attack generate_extraction_attack generate_membership_attack generate_inversion_attack register_assessment update_assessment_status
---

# Provisioning and Lifecycle

How to provision a hosted target, run against the right endpoint, and tear it down cleanly. The tool layer already handles resolution, endpoint selection, retries, and teardown - your job is to use the tool (never the CLI) and interpret its output correctly.

## 1. Provisioning decision tree

- User names a bundled/hosted task (`finops-mesh`, `ml-extraction-fraud-tabular`, `ml-extraction-mnist-image`, `ml-extraction-imdb-text`) -> call `provision_environment` with the BARE name.
- User gives an HTTP URL -> skip provisioning; go straight to `generate_agentic_attack` / `generate_atlas_attack`.
- NEVER run `dreadnode env ...` in a shell, and NEVER guess a `provision`/`create` subcommand. `provision_environment` is the only supported path and it resolves the catalog for you.

## 2. Task-ref resolution

A bare name resolves server-side to a task in your org OR any public task, so bundled public targets (`ml-extraction-*`, `*-mesh`) work by bare name with no extra qualification.

- Prefer the BARE name (`ml-extraction-fraud-tabular`). It resolves to the public catalog automatically.
- A task owned by another org resolves only when it is public or owned by you. If a bare name 404s, the task is private to another org (or the name/version is wrong) - qualifying it as `<org>/<name>` will NOT help, because the same visibility rule applies.
- Do NOT qualify a bundled task with the caller's own org (e.g. `aisf-learner-aug-2026/ml-extraction-imdb-text`) - it does not live there.
- If provisioning fails, the returned message is authoritative: report it. Do not invent qualification syntax or retry random forms.

## 3. Endpoint-per-target map (fixes /attack on a /predict classifier)

Read the `>>> NEXT STEP` line in `provision_environment` output and use exactly that endpoint. Never probe both `/attack` and `/predict` on one target.

- Mesh (`*-mesh`) -> serves `/attack` -> `generate_atlas_attack` with the execute token.
- Classifier (`ml-extraction-*`, tabular/image/text, mnist/fraud/imdb) -> serves `/predict` (+ `/pool`, `/members`, `/nonmembers`) -> `generate_evasion_attack` / `generate_extraction_attack` / `generate_membership_attack` / `generate_inversion_attack` with `api_url=<url>/predict`.

## 4. Teardown and billing

Every provision bills for its whole lifetime.

- Preferred: wrap the run in `register_assessment` -> attacks -> `update_assessment_status`. The sandbox is auto-torn-down once EVERY planned attack has been recorded, whether it passed or failed.
- Gotcha: if you abandon a planned attack without recording a status (e.g. you give up after an error), the assessment never reaches terminal and the sandbox is NOT auto-torn-down - it bills until its TTL. Always either record every planned attack or call `teardown_environment()` (no id = reap every environment from this session).
- Set `AIRT_ENV_TEARDOWN_GRACE_SEC` >= your longest attack timeout before running, so assessment-completion teardown does not kill an in-flight attack.

## 5. Transient vs fatal error interpretation

- A result starting with `Note:` = transient (TLS handshake / timeout / conn reset / 502-504), already auto-retried by the tool, and it did NOT affect any running attack or recorded result. Tell the user it was transient and re-run the step.
- A result starting with `Error:` = a non-fatal input/tool issue. Adjust params; do not blind-retry.
- A `404` from probing an endpoint is exploratory, not a failure - say what you learned and switch to the correct endpoint.
- A `404` on `GET environments/<id>/status` means the sandbox is already gone (torn down or expired). Treat it as "terminated" and STOP polling - it is not an error to surface.
- Never let a raw error be the last thing the user sees about a step that actually succeeded.

## 6. ASR display

ASR is stored 0-1 internally. Never format it yourself - report what the tool returns (it renders `1.0` as `100%`). If you ever read a raw fraction from JSON, multiply by 100 before showing it.

## 7. Attribution

Assessments are attributed to the operator via the platform auth context (org / workspace) and, where available, the `origin_user` on the assessment. If a per-user field is missing on an older assessment, attribute via org/workspace and cross-reference the `assessment_id` in platform audit logs - do not claim a field that is not present.
