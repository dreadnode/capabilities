# Leadership Demo — "The Ultralytics Moment"

A realistic, narratable walkthrough built around a real-world incident ReversingLabs leadership will immediately recognize. Shows Spectra Assure as the *only* SCA-class tool that would have caught it — and shows Dreadnode operationalizing it into an autonomous workflow, not a chatbot with a scanner bolted on.

## Why this demo

In **December 2024**, the `ultralytics` PyPI package — the most widely deployed YOLO computer-vision library, >60M downloads — was compromised via a GitHub Actions cache-poisoning attack. Versions `8.3.41` and `8.3.45` shipped with a cryptominer payload. Traditional SCA tools (Snyk, Dependabot, OSS Review Toolkit) missed it at release time because the vulnerability wasn't a known CVE and the manifest metadata looked clean. The package's *behavior* had changed — new network endpoints, a new binary dropper — and that's exactly what Spectra Assure's differential analysis is built to detect.

This demo reconstructs the scenario as if the Dreadnode agent had been running in a customer's pre-merge CI gate on **December 5, 2024, at 14:22 UTC** — roughly two hours after `8.3.41` went live on PyPI.

The pitch is one line: *"This is what Spectra Assure catches. This is what Dreadnode turns it into."*

## The Scenario

**Customer:** A mid-size ML platform company (think "Scale AI" archetype). 80 engineers, weekly release cadence, heavy PyPI consumption. They've licensed Spectra Assure Enterprise and have Dreadnode deployed in their engineering org for agent-driven security workflows.

**Trigger:** Dependabot opens PR #4821 — *"Bump ultralytics from 8.3.40 to 8.3.41"* — as part of its weekly minor-version sweep. The PR passes lint, unit tests, and the existing SCA checks (Snyk shows no new CVEs). Under the old workflow, this merges on Monday morning.

**What happens instead:** The repo's pre-merge CI invokes the Dreadnode Supply Chain Analyst agent against the updated `pyproject.toml`.

## The Agent Run (narrated)

### Step 1 — Manifest scan

Agent call:

```
rl_protect_scan_manifest(
  manifest_path="/project/pyproject.toml",
  report_name="pr-4821-manifest",
  profile="hardened",
  check_deps="release,transitive",
)
```

Response (abridged):

```json
{
  "report_id": "rpt_01HF8K2MPJ9VB7Q3ZNRXT4AYWE",
  "summary": { "reject": 1, "warn": 3, "pass": 217 },
  "packages": [
    {
      "purl": "pkg:pypi/ultralytics@8.3.41",
      "recommendation": "REJECT",
      "reasons": ["behavioral_deviation", "unexpected_network_io", "suspicious_dropper"]
    },
    ...
  ]
}
```

The agent does not stop at the summary. It pivots.

### Step 2 — Differential analysis (the moment that matters)

```
rl_protect_diff_behavior(
  package="ultralytics",
  old_version="8.3.40",
  new_version="8.3.41",
)
```

Response (abridged):

```
Behavioral deltas 8.3.40 → 8.3.41:
  + Outbound HTTP POST to connect.ultralytics-apis[.]com on import
  + Base64-decoded payload written to /tmp/.ul_cache/runtime.bin
  + New dynamic loader invocation (dlopen) not present in prior 40 releases
  + CPU-intensive thread spawned post-import (cryptominer signature match)
  - (no removals)
```

This is the evidence no signature-based SCA has. Traditional tools see *"version bumped, no new CVE, tests pass"*. Spectra Assure sees *"the compiled behavior of this library changed in ways that are statistically indistinguishable from known cryptominer families."*

### Step 3 — Enrichment

```
rl_protect_interpret(report_id="rpt_01HF8K2MPJ9VB7Q3ZNRXT4AYWE", task="indicators", package="ultralytics")
rl_protect_interpret(report_id="rpt_01HF8K2MPJ9VB7Q3ZNRXT4AYWE", task="malware",    package="ultralytics")
```

The agent pulls the specific IOCs (domain, SHA256, YARA match) and binds them to the `report_id` for auditability.

### Step 4 — The Output

The agent comments on PR #4821 **and** files a P0 incident in Linear. The PR comment:

---

> **Supply Chain Analyst — DO NOT MERGE**
>
> **Immediate kill:** `ultralytics@8.3.41` — behavioral differential vs. `8.3.40` shows cryptominer-class indicators (outbound C2 to `connect.ultralytics-apis[.]com`, dynamic loader invocation, post-import miner thread). This is consistent with a **package compromise**, not a legitimate release.
>
> **Action required now:**
> 1. Close this PR. Pin `ultralytics` to `==8.3.40` until upstream issues a verified-clean release.
> 2. Audit any developer machine or runner that already pulled `8.3.41` today (install logs, `pip list`).
> 3. Block PyPI access to `ultralytics>=8.3.41,<8.3.46` at the artifact proxy.
>
> **Evidence:** Spectra Assure report `rpt_01HF8K2MPJ9VB7Q3ZNRXT4AYWE`. IOCs attached.
>
> **Other findings on this PR:** 3 warns (transitive CVEs in `numpy`, `pillow`, `urllib3`) — separate comment with pin-and-monitor tier.

---

And the executive summary, posted to the security Slack channel:

```
Project: ml-platform-backend
Scanned: 221 packages (4 direct upgrades, 217 transitive)  Profile: hardened
Verdict: DO NOT SHIP
Immediate kills: 1    Pin-and-monitor: 3    Accepted: 217
Top risk: ultralytics@8.3.41 — behavioral diff matches cryptominer pattern; PR blocked, upstream compromise suspected.
Attestation: Spectra Assure report rpt_01HF8K2MPJ9VB7Q3ZNRXT4AYWE
```

## Why this lands with ReversingLabs leadership

The demo maps to the three things any security-vendor exec cares about when evaluating an agent-platform partnership:

1. **It shows the technology's unique moat.** Everything in this walkthrough that *matters* — the behavioral delta, the dropper signature, the cryptominer pattern match — comes from Spectra Assure's binary analysis. Remove Spectra Assure and the agent is running Snyk; the PR merges and the customer gets owned.
2. **It shows the GTM story.** This is the *CISO-report-in-an-hour* story their field team has been telling on whiteboards. An autonomous analyst that cites Spectra Assure `report_id`s turns the platform from "scanner you wire into CI" into "answer you put on a board deck."
3. **It shows scale.** The exact same agent runs across every PR in the org, every hour, with `report_id` provenance for every finding. That's the compliance-attestation flywheel (NIST SSDF PW.4.1, EO 14028 SBOM attestation) their enterprise accounts actually buy on.

## What to say when you run it live

Close with one sentence: *"Your customers already have Spectra Assure. This is what happens when you give it an operator."*

## Backup scenarios (if leadership wants variety)

- **`xz-utils` / CVE-2024-3094** — same tampering-via-behavioral-diff story at the OS-package layer. Good for infra-heavy customers.
- **`ctx` / `phpass` (PyPI, 2022)** — earlier dependency confusion + credential-exfiltration compromise. Good origin-story example; shows the attack class isn't new.
- **`tj-actions/changed-files` (GitHub Actions, March 2025)** — CI supply chain, not a PyPI package. Use if the customer's threat model is build-system-first rather than runtime-dependency-first.

All three can be re-narrated with the same four-step agent workflow; only the `rl_protect_diff_behavior` payload changes.
