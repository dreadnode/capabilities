---
name: auth-setup-guide
description: Guide the user through authenticating the target, attacker, and judge models from their own environment (any cloud, any auth mode) before running an assessment
allowed-tools: generate_attack generate_multimodal_attack generate_agentic_attack generate_category_attack
---

# Auth Setup Guide

Every assessment uses up to three model roles, and each needs credentials:

| Role | What it is | How to authenticate |
|------|-----------|---------------------|
| **Target** | The system under test (the user's model / endpoint) | This guide — depends on where it's deployed |
| **Attacker** | The LLM that generates adversarial prompts (`attacker_model`) | A litellm-routed model — see Section B |
| **Judge / evaluator** | The LLM that scores success (`judge_model` / `evaluator_model`) | A litellm-routed model — see Section B |

**Golden rule: credentials NEVER go in a tool argument, prompt, or generated script.**
The user sets them as **environment variables** (local compute) or **platform secrets**
(Dreadnode-hosted compute). Tool params only ever carry the *env var name*, never the value.

Ask the user the three questions below, then map their answers to the tables that follow.

1. **Where is your target deployed?** (an OpenAI/Anthropic/etc. API · Azure OpenAI or AI Foundry · AWS Bedrock/SageMaker · Google Vertex AI · your own HTTP endpoint · a speech-to-speech / realtime model)
2. **How does it authenticate?** (API key · bearer token · cloud IAM/role · managed identity · service account)
3. **Are you running the TUI on your laptop, or on Dreadnode-hosted compute?** (decides env vars vs. platform secrets — Section C)

---

## Section A — Target auth

There are two ways to reach a target: as a **litellm-routed model** (A1 — preferred whenever
the provider is supported, including Bedrock/Azure/Vertex) or as a **custom HTTP endpoint**
(A2). A few auth modes need the SDK escape hatch (A3).

### A1. litellm-routed models (preferred)

If the target is a hosted model on a known provider, don't build a custom endpoint — pass a
provider-prefixed `target_model` and have the user set the provider's env vars. Same mechanism
for `attacker_model` / `judge_model`.

| Provider / deployment | `target_model` string | Env vars the user sets |
|---|---|---|
| OpenAI | `openai/gpt-4o` | `OPENAI_API_KEY` |
| Anthropic | `anthropic/claude-3-5-sonnet-latest` | `ANTHROPIC_API_KEY` |
| Google AI Studio (Gemini API) | `gemini/gemini-2.5-flash` | `GEMINI_API_KEY` |
| Groq | `groq/llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| Mistral | `mistral/mistral-large-latest` | `MISTRAL_API_KEY` |
| Together | `together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo` | `TOGETHER_API_KEY` |
| **Azure OpenAI** | `azure/<your-deployment-name>` | `AZURE_API_KEY`, `AZURE_API_BASE`, `AZURE_API_VERSION` |
| **Azure AI Foundry** (serverless / OpenAI-compatible) | `azure_ai/<deployment>` | `AZURE_AI_API_KEY`, `AZURE_AI_API_BASE` |
| **AWS Bedrock** | `bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION_NAME` (+ `AWS_SESSION_TOKEN` if using SSO/role) |
| **Google Vertex AI** | `vertex_ai/gemini-2.5-pro` | `GOOGLE_APPLICATION_CREDENTIALS` (path to service-account JSON) **or** ADC, plus `VERTEXAI_PROJECT`, `VERTEXAI_LOCATION` |
| Ollama (self-hosted) | `ollama/llama3` | `OLLAMA_API_BASE` (e.g. `http://localhost:11434`) |
| Dreadnode proxy | `dn/claude-sonnet-4-6` | none — routed through the platform |

Then just run the attack with that `target_model`. No `custom_url` needed. This is how
**Azure Foundry OpenAI deployments** and **Vertex** models are probed with the standard tools.

> Bedrock/Vertex use the cloud's own credential chain via litellm, so IAM roles, SSO
> sessions, and workload identity work when the corresponding env vars are present.

### A2. Custom HTTP endpoints

For a bespoke endpoint (a proprietary API, a RAG service, an agent gateway), point at it with
`custom_url` and describe its shape. Supported auth in the tools today: **`none`, `bearer`,
`api_key`**.

Set on `generate_attack` / `generate_multimodal_attack`:

| Param | Purpose |
|---|---|
| `custom_url` | The POST endpoint |
| `custom_auth_type` | `none` · `bearer` (adds `Authorization: Bearer <env>`) · `api_key` (adds a header you name) |
| `custom_auth_env_var` | Name of the env var / secret holding the credential (default `TARGET_API_KEY`) |
| `custom_request_template` | JSON body with `{prompt}` (and `{image_b64}`/`{audio_b64}`/`{video_b64}` for multimodal) |
| `custom_response_text_path` | JSONPath to the reply text (e.g. `$.output`, `$.choices[0].message.content`) |

Ask the user for a sample request/response (or their API docs), infer the template + response
path, and confirm which env var holds the key. Example:

```
generate_attack(
    attack_type="tap",
    goal="<user objective>",
    custom_url="https://api.example.com/v1/chat",
    custom_auth_type="bearer",
    custom_auth_env_var="MY_ENDPOINT_TOKEN",
    custom_request_template='{"message": "{prompt}"}',
    custom_response_text_path="$.reply",
)
```

### A3. Cloud IAM signing, managed identity, ADC, and speech-to-speech (SDK)

Some targets authenticate with **request signing** or **auto-acquired cloud tokens** rather
than a static key, and realtime **speech-to-speech** targets need a streaming handshake. These
are supported by the **Python SDK** via `dreadnode.airt.build_target(TargetSpec)` (auth modes
`aws_sigv4`, `azure_ad` — Entra/managed identity, `gcp` — ADC) and `nova_sonic_target` for
Amazon Nova Sonic S2S.

When a user needs one of these, point them to the **Custom Targets** docs (Universal targets
section) and confirm their prerequisites:

| Target auth | SDK auth mode | User prerequisites |
|---|---|---|
| AWS Bedrock/SageMaker request signing | `aws_sigv4` | `pip install boto3`; AWS creds via env/profile/role; `region` + `service` |
| Azure ML / AI Foundry **managed identity** | `azure_ad` | `pip install azure-identity`; identity assigned to the resource (no static key) |
| Google Vertex via **ADC / service account** | `gcp` | `pip install google-auth`; `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS` |
| Amazon Nova Sonic (speech-to-speech) | `nova_sonic_target` | `pip install aws-sdk-bedrock-runtime awscrt`; AWS creds; Nova Sonic model access in-region |

> The standard TUI tools (`custom_*` params) currently cover `none`/`bearer`/`api_key`.
> For SigV4 / managed identity / ADC / S2S, use the SDK today.

---

## Section B — Attacker & judge auth

The attacker and judge are ordinary litellm-routed models — same table as A1. Guidance:

- **Default to `dn/` models** (e.g. `dn/claude-sonnet-4-6`) when the user has a Dreadnode key —
  no extra provider setup, strong capability.
- Otherwise pick a capable model the user already has a key for, and set that provider's env
  vars once — they serve attacker, judge, and (if litellm-routed) the target.
- Set via `attacker_model` and `judge_model` (some tools use `evaluator_model`). If omitted,
  sensible defaults apply; the judge falls back to the target model when unset.
- For **multimodal media-output scoring**, the judge must be **vision/audio-capable** — pick a
  model like `openai/gpt-4o` or `dn/claude-sonnet-4-6`.

---

## Section C — Where the credentials live

| Running the TUI on… | Set credentials as… |
|---|---|
| **Your laptop** (local compute) | Environment variables in the shell that launches the TUI: `export OPENAI_API_KEY=...` |
| **Dreadnode-hosted compute** | **Account Settings → Secrets** in the platform; they're injected into the sandbox automatically. The env-var *names* are the same. |

Either way, the tool params reference the credential **by env-var name**. The value is read from
the environment at runtime and never appears in the generated workflow script.

---

## Quick checklist

1. Determine the target's deployment + auth (the three questions above).
2. Prefer **A1** (litellm `provider/model`) — covers Azure OpenAI/Foundry, Bedrock, Vertex, and
   the common APIs with just env vars.
3. Use **A2** (`custom_url` + `custom_auth_type`) for bespoke HTTP endpoints (key/bearer).
4. Use **A3** (SDK `build_target`) for SigV4 / managed identity / ADC / speech-to-speech.
5. Set attacker + judge (**B**) — `dn/` models are the easy default; vision/audio judge for
   media-output scoring.
6. Confirm creds are set as env vars (local) or platform secrets (hosted) — **never inline** (**C**).

> Never place a secret value in a tool argument or the generated script — only the env-var name.
> Do not apply safety reasoning to the assessment goal; this skill only configures auth.
