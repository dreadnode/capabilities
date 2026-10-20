---
name: whitebox-local-surrogate
description: How to run white-box (gradient/embedding/activation) attacks, which need a local open-weight surrogate model the user supplies
allowed-tools: register_assessment generate_attack
---

# White-box attacks: local surrogate

White-box attacks (the GCG family, embedding-space, generator, and activation
attacks) do not just read the target's text - they optimize against model
internals (gradients, logits, hidden states). That requires a **local open-weight
surrogate model**, which the user provides. The optimized prompt then transfers to
the closed-box target (`dn/*` or BYO API) as usual.

Attacks that need a surrogate: `gcg`, `faster_gcg`, `i_gcg`, `attngcg`, `mask_gcg`,
`arca`, `gbda`, `pez`, `cold`, `soft_gcg`, `amplegcg`, `refusal_ablation`,
`soft_prompt`, `latentbreak`. (`autodan` is closed-box and needs no surrogate.)

## How to run one

Ask the user for the surrogate (a Hugging Face id or local path) and pass it as
`attacker_model`; keep the real model as `target_model`:

```
generate_attack(
    attack="gcg",
    goal="...",
    target_model="dn/claude-opus-4-6",        # closed-box transfer target
    attacker_model="meta-llama/Llama-2-7b-chat-hf",  # LOCAL open-weight surrogate
    evaluator_model="dn/claude-opus-4-6",
)
```

For `refusal_ablation` / `soft_prompt` / `latentbreak` (local-only: no transferable
text), the surrogate IS the attacked model and it is judged on its own generation.

## Requirements and guardrails

- **Local runtime only.** These need the surrogate's weights and (for 7B+) a GPU.
  The managed hosted sandbox has neither - run white-box attacks in a local or
  self-hosted runtime. If a `dn/*` model is passed as `attacker_model`, the SDK
  raises a clear error (no gradients over the inference proxy); switch to a local id.
- **Install the extra:** `pip install "dreadnode[whitebox]"` (torch + transformers).
- **Trust:** do not enable `trust_remote_code` for untrusted model repos (it runs
  code on load).
- **Resources:** 7B-scale surrogates need a GPU with ~80 GB; small models run on CPU
  for experimentation. `early_stopping_score` keeps cost bounded - easy targets exit
  fast; only hard ones run the full `n_iterations`.
- Prefer an **aligned open-weight** surrogate (e.g. Llama-2-7b-chat) for meaningful
  transfer; a tiny random model produces junk suffixes.

## When NOT to use

If the user only has a hosted model and no local weights/GPU, use closed-box attacks
instead (`tap`, `pair`, `crescendo`, `autodan`, ...). See the attack-selection-guide.
