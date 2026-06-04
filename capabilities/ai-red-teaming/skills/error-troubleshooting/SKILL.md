---
name: error-troubleshooting
description: Diagnose and fix common errors in AIRT attack generation, execution, and results collection
allowed-tools: generate_attack generate_agentic_attack execute_workflow inspect_results list_workflows
---

# Error Troubleshooting

Common errors and fixes for AIRT attack workflows.

## Model Errors

### "Model not found" / "Invalid model"
- **Cause**: Bare model name without provider prefix
- **Fix**: Always use `provider/model` format: `openai/gpt-4o`, `anthropic/claude-sonnet-4-20250514`
- **Aliases**: Use short aliases like `gpt-4o`, `claude`, `groq` — they auto-resolve

### "Rate limit exceeded" / 429
- **Cause**: Too many concurrent requests to the provider
- **Fix**: Reduce `n_iterations` or switch to a less rate-limited provider
- **For Groq**: Groq has strict rate limits. Use `groq/llama-3.3-70b-versatile` for lower limits

### "Authentication failed" / 401
- **Cause**: Missing or invalid API key for the provider
- **Fix**: Ensure the correct API key is set as a platform secret (OPENAI_API_KEY, ANTHROPIC_API_KEY, GROQ_API_KEY, etc.)
- **Check**: API keys are pre-configured in the environment. If missing, ask the user to add them via Settings > Secrets

### "Context length exceeded"
- **Cause**: Conversation history too long for model's context window
- **Fix**: Reduce `context_depth` or `n_iterations`, or switch to a model with larger context

## Transform Errors

### "Transform not found: <name>"
- **Cause**: Wrong transform name. Names must match TRANSFORM_DEFS exactly.
- **Fix**: Check the transform-reference skill for exact names
- **Common mistakes**: `base64_encode` → `base64`, `rot13_cipher` → `rot13`, `caesar_cipher` → `caesar`

### "Transform requires LLM but no transform_model"
- **Cause**: LLM-powered transforms (persuasion, language) need a model
- **Fix**: Set `transform_model` parameter, or it defaults to `attacker_model`
- **LLM transforms**: `adapt_language`, `code_switch`, `dialectal_variation`, `transliterate`, all persuasion, `role_play_wrapper`, `cognitive_hacking`, `skeleton_key_framing`, `many_shot_examples`

### "Invalid parameter for transform"
- **Cause**: Wrong parameter syntax
- **Fix**: Use parentheses: `caesar(5)`, `adapt_language(Zulu)`, `vigenere(SECRET)`, `affine(5,8)`

## Category Attack Errors

### "Unknown attack: 't'" / "Unknown attack: '['" (single characters)
- **Cause**: The `attacks` argument to `generate_category_attack` was iterated
  character-by-character. This happened when a bare string was passed and the
  runner looped over it directly (e.g. `"tap"` -> `'t'`, `'a'`, `'p'`).
- **Fix**: The runner now normalizes `attacks` via `_normalize_attack_names`,
  accepting a list (`["tap", "goat"]`), a comma-separated string
  (`"tap,goat"`), or a single name (`"tap"`). If you still see single-character
  attack errors, you are on an old build — update the capability.
- **Workaround (older builds)**: Run the category via per-goal `generate_attack`
  calls with `goal_category=<slug>` instead of `generate_category_attack`.
- **Signature to recognize**: the error lists all valid attacks but complains
  about a one-character name. That always means an iterable-splitting bug, not a
  genuinely unknown attack.

## Scorer Errors

### "Scorer not found: <name>"
- **Cause**: Wrong scorer name
- **Fix**: Check the scorer-reference skill for exact names
- **Common mistakes**: `memory_injection_detected` → `memory_injection`, `goal_hijack_detected` → `goal_hijacking`

## Execution Errors

### "Workflow execution timed out"
- **Cause**: Attack took longer than timeout (default 300s, max 600s)
- **Fix**: Increase timeout with `execute_workflow(filename, timeout=600)`, or reduce `n_iterations`
- **For long attacks**: `rainbow`, `autodan`, `beast` can take 10+ minutes. Use max timeout.

### "Syntax error in generated script"
- **Cause**: Code generation bug
- **Fix**: Regenerate with slightly different parameters. If persistent, try a different attack type.

### "ImportError: cannot import"
- **Cause**: SDK version mismatch or missing module
- **Fix**: This is an environment issue. Try a different attack that uses different SDK modules.

### "Connection refused" / "Network error"
- **Cause**: Sandbox can't reach the API or LLM provider
- **Fix**: Check SANDBOX_SERVER_URL configuration. For local dev, use `http://host.docker.internal:8000`

## Agentic Attack Errors

### "Agent endpoint returned 4xx/5xx"
- **Cause**: Wrong agent URL, auth, or request format
- **Fix**: Verify `agent_url`, `agent_auth_type`, and `agent_preset`. Test the endpoint manually first.

### "Could not extract response text"
- **Cause**: `agent_response_text_path` doesn't match the actual response structure
- **Fix**: Use `agent_preset` if the agent follows OpenAI/Anthropic format. For custom APIs, provide the correct JSONPath.

### "No tool calls in response"
- **Cause**: Agent didn't invoke tools (may not be a tool-using agent)
- **Fix**: Ensure the agent is tool-enabled. Use more aggressive transforms like `tool_restriction_bypass`.

## Results Issues

### "No analytics files found"
- **Cause**: Attack didn't complete or output directory is wrong
- **Fix**: Check `inspect_results(file_type="all")` to see what files exist

### "ASR is 0.0 but trials ran"
- **Cause**: No trials scored above threshold (0.5 default)
- **Fix**: This means the target defended well. Try different attacks or transforms.

### "0 trials completed"
- **Cause**: All trials errored or timed out
- **Fix**: Check for model/network errors. Reduce complexity (fewer transforms, simpler attack).

## Retry Strategy

1. **First failure**: Read the error message, adjust the specific parameter that failed
2. **Second failure**: Try a different model alias (e.g., full path instead of short alias)
3. **Third failure**: Simplify — fewer transforms, different attack type, lower iterations
4. **Still failing**: Try the simplest possible config: `generate_attack(attack_type="prompt", goal=..., target_model="openai/gpt-4o")` to verify basic connectivity
