---
name: attack-selection-guide
description: Decision tree for selecting AIRT attacks based on goals, target type, and constraints
allowed-tools: register_assessment save_workflow
---

# Attack Selection Guide

Use this decision tree to select the right attacks for an assessment.

## Step 1: Identify Target Type

### LLM / Chat Model
Any provider (OpenAI, Anthropic, Google, Groq, Mistral, Together, AWS Bedrock, Azure, Ollama, custom).
Use `get_generator("provider/model")` for target. All LLM jailbreak attacks apply.

### Agentic System (Tool-Using Agent)
Multi-step agents that call tools, access MCP servers, or interact with other agents.
Use `generate_agentic_attack` with the appropriate preset (`openai_assistants`, `anthropic`, `custom`).

### Custom API Endpoint
Any HTTP endpoint. Use `@task` with `httpx` to wrap. All attacks work if wrapper returns string.

### Vision Model / Classifier
Image adversarial attacks. Wrap in `@task` that returns classification label or confidence.

## Step 2: Select Attack Category

### Jailbreak Resistance

**Quick test (~50 queries):**
- `deep_inception_attack` — No attacker LLM needed, good baseline
- `renellm_attack` — ~15 queries, high ASR on GPT-4

**Standard campaign (~500 queries):**
- `tap_attack` — Best general-purpose, tree-search
- `pair_attack` — Query-efficient, 20 parallel streams
- `crescendo_attack` — Multi-turn, catches conversation-length weaknesses

**Thorough assessment (~2000+ queries):**
- All above plus: `goat_attack`, `autodan_turbo_attack`, `beast_attack`, `drattack`, `gptfuzzer_attack`, `rainbow_attack`

### Agentic Security (OWASP ASI01-ASI10)

**Tool-use manipulation:**
- Transforms: `tool_restriction_bypass`, `tool_parameter_injection`, `tool_chain_manipulation`, `tool_selection_manipulation`, `tool_output_interpretation_manipulation`
- Scorers: `tool_invoked`, `any_tool_invoked`, `tool_selection_safety`

**MCP attacks (ASI07):**
- Transforms: `tool_description_poisoning`, `cross_server_shadowing`, `rug_pull`, `tool_output_injection`, `schema_poisoning`, `ansi_cloaking`, `sampling_injection`, `mcp_csrf`, `mcp_resource_injection`, `mcp_notification_abuse`, `mcp_session_hijack`
- Scorers: `tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `tool_output_injected`, `schema_poisoned`, `ansi_cloaking`, `sampling_injection`

**Multi-agent attacks (ASI05, ASI08):**
- Transforms: `prompt_infection`, `peer_agent_spoofing`, `consensus_poisoning`, `delegation_exploit`, `a2a_protocol_smuggling`, `shared_memory_injection`, `agent_config_overwrite`, `multi_agent_session_injection`, `multi_agent_task_injection`, `multi_agent_escalation`
- Scorers: `prompt_infection`, `agent_spoofing`, `consensus_poisoned`, `delegation_exploit`, `session_smuggling`, `agent_config_overwrite`

**Memory/context manipulation:**
- Transforms: `agent_memory_injection`, `agent_context_overflow`, `agent_goal_hijacking`
- Scorers: `memory_injection_detected`, `context_overflow_detected`, `goal_hijack_detected`

### Browser Agent Attacks

- Transforms: `visual_prompt_injection`, `ai_clickfix`, `zombai_c2`, `browser_task_injection`, `browser_domain_bypass`, `navigation_hijack`, `phantom_ui`

### Exfiltration Testing

- Transforms: `markdown_image_exfil`, `mermaid_diagram_exfil`, `unicode_tag_exfil`, `dns_exfil`, `ssrf_exfil`, `link_unfurling_exfil`, `api_abuse_exfil`
- Scorers: `markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil`

### Reasoning/Chain-of-Thought Attacks

- Transforms: `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `crescendo_escalation`, `foot_in_the_door`, `deceptive_delight`, `goal_drift`
- Scorers: `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `escalation`, `goal_drift`

### Guardrail Bypass

- Transforms: `classifier_evasion`, `controlled_release`, `emoji_smuggle`, `payload_split`, `hierarchy_exploit`, `nested_fiction`

### IDE/Code Agent Attacks

- Transforms: `ide_command_injection`, `ide_context_poisoning`, `ide_output_manipulation`, `code_completion_hijack`, `ide_extension_spoofing`, `ide_workspace_manipulation`, `ide_terminal_injection`
- Scorers: `ide_command_injection`, `ide_context_poisoning`, `ide_output_manipulation`, `code_completion_hijack`, `ide_extension_spoofing`

### System Prompt Extraction

- Transforms: `direct_system_prompt_extraction`, `indirect_system_prompt_extraction`, `iterative_system_prompt_extraction`, `encoding_system_prompt_extraction`, `function_call_system_prompt_extraction`, `multi_turn_system_prompt_extraction`

### PII Extraction

- Transforms: `direct_pii_extraction`, `indirect_pii_extraction`, `social_engineering_pii_extraction`, `context_manipulation_pii_extraction`

### RAG Poisoning

- Transforms: `rag_context_injection`, `rag_retrieval_manipulation`, `rag_knowledge_conflict`, `rag_citation_spoofing`, `rag_chunk_boundary_exploit`, `rag_metadata_injection`, `rag_embedding_collision`

### Content Policy Coverage

- `rainbow_attack` — MAP-Elites covers risk×style grid automatically
- Supplement with `tap_attack` per category for depth on weak areas

### Image/Multimodal Robustness

- Decision-based: `hopskipjump_attack`
- Score-based: `nes_attack` (fast), `zoo_attack` (precise)
- Simple baseline: `simba_attack`
- Multimodal probing: `multimodal_attack`

## Step 3: Select Transforms

### Encoding / Obfuscation
`base64_encode`, `rot13`, `leetspeak`, `unicode_confusables`, `morse_code`, `hex_encoding`

### Persuasion / Social Engineering
`authority_appeal`, `emotional_appeal`, `logical_appeal`, `urgency`, `social_proof`, `reciprocity`

### Language / Cross-Lingual
`adapt_language`, `code_switch`, `dialectal_variation`, `transliterate`

### Cipher / Steganography
`caesar_cipher`, `atbash_cipher`, `vigenere_cipher`, `pig_latin`

### Prompt Engineering
`few_shot`, `chain_of_thought`, `persona`, `role_play`, `hypothetical`, `analogy`

### Injection
`direct_injection`, `indirect_injection`, `context_injection`

### Adversarial Suffix
`gcg_suffix`, `random_suffix`, `token_manipulation`

### Advanced Jailbreak
`multi_step_jailbreak`, `context_window_exploit`, `token_smuggling`, `instruction_hierarchy_attack`, `prompt_leaking`, `safety_fine_tuning_bypass`, `reward_hacking`, `constitutional_ai_bypass`, `rlhf_exploit`

### Agentic Workflow
`tool_restriction_bypass`, `tool_parameter_injection`, `tool_chain_manipulation`, `agent_memory_injection`, `agent_context_overflow`, `agent_goal_hijacking`, `multi_step_tool_exploit`, `tool_selection_manipulation`, `tool_output_interpretation_manipulation`, `agentic_persistence`, `agentic_lateral_movement`, `agentic_privilege_escalation`, `agentic_resource_abuse`

## Step 4: Assess Compute Budget

| Budget | Queries | Approach |
|--------|---------|----------|
| Minimal | ~50 | `deep_inception_attack` + `pair_attack(n_streams=5, n_iterations=2)` |
| Moderate | ~500 | `tap_attack` + `pair_attack` + `crescendo_attack` |
| Extensive | ~2000+ | Full campaign: TAP + PAIR + Crescendo + Rainbow + GOAT + AutoDAN |

## Step 5: Consider Known Defenses

| Defense | Effective Attacks |
|---------|------------------|
| Strong system prompt | `crescendo_attack`, `deep_inception_attack`, `drattack` |
| Output classifier | `beast_attack`, `autodan_turbo_attack`, `renellm_attack` |
| Rate limiting | `pair_attack` (most query-efficient), `deep_inception_attack` |
| Input sanitization | `beast_attack`, `drattack`, encoding transforms |
| Tool-call filtering | `tool_restriction_bypass`, `tool_parameter_injection`, `tool_chain_manipulation` |
| Content moderation | `classifier_evasion`, `payload_split`, `emoji_smuggle` |
| Conversation monitoring | `crescendo_escalation`, `foot_in_the_door`, `goal_drift` |

## Recommended Parameter Overrides

| Scenario | Parameter | Recommended |
|----------|-----------|-------------|
| Fast screening | `n_iterations` | 20-30 |
| Thorough test | `n_iterations` | 100+ |
| Weak target | `early_stopping_score` | 0.7 |
| Strong target | `early_stopping_score` | 0.95 |
| Budget constrained | `beam_width` | 3-5 |
| Diverse coverage | `beam_width` | 10+ |
| Multi-turn target | `context_depth` | 5-10 |
