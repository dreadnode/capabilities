---
name: attack-selection-guide
description: Decision tree for selecting AIRT attacks based on goals, target type, and constraints
allowed-tools: register_assessment generate_attack generate_agentic_attack generate_category_attack
---

# Attack Selection Guide

Use this decision tree to select the right attacks for an assessment.

## Step 1: Identify Target Type

### LLM / Chat Model
Any provider (OpenAI, Anthropic, Google, Groq, Mistral, Together, AWS Bedrock, Azure, Ollama, custom).
Use `generate_attack` with `target_model="provider/model"`. All jailbreak attacks apply.

### Agentic System (Tool-Using Agent)
Multi-step agents that call tools, access MCP servers, or interact with other agents.
Use `generate_agentic_attack` with the appropriate preset (`openai_assistants`, `anthropic`, `custom`).

### Custom API Endpoint
Any HTTP endpoint. Use `generate_agentic_attack` with `agent_preset="custom"` and provide request/response templates.

## Step 2: Select Attack Algorithm

### Jailbreak Resistance

**Quick test (~50 queries):**
- `deep_inception` — No attacker LLM needed, good baseline
- `renellm` — ~15 queries, high ASR on GPT-4

**Standard campaign (~500 queries):**
- `tap` — Best general-purpose, tree-search
- `pair` — Query-efficient, 20 parallel streams
- `crescendo` — Multi-turn, catches conversation-length weaknesses

**Standard+ campaign (~500-1000 queries):**
- `autoredteamer` — Dual-agent with strategy memory, beam search
- `refusal_aware` — Learns from refusal patterns to bypass defenses
- `cot_jailbreak` — Exploits chain-of-thought reasoning
- `persona_hijack` — Persona-based attacks with evolutionary search

**Thorough assessment (~2000+ queries):**
- All above plus: `goat`, `goat_v2`, `autodan`, `beast`, `drattack`, `gptfuzzer`, `rainbow`
- Advanced: `jbfuzz`, `jbdistill`, `templatefuzz`, `genetic_persona`, `tmap_trajectory`
- Campaign: `attack_type="tap,pair,crescendo,goat,autoredteamer,rainbow"`

### Content Policy Coverage
- `rainbow` — MAP-Elites covers risk×style grid automatically
- Supplement with `tap` per category for depth on weak areas
- Use `generate_category_attack` for systematic category sweeps

## Step 3: Select Transforms by Threat Category

### Encoding / Obfuscation
`base64`, `base32`, `hex`, `binary`, `leetspeak`, `morse`, `url_encode`, `html_entity`, `unicode_escape`, `zero_width_encode`, `upside_down`, `braille`, `ascii85`, `homoglyph`, `unicode_font`, `pig_latin`, `octal`

### Cipher / Steganography
`caesar` (or `caesar(5)`), `rot13`, `rot47`, `atbash`, `vigenere(key)`, `rail_fence(3)`, `substitution`, `affine(5,8)`, `playfair(KEY)`, `bacon`, `beaufort(key)`, `autokey(key)`

### Persuasion / Social Engineering
`authority_appeal`, `emotional_appeal`, `logical_appeal`, `urgency_scarcity`, `social_proof`, `reciprocity`, `commitment_consistency`, `combined_persuasion`

### Language / Cross-Lingual (LLM-powered)
`adapt_language(Zulu)`, `adapt_language(Welsh)`, `code_switch`, `dialectal_variation(AAVE)`, `transliterate(cyrillic)`, `transliterate(greek)`

### Perturbation
`simulate_typos`, `unicode_confusable`, `payload_splitting`, `zero_width`, `emoji_substitution`, `random_capitalization`, `zalgo`, `cognitive_hacking`, `token_smuggling`, `encoding_nesting`

### Injection
`skeleton_key_framing`, `many_shot_examples`, `position_variation`, `position_wrap`

### Text Manipulation
`prefix(text)`, `suffix(text)`, `reverse`, `word_join(_)`, `char_join(-)`

### Stylistic
`role_play_wrapper`, `ascii_art`

### Adversarial Suffix
`adversarial_suffix`, `gcg_suffix`, `jailbreak_suffix`, `flip_attack`, `suffix_sweep`, `iris_refusal_suppression`, `largo_suffix`

### Advanced Jailbreak
`actor_network_escalation`, `code_completion_evasion`, `context_fusion`, `deep_fictional_immersion`, `guardrail_dos`, `likert_exploitation`, `pipeline_manipulation`, `prefill_bypass`, `reasoning_chain_hijack`, `sockpuppeting`, `adversarial_poetry`, `content_concretization`, `cka_benign_weave`, `involuntary_jailbreak`, `immersive_world`, `metabreak_special_tokens`

### Guardrail Bypass
`classifier_evasion`, `controlled_release`, `emoji_smuggle`, `payload_split`, `hierarchy_exploit`, `nested_fiction`

### Response Steering
`affirmative_priming`, `constraint_relaxation`, `output_format_manipulation`, `protocol_establishment`, `task_deflection`

### MCP Attacks (OWASP ASI07)
Transforms: `tool_description_poison`, `cross_server_shadow`, `rug_pull_payload`, `tool_output_injection`, `schema_poisoning`, `ansi_escape_cloaking`, `mcp_sampling_injection`, `cross_server_request_forgery`, `tool_squatting`, `tool_preference_manipulation`, `log_to_leak`, `resource_amplification`, `implicit_tool_poison`, `tool_chain_sequential`, `tool_commander`, `zero_click_injection`, `calendar_invite_injection`, `confused_deputy`, `full_schema_poison`, `tool_chain_cost_amplification`
Scorers: `tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `tool_output_injected`, `schema_poisoned`, `ansi_cloaking`, `sampling_injection`, `implicit_tool_poison_detected`

### Multi-Agent Attacks (ASI08, ASI10)
Transforms: `prompt_infection`, `peer_agent_spoof`, `consensus_poisoning`, `delegation_chain_attack`, `shared_memory_poisoning`, `agent_config_overwrite`, `experience_poisoning`, `trust_exploitation`, `persistent_memory_backdoor`, `query_memory_injection`, `zombie_agent`, `contagious_jailbreak`, `mad_exploitation`, `agent_in_the_middle`, `multi_agent_prompt_fusion`, `minja_progressive_poisoning`, `memorygraft_experience_poison`, `injecmem_single_shot`, `graphrag_entity_poison`, `recursive_delegation_dos`, `sleeper_agent_activation`, `meaning_drift_propagation`, `stitch_authority_chain`
Scorers: `prompt_infection`, `agent_spoofing`, `consensus_poisoned`, `delegation_exploit`, `session_smuggling`, `agent_config_overwrite`

### Agentic Workflow Attacks (ASI03, ASI05)
Transforms: `tool_restriction_bypass`, `phase_transition_bypass`, `tool_priority_injection`, `intent_manipulation`, `session_state_injection`, `action_hijacking`, `cypher_injection`, `delayed_tool_invocation`, `exploitation_mode_confusion`, `malformed_output_injection`, `phase_downgrade_attack`, `sql_via_nlp_injection`, `success_indicator_spoof`, `todo_list_manipulation`, `tool_chain_attack`, `wordlist_exhaustion`, `workflow_step_skip`, `payload_target_mismatch`
Scorers: `tool_invoked`, `any_tool_invoked`, `tool_selection_safety`, `tool_sequence`, `tool_count`, `dangerous_tool_args`, `phase_bypass`, `phase_downgrade`, `tool_priority_manipulation`, `tool_restriction_bypass`, `agentic_workflow`, `workflow_disruption`

### Agent Skill Attacks
Transforms: `agent_memory_injection`, `agent_permission_escalation`, `soul_file_injection`, `bootstrap_hook_injection`, `workspace_file_poison`, `skill_dependency_confusion`, `skill_package_poison`, `heartbeat_hijack`, `media_protocol_exfil`
Scorers: `agent_config_tampered`, `agent_identity_leaked`, `bootstrap_hook_injected`, `heartbeat_manipulation`, `skill_integrity_compromised`, `skill_supply_chain_attack`, `workspace_poisoning`

### Browser Agent Attacks
Transforms: `visual_prompt_injection`, `ai_clickfix`, `domain_validation_bypass`, `navigation_hijack`, `task_injection`, `phantom_ui`, `hashjack`, `web_inject_pixel`, `comet_hijack`, `agenthopper_replication`, `cascading_failure_trigger`

### Exfiltration Testing
Transforms: `markdown_image_exfil`, `mermaid_diagram_exfil`, `unicode_tag_exfil`, `dns_exfil_injection`, `ssrf_via_tools`, `link_unfurling_exfil`, `api_endpoint_abuse`, `character_exfiltration`
Scorers: `markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil`

### Reasoning / Chain-of-Thought Attacks
Transforms: `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `crescendo_escalation`, `fitd_escalation`, `deceptive_delight`, `goal_drift_injection`, `cot_hijack_prepend`, `reasoning_interruption`, `overthink_dos`, `thinking_intervention`, `extend_attack`, `stance_manipulation`, `attention_eclipse`, `badthink_triggered_overthinking`, `code_contradiction_reasoning`
Scorers: `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `escalation`, `goal_drift`, `reasoning_loop_detected`

### System Prompt Extraction
Transforms: `direct_extraction`, `indirect_extraction`, `boundary_probe`, `format_exploitation`, `multi_turn_extraction`, `reflection_probe`
Scorers: `system_prompt_leaked`

### PII Extraction
Transforms: `partial_pii_completion`, `divergence_extraction`, `public_figure_pii_probe`, `repeat_word_divergence`
Scorers: `detect_pii`, `credential_leakage`

### RAG Poisoning
Transforms: `document_poison`, `context_injection`, `context_stuffing`, `query_manipulation`, `chunk_boundary_exploit`, `single_text_poison`, `bias_amplification`, `adversarial_cot_poison`, `phantom_trigger`, `authchain_authority`, `rag_blocker`, `graphrag_poison`, `metadata_poison`, `black_hole_vector`, `cache_collision`

### IDE / Code Agent Attacks
Transforms: `rules_file_backdoor`, `mcp_tool_description_poison`, `manifest_injection`, `issue_injection`, `popup_injection`, `form_injection`, `xoxo_context_poison`
Scorers: `config_persistence`, `covert_exfiltration`, `rug_pull_detection`, `shadowing_detection`, `tool_squatting`

### Documentation Poisoning
Transforms: `documentation_poison`, `dockerfile_poison`, `env_var_injection`, `npm_package_readme_poison`, `pypi_package_readme_poison`

### Backdoor / Fine-Tuning Attacks
Transforms: `demon_agent_backdoor`, `benign_overfit_10shot`, `trojan_praise`, `stego_finetune`, `trojan_speak`, `poisoned_parrot`, `grp_obliteration`, `gatebreaker_moe`, `expert_lobotomy`, `moevil_poison`, `proattack_backdoor`, `fedspy_gradient`, `medical_weight_poison`
Scorers: `merge_backdoor_detected`, `package_hallucination`, `skill_poisoning_detected`

### Supply Chain Attacks
Transforms: `slopsquatting`, `llm_router_exploit`, `dependency_confusion`

### Constitutional / Fragmentation
Transforms: `code_fragmentation`, `document_fragmentation`, `multi_turn_fragmentation`, `metaphor_encoding`, `character_separation`, `riddle_encoding`, `contextual_substitution`

### Structural Exploits
Transforms: `trojan_template_fill`, `schema_exploit`, `task_embedding`, `policy_puppetry`, `chain_of_logic_injection`
Scorers: `echo_chamber_detected`, `m2s_reformatting_detected`, `stego_acrostic_detected`, `template_exploit_detected`

### Logic Bombs
Transforms: `logic_bomb`, `time_bomb`, `environment_bomb`

## Step 4: Assess Compute Budget

| Budget | Queries | Approach |
|--------|---------|----------|
| Minimal | ~50 | `deep_inception` + `renellm` |
| Moderate | ~500 | `tap` + `pair` + `crescendo` + `autoredteamer` |
| Standard | ~1000 | Above + `refusal_aware`, `cot_jailbreak`, `humor_bypass` |
| Extensive | ~2000+ | Full campaign: `tap,pair,crescendo,goat,goat_v2,autoredteamer,rainbow,autodan,jbfuzz` |

## Step 5: Consider Known Defenses

| Defense | Effective Attacks / Transforms |
|---------|-------------------------------|
| Strong system prompt | `crescendo`, `deep_inception`, `drattack` |
| Output classifier | `beast`, `autodan`, `renellm`, `classifier_evasion` |
| Rate limiting | `pair` (most query-efficient), `deep_inception` |
| Input sanitization | `beast`, `drattack`, encoding transforms (`base64`, `hex`, `unicode_escape`) |
| Tool-call filtering | `tool_restriction_bypass`, `tool_chain_attack`, `tool_priority_injection` |
| Content moderation | `classifier_evasion`, `payload_split`, `emoji_smuggle`, `nested_fiction` |
| Conversation monitoring | `crescendo_escalation`, `fitd_escalation`, `goal_drift_injection` |
| MCP server validation | `tool_description_poison`, `schema_poisoning`, `cross_server_shadow` |

## Step 6: Recommended Parameter Overrides

| Scenario | Parameter | Recommended |
|----------|-----------|-------------|
| Fast screening | `n_iterations` | 20-30 |
| Thorough test | `n_iterations` | 100+ |
| Weak target | `early_stopping_score` | 0.7 |
| Strong target | `early_stopping_score` | 0.95 |
| Budget constrained | `beam_width` | 3-5 |
| Diverse coverage | `beam_width` | 10+ |

## Quick Reference: Attack → Transform Pairing

| Scenario | Attack | Transforms |
|----------|--------|-----------|
| Jailbreak + encoding | `tap` | `base64`, `caesar`, `rot13` |
| Jailbreak + persuasion | `pair` | `authority_appeal`, `emotional_appeal` |
| Multi-turn + language | `crescendo` | `adapt_language(Zulu)`, `code_switch` |
| MCP security | `tap` | `tool_description_poison`, `schema_poisoning`, `cross_server_shadow` |
| Agent tool abuse | `goat` | `tool_restriction_bypass`, `action_hijacking`, `tool_chain_attack` |
| Exfil + bypass | `tap` | `classifier_evasion`, `markdown_image_exfil`, `unicode_tag_exfil` |
| System prompt leak | `pair` | `direct_extraction`, `boundary_probe`, `multi_turn_extraction` |
| RAG poisoning | `tap` | `document_poison`, `context_injection`, `chunk_boundary_exploit` |
