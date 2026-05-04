---
name: compliance-mapping
description: Maps AIRT attacks, transforms, and scorers to OWASP LLM Top 10, OWASP ASI (ASI01-ASI10), MITRE ATLAS, NIST AI RMF, and Google SAIF
allowed-tools: register_assessment get_assessment_status generate_attack generate_category_attack generate_agentic_attack
---

# Compliance Mapping

Maps AIRT attacks, transforms, and scorers to major AI security compliance frameworks.

## OWASP Agentic Security Index (ASI01-ASI10)

| ASI | Category | Transforms | Scorers | Coverage |
|-----|----------|-----------|---------|----------|
| ASI01 | Prompt Injection & Manipulation | `skeleton_key_framing`, `many_shot_examples`, `position_variation`, `position_wrap`, `prompt_infection` | `prompt_infection`, `indirect_injection_success` | Strong |
| ASI02 | Misaligned Behaviors | `goal_drift_injection`, `deceptive_delight`, `intent_manipulation` | `goal_drift`, `intent_manipulation`, `goal_hijacking` | Strong |
| ASI03 | Excessive Autonomy | `tool_restriction_bypass`, `action_hijacking`, `workflow_step_skip`, `tool_chain_attack` | `tool_invoked`, `any_tool_invoked`, `tool_restriction_bypass`, `agentic_workflow` | Strong |
| ASI04 | Knowledge Poisoning | `document_poison`, `context_injection`, `context_stuffing`, `query_manipulation`, `chunk_boundary_exploit`, `single_text_poison`, `bias_amplification` | `data_exfiltration` | Strong |
| ASI05 | Unsafe Action Execution | `tool_priority_injection`, `delayed_tool_invocation`, `exploitation_mode_confusion`, `malformed_output_injection`, `sql_via_nlp_injection` | `tool_selection_safety`, `tool_invoked`, `dangerous_tool_args`, `sql_injection_via_nlp` | Strong |
| ASI06 | Data Leakage | `markdown_image_exfil`, `mermaid_diagram_exfil`, `unicode_tag_exfil`, `dns_exfil_injection`, `ssrf_via_tools`, `link_unfurling_exfil`, `api_endpoint_abuse`, `character_exfiltration` | `markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil`, `data_exfil` | Strong |
| ASI07 | Insecure Integrations | `tool_description_poison`, `cross_server_shadow`, `rug_pull_payload`, `tool_output_injection`, `schema_poisoning`, `ansi_escape_cloaking`, `mcp_sampling_injection`, `cross_server_request_forgery`, `tool_squatting`, `tool_preference_manipulation` | `tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `tool_output_injected`, `schema_poisoned`, `ansi_cloaking`, `sampling_injection` | Strong |
| ASI08 | Cascading Trust Failures | `peer_agent_spoof`, `consensus_poisoning`, `delegation_chain_attack`, `shared_memory_poisoning`, `trust_exploitation`, `experience_poisoning` | `agent_spoofing`, `consensus_poisoned`, `delegation_exploit`, `session_smuggling` | Strong |
| ASI09 | Insufficient Oversight | `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `crescendo_escalation`, `fitd_escalation` | `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `escalation` | Strong |
| ASI10 | Identity Spoofing | `agent_config_overwrite`, `peer_agent_spoof`, `persistent_memory_backdoor`, `query_memory_injection` | `agent_config_overwrite`, `agent_spoofing`, `agent_config_tampered`, `agent_identity_leaked` | Strong |

### Minimum ASI Assessment

1. `generate_agentic_attack` with `tool_restriction_bypass` + `tool_chain_attack` (ASI03, ASI05)
2. `generate_agentic_attack` with `tool_description_poison` + `cross_server_shadow` + `schema_poisoning` (ASI07)
3. `generate_agentic_attack` with `prompt_infection` + `delegation_chain_attack` (ASI01, ASI08)
4. `generate_attack` with `markdown_image_exfil` + `dns_exfil_injection` transforms (ASI06)
5. `generate_attack` with `document_poison` + `context_injection` transforms (ASI04)
6. `generate_attack` with `goal_drift_injection` + `deceptive_delight` transforms (ASI02)

## OWASP LLM Top 10 (2025)

| OWASP | Category | Attacks | Transforms | Coverage |
|-------|----------|---------|-----------|----------|
| LLM01 | Prompt Injection | `tap`, `pair`, `goat`, `crescendo`, `gptfuzzer`, `autodan`, `renellm`, `beast`, `drattack`, `deep_inception` | `skeleton_key_framing`, `many_shot_examples`, `position_variation` | Strong |
| LLM02 | Insecure Output Handling | All LLM attacks | `markdown_image_exfil`, `mermaid_diagram_exfil`, `unicode_tag_exfil` | Strong |
| LLM03 | Training Data Poisoning | — | — | Gap |
| LLM04 | Model Denial of Service | — | `reasoning_dos`, `guardrail_dos`, `wordlist_exhaustion` | Light |
| LLM05 | Supply Chain Vulns | — | `skill_dependency_confusion`, `skill_package_poison` | Light |
| LLM06 | Sensitive Info Disclosure | `tap`, `pair`, `crescendo` | `direct_extraction`, `indirect_extraction`, `boundary_probe`, `format_exploitation`, `multi_turn_extraction`, `partial_pii_completion` | Strong |
| LLM07 | Insecure Plugin Design | — | `tool_description_poison`, `schema_poisoning`, `tool_output_injection`, `tool_squatting` | Strong |
| LLM08 | Excessive Agency | — | `tool_restriction_bypass`, `action_hijacking`, `tool_chain_attack`, `workflow_step_skip` | Strong |
| LLM09 | Overreliance | `rainbow` | `document_poison`, `context_injection`, `bias_amplification` | Moderate |
| LLM10 | Model Theft | — | — | Gap |

### Minimum OWASP LLM Assessment

1. `generate_attack(attack_type="tap", ...)` with injection goals (LLM01)
2. `generate_attack(attack_type="pair", ...)` with extraction goals + `direct_extraction` transform (LLM06)
3. `generate_attack(attack_type="crescendo", ...)` with multi-turn escalation (LLM01, LLM02)
4. `generate_attack(attack_type="rainbow", ...)` for broad risk coverage (LLM01, LLM09)
5. `generate_category_attack` with `system_prompt_leak` + `credential_extraction` categories (LLM06)

## MITRE ATLAS

| ATLAS Technique | ID | Attacks / Transforms |
|----------------|-----|---------------------|
| Prompt Injection (Direct) | AML.T0051.000 | `tap`, `pair`, `goat`, `gptfuzzer`, `beast`, `drattack`, `skeleton_key_framing` |
| Prompt Injection (Indirect) | AML.T0051.001 | `crescendo`, `deep_inception`, `renellm`, `context_injection`, `document_poison` |
| LLM Jailbreak | AML.T0054 | All 12 LLM jailbreak attacks + all encoding/cipher/persuasion transforms |
| Obfuscate Artifacts | AML.T0015 | `beast`, `drattack`, `base64`, `hex`, `caesar`, `rot13`, `unicode_escape`, `homoglyph` |
| Data Exfiltration | AML.T0024 | `markdown_image_exfil`, `unicode_tag_exfil`, `dns_exfil_injection`, `ssrf_via_tools` |
| Abuse/Misuse | AML.T0048 | `tool_restriction_bypass`, `action_hijacking`, `tool_chain_attack` |
| Evade ML Model | AML.T0015 | `classifier_evasion`, `payload_split`, `emoji_smuggle`, `nested_fiction` |

## NIST AI RMF

| NIST Function | Subcategory | AIRT Coverage | How |
|--------------|-------------|---------------|-----|
| GOVERN | GV-1.1 | Assessment reporting | Reports document risk findings |
| MAP | MP-2.3 | `rainbow` + `generate_category_attack` | Broad risk category enumeration |
| MEASURE | MS-2.6 | All 12 attack algorithms | Adversarial security testing |
| MEASURE | MS-2.7 | All LLM + agentic attacks | AI-specific attack vectors |
| MANAGE | MG-2.2 | Assessment reports | Recommendations for mitigations |

## Google SAIF

| SAIF Category | Relevant Attacks / Transforms |
|--------------|------------------------------|
| Input Manipulation | All 12 jailbreak attacks, all encoding/cipher/persuasion transforms |
| Model Exploitation | `beast`, `autodan`, reasoning attacks (`cot_backdoor`, `reasoning_hijack`) |
| Data Exfiltration | All exfiltration transforms (8) + scorers (4) |
| Output Integrity | All attacks + MCP output injection transforms |
| Agent Security | All agentic workflow (18), agent skill (9), multi-agent (10) transforms |

## Coverage Summary

### Well-Covered (Strong)
- Prompt injection (direct and indirect) — 12 attack algorithms
- LLM jailbreaking — 200+ transforms across 20+ categories
- Agentic security — OWASP ASI01-ASI10 all covered
- MCP security — 12 transforms, 7 scorers
- Multi-agent security — 10 transforms, 6 scorers
- Exfiltration — 8 transforms, 5 scorers
- Content policy — 260 bundled goals across 25 sub-categories
- System prompt extraction — 6 transforms
- RAG poisoning — 7 transforms

### Partially Covered
- Reasoning attacks — 7 transforms, 5 scorers
- IDE/code agent security — 7 transforms, 5 scorers
- Browser agent attacks — 6 transforms
- Supply chain — 2 transforms (skill_dependency_confusion, skill_package_poison)

### Not Covered (Requires Different Tools)
- Training data poisoning
- Model denial of service (resource exhaustion)
- Model theft / extraction
- Infrastructure security
