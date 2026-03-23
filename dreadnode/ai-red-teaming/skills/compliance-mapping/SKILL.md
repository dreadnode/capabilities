---
name: compliance-mapping
description: Maps AIRT attacks to OWASP LLM Top 10, OWASP Agentic Security Index (ASI01-ASI10), MITRE ATLAS, NIST AI RMF, and SAIF frameworks
allowed-tools: register_assessment get_assessment_status
---

# Compliance Mapping

Maps AIRT attacks, transforms, and scorers to major AI security compliance frameworks.

## OWASP Agentic Security Index (ASI01-ASI10)

| ASI Category | Transforms | Scorers | Coverage |
|-------------|-----------|---------|----------|
| ASI01: Prompt Injection & Manipulation | `direct_injection`, `indirect_injection`, `context_injection`, `prompt_infection` | `llm_judge`, `prompt_infection` | Strong |
| ASI02: Misaligned Behaviors | `agent_goal_hijacking`, `goal_drift`, `deceptive_delight` | `goal_hijack_detected`, `goal_drift` | Strong |
| ASI03: Excessive Autonomy | `tool_restriction_bypass`, `multi_step_tool_exploit`, `agentic_resource_abuse` | `tool_invoked`, `any_tool_invoked`, `resource_abuse_detected` | Strong |
| ASI04: Knowledge Poisoning & Manipulation | `rag_context_injection`, `rag_retrieval_manipulation`, `rag_knowledge_conflict`, `rag_citation_spoofing`, `rag_chunk_boundary_exploit` | `llm_judge` | Strong |
| ASI05: Unsafe Action Execution | `tool_parameter_injection`, `tool_chain_manipulation`, `tool_selection_manipulation` | `tool_selection_safety`, `tool_invoked` | Strong |
| ASI06: Data Leakage | `markdown_image_exfil`, `unicode_tag_exfil`, `dns_exfil`, `ssrf_exfil`, `api_abuse_exfil`, `link_unfurling_exfil` | `markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil` | Strong |
| ASI07: Insecure Integrations | `tool_description_poisoning`, `cross_server_shadowing`, `rug_pull`, `tool_output_injection`, `schema_poisoning`, `ansi_cloaking`, `sampling_injection`, `mcp_csrf` | `tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `tool_output_injected`, `schema_poisoned`, `ansi_cloaking`, `sampling_injection` | Strong |
| ASI08: Cascading Trust Failures | `peer_agent_spoofing`, `consensus_poisoning`, `delegation_exploit`, `a2a_protocol_smuggling`, `shared_memory_injection` | `agent_spoofing`, `consensus_poisoned`, `delegation_exploit`, `session_smuggling` | Strong |
| ASI09: Insufficient Oversight | `cot_backdoor`, `reasoning_hijack`, `reasoning_dos` | `cot_backdoor`, `reasoning_hijack`, `reasoning_dos` | Moderate |
| ASI10: Identity Spoofing & Impersonation | `agent_config_overwrite`, `peer_agent_spoofing`, `multi_agent_session_injection` | `agent_config_overwrite`, `agent_spoofing` | Moderate |

### Minimum ASI Assessment

1. `generate_agentic_attack` with `tool_restriction_bypass` + `tool_parameter_injection` (ASI03, ASI05)
2. `generate_agentic_attack` with `tool_description_poisoning` + `cross_server_shadowing` (ASI07)
3. `generate_agentic_attack` with `prompt_infection` + `delegation_exploit` (ASI01, ASI08)
4. `tap_attack` with `markdown_image_exfil` + `dns_exfil` transforms (ASI06)
5. `tap_attack` with `rag_context_injection` + `rag_knowledge_conflict` (ASI04)
6. `tap_attack` with `agent_goal_hijacking` + `goal_drift` (ASI02)

## OWASP LLM Top 10 (2025)

| OWASP Category | Attacks | Transforms | Coverage |
|---------------|---------|-----------|----------|
| LLM01: Prompt Injection | `tap_attack`, `pair_attack`, `goat_attack`, `crescendo_attack`, `gptfuzzer_attack`, `autodan_turbo_attack`, `renellm_attack`, `beast_attack`, `drattack`, `deep_inception_attack` | `direct_injection`, `indirect_injection`, `context_injection` | Strong |
| LLM02: Insecure Output Handling | All LLM attacks | `markdown_image_exfil`, `mermaid_diagram_exfil` | Moderate |
| LLM03: Training Data Poisoning | — | — | Gap |
| LLM04: Model Denial of Service | — | `reasoning_dos` | Light |
| LLM05: Supply Chain Vulnerabilities | — | — | Gap |
| LLM06: Sensitive Info Disclosure | `tap_attack`, `pair_attack`, `crescendo_attack` | `direct_system_prompt_extraction`, `direct_pii_extraction`, `indirect_pii_extraction` | Strong |
| LLM07: Insecure Plugin Design | — | `tool_description_poisoning`, `schema_poisoning`, `tool_output_injection` | Strong |
| LLM08: Excessive Agency | — | `tool_restriction_bypass`, `multi_step_tool_exploit`, `agentic_resource_abuse` | Strong |
| LLM09: Overreliance | `rainbow_attack` | `rag_knowledge_conflict`, `rag_citation_spoofing` | Moderate |
| LLM10: Model Theft | — | — | Gap |

### Minimum OWASP LLM Assessment

1. `tap_attack` with injection goals (LLM01)
2. `pair_attack` with extraction goals (LLM06)
3. `crescendo_attack` with multi-turn escalation (LLM01, LLM02)
4. `rainbow_attack` for broad risk coverage (LLM01, LLM09)
5. `tap_attack` with `direct_system_prompt_extraction` (LLM06)

## MITRE ATLAS

| ATLAS Technique | ID | Attacks / Transforms |
|----------------|-----|---------------------|
| Prompt Injection (Direct) | AML.T0051.000 | `tap_attack`, `pair_attack`, `goat_attack`, `gptfuzzer_attack`, `beast_attack`, `drattack`, `direct_injection` |
| Prompt Injection (Indirect) | AML.T0051.001 | `crescendo_attack`, `deep_inception_attack`, `renellm_attack`, `indirect_injection` |
| LLM Jailbreak | AML.T0054 | All 12 LLM jailbreak attacks |
| Obfuscate Artifacts | AML.T0015 | `beast_attack`, `drattack`, `base64_encode`, `rot13`, `caesar_cipher` |
| Adversarial Perturbation | AML.T0043 | `simba_attack`, `nes_attack`, `zoo_attack`, `hopskipjump_attack` |
| Data Exfiltration | AML.T0024 | `markdown_image_exfil`, `unicode_tag_exfil`, `dns_exfil`, `ssrf_exfil` |
| Abuse/Misuse | AML.T0048 | `tool_restriction_bypass`, `agentic_resource_abuse` |

## NIST AI RMF

| NIST Function | Subcategory | Attacks | How |
|--------------|-------------|---------|-----|
| GOVERN | GV-1.1 | Assessment reporting | Reports document risk findings |
| MAP | MP-2.3 | `rainbow_attack` | Broad risk category enumeration |
| MEASURE | MS-2.6 | All attacks | Adversarial security testing |
| MEASURE | MS-2.7 | All LLM + image + agentic attacks | AI-specific attack vectors |
| MANAGE | MG-2.2 | Assessment reports | Recommendations for mitigations |

## Google SAIF

| SAIF Category | Relevant Attacks / Transforms |
|--------------|------------------------------|
| Input Manipulation | All LLM jailbreak attacks, transform chains, injection transforms |
| Model Exploitation | Image adversarial attacks, `beast_attack`, reasoning attacks |
| Data Exfiltration | All exfiltration transforms and scorers |
| Output Integrity | All attacks (evaluate output safety), MCP output injection |
| Agent Security | All agentic transforms (tool, memory, context, multi-agent) |

## Coverage Gap Analysis

### Well-Covered
- Prompt injection (direct and indirect)
- LLM jailbreaking (12 attack algorithms)
- Agentic security (OWASP ASI01-ASI10)
- MCP security (7 attack types, 7 scorers)
- Multi-agent security (7+ transforms, 6 scorers)
- Exfiltration (7 attack paths, 4 scorers)
- Content policy testing
- Multi-turn resilience
- System prompt extraction
- RAG poisoning

### Partially Covered
- Reasoning attacks (7 transforms, 5 scorers — growing area)
- IDE/code agent security (7 transforms, 5 scorers)
- Browser agent attacks (7 transforms, visual-only)

### Not Covered (Requires Different Tools)
- Training data poisoning
- Model denial of service (resource exhaustion)
- Supply chain vulnerabilities
- Model theft / extraction
- Infrastructure security

### Closing Gaps

For partially covered areas, design specific goals:
- **Info disclosure**: Goal = "Reveal your system prompt" with `direct_system_prompt_extraction`
- **Plugin safety**: Use MCP transforms against tool-enabled targets
- **RAG safety**: Use RAG transforms against retrieval-augmented targets
- **Agentic safety**: Use `generate_agentic_attack` against agent API endpoints
