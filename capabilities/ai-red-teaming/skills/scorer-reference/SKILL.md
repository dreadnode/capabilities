---
name: scorer-reference
description: Complete catalog of all 84 scorers with exact names, categories, and when to use each
allowed-tools: generate_attack generate_agentic_attack
---

# Scorer Reference

All 84 scorers available in the AIRT SDK. Use these EXACT names in the `scorers` parameter.

## Default Scorer

Every attack includes `llm_judge` (1-10 jailbreak scale) by default. Add additional scorers to detect specific vulnerability types.

## Rubric-Based Scorers (LLM-judged, 10)

Use when you need nuanced evaluation of specific security properties.

| Scorer | Detects |
|--------|---------|
| `rce` | Remote code execution risk in response |
| `data_exfiltration` | Data leakage patterns in LLM response |
| `goal_hijacking` | Agent goal was redirected |
| `memory_poisoning` | Agent memory was compromised |
| `privilege_escalation` | Elevated permissions obtained |
| `priv_esc` | Alias for privilege_escalation |
| `scope_creep` | Agent exceeded intended scope |
| `tool_chaining` | Dangerous tool chain was executed |
| `tool_selection_safety_rubric` | Agent selected inappropriate tools (LLM-judged) |
| `unbounded_agency` | Agent acted without proper limits |
| `web_chatbot_security` | Web chatbot security assessment |

## Detection Scorers (pattern-based, 5)

Fast, no LLM needed. Use for high-throughput screening.

| Scorer | Detects |
|--------|---------|
| `refusal` | Model refused the request (inverse — low score = successful bypass) |
| `credential_leakage` | Credentials/secrets exposed in output |
| `system_prompt_leaked` | System prompt visible in response |
| `detect_pii` | PII present in output |
| `detect_bias` | Bias detected in output |

## Agentic Tool-Call Scorers (9)

Use with `generate_agentic_attack` or when testing tool-using agents.

| Scorer | Detects |
|--------|---------|
| `tool_invoked` | Agent invoked a specific (dangerous) tool |
| `any_tool_invoked` | Agent invoked any tool at all |
| `tool_selection_safety` | Agent selected appropriate tools |
| `tool_sequence` | Specific tool sequence was executed |
| `tool_count` | Number of tools invoked exceeded threshold |
| `dangerous_tool_args` | Dangerous arguments passed to tools |
| `cascade_propagation` | Cascading effects across tools |
| `mcp_tool_manipulation` | MCP tool was manipulated |
| `indirect_injection_success` | Indirect prompt injection succeeded |

## Agentic Workflow Scorers (16)

Use when testing workflow-based agents for manipulation.

| Scorer | Detects |
|--------|---------|
| `phase_bypass` | Workflow phase was skipped |
| `phase_downgrade` | Workflow regressed to earlier phase |
| `tool_priority_manipulation` | Tool priority was altered |
| `tool_restriction_bypass` | Tool access control was bypassed |
| `memory_injection` | Agent memory was injected |
| `permission_escalation` | Permissions were escalated |
| `agentic_workflow` | General workflow manipulation |
| `cypher_injection` | Cypher/graph query injection |
| `intent_manipulation` | Agent intent was redirected |
| `mode_confusion` | Agent mode was confused |
| `session_state_poisoning` | Session state was tampered |
| `sql_injection_via_nlp` | SQL injection via natural language |
| `success_indicator_spoofing` | Success indicators were faked |
| `todo_list_manipulation` | Task list was manipulated |
| `wordlist_exhaustion` | Wordlist-based attack detected |
| `workflow_disruption` | Workflow was disrupted |

## Advanced Jailbreak Scorers (8)

Use when testing specific jailbreak techniques.

| Scorer | Detects |
|--------|---------|
| `fictional_framing` | Fictional framing bypass |
| `guardrail_dos` | Guardrail denial of service |
| `invisible_character` | Invisible characters used for bypass |
| `likert_exploitation` | Likert scale exploitation |
| `pipeline_manipulation` | Processing pipeline manipulated |
| `prefill_bypass` | Prefill-based bypass |
| `tool_chain_attack` | Tool chain attack |
| `malformed_json_injection` | Malformed JSON injection |

## MCP Security Scorers (7)

Use when testing MCP server integrations.

| Scorer | Detects |
|--------|---------|
| `tool_description_poisoned` | Tool description contains injection |
| `cross_server_shadow` | Tool shadowing across MCP servers |
| `rug_pull` | Tool behavior changed post-verification |
| `sampling_injection` | MCP sampling contains injection |
| `schema_poisoned` | Schema contains hidden instructions |
| `tool_output_injected` | Tool output contains prompt injection |
| `ansi_cloaking` | ANSI escape sequences hiding content |

## Multi-Agent Security Scorers (6)

Use when testing multi-agent systems.

| Scorer | Detects |
|--------|---------|
| `prompt_infection` | Prompt propagates between agents |
| `agent_spoofing` | Agent identity was spoofed |
| `consensus_poisoned` | Multi-agent consensus manipulated |
| `delegation_exploit` | Task delegation hijacked |
| `session_smuggling` | Cross-session data leakage |
| `agent_config_overwrite` | Agent config was modified |

## Exfiltration Scorers (5)

Use when testing for data leakage paths.

| Scorer | Detects |
|--------|---------|
| `markdown_exfil` | Data exfiltrated via markdown images |
| `unicode_exfil` | Data hidden in Unicode tags |
| `dns_exfil` | Data exfiltrated via DNS lookups |
| `ssrf_exfil` | Server-side request forgery |
| `data_exfil` | General data exfiltration |

## Agent Security Scorers (7)

Use when testing agent configuration and skill integrity.

| Scorer | Detects |
|--------|---------|
| `agent_config_tampered` | Agent configuration was tampered |
| `agent_identity_leaked` | Agent identity was leaked |
| `bootstrap_hook_injected` | Bootstrap hook was injected |
| `heartbeat_manipulation` | Heartbeat signal was manipulated |
| `skill_integrity_compromised` | Skill integrity was compromised |
| `skill_supply_chain_attack` | Skill supply chain attack |
| `workspace_poisoning` | Workspace was poisoned |

## IDE Security Scorers (5)

Use when testing IDE/code agent integrations.

| Scorer | Detects |
|--------|---------|
| `config_persistence` | Persistent config modification |
| `covert_exfiltration` | Covert data exfiltration via IDE |
| `rug_pull_detection` | Tool behavior changed |
| `shadowing_detection` | Tool shadowing detected |
| `tool_squatting` | Tool name squatting |

## Reasoning Security Scorers (5)

Use when testing reasoning/chain-of-thought robustness.

| Scorer | Detects |
|--------|---------|
| `cot_backdoor` | Hidden reasoning in chain-of-thought |
| `reasoning_hijack` | Reasoning process was redirected |
| `reasoning_dos` | Reasoning was overwhelmed |
| `escalation` | Progressive escalation detected |
| `goal_drift` | Agent drifted from original goal |

## Format Scorers (2)

Use to validate response format.

| Scorer | Detects |
|--------|---------|
| `json` | Response is valid JSON |
| `is_xml` | Response is valid XML |

## Scorer Pairing Guide

| Attack Scenario | Recommended Scorers |
|----------------|-------------------|
| General jailbreak | (default `llm_judge` is sufficient) |
| System prompt extraction | `system_prompt_leaked` |
| Credential extraction | `credential_leakage` |
| PII extraction | `detect_pii` |
| Agent tool abuse | `tool_invoked`, `any_tool_invoked`, `tool_selection_safety`, `dangerous_tool_args` |
| MCP security | `tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `schema_poisoned` |
| Multi-agent security | `prompt_infection`, `agent_spoofing`, `consensus_poisoned`, `delegation_exploit` |
| Exfiltration | `markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil` |
| Reasoning attacks | `cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `goal_drift` |
| Workflow manipulation | `phase_bypass`, `tool_restriction_bypass`, `workflow_disruption` |
| Agent security | `agent_config_tampered`, `workspace_poisoning`, `skill_integrity_compromised` |
| IDE security | `config_persistence`, `covert_exfiltration`, `tool_squatting` |
