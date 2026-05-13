# Scorer Catalog

## Rubric-Based (LLM-judged)

`rce`, `data_exfiltration`, `data_exfil`, `goal_hijacking`, `memory_poisoning`, `privilege_escalation`, `priv_esc`, `scope_creep`, `tool_chaining`, `tool_selection_safety_rubric`, `unbounded_agency`, `web_chatbot_security`

## Detection (pattern-based)

`refusal`, `credential_leakage`, `system_prompt_leaked`, `detect_pii`, `detect_bias`

## Agentic (tool-call based)

`tool_invoked`, `any_tool_invoked`, `tool_selection_safety`, `tool_sequence`, `tool_count`, `dangerous_tool_args`, `cascade_propagation`, `mcp_tool_manipulation`, `indirect_injection_success`

## Agentic Workflow Detection

`phase_bypass`, `phase_downgrade`, `tool_priority_manipulation`, `tool_restriction_bypass`, `memory_injection`, `permission_escalation`, `agentic_workflow`, `cypher_injection`, `intent_manipulation`, `mode_confusion`, `session_state_poisoning`, `sql_injection_via_nlp`, `success_indicator_spoofing`, `todo_list_manipulation`, `wordlist_exhaustion`, `workflow_disruption`

## Advanced Jailbreak Detection

`fictional_framing`, `guardrail_dos`, `invisible_character`, `likert_exploitation`, `pipeline_manipulation`, `prefill_bypass`, `tool_chain_attack`, `malformed_json_injection`

## Agent Security

`agent_config_tampered`, `agent_identity_leaked`, `bootstrap_hook_injected`, `heartbeat_manipulation`, `skill_integrity_compromised`, `skill_supply_chain_attack`, `workspace_poisoning`

## MCP Security

`tool_description_poisoned`, `cross_server_shadow`, `rug_pull`, `sampling_injection`, `schema_poisoned`, `tool_output_injected`, `ansi_cloaking`

## Multi-Agent Security

`prompt_infection`, `agent_spoofing`, `consensus_poisoned`, `delegation_exploit`, `session_smuggling`, `agent_config_overwrite`

## Exfiltration Detection

`markdown_exfil`, `unicode_exfil`, `dns_exfil`, `ssrf_exfil`

## IDE Security

`config_persistence`, `covert_exfiltration`, `rug_pull_detection`, `shadowing_detection`, `tool_squatting`

## Reasoning Security

`cot_backdoor`, `reasoning_hijack`, `reasoning_dos`, `escalation`, `goal_drift`

## Format

`json`, `is_xml`
