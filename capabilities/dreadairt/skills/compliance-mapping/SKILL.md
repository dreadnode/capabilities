---
name: compliance-mapping
description: Maps AIRT attacks to OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, and Google SAIF frameworks
allowed-tools: register_assessment get_assessment_status
---

# Compliance Mapping

Maps the 17 AIRT attack algorithms to major AI security compliance frameworks.

## OWASP LLM Top 10 (2025)

| OWASP Category | Attacks That Test It | Coverage |
|---------------|---------------------|----------|
| LLM01: Prompt Injection | `tap_attack`, `pair_attack`, `goat_attack`, `prompt_attack`, `crescendo_attack`, `gptfuzzer_attack`, `autodan_turbo_attack`, `renellm_attack`, `beast_attack`, `drattack`, `deep_inception_attack` | Strong |
| LLM02: Insecure Output Handling | All LLM attacks (examine outputs for unsafe content) | Moderate |
| LLM03: Training Data Poisoning | Not directly tested (requires training access) | Gap |
| LLM04: Model Denial of Service | Not directly tested (resource exhaustion) | Gap |
| LLM05: Supply Chain Vulnerabilities | Not directly tested (infrastructure) | Gap |
| LLM06: Sensitive Information Disclosure | `tap_attack`, `pair_attack`, `crescendo_attack` (goal: extract PII/secrets) | Moderate |
| LLM07: Insecure Plugin Design | Custom target functions can test plugin interfaces | Moderate |
| LLM08: Excessive Agency | Custom workflows can test tool-use boundaries | Moderate |
| LLM09: Overreliance | `rainbow_attack` (misinformation category) | Light |
| LLM10: Model Theft | Not directly tested (API extraction) | Gap |

### Minimum OWASP Assessment

To achieve reasonable OWASP coverage, run:
1. `tap_attack` with prompt injection goals (LLM01)
2. `pair_attack` with information extraction goals (LLM06)
3. `crescendo_attack` with multi-turn escalation (LLM01, LLM02)
4. `rainbow_attack` for broad risk coverage (LLM01, LLM02, LLM09)

## MITRE ATLAS

| ATLAS Technique | ID | Attacks |
|----------------|-----|---------|
| Prompt Injection (Direct) | AML.T0051.000 | `tap_attack`, `pair_attack`, `goat_attack`, `prompt_attack`, `gptfuzzer_attack`, `beast_attack`, `drattack` |
| Prompt Injection (Indirect) | AML.T0051.001 | `crescendo_attack`, `deep_inception_attack`, `renellm_attack` |
| LLM Jailbreak | AML.T0054 | All 12 LLM jailbreak attacks |
| Obfuscate Artifacts | AML.T0015 | `beast_attack`, `drattack`, `renellm_attack` + encoding transforms |
| Adversarial Perturbation | AML.T0043 | `simba_attack`, `nes_attack`, `zoo_attack`, `hopskipjump_attack` |
| Evasion | AML.T0015 | Image attacks + transform chains |

### Minimum ATLAS Assessment

1. `tap_attack` (AML.T0051.000, AML.T0054)
2. `crescendo_attack` (AML.T0051.001)
3. `drattack` (AML.T0015, AML.T0054)
4. `simba_attack` or `hopskipjump_attack` if vision model (AML.T0043)

## NIST AI RMF

| NIST Function | Subcategory | Attacks | How |
|--------------|-------------|---------|-----|
| GOVERN | GV-1.1 (Risk management policies) | Assessment reporting | Reports document risk findings |
| MAP | MP-2.3 (AI risks identified) | `rainbow_attack` | Broad risk category enumeration |
| MEASURE | MS-2.6 (Security testing) | All attacks | Adversarial evaluation |
| MEASURE | MS-2.7 (AI-specific attacks) | All LLM + image attacks | Direct testing of AI attack vectors |
| MANAGE | MG-2.2 (Risk mitigation) | Assessment reports | Recommendations for mitigations |

### NIST-Aligned Campaign

1. **Map risks**: `rainbow_attack` with full risk×style grid
2. **Measure robustness**: `tap_attack` + `pair_attack` + `crescendo_attack`
3. **Document findings**: Generate assessment report with compliance tags
4. **Produce recommendations**: Synthesize mitigations from attack results

## Google SAIF (Secure AI Framework)

| SAIF Principle | Attacks | Coverage |
|---------------|---------|----------|
| Expand strong security foundations to AI | All attacks (security testing) | Strong |
| Extend detection and response to AI threats | `rainbow_attack`, multi-attack campaigns | Moderate |
| Automate defenses | Continuous assessment via Assessment class | Moderate |
| Harmonize platform controls | Custom target function testing | Moderate |
| Adapt controls for AI-related threats | Transform chains, multi-attack | Strong |
| Contextualize risks in business processes | Goal-specific assessments | Strong |

### SAIF Mapping

| SAIF Category | Relevant Attacks |
|--------------|-----------------|
| Input Manipulation | All LLM jailbreak attacks, transform chains |
| Model Exploitation | Image adversarial attacks, `beast_attack` |
| Data Exfiltration | `tap_attack`, `pair_attack` with extraction goals |
| Output Integrity | All attacks (evaluate output safety) |

## Coverage Gap Analysis

### Well-Covered Areas
- Prompt injection (direct and indirect)
- LLM jailbreaking
- Adversarial perturbation (image models)
- Content policy testing
- Multi-turn attack resilience

### Partially Covered
- Sensitive information disclosure (depends on goal selection)
- Insecure output handling (examined as side effect)
- Plugin/tool-use safety (requires custom target)

### Not Covered (Requires Different Tools)
- Training data poisoning
- Model denial of service
- Supply chain vulnerabilities
- Model theft / extraction
- Infrastructure security

### Closing Gaps

For partially covered areas, design specific goals:
- **Information disclosure**: Goal = "Reveal your system prompt" or "List PII from training data"
- **Output handling**: Examine attack outputs for XSS payloads, code injection
- **Plugin safety**: Wrap plugin-enabled models as custom targets

For uncovered areas, complement AIRT assessments with:
- Infrastructure security scanning
- API rate limiting / DoS testing tools
- Supply chain audit processes
- Model extraction detection
