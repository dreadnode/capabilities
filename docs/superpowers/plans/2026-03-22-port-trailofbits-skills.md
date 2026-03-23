# Port Trail of Bits Skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port security-relevant skills from trailofbits-skills into the capabilities repo, preserving metadata (author, license, version).

**Architecture:** Each trailofbits plugin maps to a capability. Skills are copied with directory restructuring (`plugins/X/skills/Y/` → `capability/skills/Y/`). Metadata from `marketplace.json` (author, version, license CC BY-SA 4.0) is preserved in `capability.yaml`. Supporting files (references/, scripts/, tools/) come along with each skill.

**Tech Stack:** YAML manifests, Markdown skills, shell/Python scripts (as-is)

**Source metadata:**
- Author: Trail of Bits (https://github.com/trailofbits)
- License: CC-BY-SA-4.0
- Versions: per-plugin from marketplace.json

---

### Task 1: Port security-research additions (3 skills)

Add `agentic-actions-auditor`, `constant-time-analysis`, `dwarf-expert` to existing `security-research` capability.

**Files:**
- Modify: `security-research/capability.yaml` (bump version, update description/keywords)
- Create: `security-research/skills/agentic-actions-auditor/SKILL.md`
- Create: `security-research/skills/constant-time-analysis/SKILL.md` + `ct_analyzer/` + `references/`
- Create: `security-research/skills/dwarf-expert/SKILL.md` + `references/`

**Source paths:**
- `~/code/trailofbits-skills/plugins/agentic-actions-auditor/skills/agentic-actions-auditor/`
- `~/code/trailofbits-skills/plugins/constant-time-analysis/skills/constant-time-analysis/`
- `~/code/trailofbits-skills/plugins/constant-time-analysis/ct_analyzer/` (Python package, lives alongside skill)
- `~/code/trailofbits-skills/plugins/dwarf-expert/skills/dwarf-expert/`

- [ ] **Step 1: Copy agentic-actions-auditor skill**

```bash
cp -r ~/code/trailofbits-skills/plugins/agentic-actions-auditor/skills/agentic-actions-auditor \
  ~/code/capabilities/security-research/skills/agentic-actions-auditor
```

- [ ] **Step 2: Copy constant-time-analysis skill + Python package**

```bash
cp -r ~/code/trailofbits-skills/plugins/constant-time-analysis/skills/constant-time-analysis \
  ~/code/capabilities/security-research/skills/constant-time-analysis
cp -r ~/code/trailofbits-skills/plugins/constant-time-analysis/ct_analyzer \
  ~/code/capabilities/security-research/skills/constant-time-analysis/ct_analyzer
cp ~/code/trailofbits-skills/plugins/constant-time-analysis/pyproject.toml \
  ~/code/capabilities/security-research/skills/constant-time-analysis/pyproject.toml
```

Update `{baseDir}` references in SKILL.md to use paths relative to skill directory.

- [ ] **Step 3: Copy dwarf-expert skill**

```bash
cp -r ~/code/trailofbits-skills/plugins/dwarf-expert/skills/dwarf-expert \
  ~/code/capabilities/security-research/skills/dwarf-expert
```

- [ ] **Step 4: Update security-research/capability.yaml**

Bump version to 1.1.0, add Trail of Bits attribution, update description and keywords to reflect new skills.

- [ ] **Step 5: Verify SKILL.md frontmatter compatibility**

Check each SKILL.md has valid `name`, `description`, `allowed-tools` fields. Fix any `{baseDir}` references.

---

### Task 2: Port static-analysis addition (1 skill)

Add `yara-authoring` to existing `static-analysis` capability.

**Files:**
- Modify: `static-analysis/capability.yaml` (bump version, update keywords)
- Create: `static-analysis/skills/yara-authoring/SKILL.md` + `references/`

**Source path:**
- `~/code/trailofbits-skills/plugins/yara-authoring/skills/yara-rule-authoring/`

- [ ] **Step 1: Copy yara-authoring skill**

Note: source skill dir is `yara-rule-authoring`, keep that name (matches SKILL.md `name` field).

```bash
cp -r ~/code/trailofbits-skills/plugins/yara-authoring/skills/yara-rule-authoring \
  ~/code/capabilities/static-analysis/skills/yara-rule-authoring
```

- [ ] **Step 2: Update static-analysis/capability.yaml**

Bump version to 1.1.0, add keywords for yara.

- [ ] **Step 3: Verify SKILL.md frontmatter**

---

### Task 3: Create smart-contract-security capability (12 skills)

New capability with 11 building-secure-contracts skills + property-based-testing.

**Files:**
- Create: `smart-contract-security/capability.yaml`
- Create: 11 skill directories from building-secure-contracts
- Create: `smart-contract-security/skills/property-based-testing/`

**Source paths:**
- `~/code/trailofbits-skills/plugins/building-secure-contracts/skills/*/`
- `~/code/trailofbits-skills/plugins/property-based-testing/skills/property-based-testing/`

**Metadata from marketplace.json:**
- building-secure-contracts: v3.0.0
- property-based-testing: v1.1.0

- [ ] **Step 1: Create capability directory and manifest**

```yaml
# smart-contract-security/capability.yaml
schema: 1
name: smart-contract-security
version: "1.0.0"
description: >
  Smart contract security skills for auditing across Solidity, Vyper, Cairo,
  Cosmos, Solana, Substrate, Algorand, TON, and Move. Includes vulnerability
  scanners, audit preparation, code maturity assessment, token integration
  analysis, and property-based testing for blockchain projects.

author:
  name: Trail of Bits
  url: https://github.com/trailofbits
license: CC-BY-SA-4.0
keywords:
  - smart-contracts
  - blockchain-security
  - solidity
  - defi
  - vulnerability-scanning
  - property-based-testing
```

- [ ] **Step 2: Copy all 11 building-secure-contracts skills**

```bash
for skill in ~/code/trailofbits-skills/plugins/building-secure-contracts/skills/*/; do
  cp -r "$skill" ~/code/capabilities/smart-contract-security/skills/$(basename "$skill")
done
```

- [ ] **Step 3: Copy property-based-testing skill**

```bash
cp -r ~/code/trailofbits-skills/plugins/property-based-testing/skills/property-based-testing \
  ~/code/capabilities/smart-contract-security/skills/property-based-testing
```

- [ ] **Step 4: Verify all 12 SKILL.md frontmatter files**

---

### Task 4: Create security-testing capability (15 skills)

New capability with all testing-handbook-skills.

**Files:**
- Create: `security-testing/capability.yaml`
- Create: 15 skill directories from testing-handbook-skills

**Source path:**
- `~/code/trailofbits-skills/plugins/testing-handbook-skills/skills/*/`

**Metadata from marketplace.json:**
- testing-handbook-skills: v1.1.0

- [ ] **Step 1: Create capability directory and manifest**

```yaml
# security-testing/capability.yaml
schema: 1
name: security-testing
version: "1.0.0"
description: >
  Security testing and fuzzing skills from the Trail of Bits Testing Handbook.
  Covers AFL++, libFuzzer, LibAFL, cargo-fuzz, Atheris, Ruzzy, OSS-Fuzz
  integration, AddressSanitizer, coverage analysis, harness writing, fuzzing
  dictionaries, obstacle handling, constant-time testing, and Wycheproof
  test vectors.

author:
  name: Trail of Bits
  url: https://github.com/trailofbits
license: CC-BY-SA-4.0
keywords:
  - fuzzing
  - testing
  - security-testing
  - afl
  - libfuzzer
  - sanitizers
  - coverage
```

- [ ] **Step 2: Copy all 15 testing-handbook skills**

```bash
for skill in ~/code/trailofbits-skills/plugins/testing-handbook-skills/skills/*/; do
  cp -r "$skill" ~/code/capabilities/security-testing/skills/$(basename "$skill")
done
```

- [ ] **Step 3: Verify all 15 SKILL.md frontmatter files**

---

### Task 5: Final verification

- [ ] **Step 1: Validate all capability.yaml files have required fields**
- [ ] **Step 2: Verify no broken references (`{baseDir}` updated where needed)**
- [ ] **Step 3: Check git status shows expected new files**
