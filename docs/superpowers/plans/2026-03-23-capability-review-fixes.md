# Capability Review Fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all issues identified by the capability review checklist across 32 capabilities in 3 orgs.

**Architecture:** Mechanical fixes organized by issue type. No tests — these are YAML/frontmatter fixes validated by `dn capability validate`.

**Tech Stack:** YAML frontmatter in Markdown files, shell commands for cruft removal.

---

## Tool Name Mapping (Reference)

Claude Code → SDK:
- `Read` → `read`
- `Write` → `write`
- `Edit` → `edit_file`
- `Bash` → `bash`
- `Glob` → `glob`
- `Grep` → `grep`
- `WebFetch` → `fetch`
- `WebSearch` → `web_search`
- `AskUserQuestion` → `ask_user`
- `Task` → `todo`
- `TodoRead` → `todo` (consolidated)
- `TodoWrite` → `todo` (consolidated)
- `LSP` → remove (not a valid SDK tool)
- `TaskCreate`, `TaskList`, `TaskUpdate`, `TaskGet` → remove (not default SDK tools)
- `Bash(...)` patterns → `bash` (SDK doesn't support inline arg filtering)

---

### Task 1: Fix allowed-tools in Trail of Bits skills (22 capabilities)

**Files to modify** (each file's `allowed-tools` frontmatter field):

1. `trailofbits/agentic-actions-auditor/skills/agentic-actions-auditor/SKILL.md` — `Read,Grep,Glob,Bash` → `read,grep,glob,bash`
2. `trailofbits/audit-context-building/skills/audit-context/SKILL.md` — `Read,Grep,Glob,Bash,Task` → `read,grep,glob,bash,todo`
3. `trailofbits/burpsuite-project-parser/skills/burp-search/SKILL.md` — `Bash,Read` → `bash,read`
4. `trailofbits/burpsuite-project-parser/skills/burpsuite-project-parser/SKILL.md` — `Bash,Read` → `bash,read`
5. `trailofbits/constant-time-analysis/skills/ct-check/SKILL.md` — `Bash,Read,Grep,Glob` → `bash,read,grep,glob`
6. `trailofbits/differential-review/skills/differential-review/SKILL.md` — `Read,Write,Grep,Glob,Bash` → `read,write,grep,glob,bash`
7. `trailofbits/differential-review/skills/diff-review/SKILL.md` — `Read,Write,Grep,Glob,Bash` → `read,write,grep,glob,bash`
8. `trailofbits/dwarf-expert/skills/dwarf-expert/SKILL.md` — `Read,Bash,Grep,Glob,WebSearch` → `read,bash,grep,glob,web_search`
9. `trailofbits/entry-point-analyzer/skills/entry-point-analyzer/SKILL.md` — `Read,Grep,Glob,Bash` → `read,grep,glob,bash`
10. `trailofbits/entry-point-analyzer/skills/entry-points/SKILL.md` — `Read,Grep,Glob,Bash` → `read,grep,glob,bash`
11. `trailofbits/firebase-apk-scanner/skills/firebase-apk-scanner/SKILL.md` — `Bash({baseDir}/scanner.sh:*), Bash(apktool:*), Bash(curl:*), Read, Grep, Glob` → `bash, read, grep, glob`
12. `trailofbits/firebase-apk-scanner/skills/scan-apk/SKILL.md` — `Bash,Read,Grep,Glob` → `bash,read,grep,glob`
13. `trailofbits/fp-check/skills/fp-check/SKILL.md` — `Read,Grep,Glob,LSP,Bash,Task,Write,Edit,AskUserQuestion,TaskCreate,TaskUpdate` → `read,grep,glob,bash,todo,write,edit_file,ask_user`
14. `trailofbits/insecure-defaults/skills/insecure-defaults/SKILL.md` — `Read,Grep,Glob,Bash` → `read,grep,glob,bash`
15. `trailofbits/seatbelt-sandboxer/skills/seatbelt-sandboxer/SKILL.md` — `Read,Write,Bash,Glob,Grep` → `read,write,bash,glob,grep`
16. `trailofbits/second-opinion/skills/second-opinion/SKILL.md` — `Bash,Read,Glob,Grep,AskUserQuestion` → `bash,read,glob,grep,ask_user`
17. `trailofbits/semgrep-rule-creator/skills/semgrep-rule-creator/SKILL.md` — `Bash,Read,Write,Edit,Glob,Grep,WebFetch` → `bash,read,write,edit_file,glob,grep,fetch`
18. `trailofbits/semgrep-rule-creator/skills/semgrep-rule/SKILL.md` — `Bash,Read,Write,Edit,Glob,Grep,WebFetch` → `bash,read,write,edit_file,glob,grep,fetch`
19. `trailofbits/semgrep-rule-variant-creator/skills/semgrep-rule-variant-creator/SKILL.md` — `Bash,Read,Write,Edit,Glob,Grep,WebFetch` → `bash,read,write,edit_file,glob,grep,fetch`
20. `trailofbits/sharp-edges/skills/sharp-edges/SKILL.md` — `Read,Grep,Glob` → `read,grep,glob`
21. `trailofbits/skill-improver/skills/skill-improver/SKILL.md` — `Task,Read,Edit,Write,Glob,Grep` → `todo,read,edit_file,write,glob,grep`
22. `trailofbits/spec-to-code-compliance/skills/spec-compliance/SKILL.md` — `Read,Write,Grep,Glob,Bash,WebFetch` → `read,write,grep,glob,bash,fetch`
23. `trailofbits/static-analysis/skills/codeql/SKILL.md` — `Bash,Read,Write,Edit,Glob,Grep,AskUserQuestion,TaskCreate,TaskList,TaskUpdate,TaskGet` → `bash,read,write,edit_file,glob,grep,ask_user`
24. `trailofbits/static-analysis/skills/sarif-parsing/SKILL.md` — `Bash,Read,Glob,Grep` → `bash,read,glob,grep`
25. `trailofbits/static-analysis/skills/semgrep/SKILL.md` — `Bash,Read,Glob,Task,AskUserQuestion,TaskCreate,TaskList,TaskUpdate` → `bash,read,glob,todo,ask_user`
26. `trailofbits/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/SKILL.md` — `Read,Write,Bash,Glob,Grep` → `read,write,bash,glob,grep`
27. `trailofbits/variant-analysis/skills/variants/SKILL.md` — `Read,Grep,Glob,Bash,Task` → `read,grep,glob,bash,todo`
28. `trailofbits/zeroize-audit/skills/zeroize-audit/SKILL.md` — read current, fix all Claude Code names

- [ ] **Step 1:** For each file above, read the frontmatter `allowed-tools` and replace Claude Code names with SDK names per the mapping table.
- [ ] **Step 2:** Run `uv run --project ~/code/dreadnode-tiger/packages/sdk dn capability validate trailofbits/` to verify all still pass.
- [ ] **Step 3:** Commit: `fix: use SDK tool names in Trail of Bits skill allowed-tools`

### Task 2: Fix allowed-tools in Dreadnode web-security skills

**Files:**
1. `dreadnode/web-security/skills/data-exfil/SKILL.md` — list `[Read,Write,Edit,Bash,Grep,Glob]` → `[read,write,edit_file,bash,grep,glob]`
2. `dreadnode/web-security/skills/wooyun-legacy/SKILL.md` — list `[Read,Grep,Glob,Bash,WebFetch,WebSearch,Task]` → `[read,grep,glob,bash,fetch,web_search,todo]`. Also remove `user-invocable: true` from frontmatter.
3. `dreadnode/web-security/skills/agent-browser/SKILL.md` — `Bash(npx agent-browser:*), Bash(agent-browser:*)` → `bash`

- [ ] **Step 1:** Edit each file's frontmatter.
- [ ] **Step 2:** Run `dn capability validate dreadnode/web-security/`.
- [ ] **Step 3:** Commit: `fix: use SDK tool names in web-security skill allowed-tools`

### Task 3: Fix allowed-tools in Ghost Security skills

**Files:**
1. `ghostsecurity/ghost/skills/scan-code/SKILL.md` — `Read, Write, Edit, Glob, Grep, Bash` → `read, write, edit_file, glob, grep, bash`
2. `ghostsecurity/ghost/skills/repo-context/SKILL.md` — same mapping
3. `ghostsecurity/ghost/skills/report/SKILL.md` — same mapping
4. `ghostsecurity/ghost/skills/scan-secrets/SKILL.md` — `Read, Glob, Grep, Bash, Task, TodoRead, TodoWrite` → `read, glob, grep, bash, todo`
5. `ghostsecurity/ghost/skills/scan-deps/SKILL.md` — same as scan-secrets

- [ ] **Step 1:** Edit each file's frontmatter.
- [ ] **Step 2:** Run `dn capability validate ghostsecurity/ghost/`.
- [ ] **Step 3:** Commit: `fix: use SDK tool names in Ghost Security skill allowed-tools`

### Task 4: Fix skill-improver issues

**Files:**
1. `trailofbits/skill-improver/skills/cancel-skill-improver/SKILL.md` — add `name: cancel-skill-improver`, change `${CLAUDE_PLUGIN_ROOT}` → `${CAPABILITY_ROOT}`
2. `trailofbits/skill-improver/scripts/setup-skill-improver.sh` — change `${CLAUDE_PLUGIN_ROOT}` → `${CAPABILITY_ROOT}` (if present)

- [ ] **Step 1:** Edit both files.
- [ ] **Step 2:** Validate.
- [ ] **Step 3:** Commit: `fix: add missing name field and update variable refs in skill-improver`

### Task 5: Fix ai-red-teaming agent

**File:** `dreadnode/ai-red-teaming/agents/ai-red-teaming-agent.md`
- Add `description` field
- Add body content (minimal agent instructions based on capability description)
- Consider fixing `name: dreadairt-agent` → `name: ai-red-teaming-agent` to match filename

- [ ] **Step 1:** Read capability.yaml for description context, then edit the agent file.
- [ ] **Step 2:** Validate.
- [ ] **Step 3:** Commit: `fix: add missing description and body to ai-red-teaming agent`

### Task 6: Remove cruft

**Actions:**
1. Delete all `__pycache__/` directories under `dreadnode/*/tools/`
2. Delete `dreadnode/ai-red-teaming/skills/.gitkeep`
3. Delete `dreadnode/web-security/tools/.gitignore`
4. Delete empty `dreadnode/mythic-c2/agents/` directory
5. Delete empty `dreadnode/sliver-c2/agents/` directory
6. Delete `dreadnode/web-security/skills/agent-browser/` references to missing template files (remove the template section from SKILL.md, or create stub templates)

- [ ] **Step 1:** Run deletion commands.
- [ ] **Step 2:** Validate all Dreadnode capabilities.
- [ ] **Step 3:** Commit: `chore: remove cruft from Dreadnode capabilities`

### Task 7: Fix static-analysis agent tool constraint

**File:** `trailofbits/static-analysis/agents/semgrep-scanner.md`
- Source had `tools: Bash(semgrep scan:*), Bash` which constrained bash to semgrep commands
- Dest has `"bash": true` which is the correct format but lost the constraint
- Use glob pattern: `"bash(semgrep*)": true` or `"bash": true` (since SDK glob patterns use fnmatch, and the specific constraint may not be expressible)

- [ ] **Step 1:** Check if SDK tool rules support `bash(semgrep*)` pattern. If not, leave as `"bash": true` and add a note.
- [ ] **Step 2:** Validate.

### Task 8: Final validation

- [ ] **Step 1:** Run `dn capability validate` on all 32 capabilities.
- [ ] **Step 2:** Verify no regressions from the 29 OK / 3 WARN baseline.
