# Promon Shield static recovery (research-grade)

These scripts are **not wired into the routine `android-protector-triage` flow**. They are first-pass static evaluators of Promon Shield's bootstrap, smali string indirection, native ELF layout, and Java/native binding callsites. Validation across more than the one anchor sample (`in.org.npci.upiapp`) is still pending.

Use them only when the operator has explicitly chosen the Promon research path. The skill workflow's mainline detection lives in [`scripts/protector_detect.py`](../../protector_detect.py); these scripts pick up *after* detection confirms a Promon-shielded APK.

Runbook (mirrors `skills/android-protector-triage/references/promon-shield.md`):

```bash
python3 capabilities/android-apk-research/scripts/research/promon/promon_recover.py path/to.apk -o findings/<pkg>/promon
```

Outputs are documented in the reference. Treat all findings as `scanner_gap = adjacent` or `not found` — do not promote to `strong_static_chain` based on these artifacts alone.

## Files

- `promon_recover.py` — orchestrator (detect → optional apktool decode → string recovery → ELF triage → roll-up).
- `promon_string_recover.py` — smali char-array / `String.intern()` deobfuscator.
- `promon_java_triage.py` — Java/smali integration map (native methods, load-library callsites, framework hints).
- `promon_binding_triage.py` — focused extraction of native string/class binding IDs.
- `promon_elf_triage.py` — APK/ELF profiler (section metadata, entropy, `.init_array`, RASP strings, AArch64 `SVC #0` sites).

## Why not in `scripts/` proper?

These are evaluator-grade, not production-grade — moving to `scripts/research/promon/` keeps the mainline `scripts/` directory aligned with the MCP tool surface and the skill workflow. When a script here graduates (validated across multiple samples, wired into an MCP tool), promote it to `scripts/` and update the references.
