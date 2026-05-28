# CodeQL recipes for Android semantic review

CodeQL is the path-precision tier. Use it when a finding needs SARIF-grade evidence for a public/MASVS-level report or you're filing a vendor disclosure.

Source docs:

- Query help index for Java/Kotlin: https://codeql.github.com/codeql-query-help/java/
- Built-in Java/Kotlin queries: https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/java-kotlin-built-in-queries
- Android intent redirection query: https://codeql.github.com/codeql-query-help/java/java-android-intent-redirection/
- Unsafe Android WebView fetch query: https://codeql.github.com/codeql-query-help/java/java-android-unsafe-android-webview-fetch/
- Kotlin analysis support (extends Java): https://github.blog/changelog/2022-11-28-codeql-code-scanning-launches-kotlin-analysis-support-beta/

## Caveat — JADX source has limits

CodeQL was designed to run against a *buildable* project, not arbitrary decompiled output. JADX sources sometimes:

- omit Kotlin metadata
- include syntactically rough code (`--show-bad-code`)
- lack a build graph

Database creation succeeds for many real APKs but not all. Treat CodeQL as **optional escalation**, not a corpus tool. If DB creation fails, fall back to Joern (which handles JADX trees more permissively) or commit to the source project if the user has it.

## Step 1 — create a CodeQL database from JADX source

The `build-mode=none` indexer skips the build and ingests Java/Kotlin sources directly.

```bash
SRC=findings/decompiled/<pkg>/sources
DB=findings/codeql/<pkg>-db

codeql database create "$DB" \
  --language=java \
  --source-root "$SRC" \
  --build-mode=none \
  --overwrite
```

For Kotlin-heavy apps the same Java indexer handles Kotlin under the same language flag.

## Step 2 — install the query packs

```bash
codeql pack download codeql/java-queries
```

## Step 3 — run the Android-specific queries

```bash
RESULTS=findings/codeql/<pkg>.sarif

codeql database analyze "$DB" \
  codeql/java-queries:Security/CWE/CWE-926/AndroidIntentRedirection.ql \
  codeql/java-queries:Security/CWE/CWE-079/UnsafeAndroidAccess.ql \
  codeql/java-queries:Security/CWE/CWE-749/AndroidWebViewJavaScriptSettings.ql \
  codeql/java-queries:Security/CWE/CWE-201/SensitiveAndroidFileLeak.ql \
  --format=sarif-latest \
  --output "$RESULTS"
```

The full Android query set is browsable under https://codeql.github.com/codeql-query-help/java/ — search the page for "Android".

A quick way to run *every* Android query is the security-extended suite:

```bash
codeql database analyze "$DB" \
  codeql/java-queries:codeql-suites/java-security-extended.qls \
  --format=sarif-latest --output "$RESULTS"
```

Security-extended is louder but useful when you don't yet know which class of bug applies.

## Step 4 — turn SARIF into evidence

Each SARIF `result` has `ruleId`, `locations` (file/line), `codeFlows` for path-graph queries, and `partialFingerprints` for dedup. Attach these to your hypothesis as `evidence`:

```bash
jq -r '
  .runs[].results[] |
  [.ruleId,
   (.locations[0].physicalLocation.artifactLocation.uri),
   (.locations[0].physicalLocation.region.startLine|tostring),
   (.message.text // "")]
  | @tsv
' "$RESULTS"
```

For path-graph results (intent redirection, WebView fetch), iterate `result.codeFlows[].threadFlows[].locations` to extract the full source → sink chain. The chain belongs in the finding's `evidence` array verbatim — that is what CodeQL is for.

## Custom queries

When you find a recurring bug pattern that isn't covered by the default pack, write a small custom `.ql` file. The pattern usually looks like a `TaintTracking::Configuration` between an Android source predicate (intent extras, deep-link query params) and a project-specific sink. Keep custom queries beside the capability's outputs (e.g. `findings/codeql/queries/<pkg>/<name>.ql`) and cite them in the hypothesis.

## When CodeQL is the wrong tool

Skip CodeQL and rely on Joern when:

- the APK is heavily obfuscated and class names mean little
- you only need triage context for the agent's reasoning, not external evidence
- DB creation fails or takes longer than the finding is worth
- the bug class is purely behavioural (e.g. backend trust assumptions) and no Android query pack covers it
