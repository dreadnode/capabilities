---
name: math-rendering-macro-injection
description: Abuse user-controlled TeX/LaTeX macros in MathJax and KaTeX renderers to override built-in operators, spoof rendered content, inject links/scripts, or exhaust the renderer. Use when an app renders user-supplied math (GitHub-style Markdown math, wikis, comments, chat, LMS, note apps) via MathJax or KaTeX.
---

# Math Rendering Macro Injection

Apps that render user-supplied mathematics (`$...$`, `$$...$$`, ```` ```math ````) hand attacker text to a TeX processor — usually **MathJax** or **KaTeX**. TeX is a full macro language. If the app enables macro-definition packages on untrusted input, an attacker can redefine what the renderer draws, spoof content in another user's document, inject links, or wedge the renderer.

This is primarily a **content-integrity / UI-redress** class (and sometimes XSS or DoS), not classic reflected XSS. It matters most where rendered math appears in shared, trusted surfaces: repo READMEs, issues/comments, wiki pages, knowledge bases, and chat.

## When To Use

- The target renders math notation (you see `\(`, `\[`, `$$`, KaTeX/MathJax script tags, `.MathJax`/`.katex` DOM classes).
- The math is derived from untrusted input (comments, issues, profile fields, wiki, chat messages).
- You want to demonstrate impact beyond "it renders" — override, spoof, link injection, or DoS.

## Fingerprint the Renderer

| Signal | Renderer |
|---|---|
| `mathjax`/`tex-*.js`, `window.MathJax`, `.MathJax` / `mjx-container` DOM | MathJax (v2 or v3) |
| `katex.min.js`, `.katex` / `.katex-html` DOM, `\href` support | KaTeX |
| `<annotation encoding="application/x-tex">` in output | either (MathML/TeX round-trip) |

Also determine **where** the rendered node lives: same document as trusted content (e.g. a comment rendered inside a repo page) is what makes override interesting.

## Core Technique: Macro Redefinition / Operator Shadowing (MathJax)

MathJax's `newcommand` package stores every `\def`, `\newcommand`, `\let` in a dedicated `CommandMap` (`new-Command`) registered **ahead of** the base operator maps at `priority: -1`. The write path (`addMacro`) adds to that map with **no check against the base maps**, and lookup is first-match-wins. So a user definition of a built-in control sequence (`\sum`, `\sqrt`, `\int`, …) *occludes* the native one rather than being rejected.

Effect: you can make a native operator render as arbitrary text/markup, overwriting how content appears in a victim's document.

```tex
$\def\sum{\bf ATTACKER-CONTROLLED}$
$$\sum_{i=0}^n i$$      %% renders "ATTACKER-CONTROLLED" where the Σ operator should be
```

Variants to test, in rough order of impact:

| Macro | Impact |
|---|---|
| `\def`, `\newcommand`, `\let` | highest — redefine/override operators and content |
| `\renewcommand` | override an existing command |
| `\newenvironment` | redefine environment rendering |
| `\definecolor` + `\color` | recolor / hide text (low, but useful for spoofing) |

Detect enablement quickly: if `$\def\x{A}\x$` renders `A`, the `newcommand` package is active on untrusted input.

## KaTeX Equivalents

- KaTeX supports `\def`, `\gdef`, `\newcommand`, `\renewcommand` unless the host passes a restricted config. Same operator-shadowing idea applies.
- **`\href` link injection**: `\href{URL}{text}` renders a clickable link inside the math node. Test whether the host restricts the scheme — older/misconfigured setups allow `javascript:`/`data:`; the KaTeX default `trust: false` blocks `\href` entirely, and `trust: true` (or a permissive callback) is the vulnerable state.
  ```tex
  \href{javascript:alert(document.domain)}{click}
  ```
- **`\includegraphics`** / `\htmlData` / `\htmlClass` / `\htmlId` are gated by `trust`/`strict`; when enabled they become HTML-attribute injection primitives worth testing for XSS or DOM clobbering.

## Denial-of-Service Variants

- **Macro expansion blowup**: nested self-referential macros can explode expansion. MathJax caps this with `maxMacros`/`maxBuffer`; KaTeX with `maxExpand`. If the host raised or disabled the cap, a small payload can hang the renderer tab.
  ```tex
  \def\a{\b\b}\def\b{\a\a}\a
  ```
- **Deep/huge structures**: large `\underbrace`/matrix nesting or enormous `\rule` dimensions can freeze layout. Treat as client-side DoS affecting every viewer of the shared content.

## Impact Framing

- **Content spoofing / integrity**: the rendered math in a *victim's* README/issue/wiki shows attacker-chosen content — misinformation, fake values, defacement of trusted pages. This is the GitHub-class bug (paid across multiple variants).
- **Link/redirect injection** via `\href` — phishing from a trusted origin, or XSS if `javascript:`/HTML sinks are reachable.
- **DoS** — renderer hang for all viewers.
Record which surface the node renders in and who else sees it — impact scales with the trust and audience of that surface.

## Verification

1. Confirm the package is enabled: `$\def\x{PWN}\x$` → renders `PWN`.
2. Override a real operator and screenshot the rendered result in a shared/trusted context (issue, wiki, comment), not just your own scratch page.
3. For `\href`, confirm the emitted `<a>` `href` and whether the scheme survived sanitization (inspect the DOM, not the source).
4. For DoS, measure render time / tab responsiveness with a bounded payload before escalating.

## Remediation (for the report)

Disable macro-definition packages on untrusted input:
```javascript
// MathJax v3 — remove the newcommand package for user content
window.MathJax = { tex: { packages: { '[-]': ['newcommand', 'action', 'html'] } } };
```
```javascript
// KaTeX — reject definitions and dangerous commands on untrusted input
katex.render(src, el, { trust: false, strict: "error", maxExpand: 1000 });
```
Render untrusted math in an isolated origin/sandboxed iframe so an override cannot alter trusted document content.

## Chain With

- **dom-vulnerability-detection** — when `\href`/`\html*` reaches a script or attribute sink, confirm the XSS there.
- **data-exfil** — Markdown/rendered-output injection channels for exfil when a link/image sink is reachable.
- **report-preflight** — frame content-spoofing severity and eligibility before submitting.
