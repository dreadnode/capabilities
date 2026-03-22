---
name: write-path-to-rce
description: Escalate arbitrary file write into code execution by abusing framework view or template resolution. Use when you can write files but cannot execute script extensions directly, and the framework auto-loads templates or code from predictable search paths.
---

# Arbitrary File Write -> RCE via View Engine Resolution

## Pattern
- You have arbitrary file write through path traversal, upload, report generation, or similar functionality
- The web server blocks direct requests to executable extensions
- The framework still resolves, compiles, or loads files internally from the filesystem

## Key Insight
HTTP-layer request filtering and filesystem-level template lookup are different control planes. A framework can execute a written file through internal resolution even when direct URL access to that extension is blocked.

## Framework Cheatsheet

### ASP.NET MVC (Razor)
Typical search paths include:
- `~/Views/{controller}/{action}.cshtml`
- `~/Views/Shared/{action}.cshtml`

Write a Razor payload into a reachable search path and trigger the matching controller or action.

### Ruby on Rails
Zeitwerk and wildcard routing can make controller or helper writes reachable when files land inside autoload paths such as:
- `app/controllers/`
- `app/models/`
- `app/helpers/`
- `lib/`

### Express.js
If the application renders attacker-writable EJS or Pug templates from `views/`, template execution becomes server-side code execution.

### Django and Flask
If the target uses Jinja2 or unsafe template rendering paths, attacker-writable templates can execute on render.

### Laravel
Blade templates written into `resources/views/` become reachable through normal view resolution.

### Go
Go templates are usually more constrained. In Go applications, arbitrary write more often needs to chain into source replacement, build triggers, or unsafe helper functions rather than template execution alone.

## Detection
- Error messages disclose view search paths
- ProcMon or `strace` shows framework file lookups during normal requests
- Writable application paths overlap with template, view, or autoload directories

## Validation Steps
1. Confirm arbitrary write by placing a canary file.
2. Map the framework's resolution order.
3. Write a payload into a searched path.
4. Trigger the code path that resolves or renders that file.
5. Confirm execution with a benign command, callback, or file creation.

## Chain With
- `apache-confusion-attacks`
- `race-condition-single-packet`
- `parser-differential-bypass`

## References
- https://lab.ctbb.show/research/asp-net-mvc-view-engine-search-patterns
- https://lab.ctbb.show/research/write-path-traversal-to-RCE-art-department
