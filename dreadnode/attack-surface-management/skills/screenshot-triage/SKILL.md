---
name: screenshot-triage
description: Triage web application screenshots to identify high-value targets for manual investigation. Use when analyzing WEBSCREENSHOT nodes from BBOT scans or when visually assessing discovered web assets.
---

# Screenshot Triage

## Purpose

Triage web screenshots captured by BBOT (via gowitness) to identify high-value targets for human follow-up. The goal is vulnerability discovery — a screenshot is "interesting" if it suggests a high likelihood of success for a human tester.

## Retrieving Screenshots

> **Note:** the `analyzed` property on `WEBSCREENSHOT` is **not** populated by
> BBOT. It is an agent-managed flag — you must set it yourself via `query_graph`
> after triaging each screenshot (see Workflow step 3 below). The "unanalyzed"
> query below only returns useful results once you have started writing it back.

```cypher
-- Find all unanalyzed screenshots
MATCH (s:WEBSCREENSHOT) WHERE s.analyzed IS NULL RETURN s.uuid, s.url

-- Get screenshot for a specific URL
MATCH (s:WEBSCREENSHOT) WHERE s.url CONTAINS 'admin' RETURN s.uuid, s.url

-- Get screenshots with their host context
MATCH (s:WEBSCREENSHOT)-[]-(parent)
RETURN s.uuid, s.url, labels(parent)[0] as parent_type, parent.name
```

Use `get_screenshot(uuid=...)` or `get_screenshot(url=...)` to retrieve the actual image.

## Triage Principles

1. **Intent is Vulnerability Discovery**: Focus on pages suggesting high exploitation potential.
2. **Structure Over Content**: Page structure (forms, dashboards, admin panels) matters more than marketing text.
3. **Appearance as Clue**: Bare-bones internal tools often have weaker security than polished public pages.
4. **Prioritize Interaction Points**: Forms, dashboards, and control panels are far more valuable than static pages.

## Priority Classification

### Critical

- Administrative interfaces, control panels, backend management systems
- Login forms specifying "admin", "staff", or "internal"
- Database management interfaces (phpMyAdmin, Adminer, pgAdmin)
- Infrastructure dashboards (Grafana, Kibana, Jenkins, GitLab)

### High

- API documentation pages (Swagger, OpenAPI, Redoc, GraphQL Playground)
- Developer consoles or debugging interfaces
- Complex forms handling sensitive data (user settings, financial info)
- File upload functionality
- Pages displaying error messages, stack traces, or debug output
- Internal tools not meant for public viewing

### Medium

- Standard login forms without admin indicators
- Search functionality (potential for injection)
- User registration/account management pages
- Pages revealing technology versions or server information
- Legacy-looking applications built on old frameworks

### Low

- Marketing pages, blogs, documentation
- Static content with no interaction points
- Generic error pages (404, 403) without information leakage
- CDN or asset-serving endpoints

## What to Look For

### Visual Indicators of High Value

- **Unstyled or minimal design**: Internal tools, dev environments
- **Framework default pages**: Fresh installs, unconfigured services
- **Data tables**: Internal metrics, user data, logs
- **Terminal/console interfaces**: Web shells, command runners
- **Multiple form fields**: Complex data entry suggesting business logic
- **Version numbers in footers**: Technology identification

### Technology Clues

- Specific software names or logos (WordPress, Jira, Confluence, Jenkins)
- URL patterns visible in screenshots (e.g., `/wp-admin/`, `/administrator/`)
- Framework-specific UI elements (Django admin, Rails scaffolding, Spring Boot Actuator)
- Cloud provider indicators (AWS console, Azure portal elements)

### Red Flags

- Stack traces with file paths and line numbers
- Database error messages with query fragments
- Debug toolbars (Django Debug Toolbar, Symfony Profiler)
- phpinfo() output
- Directory listings
- Default credentials displayed or hinted at
- "Powered by" footers with version information

## Workflow

1. Query for unanalyzed screenshots
2. For each screenshot:
   a. Retrieve and examine the image
   b. Classify priority (critical/high/medium/low)
   c. Note specific elements of interest
   d. Record what a human should investigate next
3. Mark screenshots as analyzed via `query_graph`, e.g.
   `MATCH (s:WEBSCREENSHOT {uuid: $uuid}) SET s.analyzed = datetime() RETURN s.uuid`
4. Cross-reference high-priority screenshots with other graph data (technologies, findings, DNS names)
