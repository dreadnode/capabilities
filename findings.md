# Findings: Web-Security Issue Tracker Integrations

## Existing Web-Security Patterns

- `web-security` already declares inline MCP servers in `capability.yaml`.
- Existing `mcp/hackerone.py` is the closest integration pattern: self-contained PEP 723 script, FastMCP, lazy async `httpx.AsyncClient`, env-var auth, health tool, report create/comment tools, and mocked tests via a FastMCP stub.
- The agent prompt enforces a validation/reporting pipeline before any submission: `assess_confidence`, `report-preflight`, `exploit-verifier`, `report-writer`.
- A connector should be a delivery/export surface after validation, not part of discovery.

## Connector Scope Decisions

- Jira: likely MCP server with Cloud REST API v3, basic auth/API token first. Main formatting issue is Jira ADF; MVP can generate simple ADF paragraphs from Markdown/plain text rather than full Markdown fidelity.
- Linear: GraphQL API or official MCP. For portability inside this capability, a local MCP gives predictable tool names and tests.
- GitHub: could be skill-only with `gh`, but runtime portability favors a small local MCP unless default GitHub tooling is guaranteed.

## Official API Notes

- Jira Cloud REST issues API supports create/get/edit/assign/transition/create metadata.
- Linear GraphQL endpoint is `https://api.linear.app/graphql`; `issueCreate` accepts `title`, `description`, `teamId`.
- GitHub create issue via REST requires fine-grained token with `Issues: write`.
