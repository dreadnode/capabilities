# Future Tool Integrations

## ProjectDiscovery Tools (via pdtm)

The agent container has `pdtm` (ProjectDiscovery Tool Manager) pre-installed,
which provides access to the full ProjectDiscovery suite. These are available
as CLI tools in the container and do not need separate MCP servers or toolsets
at this time.

Available via pdtm:
- **httpx** — HTTP probing, tech detection, response analysis
- **nuclei** — Template-based vulnerability scanning
- **subfinder** — Fast passive subdomain enumeration
- **naabu** — Port scanning
- **katana** — Web crawling/spidering
- **uncover** — Meta-search across Shodan/Censys/Fofa/Hunter/ZoomEye
- **dnsx** — DNS toolkit (resolution, brute-force, wildcard filtering)
- **tlsx** — TLS/SSL inspection
- **notify** — Webhook/Slack/Discord notifications
- **cloudlist** — Cloud asset listing (AWS, Azure, GCP)
- **chaos** — ProjectDiscovery chaos dataset
- **alterx** — Subdomain wordlist generation
- **asnmap** — ASN mapping

These can be invoked directly via bash tool calls when the agent runs in
the container environment. If dedicated tool wrappers or MCP servers are
needed for any of these, add them here.

## Potential Future Additions

- **DNS intelligence toolset** — WHOIS, reverse WHOIS, historical DNS, DMARC/SPF/DKIM analysis
- **Censys MCP** — Internet-wide scan data (complementary to Shodan)
- **Reporting/export tool** — Structured ASM report generation from Neo4j graph
- **Continuous monitoring** — Graph diffing, new asset alerting, scheduled scans
