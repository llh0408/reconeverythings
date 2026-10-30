---
name: reconeverythings
description: Authorized infrastructure and OSINT reconnaissance workflow using the ReconEveryThings MCP tools. Use when asked to map an organization's external attack surface, investigate a domain, IP range, email, username, or public person, analyze JavaScript exposed by a web application, pivot between infrastructure and identity evidence, maintain an entity relationship graph, or produce a reconnaissance report.
---

# ReconEveryThings Workflow

This skill defines a disciplined reconnaissance process. The objective is to
build a defensible picture of external exposure and human-linked evidence using
passive sources and non-exploitative fingerprinting.

Use only on assets and identities within an authorized scope. Stop and request
clarification when the scope is ambiguous.

## Operating Principles

1. Prefer passive evidence. Enable stealth unless the engagement explicitly
   authorizes active service discovery and higher request rates.
2. Record every meaningful entity and relationship in the graph before moving
   to the next phase.
3. Separate observation from inference. A technology match is not proof of a
   vulnerability. A username match is not proof of identity.
4. Keep one campaign workspace per engagement. Use a stable `REC_WORKSPACE`
   value so runs, graph state, and reports remain consistent.
5. Store API keys and runtime limits in `.env` or the MCP client environment,
   never in prompts, command lines, or reports. Existing environment variables
   take precedence over `.env`.
6. Keep tool output ASCII and free of decorative characters.
7. Never run exploitation, credential attacks, authentication bypass, or
   destructive actions. This framework does not support them.
8. Breach lookups collect breach metadata only. Never retrieve, store, or use
   leaked records, passwords, or hashes, even when a provider returns them.

## Phase 0: Scope And OPSEC

Before the first tool call, write down:

- Authorized root domains, IP ranges, and organizations.
- Authorized personal identifiers such as email addresses or usernames.
- Whether active port scanning and non-stealth request rates are permitted.
- Whether social platform profiling of named individuals is permitted.
- A stop condition, such as leaving scope, finding customer data, or hitting a
  platform rate limit.
- The workspace directory and campaign name for this engagement.

OPSEC defaults:

- Start with `stealth: true` for every `rec_execute_cli` call.
- Do not raise concurrency. The engine caps stealth traffic at 2 requests per
  second, keeps at most 3 HTTP workers, and adds randomized 0.5 to 2.5 second
  jitter delays. A higher `threads` value applies only when `stealth=false`.
- Do not paste secrets, credentials, or personal data into chat messages.
  Keep findings in the workspace and reference them by entity ID.
- Prefer one target per call. A CIDR, URL, email, username, or person name is
  normalized by the engine, but mixing unrelated targets in one run weakens
  attribution.
- Use `strict=1` for OSINT identity attribution when false positives are
  costly. It requires a second identity signal and suppresses blocked or weak
  matches; suppressed counts appear in `strict_filtered`. Use `strict=0` for
  broad discovery. Strict mode is not available for infrastructure runs.

Scope gate: if the target is not clearly authorized, do not execute. Explain
the missing authorization in one sentence and wait.

## Phase 1: Broad Infrastructure Enumeration

Run the full infrastructure chain first. Do not select individual modules on
the first pass; the chain is ordered so that later modules consume earlier
evidence. If time or authorization is limited, the baseline subset is
`whois,subdomains,wayback,ip_port,techstack,waf`; add `crawler_js`, `assets`, and
`vuln_map` when the scope allows. Add `fuzz` only when active directory
enumeration is explicitly authorized, and add `vhost` only when active virtual
host probing is explicitly authorized. Use `-sm` in the CLI, or
`skip_modules` through MCP, to run the full chain without those active phases.

Tool call:

```text
rec_execute_cli(target="example.com", mode="infra", stealth=true)
```

Expected coverage:

- `whois_asn`: registrar, registrant organization, registrant emails, ASN and
  announced CIDR ranges.
- `subdomains`: passive certificate transparency and Subfinder results.
- `wayback`: passive Wayback Machine CDX lookup for the registrable domain.
  Returns historical URLs across in-scope subdomains, each with a capture
  timestamp and a replay link of the form
  `https://web.archive.org/web/<timestamp>/<url>`. The lookup queries
  archive.org only, never the target, and runs in both stealth and active
  modes. Bound it with `REC_MAX_WAYBACK_URLS`.
- `ip_port`: resolved addresses, CNAME and ASN-based CDN or WAF attribution,
  passive ports from Shodan InternetDB in stealth mode.
- `techstack`: every candidate host URL passes through ProjectDiscovery httpx
  for a liveness gate, then live URLs are fingerprinted for status, title,
  technologies, TLS certificate names, and favicon hash, and confirmed with
  whatweb and webanalyze. Pass `skip_liveness=true` to bypass the httpx gate
  and probe every collected URL directly. Stealth mode uses only built-in
  HTTP fingerprinting and does not invoke the external technology tools.
- `waf`: WAF and firewall identification through wafw00f, nmap NSE fallback,
  and passive header, cookie, and body fingerprints. Stealth mode uses passive
  fingerprints only.
- `fuzz`: bounded directory fuzzing with the bundled directory, sensitive
  file, and API wordlists, soft-404 and generic block filtering, and recursive
  traversal of discovered directories. This phase is active probing and is
  skipped in stealth mode. Use it only when the engagement explicitly
  authorizes directory enumeration, pass `stealth=false`, and keep the request
  budget bounded with `REC_MAX_FUZZ_REQUESTS`. A custom `wordlist` path
  replaces the bundled directory list; the sensitive and API lists still run.
- `vhost`: bounded virtual host discovery. Candidate `Host` headers from the
  bundled label list are sent to the target address and compared against a
  random Host baseline. Confirmed hits differ from the baseline on status,
  title, or content length. CDN and WAF-fronted hosts are skipped, and names
  already known from passive DNS are not retested. This phase is active probing
  and is skipped in stealth mode. Use it only with explicit authorization and
  bound it with `REC_MAX_VHOST_REQUESTS` and `REC_MAX_VHOST_HOSTS`. A custom
  `vhost_wordlist` path replaces the bundled list.
- `crawler_js`: crawled URLs and JavaScript endpoints, authors, emails,
  secrets.
- `assets`: dedicated file-extraction crawl across live hosts and subdomains.
  It follows in-scope HTML links up to the configured depth and records every
  referenced JavaScript, CSS, and HTML URL with its source page. JS and CSS
  URLs are reference-only; HTML pages are fetched with bounded GET requests.
  Output lists only successfully found asset URLs plus a final count summary.
  Caps are controlled by `REC_MAX_ASSET_HOSTS`, `REC_MAX_ASSET_PAGES`,
  `REC_MAX_ASSET_DEPTH`, and `REC_MAX_ASSETS`; stealth mode lowers the host and
  page caps.
- `vuln_map`: passive CVE associations with CVSS scores.

After the run:

1. Call `rec_graph_query(entity_id="all")`.
2. Confirm the graph node and edge counts increased.
3. Record the run filename from the tool response for later reporting.
4. Note which modules returned little or no evidence; absence is a finding, not
   a failure, when sources are reachable.

If the engine reports a module failure, check whether the failure is a missing
external binary, a missing API key, a rate limit, or a network timeout. Retry
only with a changed condition. Do not repeat identical failing calls.

## Phase 2: Anomaly Prioritization

Review the graph and the run JSON in this order.

### 2.1 Host And Network Anomalies

Prioritize:

- Hosts with no CDN or WAF attribution and a resolved IP. These are potential
  origin exposure candidates.
- WAF evidence that conflicts with the hosting provider or ASN, which can
  indicate a proxy layer in front of an origin.
- Hostnames containing `dev`, `staging`, `uat`, `test`, `qa`, `vpn`,
  `internal`, `api`, `jenkins`, `gitlab`, `admin`, or `jira`.
- Rare open ports outside `80` and `443`, especially database, cache,
  container, and remote administration ports.
- Certificate names that are absent from passive DNS.
- Virtual hosts that respond differently from the default site and do not
  appear in passive DNS. Treat them as origin or internal-service leads.
- Historical Wayback URLs that reveal removed administrative paths, legacy
  services, or hosts absent from current passive DNS.
- Multiple ASNs for one brand, or an ASN inconsistent with the declared
  hosting provider.
- Favicon or title matches to known administrative software.

### 2.2 Technology And Vulnerability Prioritization

Rank technologies by exposure and specificity:

1. Remote access, VPN, and identity gateways.
2. CI/CD, source control, and orchestration platforms.
3. Administrative panels and monitoring dashboards.
4. Web frameworks with versions.
5. Generic CDN and proxy layers.

Treat a CVE mapping as a lead only when all of the following hold:

- The product name is specific, not a generic category.
- A version was observed, or the CVE applies across all versions.
- The affected component appears on an internet-reachable host.
- The CVSS score is recorded with the CVE identifier.

Use the graph query for the technology or vulnerability node to see which hosts
and domains connect to it before escalating.

### 2.3 Identity And Organization Leads

From `whois_asn` and infrastructure output, collect:

- Registrant emails and organization names.
- Emails or author names embedded in JavaScript.
- TLS organization names that differ from the brand.

These become OSINT candidates in Phase 4.

## Phase 3: JavaScript And Application Analysis

Use this phase when:

- The crawl found JavaScript URLs.
- A host exposes a single-page application, API gateway, or admin console.
- The run JSON lists endpoints but no per-file detail.
- A specific JavaScript file is suspected of containing internal hostnames or
  configuration.

Tool call:

```text
rec_inspect_js(js_url="https://example.com/static/app.js", stealth=true)
```

Review the returned structure for:

- `endpoints`: API paths, GraphQL endpoints, websocket URLs, CDN and storage
  buckets. Group them by host and note non-public hosts.
- `internal_domains`: hosts outside the analyzed origin that appear in code.
- `emails` and `authors`: developer identities and contact addresses.
- `comments`: developer comments that may contain internal context.
- `potential_secrets`: API keys, tokens, private key markers, and credential
  patterns. Record the type and source URL, but do not reproduce the full
  secret in narrative text. If a live secret is confirmed, pause the assessment
  and notify the engagement owner through the agreed channel.
- Response metadata: content type, size, and truncation. A truncated file may
  hide endpoints; request a smaller chunk only if the platform supports range
  requests and the scope allows it.

Add non-public hosts and application endpoints to the graph:

```text
rec_graph_add_relation(
  source_id="example.com",
  source_type="DOMAIN",
  relation="REFERENCES_ENDPOINT",
  target_id="endpoint:<stable-hash>",
  target_type="ARTIFACT",
  metadata="source=https://example.com/static/app.js"
)
```

Use deterministic IDs. For endpoints and secrets, prefix with `endpoint:` or
`secret:` and append a short hash of the normalized value. For emails, use
`email:<address>`. For usernames, use `username:<name>`. For people, use
`person:<normalized-name>`.

## Phase 4: Cross-Mode Pivoting

Pivot only when evidence supports a new, scoped target. Read
`references/pivoting_rules.md` for the full rule set.

### 4.1 Infrastructure To OSINT

Run OSINT when infrastructure produced any of:

- A registrant email from WHOIS or RDAP.
- An email or author name in JavaScript.
- A named individual in document metadata.
- A public repository that refers to the target domain.

Tool call:

```text
rec_execute_cli(target="jane.doe@example.com", mode="osint", stealth=true)
```

Start with the full OSINT chain for an email or username. For a person name,
confirm the spelling and affiliation first; name-only searches have high false
positive rates. When precision matters more than coverage, use strict mode:

```text
rec_execute_cli(target="jane.doe", mode="osint", stealth=true, strict=1)
```

Strict mode re-fetches each candidate username profile and requires a second
identity signal in the page. It also rejects blocked challenges, suspended
accounts, non-user or mismatched accounts, and profiles whose content does not
match the candidate. `strict_filtered` counts suppressed candidates. Strict
mode reduces false positives but can suppress true matches on JavaScript-heavy
or bot-protected profiles; confirm retained matches manually before treating
them as identity evidence.

The OSINT chain covers:

- `identity`: target normalization, username variants, and email permutations.
- `username`: WhatsMyName-based checks against public profile URLs on many
  platforms. A match is a weak identity signal until corroborated.
- `social`: direct GitHub, GitLab, Reddit, Medium, LinkedIn, and Stack Overflow
  profile checks plus search engine discovery.
- `breach`: Have I Been Pwned and LeakCheck metadata lookup. It requires
  `HIBP_API_KEY` and/or `LEAKCHECK_API_KEY`, returns breach names, dates, and
  data classes, and never records leaked records or passwords.
- `git`: public repository, commit, and configuration intelligence.
- `metadata`: public document and image metadata extraction.

### 4.2 OSINT To Infrastructure

Pivot back to infrastructure when OSINT produced:

- A corporate email domain that is not the original target.
- A domain or subdomain in repository configuration or leaked indicators.
- A cloud storage bucket or internal hostname in document metadata.
- A personal domain linked from a verified profile.
- A specific software version tied to a known host, such as a project README
  naming Keycloak 21.0.1. Record `tech:<product>:<version>`, relate it to the
  host, and add the version to passive CVE review. Do not pass a bare version
  string to `rec_execute_cli`; it is not a valid recon target.

Tool call:

```text
rec_execute_cli(target="corp.example.net", mode="infra", stealth=true)
```

Pivot limits:

- Do not chase generic public domains such as `github.com`, `cloudflare.com`,
  or `google.com`.
- Do not pivot on a single unverified username match.
- Do not expand to personal accounts unrelated to the authorized scope.
- Stop after two hops unless a new hop is supported by at least two independent
  evidence sources.

### 4.3 Recording Analyst Decisions

After each pivot, record the rationale in the graph:

```text
rec_graph_add_relation(
  source_id="email:jane.doe@example.com",
  source_type="ARTIFACT",
  relation="PIVOTED_TO",
  target_id="example.net",
  target_type="DOMAIN",
  metadata="reason=corporate email domain; verified by WHOIS"
)
```

Use `CONFIRMED_BY`, `MENTIONED_IN`, `OWNS_EMAIL`, `HAS_ALIAS`,
`AFFILIATED_WITH`, `RESOLVES_TO`, `EXPOSES`, `RUNS_TECH`, `USES_ASN`,
`REFERENCES_ENDPOINT`, `EXPOSES_ARCHIVED_URL`, and `PIVOTED_TO` consistently.

## Phase 5: Reporting

Generate the report only after the graph contains the runs and analyst-confirmed
relations for the campaign.

Tool call:

```text
rec_generate_report(
  campaign_name="Example External Reconnaissance",
  output_dir="/path/to/workspace/reports/example"
)
```

Output files:

- `01_Executive_Summary.md`: decision-oriented summary with scope, OPSEC,
  attack surface metrics, host inventory, Wayback snapshots, high-value
  entities, CVE mapping, personnel and breach exposure, pivots, observations,
  next steps, and limitations.
- `02_Full_Recon_Data.json`: consolidated campaign data with every saved run,
  graph nodes and edges, and suggested pivots.
- `03_Entity_Relationship_Map.md`: Mermaid graph, ASCII tree, and legend.

Report rules:

- Follow `references/report_template.md` for section order and tone.
- State evidence and confidence for every non-trivial claim.
- Distinguish observed facts, passive correlations, and analyst hypotheses.
- Redact live secrets and personal contact details in narrative sections while
  retaining stable identifiers for traceability.
- Never claim exploitation, compromise, or unauthorized access.
- Keep the report ASCII and free of emojis or decorative symbols.

Before delivering:

1. Verify all three files exist and are non-empty.
2. Confirm the executive summary counts match the consolidated JSON.
3. Confirm the Mermaid block starts with `graph LR`.
4. Confirm the ASCII tree is present in a fenced `text` block.
5. Confirm the highest CVSS and its label agree with the vulnerability table.
6. Confirm every recommended pivot appears in the graph or the pivot table.

## Entity And Relation Conventions

Node types:

| Type | Use |
| --- | --- |
| `ORG` | Registrar, registrant, employer, or inferred organization. |
| `ASN` | Autonomous system number. |
| `DOMAIN` | Registered domain or observed hostname. |
| `IP` | Resolved IPv4 or IPv6 address. |
| `PORT` | Host and port endpoint. |
| `TECH` | Product and optional version. |
| `VULN` | CVE identifier. |
| `ARTIFACT` | Email, username, endpoint, secret, indicator, path, asset, vhost, archived URL, or breach exposure. |
| `PERSON` | Named individual. |
| `SOCIAL_ACCOUNT` | Public social or developer profile. |
| `REPO` | Public source repository. |

ID conventions:

- Domain: `example.com`
- IP: `203.0.113.10`
- Port: `203.0.113.10:443`
- ASN: `AS13335`
- Email: `email:jane.doe@example.com`
- Username: `username:jdoe`
- Person: `person:jane-doe`
- Technology: `tech:nginx:1.24.0`
- Vulnerability: `CVE-2024-0001`
- Repository: `https://github.com/org/repo`
- Endpoint: `endpoint:<16-char-hash>`
- Secret: `secret:<16-char-hash>`
- Indicator: `indicator:<16-char-hash>`
- Internal path: `path:<16-char-hash>`
- Virtual host: `vhost:<16-char-hash>`
- Asset: `asset:<16-char-hash>`
- Archived URL: `wayback:<16-char-hash>` (hash of the replay link)
- Breach exposure: `breach:<16-char-hash>` (hash of provider, breach, and identifier)

Relation direction:

- `DOMAIN RESOLVES_TO IP`
- `IP EXPOSES PORT`
- `DOMAIN USES_ASN ASN`
- `ASN ANNOUNCES CIDR`
- `DOMAIN RUNS_TECH TECH`
- `DOMAIN PROTECTED_BY TECH`
- `IP SERVES_VHOST ARTIFACT`
- `TECH AFFECTED_BY VULN`
- `PERSON OWNS_EMAIL ARTIFACT`
- `PERSON HAS_ALIAS ARTIFACT`
- `PERSON AFFILIATED_WITH ORG`
- `DOMAIN REFERENCES_ENDPOINT ARTIFACT`
- `DOMAIN EXPOSES_ARCHIVED_URL ARTIFACT`
- `PERSON EXPOSED_IN_BREACH ARTIFACT`
- `ARTIFACT EXPOSED_IN_BREACH ARTIFACT`
- `REPO MENTIONS DOMAIN`
- `ARTIFACT PIVOTED_TO DOMAIN`

Do not invert these directions. The ASCII exporter renders edges from source to
target, and later analysts rely on the direction when reading the graph.

## Quality Bar

A complete campaign satisfies all of these:

- Every executed run is saved and ingested into the graph.
- Every pivot recommendation has a stated evidence source.
- High-value entities include at least the reason they were prioritized.
- CVE leads include CVE identifier, CVSS, affected component, and host context.
- Wayback leads include the original URL, capture timestamp, and replay link.
- Breach leads include provider, breach name, date, and data classes, with no
  leaked record content.
- Username matches are labeled as unverified until corroborated.
- Strict OSINT runs record the strict level and the suppressed candidate count;
  strict acceptance is still a signal, not proof of identity.
- The executive summary is readable without the JSON.
- The relationship map renders as valid Mermaid and valid ASCII.
- Limitations and unverified assumptions are explicit.
- No out-of-scope or non-authorized action was taken.

## Failure Handling

| Symptom | Action |
| --- | --- |
| `Target must not be empty` | Supply a non-empty target. |
| Invalid module selection | Use a module from the active mode's chain, or omit `modules`. |
| Invalid skip selection | Use module names from the active mode's chain, or omit `skip_modules`. |
| External binary missing | Continue; the engine uses internal fallbacks. Do not install tools during engagement execution without authorization. |
| API rate limit | Record the gap, wait, or retry later with a key. Do not loop. |
| Breach provider key missing | Continue; report the phase as skipped and note the coverage gap. |
| Network timeout | Retry once, then record the source as unavailable. |
| Social platform blocked | Record the platform as unavailable; do not attempt bypass. |
| Graph write fails | Report the error and stop reporting until the workspace is writable. |
| Report directory is a file | Choose a directory path, not a file path. |
