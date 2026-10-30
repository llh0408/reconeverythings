# ReconEveryThings (recn)

ReconEveryThings is a reconnaissance framework with two integrated parts:

1. A Python CLI named `recn` for chained infrastructure and OSINT workflows.
2. A FastMCP server that exposes the same engine as agent tools, adds an
   entity relationship graph, and generates assessment reports.

The tool performs reconnaissance, metadata extraction, and passive CVE mapping
only. It does not include exploitation payloads.

## Features

- Two reconnaissance modes: `infra` and `osint`.
- Ordered module chains with per-module failure isolation.
- Strict JSON output validated by Pydantic models.
- Optional stealth mode with jittered pacing, rotated request headers, and
  passive port data from Shodan InternetDB instead of active scanning.
- Passive subdomain discovery through Subfinder when installed, Cert Spotter,
  and crt.sh.
- Passive Wayback Machine CDX lookup for historical URLs with replay links.
- WHOIS, RDAP, Team Cymru ASN lookup, and RIPE Stat fallback.
- HTTP technology fingerprinting, TLS certificate inspection, and favicon
  hashing.
- JavaScript crawling with endpoint, author, email, and secret extraction.
- Bounded virtual host discovery by comparing Host-header responses against a
  random baseline.
- Passive CVE mapping through NVD, optional Vulners, and Shodan CVE identifiers.
- Identity permutation, WhatsMyName-based cross-platform username checks, and
  public profile checks across GitHub, GitLab, Stack Overflow, Reddit, Medium,
  and LinkedIn.
- Passive breach-exposure metadata lookup through official Have I Been Pwned
  and LeakCheck APIs; only breach names, dates, and data classes are recorded.
- Repository intelligence from GitHub and GitLab APIs.
- Public document metadata extraction from PDF, Office Open XML, legacy Office,
  and image files.
- SQLite entity graph with Mermaid and ASCII exports.
- Three-file report generation for campaign handoff.

## Requirements

- Python 3.10 or newer.
- External binaries: `subfinder`, `naabu`, `httpx` (ProjectDiscovery),
  `katana`, `gau`, and `webanalyze`. The installer builds all six with Go and
  records their absolute paths in `.env`. Every module has an internal fallback
  when a binary is missing.
- Technology detection: `whatweb` (system package) and `webanalyze` with its
  technology definitions file, downloaded by the installer.
- WAF detection: `wafw00f` (installed automatically into the virtual
  environment when missing) and optional `nmap` for the fallback NSE check.

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Install the MCP server dependencies:

```bash
pip install -e ".[mcp]"
```

The MCP dependency is pinned below version 2 because the server targets the
FastMCP API available in `mcp` 1.x.

### One-Step Installation

Run the installer once on a new machine:

```bash
bash install.sh
```

The installer performs the complete first-time setup:

- Creates `.venv` and installs the CLI plus MCP dependencies.
- Installs the Go reconnaissance tools `subfinder`, `httpx`, `naabu`,
  `katana`, `gau`, and `webanalyze` into `~/.local/bin` and records them in
  `.env`.
- Downloads the `webanalyze` technology definitions to
  `~/.local/share/reconeverythings/technologies.json` and records the path in
  `.env`.
- Records the `whatweb` path in `.env` and prints the install command when it
  is missing.
- Installs `wafw00f` into the virtual environment when it is not already
  available, and records `wafw00f` and `nmap` paths in `.env`.
- Copies `.env.example` to `.env` when no `.env` exists.
- Installs the `reconeverythings` Agent Skill into the shared skills directory
  and into every detected harness.
- Registers the `reconeverythings` stdio MCP server in every detected harness
  using that harness's native configuration format.
- Links `recn` and `rec-mcp` into `~/.local/bin` so they run without activating
  the virtual environment.
- Skips the Go tools when Go is unavailable and prints manual instructions.

Supported harnesses are auto-detected: Qoder, Claude Code, Codex CLI,
DeepSeek Harness (DSH), Gemini CLI, OpenCode, Cursor, and GitHub Copilot CLI.
Rerun the installer after adding a new harness to the machine. Existing
configuration is merged, not replaced. Changed files receive a
`.reconeverythings.bak` backup unless `--no-backup` is used.

| Harness | Skill directory | MCP configuration |
| --- | --- | --- |
| Qoder | `~/.qoder/skills` | `~/.qoder/settings.json` |
| Claude Code | `~/.claude/skills` | `~/.claude.json` |
| Codex CLI | `~/.codex/skills` | `~/.codex/config.toml` |
| DSH | `~/.dsh/skills` | `~/.dsh/profiles/*/cordis.patch.yml` |
| Gemini CLI | `~/.gemini/skills` | `~/.gemini/config/mcp_config.json` |
| OpenCode | `~/.config/opencode/skills` | `~/.config/opencode/opencode.json` |
| Cursor | `~/.cursor/skills` | `~/.cursor/mcp.json` |
| Copilot CLI | `~/.copilot/skills` | `~/.copilot/mcp-config.json` |
| Shared | `~/.agents/skills` | Not applicable |

Installer options:

| Option | Purpose |
| --- | --- |
| `--harness auto` | Detect and configure every supported harness. Default. |
| `--harness all` | Configure all supported harnesses, creating config paths. |
| `--harness qoder,claude` | Configure only the listed harnesses. |
| `--skip-tools` | Do not install subfinder, httpx, naabu, katana, gau, and webanalyze. |
| `--skip-venv` | Reuse an existing environment instead of installing. |
| `--skip-env` | Do not create `.env`. |
| `--skip-skill` | Do not install the Agent Skill. |
| `--skip-mcp` | Do not register the MCP server. |
| `--no-link` | Do not link `recn` and `rec-mcp` into `~/.local/bin`. |
| `--no-backup` | Do not create `.reconeverythings.bak` backups. |
| `--force` | Replace a foreign skill directory with the same name. |

Restart each harness or start a new session after installation, then verify
with `/skills` and `/mcp`.

## CLI Usage

```text
recn -t TARGET -m {infra,osint} [--modules LIST] [-sm LIST] [--stealth]
     [--strict {0,1}] [--threads N] [--skip-liveness] [--wordlist FILE]
     [--vhost-wordlist FILE] [-o FILE] [--proxy URL] [-q] [--version]
```

The run starts with a gold ASCII logo, followed by three banner lines without
level prefixes: the framework name, `target=... mode=... stealth=...`, and the
authorization reminder. The logo falls back to plain ASCII when color is
disabled or output is piped. Progress lines after the banner use level prefixes
such as `[INFO]`, `[FOUND]`, and `[WARN]`.

Required arguments:

- `-t, --target`: domain, IP or CIDR, URL, email, username, or person name.
- `-m, --mode`: `infra` or `osint`.

Optional arguments:

- `--modules`: comma-separated module names. Defaults to every module in the
  selected mode.
- `-sm, --skip-modules`: comma-separated module names to exclude from the
  selected set. Every other module in the mode still runs, so
  `--modules all -sm fuzz,vhost` runs the full chain without active probing.
  Skipping every selected module is rejected.
- `--stealth`: enable jittered pacing, passive port data, and header rotation.
- `--strict {0,1}`: OSINT match strictness. `0` keeps the current search
  behavior. `1` requires stronger identity evidence and suppresses weak or
  blocked username and social profile matches. The option is rejected in infra
  mode. The default comes from `REC_STRICT` or `0`.
- `--threads N`: active-mode HTTP worker count from 1 to 64. It also raises
  the request rate floor to `N` requests per second, so active runs speed up
  without changing `REC_NORMAL_RATE`. Stealth mode ignores it and stays capped
  at 3 workers with jittered pacing.
- `--skip-liveness`: skip the httpx liveness pre-check and probe every
  collected host URL directly with the built-in HTTP client. The whatweb and
  webanalyze stages still run on the URLs that respond.
- `--wordlist`: custom directory wordlist for the fuzz phase. It replaces the
  bundled directory list; the bundled sensitive file and API lists still run.
- `--vhost-wordlist`: custom label list for the vhost phase. It replaces the
  bundled vhost wordlist.
- `-o, --output`: write the validated JSON result atomically to this file.
- `--proxy`: HTTP or SOCKS5 proxy URL for outbound HTTP requests.
- `-q, --quiet`: suppress the banner and progress logs.
- `--version`: print the tool version.

Examples:

```bash
recn -t example.com -m infra --stealth -o result.json
recn -t example.com -m infra --modules whois,subdomains,techstack
recn -t example.com -m infra --modules techstack,waf
recn -t example.com -m infra --modules techstack --skip-liveness
recn -t example.com -m infra --modules fuzz --wordlist ./dirs.txt
recn -t example.com -m infra --modules vhost --vhost-wordlist ./hosts.txt
recn -t example.com -m infra --modules wayback -o archive.json
recn -t example.com -m infra --modules all -sm fuzz,vhost -o passive.json
recn -t example.com -m infra --modules assets -o assets.json
recn -t example.com -m infra --threads 16 -o fast.json
recn -t jane.doe@example.com -m osint --stealth -o person.json
recn -t jane.doe -m osint --modules username --strict 1 -o strict.json
recn -t example.com -m infra --proxy http://127.0.0.1:8080 -o proxied.json
recn -t example.com -m infra -q -o quiet.json
```

Quiet mode behavior:

- With `-o`, only a one-line summary is printed and the JSON is written to the
  file.
- Without `-o`, the raw JSON document is printed to standard output.

Without `-q`, ASCII status logs are written to standard output and the JSON is
written only when `-o` is provided. When standard output is a terminal, log
tags are color-coded and module progress lines are highlighted in gold:

```text
[INFO] Module 5/11: TECHSTACK
[INFO] Module 6/11: WAF
```

Colors follow `REC_COLOR` (`auto`, `always`, `never`; default `auto`), the
standard `NO_COLOR` variable, and TTY detection. Piped output is always plain
ASCII, so the CLI stays safe for logs, files, and MCP transcripts.

## Modules

### Infrastructure Mode

| Module | Aliases | Purpose |
| --- | --- | --- |
| `whois_asn` | `whois`, `asn` | Registrar, registrant organization, contact emails, ASN and CIDR records. |
| `subdomains` | `subs`, `subdomain` | Passive hostname discovery from certificate transparency and Subfinder. |
| `wayback` | `wayback_machine`, `webarchive`, `archive`, `cdx`, `historical` | Passive Wayback Machine CDX lookup that records historical URLs with replay links. |
| `ip_port` | `ip`, `port`, `ports` | Host resolution, CNAME and ASN CDN detection, passive or active port discovery. |
| `techstack` | `tech`, `http` | httpx liveness gate by default, then HTTP fingerprinting, header and body technology detection, whatweb and webanalyze confirmation, TLS names, favicon hash. |
| `waf` | `wafw00f`, `firewall`, `waf_detect` | WAF and firewall identification with wafw00f, nmap NSE fallback, and passive header, cookie, and body fingerprints. |
| `fuzz` | `dirfuzz`, `dir`, `dirs`, `directory`, `content`, `sensitive` | Bounded directory fuzzing with bundled directory, sensitive file, and API wordlists, soft-404 filtering, and recursive traversal of discovered directories. |
| `vhost` | `vhosts`, `virtualhost`, `virtual_host`, `vhost_fuzz` | Bounded virtual host discovery by sending candidate `Host` headers to the target address and comparing responses against a random baseline. |
| `crawler_js` | `crawl`, `crawler`, `js` | URL crawling, JavaScript analysis, endpoint and secret extraction. |
| `assets` | `asset`, `extract`, `files`, `static`, `resources`, `webassets` | Dedicated crawl phase that extracts JavaScript, CSS, and HTML file URLs across live hosts and subdomains. |
| `vuln_map` | `vuln`, `vulns`, `cve` | Version-based passive CVE mapping with CVSS scores. |

Chain order: `whois_asn`, `subdomains`, `wayback`, `ip_port`, `techstack`, `waf`,
`fuzz`, `vhost`, `crawler_js`, `assets`, `vuln_map`.

The `wayback` phase queries the public Wayback Machine CDX index for the
registrable domain with `matchType=domain`, keeps HTTP 200 captures, and
records each unique historical URL with its capture timestamp and a replay link
of the form `https://web.archive.org/web/<timestamp>/<url>`.
Results are grouped under the host that served them, so historical subdomains
appear in the host inventory even when current passive DNS does not list them.
The lookup sends requests only to archive.org, never to the target, and runs in
both stealth and active modes. It is bounded by `REC_MAX_WAYBACK_URLS`.
Snapshot links replay archived copies, which may differ from the live service.

The `fuzz` phase sends bounded GET requests from the bundled directory,
sensitive file, and API wordlists, filters wildcard and generic block pages,
and recurses into discovered directories such as `/abc` to test
`/abc/<entry>`. Depth, host count, directory count, and total request budget
are configurable through `REC_MAX_FUZZ_*`. The phase is skipped in stealth mode
because it is active probing. A custom `--wordlist` replaces the directory list
only; the sensitive file and API lists still run. Bundled lists live in
`rec_cli/data/directory_wordlist.txt`, `rec_cli/data/sensitive_files.txt`, and
`rec_cli/data/api_wordlist.txt`; all are installed as package data.

The `vhost` phase performs bounded virtual host discovery. For the target host
it resolves the address, sends candidate `Host` headers from the bundled vhost
label list to the observed scheme and port, and keeps responses that differ
from a random Host baseline. Each hit is confirmed with a second request.
Hosts behind a CDN or WAF are skipped because the edge answers for every Host
header, and hostnames already known from passive DNS are not retested. The
phase is active probing and is skipped in stealth mode. Request budget and host
count are controlled by `REC_MAX_VHOST_REQUESTS` and `REC_MAX_VHOST_HOSTS`;
a custom label list can be supplied with `--vhost-wordlist` or
`REC_VHOST_WORDLIST`. HTTPS vhosts are evaluated through the Host header on the
resolved address, so SNI-specific routing may require separate validation.

The `assets` phase is a dedicated file-extraction crawl. It starts from every
live host URL collected by `techstack`, including subdomains, and follows
in-scope HTML links breadth-first up to `REC_MAX_ASSET_DEPTH` levels. Each page
is parsed for `<script src>`, stylesheet and module-preload links, and
navigational links, then every referenced JavaScript, CSS, and HTML URL is
recorded with its source page. JS and CSS URLs are recorded as references and
are not downloaded; HTML pages are fetched with bounded GET requests. Crawling
is capped per host by `REC_MAX_ASSET_PAGES` and globally by `REC_MAX_ASSET_HOSTS`
and `REC_MAX_ASSETS`; stealth mode lowers the host and page caps. The phase
prints only successfully found asset URLs and a final count summary. Run it
alone with `--modules assets`, or in the full chain where it runs after
`crawler_js`.

In normal mode, `techstack` sends every candidate URL derived from collected
hosts and open ports through ProjectDiscovery httpx first and probes only the
URLs it reports live. Live URLs then go through whatweb and webanalyze, and the
results are merged into the host technology list. Pass `--skip-liveness` (MCP
`skip_liveness`) to bypass the httpx gate and probe every candidate URL with
the built-in client. Stealth mode does not invoke httpx, whatweb, or
webanalyze; it fingerprints with the built-in HTTP client only.

### OSINT Mode

| Module | Aliases | Purpose |
| --- | --- | --- |
| `identity` | `emails`, `usernames` | Target normalization and username or email permutation. |
| `username` | `username_enum`, `whatsmyname`, `wmn`, `handles` | Cross-platform public profile checks using the WhatsMyName site list. |
| `social` | `profiles` | Public profile checks and search engine discovery. |
| `breach` | `breaches`, `hibp`, `leakcheck` | Passive breach-exposure metadata lookup through official provider APIs. |
| `git` | `github`, `repos` | Repository, commit, and configuration intelligence. |
| `metadata` | `documents`, `docs` | Public document, PDF, Office, and image metadata extraction. |

Chain order: `identity`, `username`, `social`, `breach`, `git`, `metadata`.

The `identity` module normalizes the target and generates candidate usernames
and emails (aliases `emails` and `usernames`). The `username` module then
downloads the WhatsMyName site definition list, or reads a local copy from
`REC_WHATSMYNAME_FILE`, and checks each candidate against the site's public
profile URL. Present and absent results follow the site's declared expected
status code and body markers. Checks are capped by `REC_MAX_USERNAME_SITES` and
lowered further in stealth mode. Sites are sampled deterministically, with half
reserved for social platforms and the rest spread across other categories, and
adult-content definitions are skipped. Every match is recorded as a social
profile and is an unverified identity lead, not proof of ownership.

The `breach` module queries official breach-notification APIs only: Have I Been
Pwned for email addresses and LeakCheck for email addresses and usernames. It
requires `HIBP_API_KEY` and/or `LEAKCHECK_API_KEY` and skips cleanly when no key
is configured. Only breach names, dates, data classes, and counts are recorded;
leaked records, passwords, and hashes returned by providers are ignored. Query
volume is bounded by `REC_MAX_BREACH_EMAILS`, `REC_MAX_BREACH_USERNAMES`, and
`REC_MAX_BREACH_FINDINGS`.

Selecting a module that belongs to the other mode is rejected with a clear
error that lists the modules available for the active mode. Skipped modules
are validated the same way, and skipping every selected module is rejected.

## Stealth Mode

`--stealth` changes the engine behavior in these ways:

- Outbound HTTP requests are capped at 2 requests per second, with randomized
  0.5 to 2.5 second jitter delays applied between requests.
- Requests use rotated browser user agents and matching header sets.
- Port data comes from Shodan InternetDB instead of active scanning.
- CVE data comes from passive sources only.
- The Wayback Machine lookup remains enabled because it queries archive.org
  only and does not contact the target.
- Username enumeration stays enabled because it reads public profile URLs on
  third-party platforms; the site cap is lowered to 40 and one username is
  checked per run.
- Breach lookup stays enabled because it queries official provider APIs only;
  it never contacts the target and never retrieves leaked records.
- External binaries are not invoked for active probing. The WAF phase uses
  passive header, cookie, and body fingerprints instead of wafw00f or nmap.
- Directory, sensitive file, and virtual host fuzzing are skipped entirely.
  Run the `fuzz` and `vhost` phases only outside stealth mode and only with
  explicit authorization.

Normal mode allows up to 8 requests per second, uses Subfinder and httpx when
available, and can run naabu plus a bounded TCP connect fallback. Both modes
avoid exploitation and only fingerprint publicly reachable services.

## Strict OSINT Matching

`--strict 1`, `REC_STRICT=1`, or MCP `strict=1` raises the evidence bar for
identity-bearing OSINT results. Level `0` keeps the current behavior. The
option is available only in OSINT mode.

- Username checks use only site definitions that publish a body marker. A
  candidate match is re-fetched from the public profile URL and is accepted
  only when the expected status is returned, the page is not a block or
  challenge page, and the body contains the username, target name, or a target
  email.
- GitHub requires an exact login and a user account, GitLab requires an active
  account, Reddit requires an exact account name that is not suspended, and
  Stack Overflow requires a matching display name or profile handle.
- Medium and LinkedIn profiles require a second identity signal in the page.
  LinkedIn HTTP 999 verification blocks are discarded instead of being
  reported as manual-review leads.
- Breach metadata is unchanged because it is already limited to records
  returned for the exact email or username.
- Suppressed candidates are counted in `osint_data.strict_filtered`; the level
  is recorded in `meta.strict_level`.

Strict matching trades recall for precision. JavaScript-rendered profiles,
login walls, and bot protection can hide the corroborating signal and cause a
true match to be suppressed.

## JSON Output

Every `-o` run writes a document with this top-level structure:

```json
{
  "meta": {
    "tool": "ReconEveryThings (recn)",
    "version": "1.0.0",
    "target": "example.com",
    "mode": "infra",
    "stealth_enabled": true,
    "strict_level": 0,
    "timestamp_utc": "2026-01-01T00:00:00Z",
    "modules_executed": ["whois_asn", "subdomains"]
  },
  "infra_data": {
    "whois_asn": {
      "registrar": "",
      "registrant_org": "",
      "registrant_emails": [],
      "asns": [
        {"asn": "", "cidr": [], "description": ""}
      ]
    },
    "hosts": [
      {
        "hostname": "",
        "ip": "",
        "cdn_waf": null,
        "waf": {
          "detected": false,
          "name": null,
          "manufacturer": "",
          "source": "",
          "evidence": []
        },
        "open_ports": [],
        "http_info": {
          "url": "",
          "status_code": 0,
          "title": "",
          "technologies": [{"name": "", "version": null}],
          "tls_cn": []
        },
        "path_findings": [
          {
            "url": "",
            "path": "",
            "status_code": 0,
            "content_length": 0,
            "content_type": "",
            "category": "discovered",
            "sensitive": false,
            "redirect_to": "",
            "depth": 0,
            "source": ""
          }
        ],
        "assets": [
          {
            "url": "",
            "kind": "html",
            "host": "",
            "source_url": "",
            "depth": 0
          }
        ],
        "vhosts": [
          {
            "hostname": "",
            "base_host": "",
            "ip": "",
            "url": "",
            "status_code": 0,
            "content_length": 0,
            "content_type": "",
            "title": ""
          }
        ],
        "historical_urls": [
          {
            "url": "",
            "timestamp": "",
            "wayback_url": "",
            "status_code": 0,
            "mime_type": ""
          }
        ],
        "js_findings": {
          "js_urls": [],
          "extracted_endpoints": [],
          "discovered_emails_or_authors": [],
          "potential_secrets": [
            {"type": "", "match": "", "source_url": ""}
          ]
        },
        "potential_vulnerabilities": [
          {
            "cve_id": "",
            "cvss": 0.0,
            "affected_Component": "",
            "summary": ""
          }
        ]
      }
    ]
  },
  "osint_data": {
    "target_identity": {
      "name": null,
      "usernames": [],
      "emails": [],
      "organization": null
    },
    "username_enum": {
      "source": "",
      "usernames_checked": [],
      "sites_checked": 0,
      "matches": 0,
      "errors": 0
    },
    "social_profiles": [
      {"platform": "", "url": "", "bio_or_notes": ""}
    ],
    "breach": {
      "providers_used": [],
      "providers_skipped": [],
      "provider_errors": [],
      "identifiers_checked": [],
      "findings": [
        {
          "identifier": "",
          "provider": "",
          "breach": "",
          "title": "",
          "domain": "",
          "breach_date": "",
          "data_classes": [],
          "pwn_count": 0,
          "verified": false,
          "sensitive": false
        }
      ]
    },
    "git_findings": [
      {"repo_url": "", "commit_emails": [], "leaked_indicators": []}
    ],
    "document_metadata": [
      {
        "file_url": "",
        "author": "",
        "creator_tool": "",
        "internal_paths": []
      }
    ],
    "strict_filtered": 0
  },
  "pivots_suggested": [
    {
      "source": "",
      "pivot_type": "infra_to_osint",
      "target_value": "",
      "reason": ""
    }
  ]
}
```

All string values are converted to printable ASCII. Unknown model fields are
rejected, so downstream automation can rely on the schema.

## Configuration File

Configuration is optional. Keys and runtime limits can be stored in a `.env`
file:

```bash
cp .env.example .env
```

The CLI and MCP server load the first existing file from this order:

1. The path in `REC_ENV_FILE`, when set in the shell.
2. `.env` in the current working directory.
3. `.env` in the project root.

Existing environment variables are never overwritten by `.env`, so shell
exports and MCP client `env` entries take precedence. The parser supports
comments, blank lines, `export KEY=value`, single-quoted values, and
double-quoted values with `\n`, `\r`, `\t`, `\"`, and `\\` escapes. Missing or
unreadable files are ignored.

Example:

```dotenv
GITHUB_TOKEN=ghp_example
NVD_API_KEY=
HIBP_API_KEY=
LEAKCHECK_API_KEY=
REC_PROXY=http://127.0.0.1:8080
REC_STEALTH_RATE=2
REC_MAX_HOSTS=100
REC_WORKSPACE=/path/to/assessment-workspace
```

Do not commit `.env`. The repository `.gitignore` excludes it. Use
`.env.example` as the template.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | Raises GitHub API limits and enables commit analysis. |
| `GITLAB_TOKEN` | Raises GitLab API limits. |
| `NVD_API_KEY` | Raises NVD CVE query limits. |
| `VULNERS_API_KEY` | Enables the optional Vulners mapping source. |
| `SHODAN_API_KEY` | Optional Shodan API access; InternetDB works without a key. |
| `GOOGLE_API_KEY` | Google Custom Search JSON API key. |
| `GOOGLE_CSE_ID` | Google Custom Search engine identifier. |
| `HIBP_API_KEY` | Have I Been Pwned API key for email breach metadata. |
| `LEAKCHECK_API_KEY` | LeakCheck v2 API key for email and username breach metadata. |
| `REC_ENV_FILE` | Alternate `.env` path. Set in the shell, not inside `.env`. |
| `REC_PROXY` | Default proxy URL when `--proxy` is not supplied. |
| `REC_TIMEOUT` | HTTP request timeout in seconds. Defaults to 15. |
| `REC_CONNECT_TIMEOUT` | Connection and DNS timeout in seconds. Defaults to 8. |
| `REC_VERIFY_TLS` | Enable TLS verification. Defaults to false for recon. |
| `REC_NORMAL_RATE` | Normal-mode requests per second. Defaults to 8. |
| `REC_STEALTH_RATE` | Stealth-mode requests per second cap. Defaults to 2. |
| `REC_STRICT` | OSINT match strictness. `0` keeps current behavior; `1` suppresses weak or blocked profile matches. Defaults to 0. |
| `REC_THREADS` | Active-mode HTTP workers and request rate floor. Defaults to 8. Stealth stays capped at 3 workers. |
| `REC_JITTER_MIN` | Minimum stealth jitter in seconds. Defaults to 0.5. |
| `REC_JITTER_MAX` | Maximum stealth jitter in seconds. Defaults to 2.5. |
| `REC_MAX_RESPONSE_BYTES` | Maximum HTTP response size. Defaults to 2500000. |
| `REC_MAX_DOCUMENT_BYTES` | Maximum document download size. Defaults to 15000000. |
| `REC_MAX_SUBDOMAINS` | Maximum collected subdomains. Defaults to 500. |
| `REC_MAX_HOSTS` | Maximum probed hosts. Defaults to 150. |
| `REC_MAX_JS_FILES` | Maximum analyzed JavaScript files. Defaults to 30. |
| `REC_MAX_CRAWL_PAGES` | Maximum crawled pages. Defaults to 12. |
| `REC_MAX_VULN_QUERIES` | Maximum CVE queries per run. Defaults to 12. |
| `REC_MAX_OSINT_ITEMS` | Maximum items per OSINT source. Defaults to 10. |
| `REC_MAX_TECH_URLS` | Maximum live URLs sent to whatweb and webanalyze. Defaults to 60. |
| `REC_MAX_FUZZ_REQUESTS` | Per-host request budget for the fuzz phase. Defaults to 900. |
| `REC_MAX_FUZZ_DEPTH` | Maximum fuzz recursion depth, including the root level. Defaults to 2. |
| `REC_MAX_FUZZ_HOSTS` | Maximum hosts fuzzed per run, target host first. Defaults to 1. |
| `REC_MAX_FUZZ_DIRS` | Maximum discovered directories queued for recursion per host. Defaults to 12. |
| `REC_MAX_ASSET_HOSTS` | Maximum hosts crawled by the assets phase, target host first. Defaults to 12. |
| `REC_MAX_ASSET_PAGES` | Maximum HTML pages fetched per host by the assets phase. Defaults to 25. |
| `REC_MAX_ASSET_DEPTH` | Maximum link-follow depth for the assets phase, including the root. Defaults to 3. |
| `REC_MAX_ASSETS` | Maximum JS, CSS, and HTML URLs recorded per run. Defaults to 800. |
| `REC_MAX_VHOST_REQUESTS` | Per-host request budget for the vhost phase. Defaults to 400. |
| `REC_MAX_VHOST_HOSTS` | Maximum hosts probed by the vhost phase, target host first. Defaults to 1. |
| `REC_MAX_WAYBACK_URLS` | Maximum archived URLs recorded from the Wayback Machine per run. Defaults to 200. |
| `REC_MAX_USERNAME_SITES` | Maximum WhatsMyName sites checked per username. Defaults to 120; stealth caps at 40. |
| `REC_WHATSMYNAME_URL` | Alternate WhatsMyName site list URL. Defaults to the upstream JSON list. |
| `REC_WHATSMYNAME_FILE` | Local WhatsMyName site list JSON. Takes precedence over the URL. |
| `REC_MAX_BREACH_EMAILS` | Maximum email addresses queried against breach providers. Defaults to 3. |
| `REC_MAX_BREACH_USERNAMES` | Maximum usernames queried against LeakCheck. Defaults to 2. |
| `REC_MAX_BREACH_FINDINGS` | Maximum breach findings recorded per run. Defaults to 200. |
| `REC_WORDLIST` | Custom directory wordlist path. Empty uses the bundled list. |
| `REC_VHOST_WORDLIST` | Custom virtual host label list. Empty uses the bundled list. |
| `REC_SUBFINDER_BIN` | Subfinder binary name or path. |
| `REC_HTTPX_BIN` | ProjectDiscovery httpx binary name or path. |
| `REC_NAABU_BIN` | Naabu binary name or path. |
| `REC_KATANA_BIN` | Katana binary name or path. |
| `REC_GAU_BIN` | Gau binary name or path. |
| `REC_WAFW00F_BIN` | wafw00f binary name or path. |
| `REC_NMAP_BIN` | nmap binary name or path, used only as a WAF fallback. |
| `REC_WHATWEB_BIN` | whatweb binary name or path. |
| `REC_WEBANALYZE_BIN` | webanalyze binary name or path. |
| `REC_WEBANALYZE_APPS` | webanalyze technology definitions JSON. Defaults to `~/.local/share/reconeverythings/technologies.json`. |
| `REC_COLOR` | Log color mode: `auto`, `always`, or `never`. Defaults to `auto`. |
| `REC_WORKSPACE` | MCP workspace directory. Defaults to `./.rec_workspace`. |
| `REC_SESSION_DIR` | Fallback MCP workspace directory when `REC_WORKSPACE` is unset. |

API keys are optional. Missing keys degrade coverage but do not stop a run.
Invalid numeric values are ignored and the documented default is used.

## MCP Server

Start the server over standard input and output:

```bash
rec-mcp
```

or:

```bash
python -m mcp_server.server
```

Register the server with an MCP client:

```json
{
  "mcpServers": {
    "reconeverythings": {
      "command": "/path/to/ReconEveryThings/.venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "REC_WORKSPACE": "/path/to/assessment-workspace",
        "GITHUB_TOKEN": "optional",
        "NVD_API_KEY": "optional",
        "HIBP_API_KEY": "optional",
        "LEAKCHECK_API_KEY": "optional"
      }
    }
  }
}
```

Run the server from the project directory, or install the package so the
`mcp_server` and `rec_cli` packages are importable.

### MCP Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `rec_execute_cli` | `target`, `mode`, `modules`, `skip_modules`, `stealth`, `strict`, `skip_liveness`, `wordlist`, `vhost_wordlist`, `threads` | Full validated reconnaissance JSON; the run is saved under `runs/` and ingested into the graph. |
| `rec_inspect_js` | `js_url`, `stealth` | Endpoints, authored references, secrets, and response details for one JavaScript file. |
| `rec_social_search` | `query`, `platform`, `target_type`, `strict` | Social and technical platform results as structured JSON. |
| `rec_graph_add_relation` | `source_id`, `source_type`, `relation`, `target_id`, `target_type`, `metadata` | Stored edge and current graph counts. |
| `rec_graph_query` | `entity_id` | Whole graph summary or one entity with incoming and outgoing edges. |
| `rec_generate_report` | `campaign_name`, `output_dir` | Paths to the three generated report files. |

Graph node types: `ORG`, `ASN`, `DOMAIN`, `IP`, `PORT`, `TECH`, `VULN`,
`ARTIFACT`, `PERSON`, `SOCIAL_ACCOUNT`, `REPO`.

Example tool sequence:

1. `rec_execute_cli` with target `example.com` and mode `infra`.
2. `rec_graph_query` with `all` to review high-value entities and unexplored
   pivots.
3. `rec_execute_cli` with an email or domain pivot in OSINT mode.
4. `rec_graph_add_relation` to record analyst-confirmed links.
5. `rec_generate_report` to export the campaign package.

### Workspace Layout

```text
.rec_workspace/
  graph.db
  manifest.json
  runs/
    20260101T000000000000Z_infra_example.com.json
```

The server writes progress and errors to standard error so that MCP transport on
standard output is never corrupted.

## Report Output

`rec_generate_report` writes exactly three files:

| File | Contents |
| --- | --- |
| `01_Executive_Summary.md` | Scope, OPSEC, attack surface, host inventory, discovered paths, virtual hosts, assets, Wayback snapshots, high-value entities, CVEs, personnel and breach exposure, pivots, next steps, limitations. |
| `02_Full_Recon_Data.json` | Consolidated campaign JSON with graph data, pivots, and every saved run. |
| `03_Entity_Relationship_Map.md` | Mermaid entity graph, ASCII relationship tree, and node type legend. |

All report content is ASCII and uses standard Markdown only.

## Agent Skill

The `agent_skill/` directory contains a workflow playbook for agent use:

- `agent_skill/SKILL.md`: phased reconnaissance procedure.
- `agent_skill/references/pivoting_rules.md`: deterministic cross-mode pivot
  rules and prioritization.
- `agent_skill/references/report_template.md`: report structure and writing
  rules.

## Project Layout

```text
ReconEveryThings/
  pyproject.toml
  README.md
  install.sh
  .env.example
  .gitignore
  rec_cli/
    __init__.py
    main.py
    config.py
    schema.py
    engine.py
    modules/
    utils/
  mcp_server/
    __init__.py
    server.py
    graph_manager.py
  agent_skill/
    SKILL.md
    references/
```

## Safety And Authorization

Use this tool only against assets you own or have explicit written permission
to assess. Prefer passive sources, respect rate limits and platform terms, and
treat all CVE mappings, username matches, and breach findings as unverified
until a human reviews the evidence. Breach lookups are metadata-only and do not
involve credential use. The framework does not exploit vulnerabilities and does
not attempt authentication bypass.

TLS certificate verification is relaxed during fingerprinting so that
expired or self-signed certificates can still be inspected. Do not submit
credentials or sensitive data over connections created by the engine.

## Verification

```bash
python -m compileall rec_cli mcp_server
recn -t example.com -m infra --stealth -o result.json
recn -t example.com -m infra --modules techstack,waf -o waf.json
recn -t example.com -m infra --modules vhost --threads 16 -o vhost.json
recn -t example.com -m infra --modules wayback -o archive.json
recn -t example.com -m infra -sm fuzz,vhost -o passive.json
recn -t example.com -m osint --modules identity --stealth -o identity.json
recn -t jane.doe -m osint --modules username -o handles.json
recn -t jane.doe@example.com -m osint --modules breach -o breaches.json
```

Then start the MCP server, call `rec_generate_report`, and confirm the three
files exist in the requested output directory.
