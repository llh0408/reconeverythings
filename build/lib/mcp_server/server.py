"""FastMCP server exposing reconnaissance, graph, and reporting tools."""

from __future__ import annotations

import atexit
import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rec_cli import TOOL_NAME, __version__
from rec_cli.config import Settings, load_env_file
from rec_cli.engine import ReconEngine, ReconError, run_json
from rec_cli.modules.infra_crawler_js import analyze_javascript
from rec_cli.modules.osint_social import social_search
from rec_cli.utils.logger import Logger, ascii_text
from rec_cli.utils.runner import StealthHTTPClient

from mcp_server.graph_manager import GraphManager, VALID_NODE_TYPES

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None  # type: ignore[assignment,misc]

load_env_file()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _workspace_path() -> Path:
    configured = os.environ.get("REC_WORKSPACE") or os.environ.get(
        "REC_SESSION_DIR"
    )
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / ".rec_workspace").resolve()


WORKSPACE = _workspace_path()
RUNS_DIR = WORKSPACE / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)
MANIFEST_PATH = WORKSPACE / "manifest.json"
GRAPH = GraphManager(WORKSPACE / "graph.db")
LOGGER = Logger(quiet=False, stream=sys.stderr)
_WORKSPACE_LOCK = asyncio.Lock()

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


@atexit.register
def _close_graph() -> None:
    try:
        GRAPH.close()
    except Exception:
        pass


def _ascii_obj(value: Any) -> Any:
    if isinstance(value, str):
        return ascii_text(value)
    if isinstance(value, list):
        return [_ascii_obj(item) for item in value]
    if isinstance(value, dict):
        return {ascii_text(key): _ascii_obj(item) for key, item in value.items()}
    return value


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"output path is a directory: {path}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(ascii_text(content))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _write_json_atomic(path: Path, payload: Any) -> None:
    serialized = json.dumps(
        _ascii_obj(payload), indent=2, ensure_ascii=True
    ) + "\n"
    _write_text_atomic(path, serialized)


def _safe_filename(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_text(value)).strip("._-")
    return (cleaned or "target")[:limit]


def _read_manifest() -> list[dict[str, Any]]:
    if not MANIFEST_PATH.exists():
        return []
    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    return data if isinstance(data, list) else []


def _record_run(
    target: str,
    mode: str,
    modules: list[str],
    stealth: bool,
    filename: str,
    graph_counts: dict[str, int],
) -> None:
    manifest = _read_manifest()
    manifest.append(
        {
            "target": ascii_text(target),
            "mode": mode,
            "modules": modules,
            "stealth": stealth,
            "file": filename,
            "timestamp_utc": _utc_now(),
            "graph_counts": graph_counts,
        }
    )
    _write_json_atomic(MANIFEST_PATH, manifest)


def _load_runs() -> list[dict[str, Any]]:
    entries = _read_manifest()
    files: list[Path] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("file"):
            continue
        candidate = Path(str(entry["file"]))
        if not candidate.is_absolute():
            candidate = WORKSPACE / candidate
        if candidate.exists():
            files.append(candidate)
    if not files:
        files.extend(sorted(RUNS_DIR.glob("*.json")))
    unique_files: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_files.append(resolved)
    runs: list[dict[str, Any]] = []
    for path in unique_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("meta"), dict):
            runs.append(payload)
    return runs


def _md_cell(value: Any, limit: int = 300) -> str:
    text = ascii_text(" ".join(str(value).split()), limit)
    return text.replace("|", "\\|")


def _dedupe_pivots(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pivots: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for run in runs:
        for pivot in run.get("pivots_suggested", []):
            if not isinstance(pivot, dict):
                continue
            key = (
                str(pivot.get("pivot_type", "")),
                str(pivot.get("target_value", "")).lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            pivots.append(pivot)
    return pivots


def _render_executive_summary(
    campaign_name: str,
    runs: list[dict[str, Any]],
    graph_data: dict[str, Any],
) -> str:
    generated = _utc_now()
    targets: list[str] = []
    modes: set[str] = set()
    modules: list[str] = []
    stealth_runs = 0
    hosts: dict[str, dict[str, Any]] = {}
    social_profiles: list[dict[str, Any]] = []
    git_findings: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []
    identity_emails: list[str] = []

    for run in runs:
        meta = run.get("meta", {})
        target = str(meta.get("target", ""))
        if target and target not in targets:
            targets.append(target)
        if meta.get("mode"):
            modes.add(str(meta["mode"]))
        if meta.get("stealth_enabled"):
            stealth_runs += 1
        for module in meta.get("modules_executed", []):
            if module not in modules:
                modules.append(str(module))
        for host in run.get("infra_data", {}).get("hosts", []):
            if isinstance(host, dict):
                hostname = str(host.get("hostname", ""))
                if hostname:
                    hosts[hostname] = host
        osint = run.get("osint_data", {})
        for profile in osint.get("social_profiles", []):
            if isinstance(profile, dict) and profile not in social_profiles:
                social_profiles.append(profile)
        for finding in osint.get("git_findings", []):
            if isinstance(finding, dict) and finding not in git_findings:
                git_findings.append(finding)
        for document in osint.get("document_metadata", []):
            if isinstance(document, dict) and document not in documents:
                documents.append(document)
        identity = osint.get("target_identity", {})
        for email in identity.get("emails", []):
            if email and email not in identity_emails:
                identity_emails.append(str(email))

    high_value = graph_data.get("high_value_targets", [])
    nodes = graph_data.get("nodes", [])
    vulnerabilities = sorted(
        [node for node in nodes if node.get("type") == "VULN"],
        key=lambda node: -float(node.get("metadata", {}).get("cvss", 0.0) or 0.0),
    )
    max_cvss = max(
        (float(vuln.get("metadata", {}).get("cvss", 0.0) or 0.0) for vuln in vulnerabilities),
        default=0.0,
    )
    risk_label = (
        "Critical"
        if max_cvss >= 9.0
        else "High"
        if max_cvss >= 7.0
        else "Moderate"
        if max_cvss > 0.0
        else "Informational"
    )
    endpoints = sum(
        len(host.get("js_findings", {}).get("extracted_endpoints", []))
        for host in hosts.values()
    )
    secrets = sum(
        len(host.get("js_findings", {}).get("potential_secrets", []))
        for host in hosts.values()
    )
    path_findings = [
        (hostname, finding)
        for hostname, host in hosts.items()
        for finding in host.get("path_findings", [])
        if isinstance(finding, dict)
    ]
    path_findings.sort(
        key=lambda item: (
            not bool(item[1].get("sensitive")),
            item[0],
            str(item[1].get("path", "")),
        )
    )
    sensitive_paths = sum(
        1 for _hostname, finding in path_findings if finding.get("sensitive")
    )

    lines: list[str] = [
        f"# Executive Summary: {ascii_text(campaign_name)}",
        "",
        "## Assessment Snapshot",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Campaign | {_md_cell(campaign_name)} |",
        f"| Generated (UTC) | {generated} |",
        f"| Tool | {TOOL_NAME} {__version__} |",
        f"| Assessment runs | {len(runs)} |",
        f"| Targets | {_md_cell(', '.join(targets) or 'none')} |",
        f"| Modes | {_md_cell(', '.join(sorted(modes)) or 'none')} |",
        f"| Stealth runs | {stealth_runs} of {len(runs)} |",
        f"| Graph entities | {graph_data.get('node_count', 0)} |",
        f"| Graph relationships | {graph_data.get('edge_count', 0)} |",
        f"| Highest CVSS | {max_cvss:.1f} ({risk_label}) |",
        "",
        "## Scope And OPSEC",
        "",
        "Reconnaissance was limited to passive metadata collection, public sources, "
        "non-exploitative service fingerprinting, and bounded path discovery. "
        "No exploitation payloads were used. ",
        f"Modules executed: {_md_cell(', '.join(modules) or 'none')}.",
        "",
        "## Attack Surface",
        "",
        "| Metric | Count |",
        "| --- | --- |",
        f"| Observed hosts | {len(hosts)} |",
        f"| Discovered paths | {len(path_findings)} |",
        f"| Sensitive paths | {sensitive_paths} |",
        f"| Discovered vulnerabilities | {len(vulnerabilities)} |",
        f"| JavaScript endpoints | {endpoints} |",
        f"| Potential secrets in JavaScript | {secrets} |",
        f"| Identity email candidates | {len(identity_emails)} |",
        f"| Social profiles | {len(social_profiles)} |",
        f"| Public repositories | {len(git_findings)} |",
        f"| Public documents | {len(documents)} |",
        "",
        "### Host Inventory",
        "",
    ]
    if hosts:
        lines.extend(
            [
                "| Host | IP | CDN/WAF | Ports | Technologies |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for hostname, host in list(hosts.items())[:40]:
            http_info = host.get("http_info", {})
            technologies = ", ".join(
                str(tech.get("name", ""))
                + (f" {tech.get('version')}" if tech.get("version") else "")
                for tech in http_info.get("technologies", [])
            )
            waf_name = str((host.get("waf") or {}).get("name") or "")
            cdn_waf = str(host.get("cdn_waf") or "")
            attribution = cdn_waf
            if waf_name and waf_name != cdn_waf:
                attribution = f"{cdn_waf} / {waf_name}" if cdn_waf else waf_name
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(hostname),
                        _md_cell(host.get("ip", "") or "unresolved"),
                        _md_cell(attribution or "none"),
                        _md_cell(",".join(str(port) for port in host.get("open_ports", []))),
                        _md_cell(technologies or "none"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No infrastructure hosts were recorded in this session.")

    lines.extend(["", "## Discovered Paths", ""])
    if path_findings:
        lines.extend(
            [
                "| Host | Path | Status | Category | Sensitive |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for hostname, finding in path_findings[:50]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(hostname),
                        _md_cell(finding.get("path", "")),
                        _md_cell(finding.get("status_code", 0)),
                        _md_cell(finding.get("category", "")),
                        "yes" if finding.get("sensitive") else "no",
                    ]
                )
                + " |"
            )
        if len(path_findings) > 50:
            lines.append("")
            lines.append(
                f"{len(path_findings) - 50} additional findings are stored in the run JSON."
            )
        lines.append("")
        lines.append(
            "Path discovery used bounded, non-exploitative GET requests. "
            "A 401 or 403 response indicates a protected path, not a bypass."
        )
    else:
        lines.append(
            "No directory or sensitive file findings were recorded. "
            "The fuzz phase runs only outside stealth mode."
        )

    lines.extend(["", "## High-Value Entities", ""])
    if high_value:
        lines.extend(
            [
                "| Type | Entity | Notes |",
                "| --- | --- | --- |",
            ]
        )
        for node in high_value[:25]:
            metadata = node.get("metadata", {})
            note = metadata.get("summary") or metadata.get("bio_or_notes") or ""
            if node.get("type") == "VULN":
                note = f"CVSS {metadata.get('cvss', 0.0)}; {metadata.get('component', '')}. {note}"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(node.get("type", "")),
                        _md_cell(node.get("label", node.get("id", ""))),
                        _md_cell(note or "review required"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No high-value entities were identified.")

    lines.extend(["", "## Vulnerability Mapping", ""])
    if vulnerabilities:
        lines.extend(
            [
                "| CVE | CVSS | Component | Summary |",
                "| --- | --- | --- | --- |",
            ]
        )
        for vuln in vulnerabilities[:30]:
            metadata = vuln.get("metadata", {})
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(vuln.get("id", "")),
                        _md_cell(metadata.get("cvss", 0.0)),
                        _md_cell(metadata.get("component", "unknown")),
                        _md_cell(metadata.get("summary", "")),
                    ]
                )
                + " |"
            )
        lines.append("")
        lines.append(
            "These mappings are passive associations between observed product versions "
            "and public CVE metadata. Exposure and exploitability require validation."
        )
    else:
        lines.append(
            "No CVE mappings were produced. Missing software versions or API rate limits "
            "may reduce coverage."
        )

    lines.extend(["", "## Personnel And Code Exposure", ""])
    if social_profiles:
        lines.extend(
            [
                "| Platform | Profile | Notes |",
                "| --- | --- | --- |",
            ]
        )
        for profile in social_profiles[:25]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(profile.get("platform", "")),
                        _md_cell(profile.get("url", "")),
                        _md_cell(profile.get("bio_or_notes", "")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No public social profiles were verified.")
    lines.append("")
    if git_findings:
        lines.extend(
            [
                "| Repository | Commit Emails | Leaked Indicators |",
                "| --- | --- | --- |",
            ]
        )
        for finding in git_findings[:25]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(finding.get("repo_url", "")),
                        _md_cell(len(finding.get("commit_emails", []))),
                        _md_cell(len(finding.get("leaked_indicators", []))),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No public repository intelligence was recovered.")
    if documents:
        lines.append("")
        lines.extend(
            [
                "| Document | Author | Creator Tool | Internal Paths |",
                "| --- | --- | --- | --- |",
            ]
        )
        for document in documents[:20]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(document.get("file_url", "")),
                        _md_cell(document.get("author", "") or "unknown"),
                        _md_cell(document.get("creator_tool", "") or "unknown"),
                        _md_cell(len(document.get("internal_paths", []))),
                    ]
                )
                + " |"
            )

    pivots = _dedupe_pivots(runs)
    lines.extend(["", "## Pivot Recommendations", ""])
    if pivots:
        lines.extend(
            [
                "| Source | Pivot | Target | Reason |",
                "| --- | --- | --- | --- |",
            ]
        )
        for pivot in pivots[:30]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(pivot.get("source", "")),
                        _md_cell(pivot.get("pivot_type", "")),
                        _md_cell(pivot.get("target_value", "")),
                        _md_cell(pivot.get("reason", "")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No cross-mode pivots were suggested.")
    unexplored = graph_data.get("unexplored_pivot_points", [])
    if unexplored:
        lines.extend(["", "Unexplored graph pivot points:", ""])
        for item in unexplored[:20]:
            lines.append(
                f"- {_md_cell(item.get('type', ''))} "
                f"{_md_cell(item.get('label', ''))}: "
                f"{_md_cell(item.get('suggested_action', ''))}"
            )

    origin_candidates = [
        hostname
        for hostname, host in hosts.items()
        if not host.get("cdn_waf") and host.get("ip")
    ]
    non_production = [
        hostname
        for hostname in hosts
        if re.search(
            r"(^|[.-])(dev|staging|uat|test|qa|vpn|internal|api|jenkins|gitlab|admin|jira)([.-]|$)",
            hostname,
            re.IGNORECASE,
        )
    ]
    lines.extend(["", "## Operational Observations", ""])
    if origin_candidates:
        lines.append(
            "Hosts without an observed CDN/WAF boundary (review for origin exposure): "
            + _md_cell(", ".join(origin_candidates[:15]))
        )
    if non_production:
        lines.append(
            "Non-production or sensitive naming patterns: "
            + _md_cell(", ".join(non_production[:15]))
        )
    if not origin_candidates and not non_production:
        lines.append(
            "No obvious CDN bypass or non-production naming anomalies were observed."
        )

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            "1. Validate high-CVSS findings against the affected component and exposure path.",
            "2. Prioritize identity-rich assets for deeper OSINT and repository review.",
            "3. Enumerate JavaScript-derived internal hosts that were not present in passive DNS.",
            "4. Review public repository indicators for unlisted services and software versions.",
            "5. Confirm scope and authorization before any active validation.",
            "",
            "## Limitations",
            "",
            "- CVE mapping is version-based and does not prove exploitability.",
            "- Passive DNS and certificate sources may be incomplete or delayed.",
            "- Social platform responses may be blocked, rate-limited, or unverified.",
            "- Document and JavaScript analysis is limited to publicly accessible content.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_relationship_map(
    campaign_name: str,
    graph_data: dict[str, Any],
) -> str:
    mermaid = GRAPH.mermaid_graph()
    tree = GRAPH.ascii_tree()
    return "\n".join(
        [
            f"# Entity Relationship Map: {ascii_text(campaign_name)}",
            "",
            f"Generated: {_utc_now()}",
            "",
            f"Entities: {graph_data.get('node_count', 0)} | "
            f"Relationships: {graph_data.get('edge_count', 0)}",
            "",
            "## Mermaid Entity Graph",
            "",
            "```mermaid",
            mermaid,
            "```",
            "",
            "## ASCII Relationship Tree",
            "",
            "```text",
            tree,
            "```",
            "",
            "## Legend",
            "",
            "- ORG: organization, registrar, or inferred employer.",
            "- ASN: autonomous system announcing infrastructure ranges.",
            "- DOMAIN: registered or observed hostname.",
            "- IP: resolved network address.",
            "- PORT: exposed TCP service endpoint.",
            "- TECH: observed software product and version where available.",
            "- VULN: passively mapped CVE identifier.",
            "- ARTIFACT: email, endpoint, indicator, path, or document evidence.",
            "- PERSON: named individual or developer identity.",
            "- SOCIAL_ACCOUNT: public social or developer profile.",
            "- REPO: public source repository.",
            "",
        ]
    )


async def rec_execute_cli(
    target: str,
    mode: str,
    modules: list[str] | None = None,
    stealth: bool = True,
    skip_liveness: bool = False,
    wordlist: str | None = None,
) -> dict[str, Any]:
    """Execute a complete reconnaissance chain and persist the result.

    Args:
        target: Domain, IP/CIDR, URL, email, username, or person name.
        mode: "infra" or "osint".
        modules: Optional module names. Defaults to all modules for the mode.
        stealth: Enable jittered pacing, passive port data, and header rotation.
        skip_liveness: Skip the httpx liveness pre-check and probe every
            collected host URL directly.
        wordlist: Optional server-local directory wordlist that replaces the
            bundled directory list for the fuzz phase.
    """
    async with _WORKSPACE_LOCK:
        engine = ReconEngine(
            target=target,
            mode=mode,
            modules=modules,
            stealth=stealth,
            skip_liveness=skip_liveness,
            wordlist=wordlist,
            logger=LOGGER,
        )
        result = await engine.run()
        payload = run_json(result)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        filename = (
            f"{stamp}_{result.meta.mode.value}_{_safe_filename(target)}.json"
        )
        run_path = RUNS_DIR / filename
        _write_json_atomic(run_path, payload)
        counts = GRAPH.ingest_recon(payload)
        _record_run(
            target=target,
            mode=result.meta.mode.value,
            modules=result.meta.modules_executed,
            stealth=result.meta.stealth_enabled,
            filename=filename,
            graph_counts=counts,
        )
        LOGGER.info(
            f"run saved to {run_path} with {counts['nodes_added']} new nodes "
            f"and {counts['edges_added']} new edges"
        )
        return payload


async def rec_inspect_js(
    js_url: str, stealth: bool = True
) -> dict[str, Any]:
    """Deeply analyze one JavaScript URL for endpoints and exposed indicators.

    Args:
        js_url: Public HTTP(S) JavaScript URL.
        stealth: Enable jittered pacing and rotated request headers.
    """
    parsed = urlparse(js_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"js_url": js_url, "error": "invalid HTTP(S) JavaScript URL"}
    settings = Settings.from_env(stealth=stealth)
    async with StealthHTTPClient(settings, LOGGER) as http:
        response = await http.get(
            js_url, max_bytes=settings.max_response_bytes
        )
    if response.error:
        return {
            "js_url": js_url,
            "status_code": response.status_code,
            "error": ascii_text(response.error),
        }
    if response.status_code >= 400:
        return {
            "js_url": js_url,
            "status_code": response.status_code,
            "error": f"HTTP {response.status_code}",
        }
    analysis = analyze_javascript(response.text, response.url)
    payload = analysis.to_dict()
    payload.update(
        {
            "final_url": response.url,
            "content_type": response.header("content-type"),
            "content_bytes": len(response.content),
            "truncated": response.truncated,
        }
    )
    return _ascii_obj(payload)


async def rec_social_search(
    query: str,
    platform: str = "all",
    target_type: str = "person",
) -> dict[str, Any]:
    """Search social and technical platforms for profiles, code, and discussions.

    Args:
        query: Person, username, email, organization, or technology query.
        platform: all, github, linkedin, stackoverflow, reddit, x, or web.
        target_type: person, company, technology, email, or domain.
    """
    allowed_types = {"person", "company", "technology", "email", "domain"}
    if target_type.lower() not in allowed_types:
        raise ValueError(
            "target_type must be one of: "
            + ", ".join(sorted(allowed_types))
        )
    settings = Settings.from_env(stealth=True)
    async with StealthHTTPClient(settings, LOGGER) as http:
        result = await social_search(
            http,
            LOGGER,
            settings,
            query,
            platform=platform,
            target_type=target_type.lower(),
        )
    return _ascii_obj(result)


def rec_graph_add_relation(
    source_id: str,
    source_type: str,
    relation: str,
    target_id: str,
    target_type: str,
    metadata: str = "",
) -> dict[str, Any]:
    """Add or update a directed relationship in the session entity graph.

    Args:
        source_id: Stable identifier for the source entity.
        source_type: ORG, ASN, DOMAIN, IP, PORT, TECH, VULN, ARTIFACT,
            PERSON, SOCIAL_ACCOUNT, or REPO.
        relation: Directed relationship label, for example OWNS or RESOLVES_TO.
        target_id: Stable identifier for the target entity.
        target_type: One of the supported node types.
        metadata: Optional ASCII note stored on the relationship.
    """
    edge = GRAPH.add_relation(
        source_id,
        source_type,
        relation,
        target_id,
        target_type,
        metadata,
    )
    return {
        "status": "ok",
        "edge": edge,
        "graph": {
            "nodes": GRAPH.node_count(),
            "edges": GRAPH.edge_count(),
            "valid_node_types": sorted(VALID_NODE_TYPES),
        },
    }


def rec_graph_query(entity_id: str = "all") -> dict[str, Any]:
    """Retrieve graph state, high-value targets, and unexplored pivot points.

    Args:
        entity_id: Entity identifier, or "all" for the complete graph.
    """
    return GRAPH.query(entity_id)


async def rec_generate_report(
    campaign_name: str, output_dir: str
) -> dict[str, Any]:
    """Export executive summary, consolidated JSON, and entity relationship map.

    Args:
        campaign_name: Human-readable assessment name.
        output_dir: Directory that receives the three report files.
    """
    output_path = Path(output_dir).expanduser().resolve()
    if output_path.exists() and not output_path.is_dir():
        raise ValueError(f"output_dir is not a directory: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    async with _WORKSPACE_LOCK:
        runs = _load_runs()
        graph_data = GRAPH.export_data()
        summary = _render_executive_summary(campaign_name, runs, graph_data)
        relationship_map = _render_relationship_map(campaign_name, graph_data)
        pivots = _dedupe_pivots(runs)
        consolidated = {
            "campaign": campaign_name,
            "generated_utc": _utc_now(),
            "tool": TOOL_NAME,
            "version": __version__,
            "run_count": len(runs),
            "summary": {
                "node_count": graph_data.get("node_count", 0),
                "edge_count": graph_data.get("edge_count", 0),
                "type_counts": graph_data.get("type_counts", {}),
            },
            "graph": graph_data,
            "pivots_suggested": pivots,
            "runs": runs,
        }
        summary_path = output_path / "01_Executive_Summary.md"
        data_path = output_path / "02_Full_Recon_Data.json"
        graph_path = output_path / "03_Entity_Relationship_Map.md"
        _write_text_atomic(summary_path, summary)
        _write_json_atomic(data_path, consolidated)
        _write_text_atomic(graph_path, relationship_map)
        LOGGER.info(f"report files written to {output_path}")
        return {
            "status": "ok",
            "campaign": campaign_name,
            "output_dir": str(output_path),
            "files": [
                str(summary_path),
                str(data_path),
                str(graph_path),
            ],
            "run_count": len(runs),
            "graph": {
                "nodes": graph_data.get("node_count", 0),
                "edges": graph_data.get("edge_count", 0),
            },
        }


mcp = (
    FastMCP(
        "ReconEveryThings-MCP",
        instructions=(
            "ReconEveryThings provides authorized infrastructure and OSINT "
            "reconnaissance. Default to stealth mode, prioritize passive evidence, "
            "and use the graph tools to record every pivot and relationship."
        ),
    )
    if FastMCP is not None
    else None
)

if mcp is not None:
    for _tool in (
        rec_execute_cli,
        rec_inspect_js,
        rec_social_search,
        rec_graph_add_relation,
        rec_graph_query,
        rec_generate_report,
    ):
        mcp.add_tool(_tool, structured_output=False)


def main() -> int:
    if mcp is None:
        print(
            "The mcp package is required. Install with: "
            "pip install 'mcp>=1.2,<2'",
            file=sys.stderr,
        )
        return 2
    mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
