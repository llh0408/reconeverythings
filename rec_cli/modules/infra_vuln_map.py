"""Passive CPE-to-CVE mapping against NVD, Vulners, and Shodan metadata."""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any

from rec_cli.config import API_ENDPOINTS
from rec_cli.schema import Vulnerability

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_CPE_PRODUCTS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "openresty": ("openresty", "openresty"),
    "apache http server": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "openssh": ("openbsd", "openssh"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "grafana": ("grafana", "grafana"),
    "kibana": ("elastic", "kibana"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "keycloak": ("redhat", "keycloak"),
    "spring framework": ("vmware", "spring_framework"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "laravel": ("laravel", "laravel"),
    "django": ("djangoproject", "django"),
    "express": ("expressjs", "express"),
    "node.js": ("nodejs", "node.js"),
    "jira": ("atlassian", "jira"),
    "atlassian jira": ("atlassian", "jira"),
    "confluence": ("atlassian", "confluence"),
    "atlassian confluence": ("atlassian", "confluence"),
    "caddy": ("caddyserver", "caddy"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "jetty": ("eclipse", "jetty"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "cpanel": ("cpanel", "cpanel"),
    "apache solr": ("apache", "solr"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "postgresql": ("postgresql", "postgresql"),
    "mysql": ("oracle", "mysql"),
}
_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9._\-]*$")


def _normalize_version(version: str | None) -> str | None:
    if not version:
        return None
    cleaned = version.strip().strip(".,;")
    if not cleaned or not _VERSION_RE.match(cleaned):
        return None
    return cleaned


def _cpe_for_technology(name: str, version: str) -> str | None:
    mapping = _CPE_PRODUCTS.get(name.strip().lower())
    if not mapping:
        return None
    vendor, product = mapping
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _legacy_cpe_to_23(value: str) -> str | None:
    candidate = value.strip()
    if candidate.startswith("cpe:2.3:"):
        parts = candidate.split(":")
        if len(parts) >= 6:
            version = parts[5]
            if version and version not in ("*", "-"):
                return candidate
        return None
    match = re.match(
        r"^cpe:/[aho]:([^:]+):([^:]+)(?::([^:]+))?", candidate, re.IGNORECASE
    )
    if not match:
        return None
    vendor, product, version = match.groups()
    if not version or version in ("*", "-"):
        return None
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _score_from_metrics(metrics: dict[str, Any]) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return 0.0


def _summary_from_cve(item: dict[str, Any]) -> str:
    descriptions = item.get("descriptions", [])
    if isinstance(descriptions, list):
        for description in descriptions:
            if isinstance(description, dict) and description.get("lang") == "en":
                text = str(description.get("value", ""))
                return " ".join(text.split())[:500]
    return ""


def _parse_nvd_payload(
    payload: Any, component: str
) -> list[Vulnerability]:
    if not isinstance(payload, dict):
        return []
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return []
    output: list[Vulnerability] = []
    for entry in vulnerabilities[:20]:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict) or not cve.get("id"):
            continue
        output.append(
            Vulnerability(
                cve_id=str(cve["id"]),
                cvss=_score_from_metrics(cve.get("metrics", {})),
                affected_Component=component,
                summary=_summary_from_cve(cve),
            )
        )
    return output


async def _wait_for_nvd_slot(ctx: "ReconContext") -> None:
    interval = 0.7 if ctx.settings.nvd_api_key else 6.2
    async with ctx.nvd_lock:
        now = time.monotonic()
        wait = ctx.nvd_next_request_at - now
        if wait > 0:
            await asyncio.sleep(wait)
        ctx.nvd_next_request_at = max(now, ctx.nvd_next_request_at) + interval


async def _nvd_by_cpe(
    ctx: "ReconContext", cpe: str, component: str
) -> list[Vulnerability] | None:
    if ctx.vuln_query_count >= ctx.settings.max_vuln_queries:
        return None
    headers = {"Accept": "application/json"}
    if ctx.settings.nvd_api_key:
        headers["apiKey"] = ctx.settings.nvd_api_key
    await _wait_for_nvd_slot(ctx)
    ctx.vuln_query_count += 1
    data, response = await ctx.http.get_json(
        API_ENDPOINTS["nvd"],
        params={"cpeName": cpe, "resultsPerPage": "20"},
        headers=headers,
        max_bytes=6_000_000,
    )
    if response.error:
        ctx.logger.warn(f"NVD query failed for {cpe}: {response.error}")
        return None
    if response.status_code in (403, 429):
        ctx.logger.warn("NVD rate limit reached; remaining mappings deferred")
        ctx.vuln_query_count = ctx.settings.max_vuln_queries
        return None
    if response.status_code >= 400:
        return None
    return _parse_nvd_payload(data, component)


async def _nvd_by_cve(
    ctx: "ReconContext", cve_id: str, component: str
) -> Vulnerability | None:
    if ctx.vuln_query_count >= ctx.settings.max_vuln_queries:
        return None
    headers = {"Accept": "application/json"}
    if ctx.settings.nvd_api_key:
        headers["apiKey"] = ctx.settings.nvd_api_key
    await _wait_for_nvd_slot(ctx)
    ctx.vuln_query_count += 1
    data, response = await ctx.http.get_json(
        API_ENDPOINTS["nvd"],
        params={"cveId": cve_id, "resultsPerPage": "1"},
        headers=headers,
        max_bytes=4_000_000,
    )
    if response.error or response.status_code >= 400:
        return None
    parsed = _parse_nvd_payload(data, component)
    return parsed[0] if parsed else None


async def _vulners_by_cpe(
    ctx: "ReconContext", cpe: str, component: str
) -> list[Vulnerability]:
    if not ctx.settings.vulners_api_key:
        return []
    result = await ctx.http.request(
        "POST",
        "https://vulners.com/api/v3/search/lucene/",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json_body={"query": f"cpe:{cpe}", "size": 20},
        max_bytes=4_000_000,
    )
    if result.error or result.status_code >= 400:
        return []
    payload = result.json()
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    entries = data.get("search")
    if not isinstance(entries, list):
        return []
    output: list[Vulnerability] = []
    for entry in entries[:20]:
        source = entry.get("_source") if isinstance(entry, dict) else None
        if not isinstance(source, dict):
            continue
        cve_id = str(source.get("id", ""))
        if not cve_id.upper().startswith("CVE-"):
            continue
        cvss_block = source.get("cvss")
        try:
            cvss = float(cvss_block.get("score", 0.0)) if isinstance(cvss_block, dict) else 0.0
        except (TypeError, ValueError):
            cvss = 0.0
        output.append(
            Vulnerability(
                cve_id=cve_id,
                cvss=cvss,
                affected_Component=component,
                summary=" ".join(str(source.get("description", "")).split())[:500],
            )
        )
    return output


def _dedupe_vulns(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    chosen: dict[tuple[str, str], Vulnerability] = {}
    for item in vulnerabilities:
        key = (item.cve_id, item.affected_Component)
        existing = chosen.get(key)
        if existing is None or item.cvss > existing.cvss:
            chosen[key] = item
    return sorted(
        chosen.values(),
        key=lambda item: (-item.cvss, item.cve_id),
    )[:200]


async def _map_component(
    ctx: "ReconContext",
    cpe: str,
    name: str,
    version: str,
    hostname: str,
) -> list[Vulnerability]:
    cache_key = f"{hostname}|{cpe}"
    if cache_key in ctx.vuln_cache:
        return ctx.vuln_cache[cache_key]
    component = f"{name} {version}"
    vulnerabilities = await _nvd_by_cpe(ctx, cpe, component)
    if vulnerabilities is None:
        vulnerabilities = await _vulners_by_cpe(ctx, cpe, component)
    elif not vulnerabilities:
        vulnerabilities = await _vulners_by_cpe(ctx, cpe, component)
    ctx.vuln_cache[cache_key] = vulnerabilities
    return vulnerabilities


async def run(ctx: "ReconContext") -> None:
    total_found = 0
    for record in ctx.infra.hosts:
        component_vulns: list[Vulnerability] = []

        for technology in record.http_info.technologies:
            version = _normalize_version(technology.version)
            if not version:
                continue
            cpe = _cpe_for_technology(technology.name, version)
            if not cpe:
                continue
            mapped = await _map_component(
                ctx, cpe, technology.name, version, record.hostname
            )
            if mapped:
                component_vulns.extend(mapped)
                ctx.logger.info(
                    f"{record.hostname}: {technology.name} {version} mapped to "
                    f"{len(mapped)} CVE record(s)"
                )

        for raw_cpe in ctx.host_cpes.get(record.hostname, [])[:10]:
            cpe = _legacy_cpe_to_23(raw_cpe)
            if not cpe:
                continue
            parts = cpe.split(":")
            product = parts[4].replace("_", " ") if len(parts) > 4 else "component"
            version = parts[5] if len(parts) > 5 else ""
            mapped = await _map_component(
                ctx, cpe, product, version, record.hostname
            )
            if mapped:
                component_vulns.extend(mapped)

        for cve_id in ctx.shodan_vulns.get(record.hostname, [])[:20]:
            cache_key = f"cve|{cve_id}"
            if cache_key in ctx.vuln_cache:
                cached = ctx.vuln_cache[cache_key]
                if cached:
                    component_vulns.append(cached[0])
                continue
            vulnerability = await _nvd_by_cve(
                ctx, cve_id, f"host {record.hostname}"
            )
            if vulnerability:
                ctx.vuln_cache[cache_key] = [vulnerability]
                component_vulns.append(vulnerability)

        record.potential_vulnerabilities = _dedupe_vulns(component_vulns)
        total_found += len(record.potential_vulnerabilities)
        for vulnerability in record.potential_vulnerabilities[:10]:
            ctx.logger.found(
                f"{record.hostname}: {vulnerability.cve_id} "
                f"CVSS {vulnerability.cvss:.1f} "
                f"({vulnerability.affected_Component})"
            )

    if total_found == 0:
        ctx.logger.info(
            "no passive CVE mappings were produced; versions or API access may be missing"
        )
    else:
        ctx.logger.info(f"passive vulnerability mapping complete: {total_found} record(s)")
