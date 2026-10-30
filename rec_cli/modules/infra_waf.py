"""WAF and firewall detection with wafw00f, nmap NSE, and passive fingerprints."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rec_cli.config import COMMON_WEB_PORTS
from rec_cli.modules import ensure_host, extract_host, target_domain
from rec_cli.schema import HostRecord, WAFInfo
from rec_cli.utils.runner import binary_available, gather_limited, run_command

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext


@dataclass(frozen=True, slots=True)
class WAFHit:
    name: str
    manufacturer: str = ""
    evidence: str = ""


_HEADER_MARKERS: dict[str, tuple[str, str]] = {
    "cf-ray": ("Cloudflare", "Cloudflare, Inc."),
    "cf-cache-status": ("Cloudflare", "Cloudflare, Inc."),
    "x-akamai-transformed": ("Akamai", "Akamai Technologies"),
    "x-akamai-request-id": ("Akamai", "Akamai Technologies"),
    "x-amz-cf-id": ("Amazon CloudFront", "Amazon.com, Inc."),
    "x-amzn-waf-action": ("AWS WAF", "Amazon.com, Inc."),
    "x-azure-ref": ("Azure Front Door", "Microsoft Corporation"),
    "x-fd-healthprobe": ("Azure Front Door", "Microsoft Corporation"),
    "x-sucuri-id": ("Sucuri", "Sucuri Inc."),
    "x-sucuri-cache": ("Sucuri", "Sucuri Inc."),
    "x-iinfo": ("Imperva", "Imperva, Inc."),
    "x-wallarm-waf": ("Wallarm", "Wallarm, Inc."),
    "x-datadome": ("DataDome", "DataDome SAS"),
    "x-dd-b": ("DataDome", "DataDome SAS"),
    "x-wa-info": ("F5 BIG-IP ASM", "F5, Inc."),
}

_SERVER_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("cloudflare", "Cloudflare", "Cloudflare, Inc."),
    ("akamai", "Akamai", "Akamai Technologies"),
    ("sucuri", "Sucuri", "Sucuri Inc."),
    ("barracuda", "Barracuda WAF", "Barracuda Networks"),
    ("incapsula", "Imperva", "Imperva, Inc."),
    ("imperva", "Imperva", "Imperva, Inc."),
    ("big-ip", "F5 BIG-IP", "F5, Inc."),
    ("bigip", "F5 BIG-IP", "F5, Inc."),
    ("mod_security", "ModSecurity", "Trustwave"),
    ("modsecurity", "ModSecurity", "Trustwave"),
    ("netscaler", "Citrix NetScaler", "Cloud Software Group"),
    ("cloudfront", "Amazon CloudFront", "Amazon.com, Inc."),
    ("awselb", "AWS Elastic Load Balancer", "Amazon.com, Inc."),
)

_COOKIE_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("__cf_bm", "Cloudflare", "Cloudflare, Inc."),
    ("cf_clearance", "Cloudflare", "Cloudflare, Inc."),
    ("incap_ses", "Imperva", "Imperva, Inc."),
    ("visid_incap", "Imperva", "Imperva, Inc."),
    ("_abck", "Akamai", "Akamai Technologies"),
    ("ak_bmsc", "Akamai", "Akamai Technologies"),
    ("bm_sz", "Akamai", "Akamai Technologies"),
    ("bigipserver", "F5 BIG-IP", "F5, Inc."),
    ("datadome", "DataDome", "DataDome SAS"),
    ("sucuri_cloudproxy", "Sucuri", "Sucuri Inc."),
    ("barra_counter_session", "Barracuda WAF", "Barracuda Networks"),
    ("citrix_ns_id", "Citrix NetScaler", "Cloud Software Group"),
    ("noyb", "ModSecurity", "Trustwave"),
    ("awselb", "AWS Elastic Load Balancer", "Amazon.com, Inc."),
)

_BODY_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("attention required! | cloudflare", "Cloudflare", "Cloudflare, Inc."),
    ("incapsula incident id", "Imperva", "Imperva, Inc."),
    ("sucuri website firewall", "Sucuri", "Sucuri Inc."),
    ("modsecurity", "ModSecurity", "Trustwave"),
)

_NMAP_WAF_RE = re.compile(r"(?<![\w-])WAF\s*:\s*(.+)$")
_NMAP_DETECT_RE = re.compile(r"WAF\s+detected", re.IGNORECASE)
_NMAP_MANUFACTURER_RE = re.compile(r"^(.*?)\s*\(([^()]*)\)\s*$")

_MAX_HOSTS = 5
_MAX_HOSTS_STEALTH = 3
_HTTPS_PORTS = {443, 8443, 9443, 4443}
_HTTP_PORTS = {80, 8080, 8000, 8888}


def _record_url(record: HostRecord) -> str:
    url = record.http_info.url.strip()
    if url:
        return url if url.endswith("/") else url + "/"
    host = record.hostname.strip()
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    ports = [port for port in record.open_ports if port in COMMON_WEB_PORTS]
    if not ports:
        ports = [443, 80]
    port = 443 if 443 in ports else ports[0]
    if port in _HTTPS_PORTS:
        scheme = "https"
    elif port in _HTTP_PORTS:
        scheme = "http"
    else:
        scheme = "https" if port > 8080 else "http"
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    suffix = "" if default else f":{port}"
    return f"{scheme}://{host}{suffix}/"


def _select_records(ctx: "ReconContext") -> list[HostRecord]:
    records = [record for record in ctx.infra.hosts if record.hostname]
    if not records:
        host = target_domain(ctx.target) or extract_host(ctx.target)
        if host:
            records = [ensure_host(ctx, host)]
    records.sort(
        key=lambda record: (0 if record.http_info.url else 1, record.hostname)
    )
    limit = _MAX_HOSTS_STEALTH if ctx.settings.stealth else _MAX_HOSTS
    return records[:limit]


def _dedupe_hits(hits: list[WAFHit]) -> list[WAFHit]:
    seen: set[str] = set()
    output: list[WAFHit] = []
    for hit in hits:
        key = hit.name.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output


async def _wafw00f(
    ctx: "ReconContext", urls: list[str]
) -> dict[str, list[WAFHit]]:
    binary = ctx.settings.wafw00f_binary
    if not binary_available(binary):
        return {}
    command = [
        binary,
        *urls,
        "-f",
        "json",
        "-o",
        "-",
        "--no-colors",
        "-T",
        str(max(5, int(ctx.settings.request_timeout))),
    ]
    if ctx.settings.proxy:
        command.extend(["-p", ctx.settings.proxy])
    result = await run_command(command, timeout=min(180, 45 + 25 * len(urls)))
    payload = result.stdout.strip()
    if not payload:
        ctx.logger.warn("wafw00f returned no data; using passive fingerprints")
        return {}
    try:
        items = json.loads(payload)
    except ValueError:
        start = payload.find("[")
        try:
            items = json.loads(payload[start:]) if start >= 0 else []
        except ValueError:
            ctx.logger.warn("wafw00f output was not valid JSON; using passive fingerprints")
            return {}
    if isinstance(items, dict):
        items = [items]
    hits: dict[str, list[WAFHit]] = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("detected"):
            continue
        url = str(item.get("url") or "").rstrip("/")
        if not url:
            continue
        name = str(item.get("firewall") or "Unknown WAF").strip()
        manufacturer = str(item.get("manufacturer") or "").strip()
        evidence = "wafw00f signature match"
        hits.setdefault(url, []).append(WAFHit(name, manufacturer, evidence))
    return hits


async def _passive(ctx: "ReconContext", url: str) -> list[WAFHit]:
    candidates = [url]
    try:
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.port in (None, 443):
            candidates.append(url.replace("https://", "http://", 1))
    except ValueError:
        pass

    result = None
    for candidate in candidates:
        result = await ctx.http.get(
            candidate,
            max_bytes=min(ctx.settings.max_response_bytes, 400_000),
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        if not result.error and result.status_code:
            break
    if result is None or result.error or result.status_code == 0:
        return []

    hits: list[WAFHit] = []
    headers = result.headers or {}
    for header, (name, manufacturer) in _HEADER_MARKERS.items():
        if header in headers:
            hits.append(WAFHit(name, manufacturer, f"header {header}"))
    server = headers.get("server", "")
    lowered_server = server.lower()
    for marker, name, manufacturer in _SERVER_MARKERS:
        if marker in lowered_server:
            hits.append(
                WAFHit(name, manufacturer, f"server={server.strip()[:80]}")
            )
    cookies = headers.get("set-cookie", "").lower()
    for marker, name, manufacturer in _COOKIE_MARKERS:
        if marker in cookies:
            hits.append(WAFHit(name, manufacturer, f"cookie {marker}"))
    body = result.text[:60_000].lower()
    for marker, name, manufacturer in _BODY_MARKERS:
        if marker in body:
            hits.append(WAFHit(name, manufacturer, f"body marker {marker}"))
    return _dedupe_hits(hits)


async def _nmap(ctx: "ReconContext", url: str) -> list[WAFHit]:
    binary = ctx.settings.nmap_binary
    if not binary_available(binary):
        return []
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return []
    if not host:
        return []
    command = [
        binary,
        "-Pn",
        "-p",
        str(port),
        "--script",
        "http-waf-fingerprint,http-waf-detect",
        "--script-timeout",
        "20s",
        "--host-timeout",
        "60s",
    ]
    if os.geteuid() != 0:
        command.append("-sT")
    command.append(host)
    result = await run_command(command, timeout=120)
    if not result.stdout.strip():
        return []
    hits: list[WAFHit] = []
    for line in result.stdout.splitlines():
        text = line.split("|", 1)[-1].strip()
        if not text:
            continue
        match = _NMAP_WAF_RE.search(text)
        if match:
            value = match.group(1).strip()
            name, manufacturer = value, ""
            pair = _NMAP_MANUFACTURER_RE.match(value)
            if pair:
                name = pair.group(1).strip()
                manufacturer = pair.group(2).strip()
            if name:
                hits.append(WAFHit(name, manufacturer, f"nmap {text[:160]}"))
        elif _NMAP_DETECT_RE.search(text):
            hits.append(
                WAFHit("WAF detected (unidentified)", "", f"nmap {text[:160]}")
            )
    return _dedupe_hits(hits)


def _apply(
    ctx: "ReconContext", record: HostRecord, hits: list[WAFHit], source: str
) -> bool:
    hits = _dedupe_hits(hits)
    if not hits:
        return False
    primary = hits[0]
    evidence = [hit.evidence for hit in hits if hit.evidence][:10]
    record.waf = WAFInfo(
        detected=True,
        name=primary.name,
        manufacturer=primary.manufacturer,
        source=source,
        evidence=evidence,
    )
    if not record.cdn_waf:
        record.cdn_waf = primary.name
    detail = f"WAF {primary.name} host={record.hostname} source={source}"
    if primary.manufacturer:
        detail += f" vendor={primary.manufacturer}"
    ctx.logger.found(detail)
    return True


async def run(ctx: "ReconContext") -> None:
    records = _select_records(ctx)
    if not records:
        ctx.logger.warn("WAF detection skipped: no eligible host")
        return

    urls = {record.hostname: _record_url(record) for record in records}
    active = not ctx.settings.stealth
    wafw00f_hits: dict[str, list[WAFHit]] = {}
    if active:
        if binary_available(ctx.settings.wafw00f_binary):
            ctx.logger.info(f"wafw00f: testing {len(urls)} URL(s)")
            wafw00f_hits = await _wafw00f(ctx, list(urls.values()))
        else:
            ctx.logger.info(
                "wafw00f is not installed; using passive fingerprints and nmap"
            )
    else:
        ctx.logger.stealth(
            "stealth mode: active WAF probes skipped; passive fingerprints only"
        )

    detected = 0
    pending = []
    for record in records:
        url = urls[record.hostname].rstrip("/")
        hits = wafw00f_hits.get(url, [])
        if hits and _apply(ctx, record, hits, "wafw00f"):
            detected += 1
        elif not hits:
            pending.append(record)

    if pending:
        passive_results = await gather_limited(
            (_passive(ctx, urls[record.hostname]) for record in pending),
            limit=ctx.settings.concurrency,
        )
        unresolved = []
        for record, hits in zip(pending, passive_results):
            if _apply(ctx, record, hits, "passive"):
                detected += 1
            else:
                unresolved.append(record)
        if (
            unresolved
            and active
            and binary_available(ctx.settings.nmap_binary)
        ):
            nmap_hits = await _nmap(ctx, urls[unresolved[0].hostname])
            if _apply(ctx, unresolved[0], nmap_hits, "nmap"):
                detected += 1

    ctx.logger.info(
        f"WAF detection complete: {detected}/{len(records)} hosts identified"
    )
