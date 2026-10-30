"""Bounded virtual host discovery through Host header comparison."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rec_cli.config import COMMON_WEB_PORTS
from rec_cli.modules import (
    ensure_host,
    extract_host,
    registrable_domain,
    target_domain,
)
from rec_cli.schema import VHostFinding
from rec_cli.utils.runner import HTTPResult, gather_limited, resolve_host_ips

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_VHOST_WORDLIST = _DATA_DIR / "vhost_wordlist.txt"

_INTERESTING_STATUS = {200, 201, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405}
_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_MAX_BODY = 65_536
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

_FALLBACK_VHOSTS = (
    "admin",
    "api",
    "app",
    "beta",
    "blog",
    "cdn",
    "dashboard",
    "demo",
    "dev",
    "docs",
    "gateway",
    "git",
    "gitlab",
    "internal",
    "intranet",
    "jenkins",
    "legacy",
    "mail",
    "mobile",
    "monitoring",
    "old",
    "portal",
    "preprod",
    "private",
    "prod",
    "qa",
    "sandbox",
    "staging",
    "static",
    "status",
    "test",
    "uat",
    "vpn",
    "webmail",
    "wiki",
    "www",
)


@dataclass(slots=True)
class _Baseline:
    status: int = 0
    location: str = ""
    length: int = 0
    signature: str = ""
    title: str = ""


@dataclass(slots=True)
class _Budget:
    remaining: int

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _read_labels(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    labels: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        item = line.strip().lower().strip(".")
        if not item or item.startswith("#") or "*" in item:
            continue
        if not _LABEL_RE.match(item) or item in seen:
            continue
        seen.add(item)
        labels.append(item)
    return labels


def _load_labels(ctx: "ReconContext") -> list[str]:
    if ctx.settings.vhost_wordlist:
        custom = Path(ctx.settings.vhost_wordlist).expanduser()
        labels = _read_labels(custom)
        if labels:
            ctx.logger.info(f"custom vhost wordlist: {len(labels)} entries from {custom}")
            return labels
        ctx.logger.warn(
            f"cannot read custom vhost wordlist {custom}; using the bundled list"
        )
    return _read_labels(_VHOST_WORDLIST) or list(_FALLBACK_VHOSTS)


def _normalized_signature(content: bytes) -> str:
    sample = content[:8192].lower()
    sample = re.sub(rb"\s+", b" ", sample)
    return hashlib.sha1(sample).hexdigest()


def _content_length(result: HTTPResult) -> int:
    header = result.header("content-length", "")
    if header.isdigit():
        return int(header)
    return len(result.content)


def _title(text: str) -> str:
    match = _TITLE_RE.search(text[:32768])
    if not match:
        return ""
    cleaned = re.sub(r"<[^>]+>", " ", match.group(1))
    return " ".join(cleaned.split())[:200]


def _baseline_from(result: HTTPResult) -> _Baseline:
    return _Baseline(
        status=result.status_code,
        location=result.header("location", "").rstrip("/"),
        length=_content_length(result),
        signature=_normalized_signature(result.content)
        if result.status_code == 200
        else "",
        title=_title(result.text),
    )


def _is_default_like(result: HTTPResult, baseline: _Baseline) -> bool:
    if baseline.status == 0:
        return False
    status = result.status_code
    if status != baseline.status:
        return False
    if status in _REDIRECT_STATUS:
        location = result.header("location", "").rstrip("/")
        return location == baseline.location
    length = _content_length(result)
    tolerance = max(64, int(baseline.length * 0.05)) if baseline.length else 64
    if status == 200:
        signature = _normalized_signature(result.content)
        if baseline.signature and signature == baseline.signature:
            return True
        title = _title(result.text)
        if title and title != baseline.title:
            return False
        return baseline.length > 0 and abs(length - baseline.length) <= tolerance
    if baseline.length > 0:
        return abs(length - baseline.length) <= tolerance
    return True


def _literal_host(address: str) -> str:
    return f"[{address}]" if ":" in address else address


def _url_for(scheme: str, literal: str, port: int) -> str:
    default = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    suffix = "" if default else f":{port}"
    return f"{scheme}://{literal}{suffix}/"


def _schemes_for(port: int) -> list[str]:
    if port in (443, 8443):
        return ["https"]
    if port in (80, 8080, 8000, 8888):
        return ["http"]
    return ["http", "https"]


def _target_bases(target: str, literal: str, hostname: str) -> list[str]:
    value = target.strip()
    if not value:
        return []
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        if parsed.hostname.lower() != hostname.lower():
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return [_url_for(parsed.scheme, literal, port)]
    host_part, separator, port_part = value.rpartition(":")
    if (
        separator
        and port_part.isdigit()
        and host_part.strip("[]").lower() == hostname.lower()
    ):
        port = int(port_part)
        if 0 < port <= 65535:
            return [_url_for(scheme, literal, port) for scheme in _schemes_for(port)]
    return []


def _base_urls(record: object, target: str = "") -> list[str]:
    literal = _literal_host(str(getattr(record, "ip", "")))
    url = getattr(getattr(record, "http_info", None), "url", "") or ""
    if url:
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return [_url_for(parsed.scheme, literal, port)]

    target_bases = _target_bases(
        target, literal, str(getattr(record, "hostname", ""))
    )
    if target_bases:
        return target_bases

    ports = [
        int(port)
        for port in getattr(record, "open_ports", [])
        if int(port) in COMMON_WEB_PORTS
    ]
    if not ports:
        ports = [443, 80]

    bases: list[str] = []
    for port in ports[:3]:
        for scheme in _schemes_for(port):
            bases.append(_url_for(scheme, literal, port))
    return bases


def _suffix_for(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass
    return f".{registrable_domain(hostname)}"


def _candidate_names(
    ctx: "ReconContext", record: object, labels: list[str]
) -> list[str]:
    hostname = str(getattr(record, "hostname", "")).lower()
    suffix = _suffix_for(hostname)
    known = {name.lower() for name in ctx.subdomains}
    known.update(ctx.host_index)
    names: list[str] = []
    seen = set(known)
    for label in labels:
        name = f"{label}{suffix}"
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


async def _probe(
    ctx: "ReconContext", base: str, vhost: str, budget: _Budget
) -> HTTPResult | None:
    if not budget.take():
        return None
    return await ctx.http.get(
        base,
        headers={"Host": vhost},
        max_bytes=_MAX_BODY,
        follow_redirects=False,
    )


async def _select_base(
    ctx: "ReconContext", record: object, suffix: str, budget: _Budget
) -> tuple[str, _Baseline] | None:
    token = f"rec-{secrets.token_hex(6)}"
    for base in _base_urls(record, ctx.target):
        result = await _probe(ctx, base, f"{token}{suffix}", budget)
        if result is None:
            return None
        if result.error is None and result.status_code > 0:
            return base, _baseline_from(result)
    return None


async def _confirm(
    ctx: "ReconContext",
    base: str,
    vhost: str,
    baseline: _Baseline,
    budget: _Budget,
) -> bool:
    await asyncio.sleep(0.3)
    result = await _probe(ctx, base, vhost, budget)
    if result is None:
        return True
    if result.error is not None:
        return False
    return result.status_code in _INTERESTING_STATUS and not _is_default_like(
        result, baseline
    )


async def _fuzz_host(
    ctx: "ReconContext",
    record: object,
    labels: list[str],
    budget: _Budget,
) -> list[VHostFinding]:
    suffix = _suffix_for(str(getattr(record, "hostname", "")))
    selected = await _select_base(ctx, record, suffix, budget)
    if selected is None:
        ctx.logger.warn(
            f"vhost fuzzing skipped for {record.hostname}: no HTTP response"
        )
        return []
    base, baseline = selected
    names = _candidate_names(ctx, record, labels)
    if not names:
        return []

    results = await gather_limited(
        (_probe(ctx, base, name, budget) for name in names),
        limit=ctx.settings.concurrency,
    )

    findings: list[VHostFinding] = []
    for name, result in zip(names, results):
        if result is None or result.error is not None:
            continue
        if result.status_code not in _INTERESTING_STATUS:
            continue
        if _is_default_like(result, baseline):
            continue
        if not await _confirm(ctx, base, name, baseline, budget):
            continue
        content_type = result.header("content-type", "").split(";")[0].strip().lower()
        finding = VHostFinding(
            hostname=name,
            base_host=str(getattr(record, "hostname", "")),
            ip=str(getattr(record, "ip", "")),
            url=base,
            status_code=result.status_code,
            content_length=_content_length(result),
            content_type=content_type,
            title=_title(result.text),
        )
        findings.append(finding)
        detail = f" title={finding.title}" if finding.title else ""
        ctx.logger.found(
            f"vhost {finding.status_code} {name} on {finding.ip} "
            f"({base}){detail}"
        )
    return findings


async def run(ctx: "ReconContext") -> None:
    if ctx.settings.stealth:
        ctx.logger.warn(
            "virtual host fuzzing skipped in stealth mode; active probing is disabled"
        )
        return

    primary = target_domain(ctx.target) or extract_host(ctx.target)
    if not ctx.infra.hosts and primary:
        ensure_host(ctx, primary)

    candidates = [record for record in ctx.infra.hosts if record.hostname]
    candidates.sort(key=lambda record: (record.hostname != primary, record.hostname))
    host_limit = max(1, int(ctx.settings.max_vhost_hosts))

    selected: list[object] = []
    for record in candidates:
        if len(selected) >= host_limit:
            break
        if record.cdn_waf:
            ctx.logger.warn(
                f"vhost fuzzing skipped for {record.hostname}: "
                "CDN or WAF boundary detected"
            )
            continue
        if not record.ip:
            ips = ctx.host_ips.get(record.hostname)
            if not ips:
                ips = await resolve_host_ips(
                    record.hostname, ctx.settings.connect_timeout
                )
                if ips:
                    ctx.host_ips[record.hostname] = ips
            if ips:
                record.ip = ips[0]
        if not record.ip:
            ctx.logger.warn(
                f"vhost fuzzing skipped for {record.hostname}: unresolved address"
            )
            continue
        selected.append(record)

    if not selected:
        ctx.logger.warn("virtual host fuzzing skipped: no eligible host")
        return

    labels = _load_labels(ctx)
    if not labels:
        ctx.logger.warn("virtual host fuzzing skipped: empty wordlist")
        return

    per_host_budget = max(1, int(ctx.settings.max_vhost_requests))
    ctx.logger.info(
        f"virtual host fuzzing: {len(selected)} host(s), {len(labels)} labels, "
        f"{per_host_budget} request(s) per host"
    )

    total = 0
    for record in selected:
        budget = _Budget(per_host_budget)
        findings = await _fuzz_host(ctx, record, labels, budget)
        existing = {item.hostname for item in record.vhosts}
        added: list[VHostFinding] = []
        for finding in findings:
            if finding.hostname in existing:
                continue
            existing.add(finding.hostname)
            record.vhosts.append(finding)
            added.append(finding)
        if not added:
            continue
        total += len(added)
        ctx.logger.info(
            f"vhost {record.hostname}: {len(added)} finding(s), "
            f"{budget.remaining} request(s) left"
        )

    ctx.logger.info(f"virtual host fuzzing complete: {total} finding(s)")
