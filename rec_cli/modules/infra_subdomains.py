"""Passive subdomain enumeration via Subfinder, Cert Spotter, and crt.sh."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules import extract_host, target_domain
from rec_cli.utils.runner import binary_available, dedupe, run_command

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$"
)


def _clean_host(value: str, base: str) -> str | None:
    host = value.strip().lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or not _HOSTNAME_RE.match(host):
        return None
    if host != base and not host.endswith("." + base):
        return None
    return host


def _extract_json_names(data: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(data, list):
        return names
    for item in data:
        if not isinstance(item, dict):
            continue
        for key in ("dns_names", "name_value", "common_name"):
            value = item.get(key)
            if isinstance(value, str):
                names.extend(value.splitlines())
            elif isinstance(value, list):
                names.extend(str(entry) for entry in value)
    return names


async def _subfinder(ctx: "ReconContext", domain: str) -> list[str]:
    binary = ctx.settings.subfinder_binary
    if not binary_available(binary):
        ctx.logger.warn(
            "subfinder is not installed; using passive HTTP certificate sources"
        )
        return []
    command = [
        binary,
        "-d",
        domain,
        "-silent",
        "-timeout",
        "15",
        "-rl",
        str(ctx.settings.subprocess_rate_limit),
    ]
    result = await run_command(command, timeout=120)
    if not result.ok:
        detail = result.stderr.strip() or "subfinder execution failed"
        ctx.logger.warn(detail[:300])
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


async def _certspotter(ctx: "ReconContext", domain: str) -> list[str]:
    data, response = await ctx.http.get_json(
        API_ENDPOINTS["certspotter"],
        params={
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        max_bytes=8_000_000,
    )
    if response.error:
        ctx.logger.warn(f"Cert Spotter lookup failed: {response.error}")
        return []
    if response.status_code == 429:
        ctx.logger.warn("Cert Spotter rate limit reached")
        return []
    if response.status_code >= 400:
        ctx.logger.warn(f"Cert Spotter returned HTTP {response.status_code}")
        return []
    return _extract_json_names(data)


async def _crt_sh(ctx: "ReconContext", domain: str) -> list[str]:
    data, response = await ctx.http.get_json(
        API_ENDPOINTS["crt_sh"],
        params={"q": f"%.{domain}", "output": "json"},
        max_bytes=12_000_000,
    )
    if response.error:
        ctx.logger.warn(f"crt.sh lookup failed: {response.error}")
        return []
    if response.status_code >= 400:
        ctx.logger.warn(f"crt.sh returned HTTP {response.status_code}")
        return []
    return _extract_json_names(data)


async def run(ctx: "ReconContext") -> None:
    domain = target_domain(ctx.target) or extract_host(ctx.target)
    if not domain or "." not in domain:
        ctx.logger.warn("subdomain enumeration skipped: target is not a domain")
        return

    collected: list[str] = []
    sources = [
        ("subfinder", await _subfinder(ctx, domain)),
        ("certspotter", await _certspotter(ctx, domain)),
        ("crt.sh", await _crt_sh(ctx, domain)),
    ]
    for source, values in sources:
        if values:
            ctx.logger.info(f"{source}: {len(values)} raw names")

    for _, values in sources:
        for value in values:
            host = _clean_host(value, domain)
            if host:
                collected.append(host)

    ordered = dedupe([domain, *collected], ctx.settings.max_subdomains)
    ctx.subdomains.update(ordered)
    for host in ordered:
        ctx.logger.found(f"subdomain: {host}")
    ctx.logger.info(f"subdomain enumeration complete: {len(ordered)} unique hosts")
