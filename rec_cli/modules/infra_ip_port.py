"""Host resolution, CDN/WAF detection, and port/service discovery."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING

from rec_cli.config import (
    ASN_VENDOR_PATTERNS,
    CDN_CNAME_SUFFIXES,
    COMMON_TCP_PORTS,
    API_ENDPOINTS,
)
from rec_cli.modules import add_ports, ensure_host, extract_host, target_domain
from rec_cli.modules.infra_whois_asn import lookup_asn_for_ip
from rec_cli.schema import ASNRecord
from rec_cli.utils.runner import (
    binary_available,
    gather_limited,
    is_projectdiscovery_binary,
    resolve_cname,
    resolve_host_ips,
    run_command,
)

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network(value)
    for value in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
]
_FASTLY_NETWORKS = [
    ipaddress.ip_network(value) for value in ("151.101.0.0/16", "199.232.0.0/16")
]


def _target_hosts(ctx: "ReconContext") -> list[str]:
    if ctx.subdomains:
        hosts = list(ctx.subdomains)
    else:
        host = extract_host(ctx.target)
        domain = target_domain(ctx.target)
        if domain:
            hosts = [domain]
        else:
            try:
                network = ipaddress.ip_network(host, strict=False)
                if network.num_addresses == 1:
                    hosts = [str(network.network_address)]
                else:
                    hosts = [
                        str(address)
                        for _, address in zip(
                            range(ctx.settings.max_hosts), network.hosts()
                        )
                    ]
                    ctx.logger.warn(
                        f"CIDR target limited to {len(hosts)} addresses for scope control"
                    )
            except ValueError:
                hosts = [host] if host else []

    result: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        cleaned = host.strip().lower().strip(".")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
        if len(result) >= ctx.settings.max_hosts:
            break
    return result


def _cdn_from_cname(cname: str | None) -> str | None:
    if not cname:
        return None
    lowered = cname.lower().rstrip(".")
    for suffix, name in CDN_CNAME_SUFFIXES.items():
        if lowered == suffix or lowered.endswith("." + suffix):
            return name
    return None


def _cdn_from_ip(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(address in network for network in _CLOUDFLARE_NETWORKS):
        return "Cloudflare"
    if any(address in network for network in _FASTLY_NETWORKS):
        return "Fastly"
    return None


def _cdn_from_asn(description: str) -> str | None:
    lowered = description.lower()
    for pattern, name in ASN_VENDOR_PATTERNS:
        if pattern in lowered:
            return name
    return None


async def _internetdb(
    ctx: "ReconContext", ip: str
) -> tuple[list[int], list[str], list[str], list[str]]:
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['shodan_internetdb']}/{ip}",
        max_bytes=1_500_000,
    )
    if response.error:
        ctx.logger.warn(f"InternetDB lookup failed for {ip}: {response.error}")
        return [], [], [], []
    if response.status_code == 404:
        return [], [], [], []
    if response.status_code >= 400:
        ctx.logger.warn(
            f"InternetDB returned HTTP {response.status_code} for {ip}"
        )
        return [], [], [], []
    if not isinstance(data, dict):
        return [], [], [], []

    ports = sorted(
        {
            int(port)
            for port in data.get("ports", [])
            if isinstance(port, int) and 0 < port <= 65535
        }
    )
    cpes = [str(value) for value in data.get("cpes", []) if value]
    vulns = [str(value) for value in data.get("vulns", []) if value]
    tags = [str(value) for value in data.get("tags", []) if value]
    return ports, cpes, vulns, tags


def _parse_naabu(output: str) -> list[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate or ":" not in candidate:
            continue
        port_text = candidate.rsplit(":", 1)[-1]
        try:
            port = int(port_text)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.add(port)
    return sorted(ports)


async def _naabu_scan(ctx: "ReconContext", ip: str) -> list[int] | None:
    binary = ctx.settings.naabu_binary
    if not binary_available(binary):
        return None
    if not await is_projectdiscovery_binary(binary):
        ctx.logger.warn("naabu binary is not ProjectDiscovery naabu; using TCP fallback")
        return None
    result = await run_command(
        [
            binary,
            "-host",
            ip,
            "-silent",
            "-top-ports",
            "100",
            "-rate",
            str(100 if not ctx.settings.stealth else 20),
            "-timeout",
            "1500",
            "-scan-type",
            "c",
        ],
        timeout=120,
    )
    if not result.ok and not result.stdout.strip():
        ctx.logger.warn(f"naabu scan failed for {ip}: {result.stderr.strip()[:200]}")
        return None
    return _parse_naabu(result.stdout)


async def _connect_probe(ip: str, port: int, timeout: float) -> int | None:
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return port
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _connect_scan(ctx: "ReconContext", ip: str) -> list[int]:
    semaphore = asyncio.Semaphore(64)
    timeout = 1.2 if not ctx.settings.stealth else 0.8

    async def probe(port: int) -> int | None:
        async with semaphore:
            return await _connect_probe(ip, port, timeout)

    results = await asyncio.gather(*(probe(port) for port in COMMON_TCP_PORTS))
    return sorted(port for port in results if port is not None)


async def _ports_for_ip(ctx: "ReconContext", ip: str) -> tuple[list[int], list[str], list[str]]:
    if ip in ctx.port_cache:
        cached = ctx.port_cache[ip]
        return cached, ctx.host_cpes.get(f"ip:{ip}", []), ctx.ip_vulns.get(ip, [])

    cpes: list[str] = []
    vulns: list[str] = []
    if ctx.settings.stealth:
        ports, cpes, vulns, tags = await _internetdb(ctx, ip)
        if tags:
            ctx.ip_tags[ip] = tags
    else:
        ports = await _naabu_scan(ctx, ip)
        if ports is None:
            ctx.logger.info(f"naabu unavailable for {ip}; starting bounded TCP fallback")
            ports = await _connect_scan(ctx, ip)

    ctx.port_cache[ip] = ports
    ctx.host_cpes[f"ip:{ip}"] = cpes
    ctx.ip_vulns[ip] = vulns
    return ports, cpes, vulns


def _append_asn(ctx: "ReconContext", record: ASNRecord) -> None:
    existing = {item.asn for item in ctx.infra.whois_asn.asns}
    if record.asn and record.asn not in existing:
        ctx.infra.whois_asn.asns.append(record)


async def run(ctx: "ReconContext") -> None:
    hosts = _target_hosts(ctx)
    if not hosts:
        ctx.logger.warn("IP/port enumeration skipped: no usable host")
        return

    ctx.logger.info(f"resolving {len(hosts)} host(s)")
    semaphore = asyncio.Semaphore(5 if ctx.settings.stealth else 12)

    async def resolve(host: str) -> tuple[str, str | None, list[str]]:
        async with semaphore:
            cname = await resolve_cname(host, ctx.settings.connect_timeout)
            ips = await resolve_host_ips(host, ctx.settings.connect_timeout)
            return host, cname, ips

    resolved = await gather_limited(
        (resolve(host) for host in hosts), limit=4
    )

    host_to_ip: dict[str, str] = {}
    unique_ips: list[str] = []
    for host, cname, ips in resolved:
        ctx.host_cnames[host] = cname or ""
        ctx.host_ips[host] = ips
        ip = ips[0] if ips else ""
        record = ensure_host(ctx, host, ip)
        host_to_ip[host] = ip
        if not ips:
            ctx.logger.warn(f"no DNS resolution for {host}")
        for address in ips:
            if address not in unique_ips:
                unique_ips.append(address)

    if not unique_ips:
        ctx.logger.warn("no IP addresses resolved; port discovery skipped")
        return

    asn_semaphore = asyncio.Semaphore(5 if ctx.settings.stealth else 10)

    async def asn_for(ip: str) -> tuple[str, ASNRecord | None]:
        async with asn_semaphore:
            return ip, await lookup_asn_for_ip(ctx, ip)

    asn_results = await gather_limited(
        (asn_for(ip) for ip in unique_ips), limit=6
    )
    ip_to_asn = {ip: record for ip, record in asn_results if record}
    for record in ip_to_asn.values():
        _append_asn(ctx, record)

    scan_ips = unique_ips[:80 if not ctx.settings.stealth else 50]
    port_results = await gather_limited(
        (_ports_for_ip(ctx, ip) for ip in scan_ips), limit=4
    )
    ip_to_ports = {ip: values[0] for ip, values in zip(scan_ips, port_results)}

    for host, ip in host_to_ip.items():
        record = ensure_host(ctx, host, ip)
        cname = ctx.host_cnames.get(host)
        cdn = _cdn_from_cname(cname) or _cdn_from_ip(ip)
        asn_record = ip_to_asn.get(ip)
        if not cdn and asn_record:
            cdn = _cdn_from_asn(asn_record.description)
        if not cdn and ip in ctx.ip_tags:
            tags = [tag.lower() for tag in ctx.ip_tags[ip]]
            if "cdn" in tags or "cloud" in tags:
                cdn = "CDN/Cloud (Shodan tag)"
        record.cdn_waf = cdn

        ports = ip_to_ports.get(ip, [])
        add_ports(record, ports)
        if ip:
            cpes = ctx.host_cpes.get(f"ip:{ip}", [])
            if cpes:
                ctx.host_cpes.setdefault(host, []).extend(cpes)
            if ctx.ip_vulns.get(ip):
                ctx.shodan_vulns.setdefault(host, []).extend(ctx.ip_vulns[ip])

        if ip:
            cdn_label = f" cdn={cdn}" if cdn else ""
            ports_label = ",".join(str(port) for port in ports[:20])
            found = f"{host} -> {ip}{cdn_label}"
            if ports_label:
                found += f" ports={ports_label}"
            ctx.logger.found(found)

    for record in ctx.infra.hosts:
        ctx.host_index[record.hostname] = record
