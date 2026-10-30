"""Custom WHOIS, RDAP, ASN, and CIDR discovery."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
from typing import TYPE_CHECKING, Any

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules import extract_host, target_domain
from rec_cli.schema import ASNRecord
from rec_cli.utils.runner import (
    dedupe,
    gather_limited,
    query_txt,
    resolve_host_ips,
)

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PRIVACY_MARKERS = (
    "redacted",
    "privacy",
    "withheld",
    "whoisguard",
    "domains by proxy",
    "data protected",
    "gdpr",
    "not disclosed",
)


async def _direct_pause(ctx: "ReconContext") -> None:
    if ctx.settings.stealth:
        await asyncio.sleep(random.uniform(0.5, 2.0))


async def _socket_whois(server: str, query: str, timeout: float = 10.0) -> str:
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=timeout
        )
        writer.write((query + "\r\n").encode("utf-8", errors="ignore"))
        await writer.drain()
        chunks: list[bytes] = []
        total = 0
        while total < 1_500_000:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _clean_value(value: str) -> str:
    return " ".join(value.split()).strip(" .")


def _is_private_email(email: str) -> bool:
    lowered = email.lower()
    return any(marker in lowered for marker in _PRIVACY_MARKERS)


def _parse_whois_text(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith(("%", "#", ">>>", "NOTICE", "TERMS")):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = _clean_value(key).lower()
        value = _clean_value(value)
        if not value:
            continue
        fields.setdefault(key, []).append(value)
    return fields


def _extract_whois_fields(fields: dict[str, list[str]]) -> tuple[str, str, list[str]]:
    registrar = ""
    for key in ("registrar", "sponsoring registrar", "registrar name"):
        if fields.get(key):
            registrar = fields[key][0]
            break

    org = ""
    for key in (
        "registrant organization",
        "registrant org",
        "registrant organisation",
        "org",
        "organisation",
        "organization",
    ):
        if fields.get(key):
            candidate = fields[key][0]
            if not _is_private_email(candidate) and "redacted" not in candidate.lower():
                org = candidate
                break

    emails: list[str] = []
    for key, values in fields.items():
        if "email" not in key:
            continue
        if not any(
            token in key
            for token in ("registrant", "admin", "technical", "tech", "abuse")
        ):
            continue
        for value in values:
            for email in _EMAIL_RE.findall(value):
                if not _is_private_email(email) and email.lower() not in {
                    item.lower() for item in emails
                }:
                    emails.append(email)
    return registrar, org, emails


def _vcard_value(vcard: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return result
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = str(item[0]).lower()
        value = item[3]
        if isinstance(value, list):
            value = " ".join(str(part) for part in value)
        result.setdefault(key, []).append(str(value))
    return result


def _parse_rdap_domain(data: dict[str, Any]) -> tuple[str, str, list[str]]:
    registrar = ""
    org = ""
    emails: list[str] = []

    def walk(entity: dict[str, Any]) -> None:
        nonlocal registrar, org
        roles = [str(role).lower() for role in entity.get("roles", [])]
        values = _vcard_value(entity.get("vcardArray"))
        names = values.get("fn", []) + values.get("org", [])
        display = _clean_value(next((n for n in names if n), ""))
        if "registrar" in roles and display and not registrar:
            registrar = display
        if "registrant" in roles:
            if display and not org:
                org = display
            for email in values.get("email", []):
                if _EMAIL_RE.match(email) and not _is_private_email(email):
                    if email not in emails:
                        emails.append(email)
        for child in entity.get("entities", []):
            if isinstance(child, dict):
                walk(child)

    for entity in data.get("entities", []):
        if isinstance(entity, dict):
            walk(entity)

    for email in _EMAIL_RE.findall(str(data.get("remarks", ""))):
        if not _is_private_email(email) and email not in emails:
            emails.append(email)
    return registrar, org, emails


async def _domain_whois(
    ctx: "ReconContext", domain: str
) -> tuple[str, str, list[str]]:
    registrar = ""
    org = ""
    emails: list[str] = []

    if not ctx.settings.stealth or not ctx.settings.proxy:
        tld = domain.rsplit(".", 1)[-1]
        await _direct_pause(ctx)
        iana = await _socket_whois("whois.iana.org", tld, ctx.settings.request_timeout)
        referral = ""
        for line in iana.splitlines():
            lowered = line.lower()
            if lowered.startswith(("refer:", "whois:")):
                referral = line.split(":", 1)[1].strip()
                break
        if referral:
            await _direct_pause(ctx)
            raw = await _socket_whois(
                referral, domain, ctx.settings.request_timeout
            )
            if raw:
                fields = _parse_whois_text(raw)
                registrar, org, emails = _extract_whois_fields(fields)
                if any((registrar, org, emails)):
                    ctx.logger.info(f"WHOIS source: {referral}")

    if not any((registrar, org, emails)):
        data, response = await ctx.http.get_json(
            f"{API_ENDPOINTS['rdap']}/domain/{domain}",
            max_bytes=2_000_000,
        )
        if isinstance(data, dict):
            registrar, org, emails = _parse_rdap_domain(data)
            if any((registrar, org, emails)):
                ctx.logger.info("WHOIS source: RDAP")
        elif response.error:
            ctx.logger.warn(f"WHOIS fallback failed for {domain}: {response.error}")

    return registrar, org, emails


def _parse_cymru_origin(value: str) -> list[tuple[str, list[str]]]:
    records: list[tuple[str, list[str]]] = []
    for segment in value.split(";"):
        parts = [part.strip() for part in segment.split("|")]
        if len(parts) < 2 or not parts[0]:
            continue
        asns = [item.strip() for item in parts[0].split() if item.strip()]
        cidrs = [item.strip() for item in parts[1].split(",") if item.strip()]
        for asn in asns:
            records.append((asn, cidrs))
    return records


async def _asn_from_cymru(ctx: "ReconContext", ip: str) -> ASNRecord | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 4:
        return None
    reversed_ip = ".".join(reversed(address.exploded.split(".")))
    origin = await query_txt(
        f"{reversed_ip}.origin.asn.cymru.com", ctx.settings.connect_timeout
    )
    for value in origin:
        parsed = _parse_cymru_origin(value)
        if not parsed:
            continue
        asn, cidrs = parsed[0]
        asn_id = f"AS{asn}" if not asn.upper().startswith("AS") else asn.upper()
        description = ""
        desc_values = await query_txt(
            f"{asn_id}.asn.cymru.com", ctx.settings.connect_timeout
        )
        if desc_values:
            parts = [part.strip() for part in desc_values[0].split("|")]
            if len(parts) >= 5:
                description = parts[4]
        return ASNRecord(asn=asn_id, cidr=cidrs, description=description)
    return None


async def _asn_from_ripe(ctx: "ReconContext", ip: str) -> ASNRecord | None:
    data, response = await ctx.http.get_json(
        "https://stat.ripe.net/data/prefix-overview/data.json",
        params={"resource": ip},
        max_bytes=1_000_000,
    )
    if response.error or not isinstance(data, dict):
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    entries = payload.get("asns")
    if not isinstance(entries, list) or not entries:
        return None
    asn_value = str(entries[0].get("asn", "")).strip()
    holder = str(entries[0].get("holder", "")).strip()
    if not asn_value:
        return None
    cidr = payload.get("prefix")
    return ASNRecord(
        asn=asn_value if asn_value.upper().startswith("AS") else f"AS{asn_value}",
        cidr=[str(cidr)] if cidr else [],
        description=holder,
    )


async def lookup_asn_for_ip(
    ctx: "ReconContext", ip: str
) -> ASNRecord | None:
    """Look up an IP's announcing ASN, caching both hits and misses."""
    if ip in ctx.asn_by_ip:
        return ctx.asn_by_ip[ip]
    if ip in ctx.asn_failures:
        return None
    record = await _asn_from_cymru(ctx, ip)
    if record is None:
        record = await _asn_from_ripe(ctx, ip)
    if record is not None:
        ctx.asn_by_ip[ip] = record
    else:
        ctx.asn_failures.add(ip)
    return record


def _preferred_ips(values: list[str]) -> list[str]:
    ipv4: list[str] = []
    other: list[str] = []
    for value in dedupe(values, 12):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4:
            ipv4.append(str(address))
        else:
            other.append(str(address))
    return (ipv4[:2] + other[:1])[:3]


def _merge_asns(records: list[ASNRecord]) -> list[ASNRecord]:
    merged: dict[str, ASNRecord] = {}
    for record in records:
        key = record.asn or record.description
        if not key:
            continue
        if key not in merged:
            merged[key] = ASNRecord(
                asn=record.asn, cidr=[], description=record.description
            )
        target = merged[key]
        for cidr in record.cidr:
            if cidr and cidr not in target.cidr:
                target.cidr.append(cidr)
        if record.description and not target.description:
            target.description = record.description
    return list(merged.values())


async def run(ctx: "ReconContext") -> None:
    target = extract_host(ctx.target)
    domain = target_domain(ctx.target)
    ctx.logger.info(f"collecting WHOIS/ASN data for {target}")

    registrar = ""
    org = ""
    emails: list[str] = []
    if domain:
        registrar, org, emails = await _domain_whois(ctx, domain)

    lookup_ips: list[str] = []
    if domain:
        lookup_ips = await resolve_host_ips(domain, ctx.settings.connect_timeout)
    else:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 1:
                for index, address in enumerate(network.hosts()):
                    lookup_ips.append(str(address))
                    if index >= 3:
                        break
            else:
                lookup_ips = [str(network.network_address)]
        except ValueError:
            pass

    lookup_ips = _preferred_ips(lookup_ips)
    records = await gather_limited(
        [lookup_asn_for_ip(ctx, ip) for ip in lookup_ips], limit=4
    )
    asns: list[ASNRecord] = []
    for ip, record in zip(lookup_ips, records):
        if record:
            asns.append(record)
            ctx.logger.found(
                f"ASN {record.asn} {record.description} for {ip}".strip()
            )

    merged = _merge_asns(asns)
    ctx.infra.whois_asn.registrar = registrar
    ctx.infra.whois_asn.registrant_org = org
    ctx.infra.whois_asn.registrant_emails = emails
    ctx.infra.whois_asn.asns = merged

    if registrar:
        ctx.logger.found(f"registrar: {registrar}")
    if org:
        ctx.logger.found(f"registrant organization: {org}")
    for email in emails:
        ctx.logger.found(f"registrant email: {email}")
