"""Reconnaissance modules and shared target normalization helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rec_cli.config import MULTI_LABEL_SUFFIXES
from rec_cli.schema import HostRecord

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.\-]+$")


def extract_host(target: str) -> str:
    value = target.strip()
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower()
    candidate = value.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError:
        pass
    if "@" in value and not value.startswith("@"):
        local, _, domain = value.partition("@")
        if _EMAIL_RE.match(f"{local}@{domain}"):
            return domain.strip().lower()
    return candidate.split("/", 1)[0].split(":", 1)[0].lower()


def target_domain(target: str) -> str | None:
    host = extract_host(target)
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if not host or "." not in host or not _HOST_RE.match(host):
        return None
    return host


def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def email_parts(value: str) -> tuple[str, str] | None:
    value = value.strip()
    if not _EMAIL_RE.match(value):
        return None
    local, _, domain = value.partition("@")
    return local, domain.lower()


def is_domain_like(value: str) -> bool:
    value = value.strip().lower().strip(".")
    if not value or " " in value or "/" in value or "@" in value:
        return False
    if "." not in value:
        return False
    return bool(_HOST_RE.match(value)) and not value.endswith(
        (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".json")
    )


def ensure_host(
    ctx: "ReconContext", hostname: str, ip: str = ""
) -> HostRecord:
    key = hostname.strip().lower()
    record = ctx.host_index.get(key)
    if record is None:
        record = HostRecord(hostname=key, ip=ip)
        ctx.host_index[key] = record
        ctx.infra.hosts.append(record)
    elif ip and not record.ip:
        record.ip = ip
    return record


def add_ports(record: HostRecord, ports: list[int]) -> None:
    for port in ports:
        if isinstance(port, int) and 0 < port <= 65535 and port not in record.open_ports:
            record.open_ports.append(port)
    record.open_ports.sort()
