"""Passive Wayback Machine historical URL discovery through the CDX API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules import ensure_host, registrable_domain, target_domain
from rec_cli.schema import ArchivedURL

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_CDX_FIELDS = ("timestamp", "original", "mimetype", "statuscode")
_MAX_RESPONSE_BYTES = 5_000_000
_MAX_LOGGED_LINKS = 10


@dataclass(slots=True)
class _Row:
    url: str
    timestamp: str
    wayback_url: str
    status_code: int = 0
    mime_type: str = ""


def _snapshot_url(timestamp: str, url: str) -> str:
    return f"https://web.archive.org/web/{timestamp}/{url}"


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _in_scope(host: str, root: str) -> bool:
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    if not host or not root:
        return False
    return host == root or host.endswith("." + root)


def _column_indexes(header: list[str]) -> tuple[dict[str, int], bool]:
    normalized = [cell.strip().lower() for cell in header]
    if "timestamp" in normalized and "original" in normalized:
        return (
            {
                name: normalized.index(name)
                for name in _CDX_FIELDS
                if name in normalized
            },
            True,
        )
    return {name: index for index, name in enumerate(_CDX_FIELDS)}, False


def _cell(row: list[str], indexes: dict[str, int], name: str) -> str:
    index = indexes.get(name)
    if index is None or index >= len(row):
        return ""
    return str(row[index]).strip()


def parse_cdx(data: object) -> list[_Row]:
    """Parse a CDX JSON payload into archived URL records."""
    if not isinstance(data, list) or not data:
        return []
    first = data[0] if isinstance(data[0], list) else []
    indexes, header_present = _column_indexes(
        [str(cell) for cell in first]
    )
    rows = data[1:] if header_present else data

    parsed: list[_Row] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        values = [str(cell) for cell in row]
        original = _cell(values, indexes, "original")
        timestamp = _cell(values, indexes, "timestamp")
        if not original or not timestamp.isdigit():
            continue
        try:
            target = urlparse(original)
        except ValueError:
            continue
        if target.scheme not in ("http", "https") or not target.hostname:
            continue
        status_text = _cell(values, indexes, "statuscode")
        status_code = int(status_text) if status_text.isdigit() else 0
        parsed.append(
            _Row(
                url=original,
                timestamp=timestamp,
                wayback_url=_snapshot_url(timestamp, original),
                status_code=status_code,
                mime_type=_cell(values, indexes, "mimetype"),
            )
        )
    return parsed


async def run(ctx: "ReconContext") -> None:
    domain = target_domain(ctx.target)
    if not domain:
        ctx.logger.warn("wayback lookup skipped: target is not a domain")
        return

    root = registrable_domain(domain)
    limit = max(1, int(ctx.settings.max_wayback_urls))
    params = {
        "url": root,
        "matchType": "domain",
        "output": "json",
        "fl": ",".join(_CDX_FIELDS),
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "sort": "reverse",
        "limit": str(limit),
    }
    ctx.logger.info(f"wayback lookup: {root} (limit {limit})")

    data, response = await ctx.http.get_json(
        API_ENDPOINTS["wayback_cdx"],
        params=params,
        max_bytes=_MAX_RESPONSE_BYTES,
    )
    if response.error is not None:
        ctx.logger.warn(f"wayback lookup failed: {response.error}")
        return
    if response.status_code != 200:
        ctx.logger.warn(
            f"wayback lookup returned HTTP {response.status_code}"
        )
        return
    if data is None:
        ctx.logger.warn("wayback lookup returned no parsable data")
        return

    selected: list[tuple[str, _Row]] = []
    seen: set[str] = set()
    for row in parse_cdx(data):
        host = _host_of(row.url)
        if not _in_scope(host, root) or row.url in seen:
            continue
        seen.add(row.url)
        selected.append((host, row))
        if len(selected) >= limit:
            break

    if not selected:
        ctx.logger.info(f"wayback: no archived URL found for {root}")
        return

    selected.sort(key=lambda item: item[1].timestamp, reverse=True)
    added: list[tuple[str, _Row]] = []
    hosts: dict[str, int] = {}
    for host, row in selected:
        record = ctx.host_index.get(host)
        if record is None:
            record = ensure_host(ctx, host)
        existing = {entry.wayback_url for entry in record.historical_urls}
        if row.wayback_url in existing:
            continue
        record.historical_urls.append(
            ArchivedURL(
                url=row.url,
                timestamp=row.timestamp,
                wayback_url=row.wayback_url,
                status_code=row.status_code,
                mime_type=row.mime_type,
            )
        )
        added.append((host, row))
        hosts[host] = hosts.get(host, 0) + 1

    if not added:
        return
    ctx.logger.info(
        f"wayback: {len(added)} archived URL(s) across {len(hosts)} host(s) "
        f"for {root}"
    )
    for host, row in added[:_MAX_LOGGED_LINKS]:
        ctx.logger.found(
            f"wayback {host} {row.timestamp} {row.url} -> {row.wayback_url}"
        )
