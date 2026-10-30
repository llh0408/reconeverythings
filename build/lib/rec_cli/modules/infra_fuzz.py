"""Bounded directory fuzzing and sensitive file discovery."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from rec_cli.config import COMMON_WEB_PORTS
from rec_cli.modules import ensure_host, extract_host, target_domain
from rec_cli.schema import PathFinding
from rec_cli.utils.runner import HTTPResult, gather_limited, resolve_host_ips

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DIRECTORY_WORDLIST = _DATA_DIR / "directory_wordlist.txt"
_SENSITIVE_WORDLIST = _DATA_DIR / "sensitive_files.txt"

_INTERESTING_STATUS = {200, 201, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405}
_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_SENSITIVE_CATEGORIES = {
    "backup",
    "config",
    "credential",
    "debug",
    "log",
    "vcs",
}
_MAX_BODY = 65_536
_CONCURRENCY = 6
_GENERIC_BLOCK_MARKERS = (
    "attention required",
    "just a moment",
    "cf-error-details",
    "challenge-platform",
    "cf-chl",
    "checking your browser",
)

_FALLBACK_DIRECTORIES = (
    "admin",
    "api",
    "app",
    "assets",
    "backup",
    "backups",
    "config",
    "dashboard",
    "dev",
    "docs",
    "downloads",
    "files",
    "images",
    "internal",
    "js",
    "logs",
    "old",
    "portal",
    "private",
    "public",
    "static",
    "status",
    "test",
    "uploads",
    "wp-admin",
    "wp-content",
)

_FALLBACK_SENSITIVE = (
    ".env",
    ".git/HEAD",
    ".git/config",
    ".htaccess",
    ".htpasswd",
    ".svn/entries",
    "backup.zip",
    "config.php.bak",
    "db.sql",
    "docker-compose.yml",
    "phpinfo.php",
    "robots.txt",
    "server-status",
    "sitemap.xml",
    "wp-config.php.bak",
)

_ARCHIVE_RE = re.compile(
    r"\.(?:zip|tar|tar\.gz|tgz|rar|7z|sql|dump|bak|old|save|orig|swp)$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class _Baseline:
    status: int = 0
    location: str = ""
    length: int = 0
    signature: str = ""


@dataclass(slots=True)
class _Budget:
    remaining: int

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _read_wordlist(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    entries: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        item = item.lstrip("/")
        if not item or "://" in item or ".." in item.split("/"):
            continue
        if item in seen:
            continue
        seen.add(item)
        entries.append(item)
    return entries


def _load_entries(
    ctx: "ReconContext", path: Path, fallback: tuple[str, ...]
) -> list[str]:
    if path is _DIRECTORY_WORDLIST and ctx.settings.wordlist:
        custom = Path(ctx.settings.wordlist).expanduser()
        entries = _read_wordlist(custom)
        if entries:
            ctx.logger.info(f"custom wordlist: {len(entries)} entries from {custom}")
            return entries
        ctx.logger.warn(
            f"cannot read custom wordlist {custom}; using the bundled directory list"
        )
    entries = _read_wordlist(path)
    return entries or list(fallback)


def _category(path: str, sensitive_source: bool) -> str:
    low = path.lower()
    if (
        low.startswith((".git/", ".svn/", ".hg/"))
        or low in {".gitignore", ".dockerignore"}
    ):
        return "vcs"
    if "backup" in low or _ARCHIVE_RE.search(low):
        return "backup"
    if (
        ".env" in low
        or "config" in low
        or "htaccess" in low
        or low.endswith((".ini", ".properties", ".yml", ".yaml", ".toml"))
    ):
        return "config"
    if any(
        marker in low
        for marker in (
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            ".pem",
            ".key",
            ".jks",
            ".pfx",
            "credential",
            "secret",
            "password",
            "htpasswd",
            "htaccess",
        )
    ):
        return "credential"
    if "log" in low:
        return "log"
    if any(
        marker in low
        for marker in (
            "phpinfo",
            "server-status",
            "server-info",
            "actuator",
            "adminer",
            "debug",
        )
    ):
        return "debug"
    if any(
        marker in low
        for marker in ("swagger", "openapi", "api-docs", "graphiql")
    ):
        return "api"
    return "sensitive" if sensitive_source else "discovered"


def _base_candidates(record: object) -> list[str]:
    url = getattr(getattr(record, "http_info", None), "url", "") or ""
    if url:
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return [f"{parsed.scheme}://{parsed.netloc}/"]

    hostname = str(getattr(record, "hostname", ""))
    host = hostname
    try:
        ipaddress.ip_address(hostname)
        host = f"[{hostname}]" if ":" in hostname else hostname
    except ValueError:
        pass

    ports = [
        port
        for port in getattr(record, "open_ports", [])
        if port in COMMON_WEB_PORTS
    ]
    if not ports:
        ports = [443, 80]

    bases: list[str] = []
    for port in ports[:3]:
        if port in (443, 8443):
            schemes = ["https"]
        elif port in (80, 8080, 8000, 8888):
            schemes = ["http"]
        else:
            schemes = ["http", "https"]
        for scheme in schemes:
            default = (scheme == "https" and port == 443) or (
                scheme == "http" and port == 80
            )
            bases.append(f"{scheme}://{host}{'' if default else f':{port}'}/")
    return bases


def _normalized_signature(content: bytes) -> str:
    sample = content[:8192].lower()
    sample = re.sub(rb"\s+", b" ", sample)
    return hashlib.sha1(sample).hexdigest()


def _content_length(result: HTTPResult) -> int:
    header = result.header("content-length", "")
    if header.isdigit():
        return int(header)
    return len(result.content)


def _baseline_from(result: HTTPResult) -> _Baseline:
    return _Baseline(
        status=result.status_code,
        location=result.header("location", "").rstrip("/"),
        length=_content_length(result),
        signature=_normalized_signature(result.content)
        if result.status_code == 200
        else "",
    )


def _is_soft_404(result: HTTPResult, baseline: _Baseline) -> bool:
    if baseline.status == 0:
        return False
    status = result.status_code
    if status != baseline.status:
        return False
    if status in (401, 403):
        # A blanket denial for an unknown path cannot distinguish real hits.
        return True
    if status in _REDIRECT_STATUS:
        location = result.header("location", "").rstrip("/")
        return location == baseline.location
    if status == 200:
        signature = _normalized_signature(result.content)
        if baseline.signature and signature == baseline.signature:
            return True
    length = _content_length(result)
    if baseline.length > 0:
        tolerance = max(48, int(baseline.length * 0.02))
        if abs(length - baseline.length) <= tolerance:
            return True
    return False


def _is_directory(
    status: int, location: str, content_type: str, content: bytes
) -> bool:
    if status in _REDIRECT_STATUS and location:
        target = urlparse(location)
        path = target.path or urlparse(urljoin("http://placeholder/", location)).path
        if path and path != "/":
            return path.endswith("/")
        return False
    if status == 200 and content_type.startswith("text/html"):
        sample = content[:16384].decode("utf-8", errors="replace").lower()
        return "index of /" in sample
    return False


def _is_generic_block(result: HTTPResult) -> bool:
    if result.status_code != 403:
        return False
    sample = result.text[:16384].lower()
    return any(marker in sample for marker in _GENERIC_BLOCK_MARKERS)


def _finding_for(
    base: str,
    path: str,
    depth: int,
    source: str,
    result: HTTPResult,
    baseline: _Baseline,
) -> tuple[PathFinding | None, bool]:
    status = result.status_code
    if result.error or status not in _INTERESTING_STATUS:
        return None, False
    if _is_generic_block(result):
        return None, False
    if _is_soft_404(result, baseline):
        return None, False

    location = result.header("location", "")
    content_type = result.header("content-type", "").split(";")[0].strip().lower()
    directory = _is_directory(status, location, content_type, result.content)
    if status in (401, 403):
        directory = False
    sensitive = source == "sensitive-list"
    category = "directory" if directory else _category(path, sensitive)
    if status in _REDIRECT_STATUS and not directory and category == "discovered":
        category = "redirect"
    if category in _SENSITIVE_CATEGORIES:
        sensitive = True

    return (
        PathFinding(
            url=f"{base}{path}",
            path=path,
            status_code=status,
            content_length=_content_length(result),
            content_type=content_type,
            category=category,
            sensitive=sensitive,
            redirect_to=location[:500],
            depth=depth,
            source=source,
        ),
        directory,
    )


async def _active_base(
    ctx: "ReconContext", record: object, budget: _Budget
) -> tuple[str, _Baseline] | None:
    token = f".rec-{secrets.token_hex(6)}"
    for base in _base_candidates(record):
        if not budget.take():
            return None
        result = await ctx.http.get(
            f"{base}{token}",
            max_bytes=_MAX_BODY,
            follow_redirects=False,
        )
        if result.error is None and result.status_code > 0:
            return base, _baseline_from(result)
    return None


def _build_entries(
    ctx: "ReconContext",
) -> list[tuple[str, str]]:
    directories = _load_entries(ctx, _DIRECTORY_WORDLIST, _FALLBACK_DIRECTORIES)
    sensitive = _load_entries(ctx, _SENSITIVE_WORDLIST, _FALLBACK_SENSITIVE)
    entries = [(entry, "sensitive-list") for entry in sensitive]
    entries.extend((entry, "directory-list") for entry in directories)
    return entries


async def _confirm_access(
    ctx: "ReconContext", url: str, status: int, budget: _Budget
) -> bool:
    await asyncio.sleep(0.4)
    if not budget.take():
        return True
    result = await ctx.http.get(
        url,
        max_bytes=_MAX_BODY,
        follow_redirects=False,
    )
    return result.error is None and result.status_code == status


async def _fuzz_host(
    ctx: "ReconContext",
    record: object,
    entries: list[tuple[str, str]],
    budget: _Budget,
) -> list[PathFinding]:
    selected = await _active_base(ctx, record, budget)
    if selected is None:
        ctx.logger.warn(f"fuzz skipped for {record.hostname}: no HTTP response")
        return []
    base, baseline = selected

    sensitive_entries = [
        item for item in entries if item[1] == "sensitive-list"
    ]
    directory_entries = [
        item for item in entries if item[1] != "sensitive-list"
    ]
    depth_limit = max(1, int(ctx.settings.max_fuzz_depth))
    max_dirs = max(1, int(ctx.settings.max_fuzz_dirs))
    seen: set[str] = set()
    findings: list[PathFinding] = []
    level: list[tuple[str, int]] = [("", 0)]
    directories_seen = 0

    while level and budget.remaining > 0:
        candidates: list[tuple[str, int, str]] = []
        for prefix, depth in level:
            if budget.remaining <= 0:
                break
            ordered = (
                sensitive_entries + directory_entries
                if depth == 0
                else directory_entries + sensitive_entries
            )
            for entry, source in ordered:
                if budget.remaining <= 0:
                    break
                path = f"{prefix}{entry}"
                if path in seen:
                    continue
                seen.add(path)
                if not budget.take():
                    break
                candidates.append((path, depth, source))
        if not candidates:
            break

        results = await gather_limited(
            (
                ctx.http.get(
                    f"{base}{path}",
                    max_bytes=_MAX_BODY,
                    follow_redirects=False,
                )
                for path, _depth, _source in candidates
            ),
            limit=_CONCURRENCY,
        )

        next_level: list[tuple[str, int]] = []
        for (path, depth, source), result in zip(candidates, results):
            finding, directory = _finding_for(
                base, path, depth, source, result, baseline
            )
            if finding is None:
                continue
            if result.status_code in (401, 403):
                confirmed = await _confirm_access(
                    ctx, finding.url, result.status_code, budget
                )
                if not confirmed:
                    continue
            findings.append(finding)
            marker = "sensitive" if finding.sensitive else finding.category
            ctx.logger.found(
                f"path {finding.status_code} {finding.url} ({marker})"
            )
            if (
                directory
                and depth + 1 < depth_limit
                and directories_seen < max_dirs
            ):
                directories_seen += 1
                next_level.append((f"{path.rstrip('/')}/", depth + 1))

        level = next_level

    return findings


async def run(ctx: "ReconContext") -> None:
    if ctx.settings.stealth:
        ctx.logger.warn(
            "directory fuzzing skipped in stealth mode; active probing is disabled"
        )
        return

    if not ctx.infra.hosts:
        host = target_domain(ctx.target) or extract_host(ctx.target)
        if host:
            record = ensure_host(ctx, host)
            if not record.ip:
                ips = await resolve_host_ips(host, ctx.settings.connect_timeout)
                if ips:
                    record.ip = ips[0]
                    ctx.host_ips[host] = ips

    hosts = [
        record
        for record in ctx.infra.hosts
        if record.hostname
    ][: max(1, int(ctx.settings.max_fuzz_hosts))]
    if not hosts:
        ctx.logger.warn("directory fuzzing skipped: no hosts")
        return

    entries = _build_entries(ctx)
    if not entries:
        ctx.logger.warn("directory fuzzing skipped: empty wordlist")
        return

    budget = _Budget(max(1, int(ctx.settings.max_fuzz_requests)))
    ctx.logger.info(
        f"directory fuzzing: {len(hosts)} host(s), {len(entries)} entries, "
        f"{budget.remaining} request budget, depth {ctx.settings.max_fuzz_depth}"
    )

    total = 0
    sensitive_total = 0
    for record in hosts:
        if budget.remaining <= 0:
            ctx.logger.warn("directory fuzzing stopped: request budget exhausted")
            break
        findings = await _fuzz_host(ctx, record, entries, budget)
        if not findings:
            continue
        existing = {finding.path for finding in record.path_findings}
        added: list[PathFinding] = []
        for finding in findings:
            if finding.path in existing:
                continue
            existing.add(finding.path)
            record.path_findings.append(finding)
            added.append(finding)
        total += len(added)
        sensitive_total += sum(1 for finding in added if finding.sensitive)
        directories = sum(
            1 for finding in added if finding.category == "directory"
        )
        ctx.logger.info(
            f"fuzz {record.hostname}: {len(added)} finding(s), "
            f"{directories} directory(ies), {budget.remaining} request(s) left"
        )

    ctx.logger.info(
        f"directory fuzzing complete: {total} finding(s), "
        f"{sensitive_total} sensitive, {budget.remaining} request(s) unused"
    )
