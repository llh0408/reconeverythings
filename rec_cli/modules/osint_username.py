"""Cross-platform public username checks driven by the WhatsMyName list."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

from rec_cli.modules.osint_identity import (
    _parse_target,
    generate_username_variants,
    normalize_username,
)
from rec_cli.schema import SocialProfile
from rec_cli.utils.logger import safe_text
from rec_cli.utils.runner import gather_limited
from rec_cli.utils.strict import has_identity_signal, looks_blocked

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext
    from rec_cli.utils.runner import HTTPResult

_ACCOUNT_TOKEN = "{account}"
_LEGACY_TOKEN = "{username}"
_MAX_LIST_BYTES = 6_000_000
_CHECK_MAX_BYTES = 400_000
_STEALTH_SITE_CAP = 40
_ACTIVE_SITE_CAP = 120
_STEALTH_USERNAME_LIMIT = 1
_ACTIVE_USERNAME_LIMIT = 2
_SAFE_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")
_SOCIAL_CATEGORY = "social"
_SKIP_CATEGORIES = {"xx nsfw xx"}


@dataclass(slots=True)
class _Site:
    name: str
    uri_check: str
    uri_pretty: str
    e_code: int
    e_string: str
    m_code: int
    m_string: str
    category: str


def _as_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if 100 <= number <= 599 else 0


def _valid_check_url(value: str) -> bool:
    if len(value) > 2000:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    host = parsed.hostname.strip("[]").lower()
    if host in {"localhost", "localhost.localdomain"}:
        return False
    # Site definitions are third-party data; refuse loopback and private literals.
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return address.is_global


def _parse_site_list(data: Any) -> list[_Site]:
    if isinstance(data, dict):
        entries = data.get("sites")
    elif isinstance(data, list):
        entries = data
    else:
        return []
    if not isinstance(entries, list):
        return []

    sites: list[_Site] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("valid") is False or entry.get("disabled") is True:
            continue
        name = safe_text(str(entry.get("name", "") or "").strip(), 100)
        uri_check = str(entry.get("uri_check", "") or "").strip()
        if not name or not uri_check:
            continue
        uri_check = uri_check.replace(_LEGACY_TOKEN, _ACCOUNT_TOKEN)
        if _ACCOUNT_TOKEN not in uri_check or not _valid_check_url(uri_check):
            continue
        uri_pretty = str(entry.get("uri_pretty", "") or "").strip()
        uri_pretty = uri_pretty.replace(_LEGACY_TOKEN, _ACCOUNT_TOKEN)
        if _ACCOUNT_TOKEN not in uri_pretty or not _valid_check_url(uri_pretty):
            uri_pretty = uri_check
        e_code = _as_int(entry.get("e_code"))
        e_string = str(entry.get("e_string", "") or "")
        m_code = _as_int(entry.get("m_code"))
        m_string = str(entry.get("m_string", "") or "")
        if not (e_code or e_string):
            continue
        key = uri_check.lower()
        if key in seen:
            continue
        seen.add(key)
        sites.append(
            _Site(
                name=name,
                uri_check=uri_check,
                uri_pretty=uri_pretty,
                e_code=e_code,
                e_string=e_string,
                m_code=m_code,
                m_string=m_string,
                category=safe_text(str(entry.get("cat", "") or ""), 60),
            )
        )
    return sites


async def _load_sites(ctx: "ReconContext") -> list[_Site]:
    path = ctx.settings.whatsmyname_file
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
            sites = _parse_site_list(json.loads(text))
            if sites:
                ctx.logger.info(
                    f"username site list loaded from file: {path} ({len(sites)} sites)"
                )
                return sites
            ctx.logger.warn(f"username site list has no usable entries: {path}")
        except (OSError, UnicodeError, ValueError) as exc:
            ctx.logger.warn(f"could not read username site list {path}: {exc}")

    data, response = await ctx.http.get_json(
        ctx.settings.whatsmyname_url,
        max_bytes=_MAX_LIST_BYTES,
    )
    if response.error is not None:
        ctx.logger.warn(f"username site list download failed: {response.error}")
        return []
    if response.status_code != 200 or data is None:
        ctx.logger.warn(
            f"username site list unavailable (HTTP {response.status_code})"
        )
        return []
    sites = _parse_site_list(data)
    if not sites:
        ctx.logger.warn("username site list returned no usable entries")
    else:
        ctx.logger.info(f"username site list loaded: {len(sites)} sites")
    return sites


def _even_sample(sites: list[_Site], count: int) -> list[_Site]:
    if count <= 0:
        return []
    if count >= len(sites):
        return list(sites)
    if count == 1:
        return [sites[len(sites) // 2]]
    step = (len(sites) - 1) / (count - 1)
    return [sites[round(index * step)] for index in range(count)]


def _select_sites(sites: list[_Site], cap: int) -> list[_Site]:
    usable = [
        site for site in sites if site.category.lower() not in _SKIP_CATEGORIES
    ]
    if not usable:
        usable = sites
    if cap >= len(usable):
        return usable

    social = [
        site for site in usable if site.category.lower() == _SOCIAL_CATEGORY
    ]
    other = [
        site for site in usable if site.category.lower() != _SOCIAL_CATEGORY
    ]
    social_quota = min(len(social), max(1, cap // 2)) if social else 0
    other_quota = min(len(other), cap - social_quota)
    if social_quota + other_quota < cap:
        social_quota = min(len(social), cap - other_quota)
    return _even_sample(social, social_quota) + _even_sample(other, other_quota)


def _classify(site: _Site, response: "HTTPResult") -> str:
    if response.error is not None:
        return "error"
    body = response.text
    code_matches = bool(site.e_code) and response.status_code == site.e_code
    if site.e_string:
        # Upstream WhatsMyName requires the expected body marker and status code.
        present = site.e_string in body and (code_matches or not site.e_code)
    else:
        present = code_matches
    if present:
        return "present"
    if site.m_string and site.m_string in body:
        return "absent"
    if site.m_code and response.status_code == site.m_code:
        return "absent"
    return "unknown"


async def _strict_confirm(
    ctx: "ReconContext", site: _Site, username: str, encoded: str
) -> tuple[str, str]:
    url = site.uri_pretty.replace(_ACCOUNT_TOKEN, encoded)
    response = await ctx.http.get(url, max_bytes=_CHECK_MAX_BYTES)
    if response.error is not None:
        return "error", response.error
    if response.status_code >= 400 or (
        site.e_code and response.status_code != site.e_code
    ):
        return "filtered", f"HTTP {response.status_code}"
    body = response.text or ""
    if looks_blocked(body):
        return "filtered", "block page"
    identity = ctx.osint.target_identity
    values = [username, *identity.usernames, *identity.emails, identity.name or ""]
    if not has_identity_signal(body, values):
        return "filtered", "no identity signal"
    return "confirmed", ""


def _candidate_usernames(ctx: "ReconContext", limit: int) -> list[str]:
    identity = ctx.osint.target_identity
    candidates = [item for item in identity.usernames if item]
    if not candidates and identity.emails:
        candidates = [
            normalize_username(identity.emails[0].split("@", 1)[0])
        ]
    if not candidates:
        parsed = _parse_target(ctx.target)
        candidates = generate_username_variants(
            str(parsed["name"]) or None,
            str(parsed["username"]) or None,
        )
        email = str(parsed["email"])
        if not candidates and email:
            candidates = [normalize_username(email.split("@", 1)[0])]
    unique: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        cleaned = value if _SAFE_USERNAME_RE.match(value) else normalize_username(value)
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
        if len(unique) >= limit:
            break
    return unique


async def run(ctx: "ReconContext") -> None:
    limit = (
        _STEALTH_USERNAME_LIMIT if ctx.settings.stealth else _ACTIVE_USERNAME_LIMIT
    )
    usernames = _candidate_usernames(ctx, limit)
    if not usernames:
        ctx.logger.warn("username enumeration skipped: no usable username")
        return

    sites = await _load_sites(ctx)
    if not sites:
        ctx.logger.warn("username enumeration skipped: no site definitions")
        return
    if ctx.settings.strict:
        marker_sites = [site for site in sites if site.e_string]
        if not marker_sites:
            ctx.logger.warn(
                "username enumeration skipped: no strict sites with body markers"
            )
            return
        if len(marker_sites) < len(sites):
            ctx.logger.info(
                f"strict mode: using {len(marker_sites)} of {len(sites)} "
                "sites with body markers"
            )
        sites = marker_sites

    cap = min(
        int(ctx.settings.max_username_sites),
        _STEALTH_SITE_CAP if ctx.settings.stealth else _ACTIVE_SITE_CAP,
    )
    sites = _select_sites(sites, max(1, cap))
    ctx.logger.info(
        f"username enumeration: {len(usernames)} username(s) against "
        f"{len(sites)} site(s)"
    )

    tasks: list[Any] = []
    for username in usernames:
        encoded = quote(username, safe="")
        for site in sites:
            tasks.append((username, site, encoded))

    concurrency = 2 if ctx.settings.stealth else 6

    async def check(
        username: str, site: _Site, encoded: str
    ) -> tuple[str, _Site, str, str]:
        url = site.uri_check.replace(_ACCOUNT_TOKEN, encoded)
        response = await ctx.http.get(url, max_bytes=_CHECK_MAX_BYTES)
        return username, site, _classify(site, response), encoded

    results = await gather_limited(
        (check(username, site, encoded) for username, site, encoded in tasks),
        limit=concurrency,
    )

    existing = {profile.url for profile in ctx.osint.social_profiles}
    matched = 0
    errors = 0
    filtered = 0
    for username, site, outcome, encoded in results:
        if outcome == "error":
            errors += 1
            continue
        if outcome != "present":
            continue
        url = site.uri_pretty.replace(_ACCOUNT_TOKEN, encoded)
        if url in existing:
            continue
        if ctx.settings.strict:
            state, detail = await _strict_confirm(ctx, site, username, encoded)
            if state == "error":
                errors += 1
                ctx.logger.warn(
                    f"strict verification failed for {site.name} {username}: {detail}"
                )
                continue
            if state != "confirmed":
                filtered += 1
                ctx.osint.strict_filtered += 1
                ctx.logger.info(
                    f"strict match rejected: {site.name} {username} ({detail})"
                )
                continue
        existing.add(url)
        note = "source=WhatsMyName"
        if site.category:
            note += f"; category={site.category}"
        if ctx.settings.strict:
            note += "; strict=confirmed"
        ctx.osint.social_profiles.append(
            SocialProfile(
                platform=site.name,
                url=safe_text(url, 1000),
                bio_or_notes=note,
            )
        )
        matched += 1
        ctx.logger.found(f"username {username} on {site.name}: {url}")

    summary = ctx.osint.username_enum
    summary.source = "WhatsMyName"
    summary.usernames_checked = usernames
    summary.sites_checked += len(sites)
    summary.matches += matched
    summary.errors += errors

    ctx.logger.info(
        f"username enumeration complete: checked={len(sites)} "
        f"matches={matched} errors={errors} filtered={filtered}"
    )
    if errors:
        ctx.logger.warn(
            f"{errors} site check(s) returned network or platform errors"
        )
    if ctx.settings.strict:
        ctx.logger.info(
            f"strict mode: {filtered} candidate match(es) suppressed"
        )
