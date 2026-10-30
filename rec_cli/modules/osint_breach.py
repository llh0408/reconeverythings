"""Passive breach-exposure metadata lookup through official provider APIs.

Only breach names, dates, and data-class metadata are recorded. Leaked
records, passwords, and hashes returned by providers are never stored,
logged, or displayed.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules.osint_identity import _parse_target, generate_username_variants
from rec_cli.schema import BreachFinding
from rec_cli.utils.logger import safe_text
from rec_cli.utils.runner import dedupe

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")
_HIBP_DELAY = 1.6
_LEAKCHECK_DELAY = 1.0
_MAX_ERRORS = 10


def _clean_list(values: Any, limit: int = 30) -> list[str]:
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values[:limit]:
        text = safe_text(str(value or ""), 80).strip()
        if text and text not in output:
            output.append(text)
    return output


def _as_count(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def _hibp_findings(identifier: str, data: Any) -> list[BreachFinding]:
    if not isinstance(data, list):
        return []
    findings: list[BreachFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = safe_text(str(item.get("Name", "") or ""), 200).strip()
        if not name:
            continue
        findings.append(
            BreachFinding(
                identifier=identifier,
                provider="HIBP",
                breach=name,
                title=safe_text(str(item.get("Title", "") or ""), 300),
                domain=safe_text(str(item.get("Domain", "") or ""), 200),
                breach_date=safe_text(
                    str(item.get("BreachDate", "") or ""), 20
                ),
                data_classes=_clean_list(item.get("DataClasses")),
                pwn_count=_as_count(item.get("PwnCount")),
                verified=bool(item.get("IsVerified", False)),
                sensitive=bool(item.get("IsSensitive", False)),
            )
        )
    return findings


async def _hibp(
    ctx: "ReconContext", email: str
) -> tuple[list[BreachFinding], str, bool]:
    key = ctx.settings.hibp_api_key or ""
    if not key:
        return [], "no API key", True
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['hibp']}/{quote(email, safe='')}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": key},
        max_bytes=2_000_000,
    )
    if response.status_code == 404:
        return [], "", False
    if response.status_code == 401:
        return [], "invalid API key", True
    if response.status_code == 429:
        return [], "rate limit reached", True
    if response.status_code >= 400 or response.error is not None:
        detail = response.error or f"HTTP {response.status_code}"
        return [], safe_text(detail, 200), False
    return _hibp_findings(email, data), "", False


def _leakcheck_findings(identifier: str, data: Any) -> list[BreachFinding]:
    if not isinstance(data, dict):
        return []
    # Only source metadata is read. The record payload is ignored by design.
    fields = _clean_list(data.get("fields"))
    sources = data.get("sources")
    if not isinstance(sources, list):
        return []
    findings: list[BreachFinding] = []
    seen: set[str] = set()
    for source in sources[:100]:
        if isinstance(source, dict):
            name = str(
                source.get("name")
                or source.get("breach")
                or source.get("source")
                or ""
            ).strip()
            date = str(
                source.get("date") or source.get("breach_date") or ""
            ).strip()
        elif isinstance(source, str):
            name = source.strip()
            date = ""
        else:
            continue
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            BreachFinding(
                identifier=identifier,
                provider="LeakCheck",
                breach=safe_text(name, 200),
                title=safe_text(name, 300),
                breach_date=safe_text(date, 20),
                data_classes=list(fields),
            )
        )
    return findings


async def _leakcheck(
    ctx: "ReconContext", identifier: str
) -> tuple[list[BreachFinding], str, bool]:
    key = ctx.settings.leakcheck_api_key or ""
    if not key:
        return [], "no API key", True
    query_type = "email" if "@" in identifier else "username"
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['leakcheck']}/{quote(identifier, safe='')}",
        params={"type": query_type},
        headers={"X-API-Key": key},
        max_bytes=2_000_000,
    )
    if response.status_code == 404:
        return [], "", False
    if response.status_code in (401, 403):
        return [], "invalid API key", True
    if response.status_code == 429:
        return [], "rate limit reached", True
    if response.status_code >= 400 or response.error is not None:
        detail = response.error or f"HTTP {response.status_code}"
        return [], safe_text(detail, 200), False
    if isinstance(data, dict) and data.get("success") is False:
        message = safe_text(str(data.get("error", "") or "lookup failed"), 200)
        return [], message, False
    return _leakcheck_findings(identifier, data), "", False


def _identifiers(ctx: "ReconContext") -> tuple[list[str], list[str]]:
    identity = ctx.osint.target_identity
    emails = [
        email.lower()
        for email in identity.emails
        if email and _EMAIL_RE.fullmatch(email.strip())
    ]
    usernames = [
        username.lower()
        for username in identity.usernames
        if username and _USERNAME_RE.fullmatch(username.strip())
    ]
    if not emails and not usernames:
        parsed = _parse_target(ctx.target)
        email = str(parsed["email"]).strip().lower()
        username = str(parsed["username"]).strip().lower()
        name = str(parsed["name"]).strip()
        if email:
            emails = [email]
        elif _USERNAME_RE.fullmatch(username):
            usernames = [username]
        elif name:
            usernames = [
                item
                for item in generate_username_variants(name, None)
                if _USERNAME_RE.fullmatch(item)
            ][:1]
    return (
        dedupe(emails, max(1, int(ctx.settings.max_breach_emails))),
        dedupe(usernames, max(1, int(ctx.settings.max_breach_usernames))),
    )


def _record(
    ctx: "ReconContext",
    findings: list[BreachFinding],
    seen: set[tuple[str, str, str]],
) -> int:
    added = 0
    cap = max(1, int(ctx.settings.max_breach_findings))
    for finding in findings:
        if len(ctx.osint.breach.findings) >= cap:
            break
        key = (
            finding.identifier.lower(),
            finding.provider.lower(),
            finding.breach.lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        ctx.osint.breach.findings.append(finding)
        added += 1
        date = f" ({finding.breach_date})" if finding.breach_date else ""
        ctx.logger.found(
            f"breach {finding.identifier} {finding.provider} "
            f"{finding.breach}{date}"
        )
    return added


async def run(ctx: "ReconContext") -> None:
    summary = ctx.osint.breach
    emails, usernames = _identifiers(ctx)
    summary.identifiers_checked = dedupe(emails + usernames)

    if not ctx.settings.hibp_api_key:
        summary.providers_skipped.append("HIBP")
    if not ctx.settings.leakcheck_api_key:
        summary.providers_skipped.append("LeakCheck")
    if summary.providers_skipped:
        ctx.logger.info(
            "breach providers skipped: "
            + ", ".join(summary.providers_skipped)
            + " (set HIBP_API_KEY or LEAKCHECK_API_KEY to enable)"
        )
    if not ctx.settings.hibp_api_key and not ctx.settings.leakcheck_api_key:
        ctx.logger.warn(
            "breach lookup skipped: no breach provider API key configured"
        )
        return
    if not emails and not usernames:
        ctx.logger.warn("breach lookup skipped: no usable email or username")
        return

    seen: set[tuple[str, str, str]] = set()

    if ctx.settings.hibp_api_key and emails:
        summary.providers_used.append("HIBP")
        for index, email in enumerate(emails):
            if index:
                await asyncio.sleep(_HIBP_DELAY)
            findings, error, fatal = await _hibp(ctx, email)
            if error:
                message = f"HIBP: {error}"
                if len(summary.provider_errors) < _MAX_ERRORS:
                    summary.provider_errors.append(message)
                ctx.logger.warn(message)
                if fatal:
                    break
                continue
            _record(ctx, findings, seen)

    if ctx.settings.leakcheck_api_key:
        summary.providers_used.append("LeakCheck")
        queries = [(email, "email") for email in emails]
        queries.extend((username, "username") for username in usernames)
        for index, (identifier, _kind) in enumerate(queries):
            if index:
                await asyncio.sleep(_LEAKCHECK_DELAY)
            findings, error, fatal = await _leakcheck(ctx, identifier)
            if error:
                message = f"LeakCheck: {error}"
                if len(summary.provider_errors) < _MAX_ERRORS:
                    summary.provider_errors.append(message)
                ctx.logger.warn(message)
                if fatal:
                    break
                continue
            _record(ctx, findings, seen)

    ctx.logger.info(
        f"breach lookup complete: identifiers={len(summary.identifiers_checked)} "
        f"providers={','.join(summary.providers_used) or 'none'} "
        f"findings={len(summary.findings)}"
    )
