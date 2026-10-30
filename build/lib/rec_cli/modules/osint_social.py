"""Public profile checks and social/technical search helpers."""

from __future__ import annotations

import html
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules import is_domain_like
from rec_cli.schema import SocialProfile
from rec_cli.utils.logger import safe_text
from rec_cli.utils.runner import dedupe, gather_limited

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext
    from rec_cli.config import Settings
    from rec_cli.utils.logger import Logger
    from rec_cli.utils.runner import StealthHTTPClient

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TAG_RE = re.compile(r"<[^>]+>")
_RESULT_LINK_RE = re.compile(
    r"<a[^>]+class=\"[^\"]*result__a[^\"]*\"[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_RESULT_SNIPPET_RE = re.compile(
    r"<a[^>]+class=\"[^\"]*result__snippet[^\"]*\"[^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_META_DESCRIPTION_RE = re.compile(
    r"<meta[^>]+name=[\"']description[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _strip_html(value: str) -> str:
    return safe_text(html.unescape(_TAG_RE.sub(" ", value)), 500)


def _decode_ddg_url(value: str) -> str:
    if value.startswith("//"):
        value = "https:" + value
    try:
        parsed = urlparse(value)
    except ValueError:
        return value
    if "duckduckgo.com" in (parsed.hostname or "") and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg")
        if target:
            return unquote(target[0])
    return value


def _normalize_result(
    platform: str, title: str, url: str, snippet: str
) -> dict[str, str]:
    return {
        "platform": platform,
        "title": safe_text(title, 300),
        "url": safe_text(url, 1000),
        "snippet": safe_text(snippet, 500),
    }


async def _google_cse(
    http: "StealthHTTPClient",
    settings: "Settings",
    query: str,
    limit: int,
) -> list[dict[str, str]]:
    if not settings.google_api_key or not settings.google_cse_id:
        return []
    data, response = await http.get_json(
        API_ENDPOINTS["google_cse"],
        params={
            "key": settings.google_api_key,
            "cx": settings.google_cse_id,
            "q": query,
            "num": min(limit, 10),
        },
        max_bytes=2_000_000,
    )
    if response.error or not isinstance(data, dict):
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []
    results = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        results.append(
            _normalize_result(
                "web",
                str(item.get("title", "")),
                str(item.get("link", "")),
                str(item.get("snippet", "")),
            )
        )
    return results


async def _duckduckgo(
    http: "StealthHTTPClient", query: str, limit: int
) -> list[dict[str, str]]:
    response = await http.get(
        API_ENDPOINTS["duckduckgo_html"],
        params={"q": query},
        max_bytes=3_000_000,
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    if response.error or response.status_code >= 400:
        return []
    links = _RESULT_LINK_RE.findall(response.text)
    snippets = _RESULT_SNIPPET_RE.findall(response.text)
    results: list[dict[str, str]] = []
    for index, (url, title) in enumerate(links[:limit]):
        snippet = snippets[index] if index < len(snippets) else ""
        results.append(
            _normalize_result(
                "web",
                _strip_html(title),
                _decode_ddg_url(html.unescape(url)),
                _strip_html(snippet),
            )
        )
    return results


async def _bing_rss(
    http: "StealthHTTPClient", query: str, limit: int
) -> list[dict[str, str]]:
    response = await http.get(
        "https://www.bing.com/search",
        params={"q": query, "format": "rss"},
        max_bytes=3_000_000,
        headers={"Accept": "application/rss+xml,text/xml"},
    )
    if response.error or response.status_code >= 400:
        return []
    results: list[dict[str, str]] = []
    for block in re.findall(r"<item>(.*?)</item>", response.text, re.DOTALL)[:limit]:
        title_match = re.search(r"<title>(.*?)</title>", block, re.DOTALL)
        link_match = re.search(r"<link>(.*?)</link>", block, re.DOTALL)
        description_match = re.search(
            r"<description>(.*?)</description>", block, re.DOTALL
        )
        if not title_match or not link_match:
            continue
        results.append(
            _normalize_result(
                "web",
                _strip_html(title_match.group(1)),
                html.unescape(link_match.group(1).strip()),
                _strip_html(
                    description_match.group(1) if description_match else ""
                ),
            )
        )
    return results


async def web_search(
    http: "StealthHTTPClient",
    logger: "Logger",
    settings: "Settings",
    query: str,
    limit: int = 5,
) -> list[dict[str, str]]:
    """Search via Google CSE when configured, then DuckDuckGo, then Bing RSS."""
    results = await _google_cse(http, settings, query, limit)
    if not results:
        results = await _duckduckgo(http, query, limit)
    if not results:
        results = await _bing_rss(http, query, limit)
    output: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in results:
        url = item["url"]
        if not url or url in seen:
            continue
        seen.add(url)
        output.append(item)
        if len(output) >= limit:
            break
    if not output:
        logger.info(f"web search returned no results for query: {query}")
    return output


async def _github_user(
    ctx: "ReconContext", username: str
) -> SocialProfile | None:
    headers = {"Accept": "application/vnd.github+json"}
    if ctx.settings.github_token:
        headers["Authorization"] = f"Bearer {ctx.settings.github_token}"
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['github_api']}/users/{quote_plus(username)}",
        headers=headers,
        max_bytes=1_000_000,
    )
    if response.status_code == 404:
        return None
    if response.status_code == 403:
        ctx.logger.warn("GitHub API rate limit reached")
        return None
    if response.error or not isinstance(data, dict):
        return None
    notes = []
    for label, key in (
        ("name", "name"),
        ("company", "company"),
        ("blog", "blog"),
        ("location", "location"),
        ("bio", "bio"),
        ("public_repos", "public_repos"),
    ):
        value = data.get(key)
        if value not in (None, "", 0):
            notes.append(f"{label}={value}")
    return SocialProfile(
        platform="GitHub",
        url=str(data.get("html_url", f"https://github.com/{username}")),
        bio_or_notes=safe_text("; ".join(notes), 700),
    )


async def _gitlab_user(
    ctx: "ReconContext", username: str
) -> SocialProfile | None:
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['gitlab_api']}/users",
        params={"username": username},
        max_bytes=1_000_000,
    )
    if response.error or not isinstance(data, list) or not data:
        return None
    for item in data:
        if not isinstance(item, dict):
            continue
        if str(item.get("username", "")).lower() != username.lower():
            continue
        notes = [
            f"{label}={item[key]}"
            for label, key in (
                ("name", "name"),
                ("state", "state"),
                ("organization", "organization"),
                ("bio", "bio"),
                ("location", "location"),
            )
            if item.get(key)
        ]
        return SocialProfile(
            platform="GitLab",
            url=str(item.get("web_url", f"https://gitlab.com/{username}")),
            bio_or_notes=safe_text("; ".join(notes), 700),
        )
    return None


async def _reddit_user(
    ctx: "ReconContext", username: str
) -> SocialProfile | None:
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['reddit_api']}/user/{quote_plus(username)}/about.json",
        max_bytes=1_000_000,
        headers={"Accept": "application/json"},
    )
    if response.status_code in (403, 404) or response.error:
        return None
    if not isinstance(data, dict):
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    notes = [
        f"{label}={payload[key]}"
        for label, key in (
            ("name", "name"),
            ("link_karma", "link_karma"),
            ("comment_karma", "comment_karma"),
        )
        if payload.get(key) is not None
    ]
    description = payload.get("public_description")
    if description:
        notes.append(f"bio={description}")
    return SocialProfile(
        platform="Reddit",
        url=f"https://www.reddit.com/user/{username}/",
        bio_or_notes=safe_text("; ".join(notes), 700),
    )


async def _medium_user(
    ctx: "ReconContext", username: str
) -> SocialProfile | None:
    response = await ctx.http.get(
        f"https://medium.com/@{quote_plus(username)}",
        max_bytes=1_500_000,
        headers={"Accept": "text/html"},
    )
    if response.error or response.status_code >= 400:
        return None
    lowered = response.text.lower()
    if "page not found" in lowered[:100_000] or "404" in response.url:
        return None
    match = _META_DESCRIPTION_RE.search(response.text)
    notes = _strip_html(match.group(1)) if match else "public profile returned HTTP 200"
    return SocialProfile(
        platform="Medium",
        url=f"https://medium.com/@{username}",
        bio_or_notes=notes,
    )


async def _linkedin_user(
    ctx: "ReconContext", username: str
) -> SocialProfile | None:
    response = await ctx.http.get(
        f"https://www.linkedin.com/in/{quote_plus(username)}",
        max_bytes=1_000_000,
        headers={"Accept": "text/html"},
    )
    if response.error:
        return None
    if response.status_code == 999:
        return SocialProfile(
            platform="LinkedIn",
            url=f"https://www.linkedin.com/in/{username}",
            bio_or_notes=(
                "HTTP 999: automated verification blocked; manual review required"
            ),
        )
    if response.status_code != 200:
        return None
    if "page not found" in response.text.lower()[:100_000]:
        return None
    return SocialProfile(
        platform="LinkedIn",
        url=f"https://www.linkedin.com/in/{username}",
        bio_or_notes="public profile returned HTTP 200; content requires manual review",
    )


async def _stackoverflow_user(
    ctx: "ReconContext", query: str
) -> list[SocialProfile]:
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['stackexchange_api']}/users",
        params={
            "inname": query,
            "site": "stackoverflow",
            "pagesize": "3",
            "order": "desc",
            "sort": "reputation",
        },
        max_bytes=1_500_000,
    )
    if response.error or not isinstance(data, dict):
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []
    results: list[SocialProfile] = []
    for item in items[:3]:
        if not isinstance(item, dict) or not item.get("link"):
            continue
        notes = [
            f"{label}={item[key]}"
            for label, key in (
                ("display_name", "display_name"),
                ("reputation", "reputation"),
                ("answer_count", "answer_count"),
            )
            if item.get(key) is not None
        ]
        results.append(
            SocialProfile(
                platform="Stack Overflow",
                url=str(item["link"]),
                bio_or_notes=safe_text("; ".join(notes), 500),
            )
        )
    return results


def _collect_identity_signals(ctx: "ReconContext", profile: SocialProfile) -> None:
    text = f"{profile.bio_or_notes} {profile.url}"
    for email in _EMAIL_RE.findall(text):
        lowered = email.lower()
        if lowered not in ctx.osint.target_identity.emails:
            ctx.osint.target_identity.emails.append(lowered)
    for url in _URL_RE.findall(text):
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if not host or host in {
            "github.com", "gitlab.com", "linkedin.com", "www.linkedin.com",
            "medium.com", "reddit.com", "www.reddit.com", "stackoverflow.com",
            "x.com", "twitter.com",
        }:
            continue
        if is_domain_like(host):
            ctx.osint_to_infra_candidates.append(
                (
                    f"social:{profile.platform}",
                    host,
                    "external domain referenced in a public profile",
                )
            )


async def check_profiles(ctx: "ReconContext") -> None:
    identity = ctx.osint.target_identity
    usernames = identity.usernames[: 2 if ctx.settings.stealth else 3]
    profiles: list[SocialProfile] = []
    if not usernames and identity.emails:
        usernames = [identity.emails[0].split("@", 1)[0]]

    tasks = []
    for username in usernames:
        tasks.extend(
            [
                _github_user(ctx, username),
                _gitlab_user(ctx, username),
                _reddit_user(ctx, username),
                _medium_user(ctx, username),
                _linkedin_user(ctx, username),
            ]
        )
    if identity.name:
        profiles.extend(await _stackoverflow_user(ctx, identity.name))
    elif usernames:
        profiles.extend(await _stackoverflow_user(ctx, usernames[0]))

    if tasks:
        results = await gather_limited(tasks, limit=3 if ctx.settings.stealth else 5)
        for profile in results:
            if isinstance(profile, SocialProfile):
                profiles.append(profile)

    existing = {profile.url for profile in ctx.osint.social_profiles}
    for profile in profiles:
        if profile.url in existing:
            continue
        ctx.osint.social_profiles.append(profile)
        existing.add(profile.url)
        ctx.logger.found(
            f"{profile.platform} profile: {profile.url} ({profile.bio_or_notes[:160]})"
        )
        _collect_identity_signals(ctx, profile)

    if not profiles:
        ctx.logger.info("no public profiles verified for the supplied identifiers")


async def _github_search(
    http: "StealthHTTPClient",
    settings: "Settings",
    query: str,
    target_type: str,
    limit: int,
) -> list[dict[str, str]]:
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    if target_type == "person":
        data, response = await http.get_json(
            f"{API_ENDPOINTS['github_api']}/search/users",
            params={"q": query, "per_page": str(limit)},
            headers=headers,
            max_bytes=1_500_000,
        )
        if response.error or not isinstance(data, dict):
            return []
        results = []
        for item in data.get("items", [])[:limit]:
            if not isinstance(item, dict):
                continue
            results.append(
                _normalize_result(
                    "github",
                    f"GitHub user: {item.get('login', '')}",
                    str(item.get("html_url", "")),
                    "profile match from GitHub user search",
                )
            )
        return results

    data, response = await http.get_json(
        f"{API_ENDPOINTS['github_api']}/search/repositories",
        params={
            "q": f"{query} in:name,description,readme",
            "per_page": str(limit),
        },
        headers=headers,
        max_bytes=2_000_000,
    )
    if response.error or not isinstance(data, dict):
        return []
    results = []
    for item in data.get("items", [])[:limit]:
        if not isinstance(item, dict):
            continue
        description = str(item.get("description") or "")
        language = str(item.get("language") or "")
        results.append(
            _normalize_result(
                "github",
                f"GitHub repository: {item.get('full_name', '')}",
                str(item.get("html_url", "")),
                f"{description} language={language}".strip(),
            )
        )
    return results


async def _stackoverflow_search(
    http: "StealthHTTPClient", query: str, target_type: str, limit: int
) -> list[dict[str, str]]:
    if target_type == "person":
        data, response = await http.get_json(
            f"{API_ENDPOINTS['stackexchange_api']}/users",
            params={
                "inname": query,
                "site": "stackoverflow",
                "pagesize": str(limit),
                "order": "desc",
                "sort": "reputation",
            },
            max_bytes=1_500_000,
        )
        if response.error or not isinstance(data, dict):
            return []
        results = []
        for item in data.get("items", [])[:limit]:
            if not isinstance(item, dict):
                continue
            results.append(
                _normalize_result(
                    "stackoverflow",
                    f"Stack Overflow user: {item.get('display_name', '')}",
                    str(item.get("link", "")),
                    f"reputation={item.get('reputation', 'unknown')}",
                )
            )
        return results

    data, response = await http.get_json(
        f"{API_ENDPOINTS['stackexchange_api']}/search/advanced",
        params={
            "q": query,
            "site": "stackoverflow",
            "pagesize": str(limit),
            "order": "desc",
            "sort": "relevance",
        },
        max_bytes=2_000_000,
    )
    if response.error or not isinstance(data, dict):
        return []
    results = []
    for item in data.get("items", [])[:limit]:
        if not isinstance(item, dict):
            continue
        tags = ",".join(str(tag) for tag in item.get("tags", [])[:6])
        results.append(
            _normalize_result(
                "stackoverflow",
                str(item.get("title", "")),
                str(item.get("link", "")),
                f"tags={tags}",
            )
        )
    return results


async def _reddit_search(
    http: "StealthHTTPClient", query: str, limit: int
) -> list[dict[str, str]]:
    data, response = await http.get_json(
        f"{API_ENDPOINTS['reddit_api']}/search.json",
        params={"q": query, "limit": str(limit), "sort": "relevance", "raw_json": "1"},
        max_bytes=2_000_000,
        headers={"Accept": "application/json"},
    )
    if response.error or not isinstance(data, dict):
        return []
    payload = data.get("data")
    if not isinstance(payload, dict):
        return []
    results = []
    for child in payload.get("children", [])[:limit]:
        item = child.get("data") if isinstance(child, dict) else None
        if not isinstance(item, dict):
            continue
        permalink = str(item.get("permalink", ""))
        results.append(
            _normalize_result(
                "reddit",
                str(item.get("title", "")),
                f"https://www.reddit.com{permalink}" if permalink else "",
                str(item.get("subreddit_name_prefixed", "")),
            )
        )
    return [item for item in results if item["url"]]


async def social_search(
    http: "StealthHTTPClient",
    logger: "Logger",
    settings: "Settings",
    query: str,
    platform: str = "all",
    target_type: str = "person",
) -> dict[str, Any]:
    """Run targeted profile, repository, discussion, and web dork searches."""
    requested = platform.strip().lower() or "all"
    allowed = {"all", "github", "linkedin", "stackoverflow", "reddit", "x", "web"}
    if requested not in allowed:
        raise ValueError(f"unsupported platform: {platform}")

    results: list[dict[str, str]] = []
    platforms = (
        ["github", "stackoverflow", "reddit", "linkedin", "x", "web"]
        if requested == "all"
        else [requested]
    )

    for current in platforms:
        if current == "github":
            results.extend(
                await _github_search(http, settings, query, target_type, 5)
            )
        elif current == "stackoverflow":
            results.extend(
                await _stackoverflow_search(http, query, target_type, 5)
            )
        elif current == "reddit":
            results.extend(await _reddit_search(http, query, 5))
        elif current in ("linkedin", "x"):
            sites = {
                "linkedin": "site:linkedin.com/in",
                "x": "site:x.com OR site:twitter.com",
            }[current]
            found = await web_search(
                http,
                logger,
                settings,
                f'{sites} "{query}"',
                limit=5,
            )
            for item in found:
                item["platform"] = current
            results.extend(found)
        else:
            dork = query
            if target_type == "technology":
                dork = f'"{query}" (error OR stacktrace OR misconfiguration)'
            results.extend(
                await web_search(http, logger, settings, dork, limit=5)
            )

    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in results:
        url = item.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(item)
    return {
        "query": query,
        "platform": requested,
        "target_type": target_type,
        "result_count": len(deduped[:50]),
        "results": deduped[:50],
    }


async def run(ctx: "ReconContext") -> None:
    await check_profiles(ctx)
