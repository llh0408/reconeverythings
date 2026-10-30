"""URL discovery and JavaScript endpoint, author, and secret analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable
from urllib.parse import urljoin, urlparse

from rec_cli.modules import (
    ensure_host,
    extract_host,
    is_domain_like,
    registrable_domain,
    target_domain,
)
from rec_cli.schema import JSFindings, SecretFinding
from rec_cli.utils.runner import binary_available, dedupe, gather_limited, run_command

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{4,500}")
_QUOTED_PATH_RE = re.compile(
    r"[\"'`]((?:/(?:api|graphql|rest|internal|admin|auth|oauth|upload|debug|v[0-9]+)"
    r"(?:/[^\"'`\s\\]*)?)|(?:https?://[^\"'`\s\\]+))[\"'`]",
    re.IGNORECASE,
)
_COMMENT_RE = re.compile(
    r"//[^\n]{0,500}|/\*[\s\S]{0,1500}?\*/",
)
_AUTHOR_RE = re.compile(
    r"(?i)(?:@author|author|developer|maintainer|created by|owner)\s*[:\-]\s*"
    r"([A-Za-z][A-Za-z0-9 ._'\-]{2,60})"
)
_HTML_LINK_RE = re.compile(
    r"(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)</script>", re.IGNORECASE
)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]+)\s*</loc>", re.IGNORECASE)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
    ),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    (
        "GitHub Token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,200}\b"),
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
    ),
    (
        "SendGrid API Key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    (
        "Private Key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
    ),
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|"
            r"auth[_-]?token|password|passwd|secret)\b\s*[:=]\s*"
            r"[\"']([^\"'\n]{8,120})[\"']"
        ),
    ),
)

_PLACEHOLDER_MARKERS = (
    "example",
    "your_",
    "your-",
    "changeme",
    "placeholder",
    "dummy",
    "redacted",
    "xxxx",
    "process.env",
    "import.meta.env",
    "${",
    "{{",
    "undefined",
    "null",
)
_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".pdf",
)


@dataclass(slots=True)
class JSAnalysis:
    js_url: str
    endpoints: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    internal_domains: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    error: str | None = None
    status_code: int = 0

    def to_js_findings(self) -> JSFindings:
        return JSFindings(
            js_urls=[self.js_url] if self.js_url else [],
            extracted_endpoints=self.endpoints,
            discovered_emails_or_authors=dedupe(self.emails + self.authors),
            potential_secrets=self.secrets,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "js_url": self.js_url,
            "status_code": self.status_code,
            "error": self.error,
            "endpoints": self.endpoints,
            "internal_domains": self.internal_domains,
            "emails": self.emails,
            "authors": self.authors,
            "comments": self.comments,
            "potential_secrets": [
                {
                    "type": secret.type,
                    "match": secret.match,
                    "source_url": secret.source_url,
                }
                for secret in self.secrets
            ],
        }


def _looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _scope_root(value: str) -> str:
    domain = target_domain(value)
    if not domain:
        return extract_host(value)
    return registrable_domain(domain)


def _is_in_scope(host: str, scope_root: str) -> bool:
    host = host.lower().rstrip(".")
    root = scope_root.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def _extract_internal_domains(
    urls: Iterable[str], scope_root: str
) -> list[str]:
    domains: list[str] = []
    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if _is_in_scope(host, scope_root) or any(
            marker in host for marker in ("internal", "corp", "intranet", "admin")
        ):
            if host not in domains:
                domains.append(host)
    return domains[:100]


def _extract_secrets(text: str, source_url: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if label == "Generic Secret Assignment":
                candidate = match.group(1) if match.lastindex else value
                if _looks_placeholder(candidate):
                    continue
                rendered = value.strip()
            else:
                rendered = value.strip()
            if _looks_placeholder(rendered):
                continue
            key = (label, rendered)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                SecretFinding(
                    type=label,
                    match=rendered[:240],
                    source_url=source_url,
                )
            )
            if len(findings) >= 50:
                return findings
    return findings


def _extract_comments(text: str) -> list[str]:
    comments = [
        " ".join(match.group(0).split())[:500]
        for match in _COMMENT_RE.finditer(text)
        if match.group(0).strip()
    ]
    return dedupe(comments, 40)


def analyze_javascript(
    text: str, source_url: str, *, include_comments: bool = True
) -> JSAnalysis:
    """Analyze JavaScript source for endpoints, identities, and secrets."""
    scope_root = _scope_root(source_url)
    path_matches = [
        match.group(1)
        for match in _QUOTED_PATH_RE.finditer(text)
        if match.group(1)
    ]
    absolute_urls = _ABS_URL_RE.findall(text)
    endpoint_candidates = path_matches + absolute_urls
    endpoints = dedupe(endpoint_candidates, 500)

    emails = dedupe(_EMAIL_RE.findall(text), 100)
    comments = _extract_comments(text) if include_comments else []
    authors: list[str] = []
    for comment in comments:
        for match in _AUTHOR_RE.finditer(comment):
            author = " ".join(match.group(1).split()).strip(" .,;:-")
            if author and not _looks_placeholder(author):
                authors.append(author)
    for email in emails:
        local = email.split("@", 1)[0].replace(".", " ").replace("_", " ")
        if 2 <= len(local) <= 50:
            authors.append(local.title())

    return JSAnalysis(
        js_url=source_url,
        endpoints=endpoints,
        emails=emails,
        authors=dedupe(authors, 50),
        secrets=_extract_secrets(text, source_url),
        internal_domains=_extract_internal_domains(endpoint_candidates, scope_root),
        comments=comments,
    )


def _merge_js_findings(target: JSFindings, analysis: JSAnalysis) -> None:
    target.js_urls = dedupe(target.js_urls + analysis.to_js_findings().js_urls, 300)
    target.extracted_endpoints = dedupe(
        target.extracted_endpoints + analysis.endpoints, 600
    )
    identities = analysis.emails + analysis.authors
    target.discovered_emails_or_authors = dedupe(
        target.discovered_emails_or_authors + identities, 200
    )
    existing = {(item.type, item.match) for item in target.potential_secrets}
    for secret in analysis.secrets:
        key = (secret.type, secret.match)
        if key not in existing:
            target.potential_secrets.append(secret)
            existing.add(key)
    target.potential_secrets = target.potential_secrets[:100]


def _is_js_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    path = parsed.path.lower()
    return path.endswith((".js", ".mjs", ".cjs")) or ".js?" in url.lower()


def _is_crawlable(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    path = parsed.path.lower()
    if path.endswith(_ASSET_EXTENSIONS):
        return False
    return not _is_js_url(url)


async def _gau(ctx: "ReconContext", domain: str) -> list[str]:
    binary = ctx.settings.gau_binary
    if not binary_available(binary):
        return []
    result = await run_command(
        [
            binary,
            "--subs",
            domain,
            "--threads",
            "1" if ctx.settings.stealth else "3",
            "--timeout",
            "20",
        ],
        timeout=120,
    )
    if not result.ok and not result.stdout.strip():
        ctx.logger.warn(f"gau failed: {result.stderr.strip()[:200]}")
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


async def _katana(ctx: "ReconContext", base_urls: list[str]) -> list[str]:
    if ctx.settings.stealth:
        return []
    binary = ctx.settings.katana_binary
    if not binary_available(binary):
        return []
    results: list[str] = []
    for base in base_urls[:3]:
        result = await run_command(
            [
                binary,
                "-u",
                base,
                "-silent",
                "-jc",
                "-d",
                "2",
                "-rl",
                str(ctx.settings.subprocess_rate_limit),
                "-timeout",
                str(int(ctx.settings.request_timeout)),
            ],
            timeout=90,
        )
        if result.ok or result.stdout.strip():
            results.extend(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        else:
            ctx.logger.warn(f"katana failed for {base}: {result.stderr.strip()[:200]}")
            break
    return results


def _script_urls_from_html(html_text: str, page_url: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(
        r"<script[^>]+src=[\"']([^\"']+)[\"']", html_text, re.IGNORECASE
    ):
        urls.append(urljoin(page_url, match.group(1)))
    for value in _HTML_LINK_RE.findall(html_text):
        joined = urljoin(page_url, value)
        if _is_js_url(joined):
            urls.append(joined)
    return dedupe(urls, 100)


def _inline_scripts(html_text: str) -> list[str]:
    return [
        match.group(1)
        for match in _INLINE_SCRIPT_RE.finditer(html_text)
        if match.group(1).strip()
    ]


async def _fetch_sitemap(ctx: "ReconContext", base: str) -> tuple[list[str], list[str]]:
    pages: list[str] = []
    scripts: list[str] = []
    sitemap = await ctx.http.get(
        urljoin(base, "/sitemap.xml"), max_bytes=2_000_000
    )
    if not sitemap.error and sitemap.status_code == 200:
        pages.extend(_SITEMAP_LOC_RE.findall(sitemap.text))
    robots = await ctx.http.get(urljoin(base, "/robots.txt"), max_bytes=200_000)
    if not robots.error and robots.status_code == 200:
        for line in robots.text.splitlines():
            if line.lower().startswith(("sitemap:", "disallow:", "allow:")):
                value = line.split(":", 1)[1].strip()
                if value.startswith("http"):
                    pages.append(value)
    return dedupe(pages, 200), scripts


async def _custom_crawl(
    ctx: "ReconContext", base_urls: list[str], scope_root: str
) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    pages_seen: set[str] = set()
    queue: list[str] = []
    discovered_pages: list[str] = []
    discovered_js: list[str] = []
    inline_analyses: list[tuple[str, str]] = []

    for base in base_urls[:3]:
        sitemap_pages, _ = await _fetch_sitemap(ctx, base)
        for url in sitemap_pages:
            if _is_js_url(url):
                discovered_js.append(url)
            elif _is_crawlable(url):
                queue.append(url)
        queue.insert(0, base)

    page_limit = 4 if ctx.settings.stealth else ctx.settings.max_crawl_pages
    while queue and len(pages_seen) < page_limit:
        url = queue.pop(0)
        if url in pages_seen:
            continue
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if not _is_in_scope(host, scope_root):
            continue
        pages_seen.add(url)
        discovered_pages.append(url)

        response = await ctx.http.get(url, max_bytes=ctx.settings.max_response_bytes)
        if response.error or response.status_code >= 400:
            continue
        if "html" not in response.header("content-type", "text/html").lower():
            continue
        discovered_js.extend(_script_urls_from_html(response.text, response.url))
        for index, script in enumerate(_inline_scripts(response.text)):
            inline_analyses.append((f"{response.url}#inline-{index + 1}", script))
        for link in _HTML_LINK_RE.findall(response.text):
            joined = urljoin(response.url, link)
            if _is_js_url(joined):
                discovered_js.append(joined)
            elif _is_crawlable(joined) and joined not in pages_seen:
                try:
                    link_host = (urlparse(joined).hostname or "").lower()
                except ValueError:
                    continue
                if _is_in_scope(link_host, scope_root):
                    queue.append(joined)

    return dedupe(discovered_pages, 200), dedupe(discovered_js, 400), inline_analyses


def _base_urls(ctx: "ReconContext") -> list[str]:
    urls: list[str] = []
    for record in ctx.infra.hosts:
        if record.http_info.url:
            urls.append(record.http_info.url)
            continue
        if not record.ip:
            continue
        hostname = record.hostname
        display = f"[{hostname}]" if ":" in hostname else hostname
        ports = record.open_ports
        if 443 in ports or 8443 in ports:
            urls.append(f"https://{display}/")
        elif 80 in ports or 8080 in ports:
            urls.append(f"http://{display}/")
        else:
            urls.append(f"https://{display}/")
            urls.append(f"http://{display}/")
    if not urls:
        host = target_domain(ctx.target) or extract_host(ctx.target)
        if host:
            display = f"[{host}]" if ":" in host else host
            urls.append(f"https://{display}/")
    return dedupe(urls, 20)


def _find_host_record(ctx: "ReconContext", url: str) -> object | None:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return None
    record = ctx.host_index.get(host)
    if record:
        return record
    if ctx.infra.hosts:
        return ctx.infra.hosts[0]
    return None


async def _analyze_js_url(
    ctx: "ReconContext", url: str
) -> tuple[JSAnalysis | None, bool]:
    response = await ctx.http.get(url, max_bytes=ctx.settings.max_response_bytes)
    if response.error:
        return None, response.status_code == 0
    if response.status_code >= 400:
        return (
            JSAnalysis(
                js_url=url,
                status_code=response.status_code,
                error=f"HTTP {response.status_code}",
            ),
            False,
        )
    analysis = analyze_javascript(response.text, response.url)
    analysis.status_code = response.status_code
    return analysis, False


async def run(ctx: "ReconContext") -> None:
    domain = target_domain(ctx.target)
    scope_root = (
        registrable_domain(domain) if domain else extract_host(ctx.target)
    )
    base_urls = _base_urls(ctx)
    if not base_urls:
        ctx.logger.warn("crawler/JS analysis skipped: no base URL")
        return

    historical: list[str] = []
    if domain:
        historical.extend(await _gau(ctx, domain))
    if not ctx.settings.stealth:
        historical.extend(await _katana(ctx, base_urls))
    pages, crawled_js, inline_scripts = await _custom_crawl(
        ctx, base_urls, scope_root
    )
    historical.extend(pages)
    historical.extend(crawled_js)

    scoped_urls: list[str] = []
    for url in historical:
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host and _is_in_scope(host, scope_root):
            scoped_urls.append(url)
    scoped_urls = dedupe(scoped_urls, 2000)
    js_urls = dedupe([url for url in scoped_urls if _is_js_url(url)], 400)
    js_limit = 10 if ctx.settings.stealth else ctx.settings.max_js_files
    js_urls = js_urls[:js_limit]

    ctx.logger.info(
        f"crawler sources: {len(scoped_urls)} URLs, {len(js_urls)} JS files, "
        f"{len(inline_scripts)} inline scripts"
    )

    results = await gather_limited(
        (_analyze_js_url(ctx, url) for url in js_urls),
        limit=ctx.settings.concurrency,
    )
    for analysis, _failed in results:
        if analysis is None:
            continue
        record = _find_host_record(ctx, analysis.js_url)
        if record is None:
            ensure_host(ctx, urlparse(analysis.js_url).hostname or "unknown")
            record = ctx.host_index.get(
                (urlparse(analysis.js_url).hostname or "").lower()
            )
        if record is None:
            continue
        _merge_js_findings(record.js_findings, analysis)
        if analysis.error:
            ctx.logger.warn(f"JS fetch {analysis.js_url}: {analysis.error}")
            continue
        ctx.logger.found(
            f"js {analysis.js_url} endpoints={len(analysis.endpoints)} "
            f"identities={len(analysis.emails) + len(analysis.authors)} "
            f"secrets={len(analysis.secrets)}"
        )
        for secret in analysis.secrets:
            ctx.logger.warn(
                f"potential secret ({secret.type}) in {analysis.js_url}"
            )

    for index, (source_url, script) in enumerate(inline_scripts[:100]):
        analysis = analyze_javascript(script, source_url)
        record = _find_host_record(ctx, source_url)
        if record is not None:
            _merge_js_findings(record.js_findings, analysis)
            if analysis.endpoints or analysis.secrets:
                ctx.logger.found(
                    f"inline script {source_url} endpoints={len(analysis.endpoints)} "
                    f"secrets={len(analysis.secrets)}"
                )

    internal_hosts: set[str] = set()
    for record in ctx.infra.hosts:
        for endpoint in record.js_findings.extracted_endpoints:
            if not endpoint.startswith("http"):
                continue
            try:
                host = (urlparse(endpoint).hostname or "").lower()
            except ValueError:
                continue
            if host and host != record.hostname and is_domain_like(host):
                internal_hosts.add(host)
    for host in sorted(internal_hosts)[:50]:
        if host not in ctx.host_index:
            ensure_host(ctx, host)
            ctx.logger.found(f"host referenced by JavaScript: {host}")
