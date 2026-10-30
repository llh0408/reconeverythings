"""Bounded HTML crawling that extracts JavaScript, CSS, and HTML asset URLs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urldefrag, urljoin, urlparse

from rec_cli.modules import (
    ensure_host,
    extract_host,
    registrable_domain,
    target_domain,
)
from rec_cli.schema import AssetFinding
from rec_cli.utils.runner import gather_limited

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext
    from rec_cli.schema import HostRecord

_JS_EXTENSIONS = (".js", ".mjs", ".cjs")
_CSS_EXTENSIONS = (".css",)
_HTML_EXTENSIONS = (
    ".html",
    ".htm",
    ".xhtml",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".shtml",
    ".phtml",
    ".cgi",
)
_MAX_BODY = 1_500_000
_MAX_URL_LENGTH = 1000


class _HTMLReferences(HTMLParser):
    """Collect script, stylesheet, and navigational references."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.links: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values: dict[str, str] = {}
        for key, value in attrs:
            if value is not None and key not in values:
                values[key] = value

        if tag == "script":
            src = values.get("src")
            if src:
                self.scripts.append(src)
            return
        if tag == "link":
            href = values.get("href")
            if not href:
                return
            rel = (values.get("rel") or "").lower().split()
            as_type = (values.get("as") or "").lower()
            if "stylesheet" in rel or ("preload" in rel and as_type == "style"):
                self.stylesheets.append(href)
            elif "modulepreload" in rel or (
                "preload" in rel and as_type == "script"
            ):
                self.scripts.append(href)
            elif "canonical" in rel:
                self.links.append(href)
            return
        if tag in ("a", "area"):
            href = values.get("href")
            if href:
                self.links.append(href)
            return
        if tag in ("iframe", "frame"):
            src = values.get("src")
            if src:
                self.links.append(src)


def _absolute_url(base: str, reference: str) -> str | None:
    reference = reference.strip()
    if not reference:
        return None
    if reference.lower().startswith(
        ("#", "mailto:", "tel:", "javascript:", "data:", "blob:")
    ):
        return None
    try:
        joined = urljoin(base, reference)
    except ValueError:
        return None
    joined, _fragment = urldefrag(joined)
    if len(joined) > _MAX_URL_LENGTH:
        return None
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return joined


def _kind_of(url: str) -> str | None:
    path = urlparse(url).path.lower()
    if path.endswith(_JS_EXTENSIONS):
        return "js"
    if path.endswith(_CSS_EXTENSIONS):
        return "css"
    if path.endswith(_HTML_EXTENSIONS):
        return "html"
    return None


def _looks_like_page(url: str) -> bool:
    path = urlparse(url).path.lower()
    if path.endswith(_HTML_EXTENSIONS):
        return True
    return "." not in path.rsplit("/", 1)[-1]


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _in_scope(url: str, scope_root: str) -> bool:
    host = _host_of(url).rstrip(".")
    root = scope_root.lower().rstrip(".")
    if not host or not root:
        return False
    return host == root or host.endswith("." + root)


def _scope_root(ctx: "ReconContext") -> str:
    domain = target_domain(ctx.target)
    return registrable_domain(domain) if domain else extract_host(ctx.target)


def _host_targets(
    ctx: "ReconContext",
) -> list[tuple["HostRecord", list[str]]]:
    preferred = extract_host(ctx.target)
    records = sorted(
        ctx.infra.hosts,
        key=lambda item: (item.hostname != preferred, item.hostname),
    )
    targets: list[tuple["HostRecord", list[str]]] = []
    for record in records:
        if record.http_info.url:
            targets.append((record, [record.http_info.url]))
            continue
        if not record.hostname:
            continue
        display = (
            f"[{record.hostname}]"
            if ":" in record.hostname
            else record.hostname
        )
        targets.append(
            (record, [f"https://{display}/", f"http://{display}/"])
        )
    if targets:
        return targets

    target = ctx.target.strip()
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        seeds = [target]
        host = (parsed.hostname or "").lower()
    else:
        host = target_domain(target) or extract_host(target)
        if not host:
            return []
        display = f"[{host}]" if ":" in host else host
        seeds = [f"https://{display}/", f"http://{display}/"]
    if not host:
        return []
    return [(ensure_host(ctx, host), seeds)]


@dataclass
class _Collector:
    ctx: "ReconContext"
    seen: set[str] = field(default_factory=set)
    limit: int = 800
    total: int = 0
    counts: dict[str, int] = field(
        default_factory=lambda: {"js": 0, "css": 0, "html": 0}
    )

    @property
    def full(self) -> bool:
        return self.total >= self.limit

    def add(
        self,
        record: "HostRecord",
        kind: str,
        url: str,
        source_url: str,
        depth: int,
    ) -> bool:
        if self.full or url in self.seen:
            return False
        self.seen.add(url)
        self.total += 1
        self.counts[kind] = self.counts.get(kind, 0) + 1
        record.assets.append(
            AssetFinding(
                url=url,
                kind=kind,
                host=_host_of(url),
                source_url=source_url,
                depth=depth,
            )
        )
        self.ctx.logger.found(f"{kind} {url}")
        return True


def _page_assets(
    record: "HostRecord",
    page_url: str,
    text: str,
    depth: int,
    scope_root: str,
    depth_limit: int,
    collector: _Collector,
) -> list[tuple[str, int, str]]:
    parser = _HTMLReferences()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        pass

    for reference in parser.scripts:
        asset = _absolute_url(page_url, reference)
        if asset:
            collector.add(record, "js", asset, page_url, depth)
    for reference in parser.stylesheets:
        asset = _absolute_url(page_url, reference)
        if asset:
            collector.add(record, "css", asset, page_url, depth)

    queued: list[tuple[str, int, str]] = []
    if depth + 1 >= depth_limit or collector.full:
        return queued
    for reference in parser.links:
        asset = _absolute_url(page_url, reference)
        if not asset or not _in_scope(asset, scope_root):
            continue
        kind = _kind_of(asset)
        if kind in ("js", "css"):
            collector.add(record, kind, asset, page_url, depth + 1)
        elif kind == "html" or (kind is None and _looks_like_page(asset)):
            queued.append((asset, depth + 1, page_url))
    return queued


async def _fetch_page(
    ctx: "ReconContext", url: str, scope_root: str, body_limit: int
) -> tuple[str, str] | None:
    response = await ctx.http.get(url, max_bytes=body_limit)
    if response.error or response.status_code >= 400:
        return None
    if "html" not in response.header("content-type", "text/html").lower():
        return None
    page_url = response.url or url
    if not _in_scope(page_url, scope_root):
        return None
    return page_url, response.text


async def _crawl_host(
    ctx: "ReconContext",
    record: "HostRecord",
    seeds: list[str],
    scope_root: str,
    collector: _Collector,
    seen_pages: set[str],
    page_limit: int,
    depth_limit: int,
    concurrency: int,
) -> None:
    body_limit = min(ctx.settings.max_response_bytes, _MAX_BODY)
    attempt_limit = max(page_limit, page_limit * 2)
    attempts = 0
    fetched = 0

    root: tuple[str, str] | None = None
    for seed in seeds:
        if attempts >= attempt_limit:
            break
        attempts += 1
        root = await _fetch_page(ctx, seed, scope_root, body_limit)
        if root is not None:
            break
    if root is None:
        return

    fetched += 1
    root_url, root_text = root
    collector.add(record, "html", root_url, "", 0)
    queue: deque[tuple[str, int, str]] = deque(
        _page_assets(
            record, root_url, root_text, 0, scope_root, depth_limit, collector
        )
    )

    while (
        queue
        and fetched < page_limit
        and attempts < attempt_limit
        and not collector.full
    ):
        batch: list[tuple[str, int, str]] = []
        while (
            queue
            and len(batch) < concurrency
            and fetched + len(batch) < page_limit
            and attempts + len(batch) < attempt_limit
        ):
            url, depth, referred_from = queue.popleft()
            if url in seen_pages:
                continue
            seen_pages.add(url)
            batch.append((url, depth, referred_from))
        if not batch:
            break

        attempts += len(batch)
        results = await gather_limited(
            (
                _fetch_page(ctx, url, scope_root, body_limit)
                for url, _depth, _source in batch
            ),
            limit=concurrency,
        )

        for (_url, depth, referred_from), page in zip(batch, results):
            if page is None:
                continue
            page_url, text = page
            fetched += 1
            collector.add(record, "html", page_url, referred_from, depth)
            queue.extend(
                _page_assets(
                    record,
                    page_url,
                    text,
                    depth,
                    scope_root,
                    depth_limit,
                    collector,
                )
            )


async def run(ctx: "ReconContext") -> None:
    scope_root = _scope_root(ctx)
    targets = _host_targets(ctx)
    if not targets or not scope_root:
        ctx.logger.warn("asset extraction skipped: no HTTP host to crawl")
        return

    host_limit = max(1, int(ctx.settings.max_asset_hosts))
    page_limit = max(1, int(ctx.settings.max_asset_pages))
    depth_limit = max(1, int(ctx.settings.max_asset_depth))
    if ctx.settings.stealth:
        host_limit = min(host_limit, 3)
        page_limit = min(page_limit, 4)

    collector = _Collector(
        ctx=ctx,
        limit=max(1, int(ctx.settings.max_assets)),
    )
    seen_pages: set[str] = set()

    for record, seeds in targets[:host_limit]:
        if collector.full:
            break
        await _crawl_host(
            ctx,
            record,
            seeds,
            scope_root,
            collector,
            seen_pages,
            page_limit,
            depth_limit,
            ctx.settings.concurrency,
        )

    if collector.total:
        ctx.logger.found(
            f"asset extraction: {collector.total} URL(s) "
            f"(js={collector.counts.get('js', 0)} "
            f"css={collector.counts.get('css', 0)} "
            f"html={collector.counts.get('html', 0)})"
        )
