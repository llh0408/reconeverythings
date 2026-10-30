"""HTTP fingerprinting, TLS metadata, favicon hashing, and tech detection."""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from rec_cli.config import COMMON_WEB_PORTS
from rec_cli.modules import add_ports, ensure_host, extract_host, target_domain
from rec_cli.schema import HTTPInfo, Technology
from rec_cli.utils.runner import (
    HTTPResult,
    binary_available,
    gather_limited,
    is_projectdiscovery_binary,
    resolve_host_ips,
    run_command,
)

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_GENERATOR_RE_REVERSED = re.compile(
    r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,4})")


@dataclass(slots=True)
class ProbeData:
    url: str
    status_code: int
    title: str = ""
    technologies: list[Technology] = field(default_factory=list)
    tls_cn: list[str] = field(default_factory=list)
    favicon_hash: str = ""
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32 for favicon fingerprinting."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed
    rounded_end = length & ~0x3

    for index in range(0, rounded_end, 4):
        k1 = (
            data[index]
            | (data[index + 1] << 8)
            | (data[index + 2] << 16)
            | (data[index + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded_end:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _favicon_hash(content: bytes) -> str:
    encoded = base64.encodebytes(content)
    return str(_murmur3_32(encoded))


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    return " ".join(html.unescape(match.group(1)).split())[:300]


def _version_from(text: str) -> str | None:
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def _add_tech(
    output: dict[str, Technology], name: str, version: str | None = None
) -> None:
    normalized_name = name.strip()
    if not normalized_name:
        return
    existing = output.get(normalized_name.lower())
    if existing is None:
        output[normalized_name.lower()] = Technology(
            name=normalized_name, version=version
        )
    elif version and not existing.version:
        existing.version = version


def _detect_technologies(
    headers: dict[str, str], body: str, url: str
) -> list[Technology]:
    found: dict[str, Technology] = {}
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    cookies = headers.get("set-cookie", "").lower()
    generator = ""
    for regex in (_GENERATOR_RE, _GENERATOR_RE_REVERSED):
        match = regex.search(body)
        if match:
            generator = match.group(1)
            break
    fingerprint = " ".join((server, x_powered, generator, url)).lower()
    body_lower = body[:600_000].lower()

    server_patterns = (
        (r"nginx(?:/([0-9.]+))?", "nginx"),
        (r"openresty(?:/([0-9.]+))?", "OpenResty"),
        (r"apache(?:/([0-9.]+))?", "Apache HTTP Server"),
        (r"microsoft-iis(?:/([0-9.]+))?", "Microsoft IIS"),
        (r"litespeed(?:/([0-9.]+))?", "LiteSpeed"),
        (r"caddy(?:/([0-9.]+))?", "Caddy"),
        (r"cloudflare", "Cloudflare"),
        (r"gunicorn(?:/([0-9.]+))?", "Gunicorn"),
        (r"uvicorn", "Uvicorn"),
        (r"jetty(?:\(([0-9.]+)\))?", "Jetty"),
        (r"tomcat(?:/([0-9.]+))?", "Apache Tomcat"),
    )
    for pattern, name in server_patterns:
        match = re.search(pattern, server, re.IGNORECASE)
        if match:
            _add_tech(found, name, match.group(1) if match.groups() else None)

    powered_patterns = (
        (r"php/([0-9.]+)", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"express", "Express"),
        (r"servlet/([0-9.]+)", "Java Servlet"),
        (r"node\.js", "Node.js"),
    )
    for pattern, name in powered_patterns:
        match = re.search(pattern, x_powered, re.IGNORECASE)
        if match:
            _add_tech(found, name, match.group(1) if match.groups() else None)

    if "x-aspnet-version" in headers:
        _add_tech(found, "ASP.NET", headers.get("x-aspnet-version"))
    if headers.get("x-drupal-cache") or "drupal" in body_lower[:20000]:
        _add_tech(found, "Drupal")
    if headers.get("x-generator"):
        _add_tech(found, headers["x-generator"], _version_from(headers["x-generator"]))
    if headers.get("x-jenkins"):
        _add_tech(found, "Jenkins", headers.get("x-jenkins"))
    if headers.get("x-gitlab-meta") or "x-gitlab" in headers:
        _add_tech(found, "GitLab")
    if headers.get("x-consul-index"):
        _add_tech(found, "HashiCorp Consul")

    cookie_map = (
        ("phpsessid", "PHP", None),
        ("jsessionid", "Java", None),
        ("asp.net_sessionid", "ASP.NET", None),
        ("laravel_session", "Laravel", None),
        ("csrftoken", "Django", None),
        ("_rails", "Ruby on Rails", None),
        ("wordpress_", "WordPress", None),
        ("wp-settings", "WordPress", None),
        ("cf_clearance", "Cloudflare", None),
        ("jenkins", "Jenkins", None),
        ("gitlab", "GitLab", None),
    )
    for marker, name, version in cookie_map:
        if marker in cookies:
            _add_tech(found, name, version)

    if generator:
        name = re.split(r"[\s/]", generator.strip(), maxsplit=1)[0]
        _add_tech(found, name or generator, _version_from(generator))

    body_patterns = (
        (r"wp-content/|wp-includes/", "WordPress"),
        (r"/sites/default/files/", "Drupal"),
        (r"/components/com_", "Joomla"),
        (r"/_next/static/", "Next.js"),
        (r"__next_data__", "Next.js"),
        (r"/static/js/main\.[a-f0-9]+\.js", "React"),
        (r"ng-version=[\"']([0-9.]+)", "Angular"),
        (r"vue(?:\.runtime)?(?:\.min)?\.js", "Vue.js"),
        (r"jquery[-.]?([0-9.]+)?(?:\.min)?\.js", "jQuery"),
        (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap"),
        (r"/keycloak/|keycloak\.js", "Keycloak"),
        (r"grafana", "Grafana"),
        (r"kibana", "Kibana"),
        (r"jira", "Atlassian Jira"),
        (r"confluence", "Atlassian Confluence"),
        (r"jenkins", "Jenkins"),
        (r"gitlab", "GitLab"),
        (r"phpmyadmin", "phpMyAdmin"),
        (r"cpanel", "cPanel"),
        (r"drupal-settings-json", "Drupal"),
        (r"springframework|whitelabel error page", "Spring Framework"),
    )
    for pattern, name in body_patterns:
        match = re.search(pattern, body_lower)
        if match:
            version = match.group(1) if match.groups() else None
            _add_tech(found, name, version)

    if "wordpress" in fingerprint:
        _add_tech(found, "WordPress", _version_from(generator))
    if "/graphql" in body_lower:
        _add_tech(found, "GraphQL", None)
    return sorted(found.values(), key=lambda item: item.name.lower())


def _tls_names_sync(host: str, port: int, timeout: float) -> list[str]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:
        return []
    if not der:
        return []
    try:
        from cryptography import x509  # type: ignore
        from cryptography.x509.oid import ExtensionOID  # type: ignore
    except Exception:
        return []

    try:
        certificate = x509.load_der_x509_certificate(der)
        names: list[str] = []
        try:
            san = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            names.extend(str(name).strip().lower() for name in san.get_values_for_type(x509.DNSName))
        except Exception:
            pass
        for attribute in certificate.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        ):
            value = str(attribute.value).strip().lower()
            if value and value not in names:
                names.append(value)
        return names[:50]
    except Exception:
        return []


async def _tls_names(
    ctx: "ReconContext", host: str, port: int
) -> list[str]:
    if ctx.settings.stealth and ctx.settings.proxy:
        ctx.logger.stealth("TLS direct inspection skipped to preserve proxy OPSEC")
        return []
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _tls_names_sync, host, port, ctx.settings.connect_timeout
            ),
            timeout=ctx.settings.connect_timeout + 2,
        )
    except Exception:
        return []


def _parse_pd_tech(value: Any) -> list[Technology]:
    if not isinstance(value, list):
        return []
    technologies: list[Technology] = []
    for item in value:
        text = str(item).strip()
        if not text:
            continue
        if ":" in text:
            name, version = text.split(":", 1)
        else:
            name, version = text, None
        technologies.append(
            Technology(name=name.strip(), version=version.strip() or None)
        )
    return technologies


async def _projectdiscovery_probe(
    ctx: "ReconContext", urls: list[str]
) -> tuple[dict[str, dict[str, Any]], bool]:
    """Return httpx hints and whether the liveness check actually ran."""
    if ctx.settings.stealth or ctx.settings.skip_liveness or not urls:
        return {}, False
    binary = ctx.settings.httpx_binary
    if not binary_available(binary) or not await is_projectdiscovery_binary(binary):
        return {}, False
    command = [
        binary,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-cdn",
        "-no-color",
        "-rl",
        str(ctx.settings.subprocess_rate_limit),
        "-timeout",
        str(int(ctx.settings.request_timeout)),
    ]
    if ctx.settings.proxy:
        command.extend(["-proxy", ctx.settings.proxy])
    result = await run_command(
        command,
        timeout=180,
        input_bytes=("\n".join(urls[:300]) + "\n").encode("utf-8"),
    )
    if not result.ok and not result.stdout.strip():
        ctx.logger.warn("ProjectDiscovery httpx wrapper failed; using custom probes")
        return {}, False
    hints: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict) or not item.get("url"):
            continue
        hints[str(item["url"]).rstrip("/")] = item
    if hints:
        ctx.logger.info(f"ProjectDiscovery httpx returned {len(hints)} probe hints")
    return hints, True


def _candidate_urls(record_ports: list[int], hostname: str) -> list[str]:
    hosts = hostname
    try:
        ipaddress.ip_address(hostname)
        hosts = f"[{hostname}]" if ":" in hostname else hostname
    except ValueError:
        pass

    ports = [port for port in record_ports if port in COMMON_WEB_PORTS]
    if not ports:
        ports = [443, 80]
    urls: list[str] = []
    for port in ports[:4]:
        https_ports = {443, 8443, 9443, 4443}
        if port in https_ports:
            schemes = ["https"]
        elif port in (80, 8080, 8000, 8888):
            schemes = ["http"]
        else:
            schemes = ["http", "https"]
        for scheme in schemes:
            default = (scheme == "https" and port == 443) or (
                scheme == "http" and port == 80
            )
            suffix = "" if default else f":{port}"
            urls.append(f"{scheme}://{hosts}{suffix}/")
    return urls[:4]


async def _probe_url(
    ctx: "ReconContext", hostname: str, url: str
) -> ProbeData | None:
    result: HTTPResult = await ctx.http.get(
        url,
        max_bytes=ctx.settings.max_response_bytes,
        headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
    )
    if result.error or result.status_code == 0:
        return None

    title = _extract_title(result.text)
    technologies = _detect_technologies(result.headers, result.text, result.url)
    server = result.header("server")
    tls_cn: list[str] = []
    favicon_hash = ""

    if result.url.startswith("https://"):
        port = 443
        try:
            from urllib.parse import urlparse

            parsed = urlparse(result.url)
            port = parsed.port or 443
        except Exception:
            pass
        tls_cn = await _tls_names(ctx, hostname, port)

    favicon = await ctx.http.get(
        urljoin(result.url, "/favicon.ico"),
        max_bytes=200_000,
    )
    if (
        not favicon.error
        and favicon.status_code == 200
        and favicon.content
        and not favicon.header("content-type", "").startswith("text/html")
    ):
        favicon_hash = _favicon_hash(favicon.content)
        ctx.host_favicons[hostname] = favicon_hash

    return ProbeData(
        url=result.url,
        status_code=result.status_code,
        title=title,
        technologies=technologies,
        tls_cn=tls_cn,
        favicon_hash=favicon_hash,
        server=server,
        headers=result.headers,
    )


def _score(probe: ProbeData) -> tuple[int, int, int]:
    success = 1 if 200 <= probe.status_code < 400 else 0
    https = 1 if probe.url.startswith("https://") else 0
    return success, https, -probe.status_code


def _hint_to_probe(hint: dict[str, Any]) -> ProbeData | None:
    try:
        status = int(hint.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    if status <= 0:
        return None
    return ProbeData(
        url=str(hint.get("url", "")),
        status_code=status,
        title=str(hint.get("title", "") or ""),
        technologies=_parse_pd_tech(hint.get("tech")),
        server=str(hint.get("webserver", "") or ""),
    )


async def _probe_host(
    ctx: "ReconContext",
    record: Any,
    hints: dict[str, dict[str, Any]],
    live_urls: list[str] | None = None,
) -> ProbeData | None:
    candidates = _candidate_urls(record.open_ports, record.hostname)
    urls = candidates
    if live_urls:
        live = {value.rstrip("/") for value in live_urls}
        filtered = [url for url in candidates if url.rstrip("/") in live]
        if filtered:
            urls = filtered
    probes = await gather_limited(
        (_probe_url(ctx, record.hostname, url) for url in urls),
        limit=2,
    )
    valid = [probe for probe in probes if probe is not None]
    if not valid:
        for url in urls:
            hint = hints.get(url.rstrip("/"))
            if hint:
                probe = _hint_to_probe(hint)
                if probe:
                    valid.append(probe)

    if not valid:
        ctx.logger.warn(f"no HTTP service identified for {record.hostname}")
        return None

    best = max(valid, key=_score)
    tech_map: dict[str, Technology] = {}
    for probe in valid:
        for technology in probe.technologies:
            key = technology.name.lower()
            existing = tech_map.get(key)
            if existing is None:
                tech_map[key] = technology
            elif technology.version and not existing.version:
                existing.version = technology.version

    tls_names: list[str] = []
    for probe in valid:
        for name in probe.tls_cn:
            if name not in tls_names:
                tls_names.append(name)

    record.http_info = HTTPInfo(
        url=best.url,
        status_code=best.status_code,
        title=best.title,
        technologies=sorted(tech_map.values(), key=lambda item: item.name.lower()),
        tls_cn=tls_names,
    )
    if best.server:
        lowered = best.server.lower()
        if "cloudflare" in lowered:
            record.cdn_waf = record.cdn_waf or "Cloudflare"
        elif "akamai" in lowered:
            record.cdn_waf = record.cdn_waf or "Akamai"
        elif "sucuri" in lowered:
            record.cdn_waf = record.cdn_waf or "Sucuri"
    try:
        from urllib.parse import urlparse

        parsed = urlparse(best.url)
        if parsed.port:
            add_ports(record, [parsed.port])
        elif parsed.scheme == "https":
            add_ports(record, [443])
        elif parsed.scheme == "http":
            add_ports(record, [80])
    except Exception:
        pass

    version_detail = ", ".join(
        f"{tech.name}/{tech.version}" if tech.version else tech.name
        for tech in record.http_info.technologies[:8]
    )
    detail = f"HTTP {best.status_code} {best.url}"
    if best.title:
        detail += f" title={best.title!r}"
    if version_detail:
        detail += f" tech={version_detail}"
    ctx.logger.found(detail)
    if best.favicon_hash:
        ctx.logger.info(f"favicon hash {record.hostname}: {best.favicon_hash}")
    return best


_WHATWEB_NOISE = {
    "allow",
    "content-security-policy",
    "cookies",
    "country",
    "email",
    "html5",
    "ip",
    "object",
    "passwordfield",
    "permissions-policy",
    "redirectlocation",
    "referrer-policy",
    "script",
    "strict-transport-security",
    "title",
    "uncommonheaders",
    "url",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
}

_WHATWEB_VALUE_PLUGINS = {"httpserver", "x-powered-by", "powered-by", "metagenerator"}


def _whatweb_version(info: Any) -> str | None:
    if not isinstance(info, dict):
        return None
    versions = info.get("version")
    if isinstance(versions, list):
        for value in versions:
            text = str(value).strip()
            if text:
                return text[:80]
    return None


def _whatweb_strings(info: Any) -> list[str]:
    if not isinstance(info, dict):
        return []
    values = info.get("string")
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text.lower() not in {"", "unknown", "none"}:
            output.append(text[:80])
    return output


def _parse_whatweb(payload: str) -> list[Technology]:
    try:
        blocks = json.loads(payload)
    except ValueError:
        return []
    if isinstance(blocks, dict):
        blocks = [blocks]
    if not isinstance(blocks, list):
        return []
    technologies: list[Technology] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        plugins = block.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, info in plugins.items():
            label = str(name).strip()
            key = label.lower()
            if not label or key in _WHATWEB_NOISE:
                continue
            if key in _WHATWEB_VALUE_PLUGINS:
                for value in _whatweb_strings(info):
                    technologies.append(Technology(name=value))
                continue
            technologies.append(
                Technology(name=label[:80], version=_whatweb_version(info))
            )
    return technologies


async def _whatweb(ctx: "ReconContext", url: str) -> list[Technology]:
    binary = ctx.settings.whatweb_binary
    if not binary_available(binary):
        return []
    command = [binary, "--color=never", "--no-errors", "-q", "--log-json=-", url]
    if ctx.settings.proxy:
        parsed = urlparse(ctx.settings.proxy)
        proxy = parsed.hostname or ""
        if parsed.port:
            proxy += f":{parsed.port}"
        if proxy:
            command.insert(1, f"--proxy={proxy}")
    result = await run_command(command, timeout=60)
    return _parse_whatweb(result.stdout)


async def _webanalyze(ctx: "ReconContext", url: str) -> list[Technology]:
    binary = ctx.settings.webanalyze_binary
    apps = ctx.settings.webanalyze_apps
    if not binary_available(binary) or not apps or not os.path.isfile(apps):
        return []
    command = [
        binary,
        "-host",
        url,
        "-apps",
        apps,
        "-output",
        "json",
        "-silent",
    ]
    result = await run_command(command, timeout=60)
    technologies: list[Technology] = []
    for line in result.stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        for match in item.get("matches") or []:
            if not isinstance(match, dict):
                continue
            name = str(match.get("app_name") or "").strip()
            if not name:
                continue
            version = str(match.get("version") or "").strip()
            technologies.append(
                Technology(
                    name=name[:80],
                    version=version[:80] if version else None,
                )
            )
    return technologies


def _merge_technologies(
    existing: list[Technology], incoming: list[Technology]
) -> list[Technology]:
    output = list(existing)
    index = {tech.name.strip().lower(): tech for tech in output}
    for tech in incoming:
        name = tech.name.strip()
        if not name:
            continue
        key = name.lower()
        current = index.get(key)
        if current is None:
            copy = Technology(name=name[:80], version=tech.version)
            output.append(copy)
            index[key] = copy
        elif tech.version and not current.version:
            current.version = tech.version
    return output


async def _external_technologies(
    ctx: "ReconContext", url: str
) -> list[Technology]:
    results = await gather_limited(
        (_whatweb(ctx, url), _webanalyze(ctx, url)), limit=2
    )
    merged: list[Technology] = []
    for items in results:
        merged = _merge_technologies(merged, items)
    return merged


async def run(ctx: "ReconContext") -> None:
    if not ctx.infra.hosts:
        host = target_domain(ctx.target) or extract_host(ctx.target)
        if host:
            record = ensure_host(ctx, host)
            if not record.ip:
                ips = await resolve_host_ips(host, ctx.settings.connect_timeout)
                if ips:
                    record.ip = ips[0]
                    ctx.host_ips[host] = ips

    if not ctx.infra.hosts:
        ctx.logger.warn("tech stack probing skipped: no hosts")
        return

    hosts = list(ctx.infra.hosts)[: ctx.settings.max_hosts]
    if not hosts:
        ctx.logger.warn("tech stack probing skipped: no hosts")
        return

    candidate_map: dict[str, list[str]] = {}
    url_candidates: list[str] = []
    for record in hosts:
        urls = _candidate_urls(record.open_ports, record.hostname)
        candidate_map[record.hostname] = urls
        url_candidates.extend(urls)

    hints, liveness_checked = await _projectdiscovery_probe(ctx, url_candidates)
    live_urls: dict[str, list[str]] = {}
    if liveness_checked:
        for record in hosts:
            live = [
                url
                for url in candidate_map[record.hostname]
                if url.rstrip("/") in hints
            ]
            if live:
                live_urls[record.hostname] = live
        ctx.logger.info(
            f"httpx liveness: {len(live_urls)}/{len(hosts)} host(s) live"
        )
        if not live_urls:
            ctx.logger.warn(
                "httpx reported no live hosts; probing all hosts directly"
            )
            liveness_checked = False
    elif ctx.settings.skip_liveness and not ctx.settings.stealth:
        ctx.logger.info("liveness pre-check skipped; probing all collected hosts")

    targets = (
        [record for record in hosts if record.hostname in live_urls]
        if liveness_checked
        else hosts
    )
    ctx.logger.info(f"probing {len(targets)} host(s) for web services")
    probed = await gather_limited(
        (
            _probe_host(
                ctx,
                record,
                hints,
                live_urls.get(record.hostname) if liveness_checked else None,
            )
            for record in targets
        ),
        limit=3 if ctx.settings.stealth else 5,
    )

    if ctx.settings.stealth:
        return

    tool_targets = [
        (record, probe)
        for record, probe in zip(targets, probed)
        if probe is not None and probe.url
    ][: ctx.settings.max_tech_urls]
    if not tool_targets:
        return
    ctx.logger.info(
        f"whatweb/webanalyze: testing {len(tool_targets)} URL(s)"
    )
    tool_results = await gather_limited(
        (_external_technologies(ctx, probe.url) for _, probe in tool_targets),
        limit=3,
    )
    for (record, _probe), found in zip(tool_targets, tool_results):
        if not found:
            continue
        record.http_info.technologies = _merge_technologies(
            record.http_info.technologies, found
        )
        detail = ", ".join(
            f"{tech.name}/{tech.version}" if tech.version else tech.name
            for tech in found[:8]
        )
        ctx.logger.info(f"tech tools {record.hostname}: {detail}")
