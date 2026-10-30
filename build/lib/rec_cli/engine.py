"""Decoupled reconnaissance pipeline shared by the CLI and MCP server."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from rec_cli.config import Settings
from rec_cli.modules import infra_crawler_js, infra_fuzz, infra_ip_port
from rec_cli.modules import infra_subdomains, infra_techstack, infra_vuln_map
from rec_cli.modules import infra_waf
from rec_cli.modules import infra_whois_asn
from rec_cli.modules import osint_git, osint_identity, osint_metadata, osint_social
from rec_cli.modules import is_domain_like
from rec_cli.schema import (
    ASNRecord,
    HostRecord,
    InfraData,
    Mode,
    OSINTData,
    PivotSuggestion,
    PivotType,
    ReconResult,
    Vulnerability,
    build_meta,
)
from rec_cli.utils.logger import Logger, ascii_text
from rec_cli.utils.runner import StealthHTTPClient, dedupe

ModuleCallable = Callable[["ReconContext"], Awaitable[None]]


INFRA_CHAIN = [
    "whois_asn",
    "subdomains",
    "ip_port",
    "techstack",
    "waf",
    "fuzz",
    "crawler_js",
    "vuln_map",
]
OSINT_CHAIN = ["identity", "social", "git", "metadata"]

MODULE_RUNNERS: dict[str, ModuleCallable] = {
    "whois_asn": infra_whois_asn.run,
    "subdomains": infra_subdomains.run,
    "ip_port": infra_ip_port.run,
    "techstack": infra_techstack.run,
    "waf": infra_waf.run,
    "fuzz": infra_fuzz.run,
    "crawler_js": infra_crawler_js.run,
    "vuln_map": infra_vuln_map.run,
    "identity": osint_identity.run,
    "social": osint_social.run,
    "git": osint_git.run,
    "metadata": osint_metadata.run,
}

MODULE_ALIASES: dict[str, str] = {
    "whois": "whois_asn",
    "asn": "whois_asn",
    "whois_asn": "whois_asn",
    "subs": "subdomains",
    "subdomain": "subdomains",
    "subdomains": "subdomains",
    "ip": "ip_port",
    "port": "ip_port",
    "ports": "ip_port",
    "ip_port": "ip_port",
    "tech": "techstack",
    "http": "techstack",
    "techstack": "techstack",
    "waf": "waf",
    "wafw00f": "waf",
    "firewall": "waf",
    "waf_detect": "waf",
    "fuzz": "fuzz",
    "dirfuzz": "fuzz",
    "dir": "fuzz",
    "dirs": "fuzz",
    "directory": "fuzz",
    "content": "fuzz",
    "sensitive": "fuzz",
    "crawl": "crawler_js",
    "crawler": "crawler_js",
    "js": "crawler_js",
    "crawler_js": "crawler_js",
    "vuln": "vuln_map",
    "vulns": "vuln_map",
    "cve": "vuln_map",
    "vuln_map": "vuln_map",
    "identity": "identity",
    "emails": "identity",
    "usernames": "identity",
    "social": "social",
    "profiles": "social",
    "git": "git",
    "github": "git",
    "repos": "git",
    "metadata": "metadata",
    "documents": "metadata",
    "docs": "metadata",
}

_PUBLIC_PIVOT_DOMAINS = {
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "linkedin.com",
    "stackoverflow.com",
    "reddit.com",
    "medium.com",
    "x.com",
    "twitter.com",
    "google.com",
    "microsoft.com",
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "docker.io",
    "w3.org",
    "schema.org",
}

_FREE_MAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "yandex.com",
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
    "hey.com",
}

_NON_PUBLIC_TLDS = {
    "local",
    "localdomain",
    "internal",
    "lan",
    "home",
    "arpa",
    "test",
    "invalid",
    "example",
}

# Two-letter country codes that are also common source file extensions.
_AMBIGUOUS_FILE_TLDS = {"md", "sh", "py", "pl", "rs", "so", "am", "pm"}

_COMMON_PIVOT_TLDS = {
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "mobi",
    "asia",
    "tel",
    "travel",
    "jobs",
    "museum",
    "aero",
    "coop",
    "cat",
    "io",
    "ai",
    "co",
    "me",
    "tv",
    "cc",
    "ws",
    "fm",
    "gg",
    "sh",
    "ly",
    "to",
    "xyz",
    "online",
    "site",
    "store",
    "shop",
    "tech",
    "dev",
    "app",
    "cloud",
    "blog",
    "news",
    "media",
    "page",
    "space",
    "website",
    "top",
    "vip",
    "club",
    "link",
    "live",
    "email",
    "mail",
    "digital",
    "agency",
    "studio",
    "design",
    "art",
    "photo",
    "photos",
    "graphics",
    "video",
    "music",
    "audio",
    "camera",
    "gallery",
    "show",
    "theater",
    "tickets",
    "events",
    "social",
    "community",
    "team",
    "company",
    "business",
    "enterprise",
    "industries",
    "engineering",
    "technology",
    "computer",
    "software",
    "systems",
    "network",
    "security",
    "services",
    "solutions",
    "support",
    "help",
    "care",
    "health",
    "clinic",
    "hospital",
    "doctor",
    "dentist",
    "pharmacy",
    "fitness",
    "gym",
    "coach",
    "training",
    "academy",
    "school",
    "college",
    "university",
    "institute",
    "education",
    "courses",
    "study",
    "science",
    "research",
    "foundation",
    "church",
    "global",
    "world",
    "international",
    "group",
    "holdings",
    "partners",
    "associates",
    "management",
    "consulting",
    "ventures",
    "capital",
    "finance",
    "financial",
    "bank",
    "insurance",
    "legal",
    "attorney",
    "lawyer",
    "tax",
    "accounting",
    "loans",
    "credit",
    "mortgage",
    "fund",
    "investments",
    "exchange",
    "markets",
    "trading",
    "broker",
    "review",
    "reviews",
    "report",
    "reports",
    "feedback",
    "expert",
    "guru",
    "ninja",
    "rocks",
    "codes",
    "works",
    "tools",
    "labs",
    "hosting",
    "domains",
    "press",
    "wiki",
    "forum",
    "chat",
    "life",
    "style",
    "fashion",
    "beauty",
    "fit",
    "run",
    "bike",
    "auto",
    "car",
    "hotel",
    "holiday",
    "vacation",
    "cruise",
    "flights",
    "family",
    "baby",
    "kids",
    "toys",
    "games",
    "fun",
    "poker",
    "casino",
    "bet",
    "dating",
    "singles",
    "adult",
    "xxx",
    "jetzt",
    "reise",
    "versicherung",
    "immobilien",
}


class ReconError(Exception):
    """Raised for invalid reconnaissance inputs or module selection."""


@dataclass
class ReconContext:
    target: str
    mode: Mode
    settings: Settings
    logger: Logger
    http: StealthHTTPClient
    infra: InfraData = field(default_factory=InfraData)
    osint: OSINTData = field(default_factory=OSINTData)
    subdomains: set[str] = field(default_factory=set)
    host_index: dict[str, HostRecord] = field(default_factory=dict)
    host_ips: dict[str, list[str]] = field(default_factory=dict)
    host_cnames: dict[str, str] = field(default_factory=dict)
    host_cpes: dict[str, list[str]] = field(default_factory=dict)
    host_favicons: dict[str, str] = field(default_factory=dict)
    port_cache: dict[str, list[int]] = field(default_factory=dict)
    ip_vulns: dict[str, list[str]] = field(default_factory=dict)
    ip_tags: dict[str, list[str]] = field(default_factory=dict)
    asn_by_ip: dict[str, ASNRecord] = field(default_factory=dict)
    asn_failures: set[str] = field(default_factory=set)
    shodan_vulns: dict[str, list[str]] = field(default_factory=dict)
    vuln_cache: dict[str, list[Vulnerability]] = field(default_factory=dict)
    vuln_query_count: int = 0
    nvd_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    nvd_next_request_at: float = 0.0
    osint_to_infra_candidates: list[tuple[str, str, str]] = field(
        default_factory=list
    )
    git_seen_repos: set[str] = field(default_factory=set)
    github_exhausted: bool = False
    gitlab_exhausted: bool = False


def _resolve_modules(mode: Mode, modules: list[str] | None) -> list[str]:
    chain = INFRA_CHAIN if mode == Mode.INFRA else OSINT_CHAIN
    if not modules:
        return list(chain)
    requested = {
        token.strip().lower()
        for module in modules
        for token in module.split(",")
        if token.strip()
    }
    if not requested:
        raise ReconError("no modules were specified")
    if "all" in requested:
        return list(chain)

    selected: set[str] = set()
    invalid: list[str] = []
    for item in requested:
        normalized = MODULE_ALIASES.get(item)
        if not normalized:
            invalid.append(item)
        elif normalized not in chain:
            invalid.append(f"{item} (not available in {mode.value} mode)")
        else:
            selected.add(normalized)
    if invalid:
        raise ReconError(
            f"invalid module selection: {', '.join(sorted(invalid))}. "
            f"Available: {', '.join(chain)}"
        )
    return [name for name in chain if name in selected]


def _to_ascii(value: Any) -> Any:
    if isinstance(value, str):
        return ascii_text(value)
    if isinstance(value, list):
        return [_to_ascii(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_ascii(item) for key, item in value.items()}
    return value


def _valid_pivot_domain(value: str) -> bool:
    candidate = value.strip().lower().strip(".")
    if not candidate or "@" in candidate or not is_domain_like(candidate):
        return False
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld in _NON_PUBLIC_TLDS or (tld in _AMBIGUOUS_FILE_TLDS and len(labels) == 2):
        return False
    if not (len(tld) == 2 and tld.isalpha()) and tld not in _COMMON_PIVOT_TLDS:
        return False
    if any(
        candidate == domain or candidate.endswith("." + domain)
        for domain in _PUBLIC_PIVOT_DOMAINS | _FREE_MAIL_DOMAINS
    ):
        return False
    return True


def _build_pivots(ctx: "ReconContext", target: str) -> list[PivotSuggestion]:
    suggestions: list[PivotSuggestion] = []
    seen: set[tuple[str, str]] = set()

    def add(
        source: str,
        pivot_type: PivotType,
        target_value: str,
        reason: str,
    ) -> None:
        value = " ".join(str(target_value).split()).strip()
        if not value or len(value) > 300:
            return
        key = (pivot_type.value, value.lower())
        if key in seen:
            return
        seen.add(key)
        suggestions.append(
            PivotSuggestion(
                source=source,
                pivot_type=pivot_type,
                target_value=value,
                reason=reason,
            )
        )

    for email in ctx.infra.whois_asn.registrant_emails:
        add(
            "whois_asn.registrant_emails",
            PivotType.INFRA_TO_OSINT,
            email,
            "Registrant email can be used for public profile and repository analysis.",
        )

    for record in ctx.infra.hosts:
        for value in record.js_findings.discovered_emails_or_authors:
            if "@" in value:
                add(
                    f"crawler_js:{record.hostname}",
                    PivotType.INFRA_TO_OSINT,
                    value,
                    "Email or author identifier was exposed in client-side code.",
                )
            elif len(value) >= 3:
                add(
                    f"crawler_js:{record.hostname}",
                    PivotType.INFRA_TO_OSINT,
                    value,
                    "Developer identity was exposed in a JavaScript comment.",
                )
    for finding in ctx.osint.git_findings:
        for indicator in finding.leaked_indicators:
            for token in indicator.replace(":", " ").split():
                candidate = token.strip(".,;()[]<>\"'")
                if _valid_pivot_domain(candidate):
                    add(
                        f"git:{finding.repo_url}",
                        PivotType.OSINT_TO_INFRA,
                        candidate,
                        "Repository metadata references a domain that may be in scope.",
                    )

    for document in ctx.osint.document_metadata:
        if document.author:
            add(
                f"metadata:{document.file_url}",
                PivotType.INFRA_TO_OSINT,
                document.author,
                "Document metadata author can be pivoted into public profile research.",
            )

    identity = ctx.osint.target_identity
    for email in identity.emails:
        domain = email.split("@", 1)[-1].strip().lower()
        if _valid_pivot_domain(domain):
            add(
                "identity.emails",
                PivotType.OSINT_TO_INFRA,
                domain,
                "Email domain is a candidate for infrastructure enumeration.",
            )
    for source, value, reason in ctx.osint_to_infra_candidates:
        if _valid_pivot_domain(value) and value.lower() != target.lower():
            add(source, PivotType.OSINT_TO_INFRA, value, reason)

    return suggestions[:100]


def _sanitize_result(result: ReconResult) -> ReconResult:
    payload = result.model_dump(mode="json", by_alias=True)
    cleaned = _to_ascii(payload)
    return ReconResult.model_validate(cleaned)


def run_json(result: ReconResult) -> dict[str, Any]:
    return result.model_dump(mode="json", by_alias=True, exclude_none=False)


class ReconEngine:
    """Execute chained reconnaissance modules and return a validated result."""

    def __init__(
        self,
        target: str,
        mode: str | Mode = Mode.INFRA,
        modules: list[str] | None = None,
        *,
        stealth: bool = True,
        proxy: str | None = None,
        skip_liveness: bool = False,
        wordlist: str | None = None,
        logger: Logger | None = None,
        settings: Settings | None = None,
    ) -> None:
        cleaned_target = target.strip()
        if not cleaned_target:
            raise ReconError("target must not be empty")
        try:
            parsed_mode = mode if isinstance(mode, Mode) else Mode(mode.lower())
        except ValueError as exc:
            raise ReconError("mode must be 'infra' or 'osint'") from exc

        self.target = cleaned_target
        self.mode = parsed_mode
        self.modules = _resolve_modules(parsed_mode, modules)
        self.settings = settings or Settings.from_env(
            stealth=stealth, proxy=proxy
        )
        self.settings.stealth = stealth
        self.settings.skip_liveness = skip_liveness
        if wordlist:
            self.settings.wordlist = os.path.expanduser(wordlist)
        if proxy:
            self.settings.proxy = proxy
        self.logger = logger or Logger(quiet=True, stream=sys.stderr)
        self.result: ReconResult | None = None

    async def run(self) -> ReconResult:
        started = time.monotonic()
        if self.settings.stealth:
            self.logger.stealth(
                "stealth mode: jittered pacing, passive port data, rotated headers"
            )
        async with StealthHTTPClient(self.settings, self.logger) as http:
            ctx = ReconContext(
                target=self.target,
                mode=self.mode,
                settings=self.settings,
                logger=self.logger,
                http=http,
            )
            total = len(self.modules)
            for index, name in enumerate(self.modules, start=1):
                runner = MODULE_RUNNERS[name]
                self.logger.module_start(name, index, total)
                module_started = time.monotonic()
                try:
                    await runner(ctx)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.logger.error(
                        f"module {name.upper()} failed: {type(exc).__name__}: {exc}"
                    )
                else:
                    self.logger.module_done(
                        name, time.monotonic() - module_started
                    )

            result = ReconResult(
                meta=build_meta(
                    self.target, self.mode, self.settings.stealth, self.modules
                ),
                infra_data=ctx.infra,
                osint_data=ctx.osint,
                pivots_suggested=_build_pivots(ctx, self.target),
            )
            result = _sanitize_result(result)
            self.result = result
            self.logger.info(
                f"reconnaissance completed in {time.monotonic() - started:.2f}s"
            )
            return result


async def run_recon(
    target: str,
    mode: str | Mode = Mode.INFRA,
    modules: list[str] | None = None,
    *,
    stealth: bool = True,
    proxy: str | None = None,
    skip_liveness: bool = False,
    wordlist: str | None = None,
    logger: Logger | None = None,
    settings: Settings | None = None,
) -> ReconResult:
    engine = ReconEngine(
        target,
        mode,
        modules,
        stealth=stealth,
        proxy=proxy,
        skip_liveness=skip_liveness,
        wordlist=wordlist,
        logger=logger,
        settings=settings,
    )
    return await engine.run()
