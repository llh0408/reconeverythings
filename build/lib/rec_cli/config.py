"""Runtime configuration, limits, API endpoints, and stealth defaults."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
)

COMMON_WEB_PORTS: tuple[int, ...] = (80, 443, 8000, 8080, 8443, 8888, 9000)
COMMON_TCP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017,
)

MULTI_LABEL_SUFFIXES: tuple[str, ...] = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "com.cn", "com.sg", "com.tr", "com.mx",
    "co.in", "co.za", "co.kr", "com.ar", "com.pl", "com.tw", "com.hk",
)

CDN_CNAME_SUFFIXES: dict[str, str] = {
    "cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "cloudfront.net": "AWS CloudFront",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "incapdns.net": "Imperva",
    "sucuri.net": "Sucuri",
    "stackpathdns.com": "StackPath",
    "cdn77.org": "CDN77",
    "bunnycdn.com": "Bunny CDN",
}

ASN_VENDOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("amazon", "AWS"),
    ("aws", "AWS"),
    ("cloudfront", "AWS CloudFront"),
    ("google", "Google"),
    ("microsoft", "Azure"),
    ("imperva", "Imperva"),
    ("incapsula", "Imperva"),
    ("sucuri", "Sucuri"),
    ("stackpath", "StackPath"),
    ("cdn77", "CDN77"),
    ("bunny", "Bunny CDN"),
)


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_ESCAPE_RE = re.compile(r'\\([nrt"\\])')
_ENV_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
_LOADED_ENV_FILES: set[Path] = set()


def _parse_env_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in ('"', "'"):
        quote = value[0]
        closing = value.rfind(quote)
        inner = value[1:closing] if closing > 0 else value[1:]
        if quote == '"':
            inner = _ENV_ESCAPE_RE.sub(
                lambda match: _ENV_ESCAPES[match.group(1)], inner
            )
        return inner
    return re.split(r"\s+#", value, 1)[0].strip()


def load_env_file(
    path: str | Path | None = None, *, override: bool = False
) -> Path | None:
    """Load an optional .env file without overwriting existing variables.

    Search order is the explicit path, REC_ENV_FILE, ./.env, then the
    project root .env. Missing or unreadable files are ignored.
    """
    if path is not None:
        candidates = [Path(path)]
    else:
        configured = os.environ.get("REC_ENV_FILE")
        if configured:
            candidates = [Path(configured)]
        else:
            candidates = [
                Path.cwd() / ".env",
                Path(__file__).resolve().parent.parent / ".env",
            ]

    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved in _LOADED_ENV_FILES:
            return resolved
        if not resolved.is_file():
            continue
        try:
            text = resolved.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            continue
        protected = set(os.environ)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("export "):
                stripped = stripped[7:].lstrip()
            key, separator, value = stripped.partition("=")
            if not separator:
                continue
            key = key.strip()
            if not _ENV_KEY_RE.match(key):
                continue
            parsed = _parse_env_value(value)
            if override or key not in protected:
                os.environ[key] = parsed
        _LOADED_ENV_FILES.add(resolved)
        return resolved
    return None


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _default_webanalyze_apps() -> str:
    return str(
        Path.home() / ".local" / "share" / "reconeverythings" / "technologies.json"
    )


@dataclass(slots=True)
class Settings:
    """Effective settings for one reconnaissance run."""

    stealth: bool = False
    skip_liveness: bool = False
    proxy: str | None = None
    request_timeout: float = 15.0
    connect_timeout: float = 8.0
    max_redirects: int = 5
    user_agents: tuple[str, ...] = DEFAULT_USER_AGENTS
    verify_tls: bool = False

    normal_rate: float = 8.0
    stealth_rate: float = 2.0
    jitter_min: float = 0.5
    jitter_max: float = 2.5

    max_response_bytes: int = 2_500_000
    max_document_bytes: int = 15_000_000
    max_subdomains: int = 500
    max_hosts: int = 150
    max_js_files: int = 30
    max_crawl_pages: int = 12
    max_vuln_queries: int = 12
    max_osint_items: int = 10
    max_tech_urls: int = 60
    max_fuzz_requests: int = 900
    max_fuzz_depth: int = 2
    max_fuzz_hosts: int = 3
    max_fuzz_dirs: int = 12
    wordlist: str = ""

    github_token: str | None = None
    gitlab_token: str | None = None
    nvd_api_key: str | None = None
    vulners_api_key: str | None = None
    shodan_api_key: str | None = None
    google_api_key: str | None = None
    google_cse_id: str | None = None

    subfinder_binary: str = "subfinder"
    httpx_binary: str = "httpx"
    naabu_binary: str = "naabu"
    katana_binary: str = "katana"
    gau_binary: str = "gau"
    wafw00f_binary: str = "wafw00f"
    nmap_binary: str = "nmap"
    whatweb_binary: str = "whatweb"
    webanalyze_binary: str = "webanalyze"
    webanalyze_apps: str = field(default_factory=_default_webanalyze_apps)

    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(
        cls,
        *,
        stealth: bool = False,
        proxy: str | None = None,
        quiet: bool = False,
    ) -> "Settings":
        del quiet
        load_env_file()
        jitter_min = _env_float("REC_JITTER_MIN", 0.5, 0.0)
        jitter_max = _env_float("REC_JITTER_MAX", 2.5, 0.0)
        if jitter_max < jitter_min:
            jitter_max = jitter_min
        return cls(
            stealth=stealth,
            proxy=proxy or os.environ.get("REC_PROXY") or None,
            request_timeout=_env_float("REC_TIMEOUT", 15.0, 0.1),
            connect_timeout=_env_float("REC_CONNECT_TIMEOUT", 8.0, 0.1),
            verify_tls=_env_bool("REC_VERIFY_TLS", False),
            normal_rate=_env_float("REC_NORMAL_RATE", 8.0, 0.1),
            stealth_rate=_env_float("REC_STEALTH_RATE", 2.0, 0.1),
            jitter_min=jitter_min,
            jitter_max=jitter_max,
            max_response_bytes=_env_int("REC_MAX_RESPONSE_BYTES", 2_500_000),
            max_document_bytes=_env_int("REC_MAX_DOCUMENT_BYTES", 15_000_000),
            max_subdomains=_env_int("REC_MAX_SUBDOMAINS", 500),
            max_hosts=_env_int("REC_MAX_HOSTS", 150),
            max_js_files=_env_int("REC_MAX_JS_FILES", 30),
            max_crawl_pages=_env_int("REC_MAX_CRAWL_PAGES", 12),
            max_vuln_queries=_env_int("REC_MAX_VULN_QUERIES", 12),
            max_osint_items=_env_int("REC_MAX_OSINT_ITEMS", 10),
            max_tech_urls=_env_int("REC_MAX_TECH_URLS", 60),
            max_fuzz_requests=_env_int("REC_MAX_FUZZ_REQUESTS", 900),
            max_fuzz_depth=_env_int("REC_MAX_FUZZ_DEPTH", 2),
            max_fuzz_hosts=_env_int("REC_MAX_FUZZ_HOSTS", 3),
            max_fuzz_dirs=_env_int("REC_MAX_FUZZ_DIRS", 12),
            wordlist=os.path.expanduser(os.environ.get("REC_WORDLIST") or ""),
            github_token=os.environ.get("GITHUB_TOKEN") or None,
            gitlab_token=os.environ.get("GITLAB_TOKEN") or None,
            nvd_api_key=os.environ.get("NVD_API_KEY") or None,
            vulners_api_key=os.environ.get("VULNERS_API_KEY") or None,
            shodan_api_key=os.environ.get("SHODAN_API_KEY") or None,
            google_api_key=os.environ.get("GOOGLE_API_KEY") or None,
            google_cse_id=os.environ.get("GOOGLE_CSE_ID") or None,
            subfinder_binary=os.environ.get("REC_SUBFINDER_BIN") or "subfinder",
            httpx_binary=os.environ.get("REC_HTTPX_BIN") or "httpx",
            naabu_binary=os.environ.get("REC_NAABU_BIN") or "naabu",
            katana_binary=os.environ.get("REC_KATANA_BIN") or "katana",
            gau_binary=os.environ.get("REC_GAU_BIN") or "gau",
            wafw00f_binary=os.environ.get("REC_WAFW00F_BIN") or "wafw00f",
            nmap_binary=os.environ.get("REC_NMAP_BIN") or "nmap",
            whatweb_binary=os.environ.get("REC_WHATWEB_BIN") or "whatweb",
            webanalyze_binary=os.environ.get("REC_WEBANALYZE_BIN")
            or "webanalyze",
            webanalyze_apps=os.path.expanduser(
                os.environ.get("REC_WEBANALYZE_APPS") or _default_webanalyze_apps()
            ),
        )

    @property
    def requests_per_second(self) -> float:
        return self.stealth_rate if self.stealth else self.normal_rate

    @property
    def subprocess_rate_limit(self) -> int:
        return 2 if self.stealth else 10


API_ENDPOINTS: dict[str, str] = {
    "certspotter": "https://api.certspotter.com/v1/issuances",
    "crt_sh": "https://crt.sh/",
    "rdap": "https://rdap.org",
    "shodan_internetdb": "https://internetdb.shodan.io",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "github_api": "https://api.github.com",
    "gitlab_api": "https://gitlab.com/api/v4",
    "stackexchange_api": "https://api.stackexchange.com/2.3",
    "reddit_api": "https://www.reddit.com",
    "duckduckgo_html": "https://html.duckduckgo.com/html/",
    "google_cse": "https://www.googleapis.com/customsearch/v1",
    "cloudflare_ips_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_ips_v6": "https://www.cloudflare.com/ips-v6",
}
