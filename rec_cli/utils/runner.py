"""Async subprocess and HTTP primitives with OPSEC-aware pacing."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import re
import shutil
import socket
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Awaitable, Iterable, Sequence, TypeVar

import httpx

from rec_cli.config import Settings
from rec_cli.utils.logger import Logger, safe_text

try:
    import dns.asyncresolver  # type: ignore
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore

    _DNS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency path
    _DNS_AVAILABLE = False


T = TypeVar("T")
_CHARSET_RE = re.compile(r"charset=([A-Za-z0-9._-]+)", re.IGNORECASE)


@dataclass(slots=True)
class HTTPResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    text: str = ""
    error: str | None = None
    elapsed: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def json(self) -> Any:
        if not self.content:
            return None
        try:
            return json.loads(self.text or self.content.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return None


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    available: bool = True
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.available and not self.timed_out and self.returncode == 0


@lru_cache(maxsize=256)
def binary_available(name: str) -> bool:
    return shutil.which(name) is not None


async def run_command(
    command: Sequence[str],
    *,
    timeout: float = 60.0,
    input_bytes: bytes | None = None,
    max_output: int = 8_000_000,
) -> CommandResult:
    """Execute a command without a shell and return bounded output."""
    argv = [str(part) for part in command]
    if not argv:
        return CommandResult(argv, available=False, returncode=127)
    if not binary_available(argv[0]):
        return CommandResult(
            argv,
            available=False,
            returncode=127,
            stderr=f"binary not found: {argv[0]}",
        )

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if input_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return CommandResult(argv, available=False, returncode=126, stderr=str(exc))

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            process.communicate(input_bytes), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        stdout_b, stderr_b = await process.communicate()
        return CommandResult(
            argv,
            returncode=124,
            stdout=stdout_b[:max_output].decode("utf-8", errors="replace"),
            stderr=stderr_b[:max_output].decode("utf-8", errors="replace"),
            timed_out=True,
        )

    return CommandResult(
        argv,
        returncode=process.returncode or 0,
        stdout=stdout_b[:max_output].decode("utf-8", errors="replace"),
        stderr=stderr_b[:max_output].decode("utf-8", errors="replace"),
    )


async def is_projectdiscovery_binary(name: str) -> bool:
    """Guard against the unrelated Python httpx CLI sharing the binary name."""
    if not binary_available(name):
        return False
    result = await run_command([name, "-version"], timeout=8)
    output = (result.stdout + "\n" + result.stderr).lower()
    if name == "httpx":
        return "projectdiscovery" in output
    return result.returncode == 0 or bool(output.strip())


async def resolve_host_ips(host: str, timeout: float = 8.0) -> list[str]:
    """Resolve A/AAAA records with dnspython and system resolver fallback."""
    candidate = host.strip().strip("[]")
    if not candidate:
        return []
    try:
        ip = ipaddress.ip_address(candidate)
        return [str(ip)]
    except ValueError:
        pass

    ips: list[str] = []
    if _DNS_AVAILABLE:
        resolver = dns.asyncresolver.Resolver(configure=True)
        for record_type in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(
                    candidate, record_type, lifetime=timeout, raise_on_no_answer=False
                )
                if answer.rrset:
                    ips.extend(str(item) for item in answer.rrset)
            except Exception:
                continue

    if not ips:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(candidate, None, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            ips.extend(info[4][0] for info in infos)
        except Exception:
            pass

    unique: list[str] = []
    seen: set[str] = set()
    for value in ips:
        normalized = value.split("%", 1)[0]
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


async def resolve_cname(host: str, timeout: float = 8.0) -> str | None:
    if not _DNS_AVAILABLE or not host:
        return None
    resolver = dns.asyncresolver.Resolver(configure=True)
    try:
        answer = await resolver.resolve(
            host, "CNAME", lifetime=timeout, raise_on_no_answer=False
        )
        if answer.rrset:
            return str(next(iter(answer.rrset))).rstrip(".")
    except Exception:
        return None
    return None


async def query_txt(name: str, timeout: float = 8.0) -> list[str]:
    values: list[str] = []
    if _DNS_AVAILABLE:
        resolver = dns.asyncresolver.Resolver(configure=True)
        try:
            answer = await resolver.resolve(
                name, "TXT", lifetime=timeout, raise_on_no_answer=False
            )
            if answer.rrset:
                for record in answer.rrset:
                    chunks = getattr(record, "strings", None)
                    if chunks:
                        values.append(
                            b"".join(chunks).decode("utf-8", errors="replace")
                            if isinstance(chunks[0], bytes)
                            else "".join(chunks)
                        )
                    else:
                        values.append(str(record).strip('"'))
        except Exception:
            pass

    if not values and binary_available("dig"):
        result = await run_command(["dig", "+short", "TXT", name], timeout=timeout)
        for line in result.stdout.splitlines():
            cleaned = line.strip().strip('"').replace('" "', "")
            if cleaned:
                values.append(cleaned)
    return values


def _decode_body(content: bytes, headers: dict[str, str]) -> str:
    match = _CHARSET_RE.search(headers.get("content-type", ""))
    charset = match.group(1) if match else "utf-8"
    try:
        return content.decode(charset, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


class StealthHTTPClient:
    """Shared HTTP client that enforces rate limits, jitter, and UA rotation."""

    def __init__(self, settings: Settings, logger: Logger) -> None:
        self.settings = settings
        self.logger = logger
        self._lock = asyncio.Lock()
        self._next_request_at = 0.0
        self._closed = False

        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(
                settings.request_timeout,
                connect=settings.connect_timeout,
            ),
            "follow_redirects": True,
            "max_redirects": settings.max_redirects,
            "verify": settings.verify_tls,
            "trust_env": False,
            "headers": {},
        }
        if settings.proxy:
            try:
                self._client = httpx.AsyncClient(proxy=settings.proxy, **client_kwargs)
            except TypeError:  # pragma: no cover - compatibility with older httpx
                self._client = httpx.AsyncClient(
                    proxies=settings.proxy, **client_kwargs
                )
        else:
            self._client = httpx.AsyncClient(**client_kwargs)

    def _headers(self, extra: dict[str, str] | None, json_mode: bool) -> dict[str, str]:
        headers = {
            "User-Agent": random.choice(self.settings.user_agents),
            "Accept": (
                "application/json, text/plain, */*"
                if json_mode
                else "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": random.choice(
                ("en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8")
            ),
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        headers.update(self.settings.extra_headers)
        if extra:
            headers.update(extra)
        return headers

    async def _pace(self) -> None:
        async with self._lock:
            if self.settings.stealth:
                delay = random.uniform(
                    self.settings.jitter_min, self.settings.jitter_max
                )
                await asyncio.sleep(delay)
            minimum_interval = 1.0 / max(self.settings.requests_per_second, 0.1)
            now = time.monotonic()
            wait = self._next_request_at - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._next_request_at = max(now, self._next_request_at) + minimum_interval

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        data: Any | None = None,
        max_bytes: int | None = None,
        retries: int | None = None,
        follow_redirects: bool | None = None,
    ) -> HTTPResult:
        if self._closed:
            return HTTPResult(url=url, error="HTTP client is closed")
        if retries is None:
            retries = 0 if self.settings.stealth else 1
        body_limit = max_bytes or self.settings.max_response_bytes
        header_values = headers or {}
        json_mode = (
            json_body is not None
            or "json" in header_values.get("Accept", "").lower()
            or "/api/" in url
        )

        last_error: str | None = None
        for attempt in range(retries + 1):
            await self._pace()
            started = time.monotonic()
            send_options: dict[str, Any] = {}
            if follow_redirects is not None:
                send_options["follow_redirects"] = follow_redirects
            try:
                async with self._client.stream(
                    method.upper(),
                    url,
                    params=params,
                    headers=self._headers(headers, json_mode),
                    json=json_body,
                    data=data,
                    **send_options,
                ) as response:
                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        if total + len(chunk) > body_limit:
                            chunks.append(chunk[: body_limit - total])
                            truncated = True
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                    content = b"".join(chunks)
                    response_headers = {
                        key.lower(): value for key, value in response.headers.items()
                    }
                    result = HTTPResult(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=response_headers,
                        content=content,
                        text=_decode_body(content, response_headers),
                        elapsed=time.monotonic() - started,
                        truncated=truncated,
                    )
                if result.status_code >= 500 and attempt < retries:
                    last_error = f"HTTP {result.status_code}"
                else:
                    return result
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < retries:
                    await asyncio.sleep(random.uniform(0.2, 0.8))
            except Exception as exc:  # defensive boundary around untrusted URLs
                last_error = f"{type(exc).__name__}: {exc}"
                break

        return HTTPResult(url=url, error=last_error or "request failed")

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        retries: int | None = None,
        follow_redirects: bool | None = None,
    ) -> HTTPResult:
        return await self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            max_bytes=max_bytes,
            retries=retries,
            follow_redirects=follow_redirects,
        )

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> tuple[Any, HTTPResult]:
        extra = {"Accept": "application/json, text/plain, */*"}
        if headers:
            extra.update(headers)
        result = await self.get(
            url, params=params, headers=extra, max_bytes=max_bytes
        )
        return result.json(), result

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def __aenter__(self) -> "StealthHTTPClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()


async def gather_limited(
    awaitables: Iterable[Awaitable[T]], limit: int = 10
) -> list[T]:
    """Run awaitables with a concurrency ceiling while preserving order."""
    semaphore = asyncio.Semaphore(max(1, limit))

    async def guarded(awaitable: Awaitable[T]) -> T:
        async with semaphore:
            return await awaitable

    return list(await asyncio.gather(*(guarded(item) for item in awaitables)))


def dedupe(values: Iterable[str], limit: int | None = None) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = safe_text(value, 1000).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
        if limit is not None and len(output) >= limit:
            break
    return output
