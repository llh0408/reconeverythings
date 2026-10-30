"""Shared helpers for strict OSINT identity attribution checks."""

from __future__ import annotations

import re
from typing import Iterable

_TOKEN_RE = re.compile(r"[^a-z0-9]+")
_MAX_SCAN_BYTES = 300_000

BLOCK_MARKERS: tuple[str, ...] = (
    "access denied",
    "bot verification",
    "captcha challenge",
    "cf-chl",
    "complete the captcha",
    "enable javascript and cookies",
    "just a moment",
    "request blocked",
    "solve the captcha",
    "unusual traffic",
    "verify you are human",
)


def normalize_token(value: str) -> str:
    return _TOKEN_RE.sub("", value.lower())[:200]


def looks_blocked(text: str) -> bool:
    lowered = (text or "")[:_MAX_SCAN_BYTES].lower()
    return any(marker in lowered for marker in BLOCK_MARKERS)


def has_identity_signal(text: str, values: Iterable[str]) -> bool:
    sample = (text or "")[:_MAX_SCAN_BYTES]
    lowered = sample.lower()
    compact = normalize_token(sample)
    for value in values:
        token = str(value or "").strip().lower()
        if len(token) < 3:
            continue
        if token in lowered:
            return True
        normalized = normalize_token(token)
        if len(normalized) >= 4 and normalized in compact:
            return True
    return False
