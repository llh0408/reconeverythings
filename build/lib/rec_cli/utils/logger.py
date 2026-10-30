"""Clean ASCII stdout logging for the CLI and engine."""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from typing import TextIO


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_GOLD = "1;38;5;220"
_LEVEL_STYLES = {
    "INFO": "38;5;220",
    "FOUND": "38;5;46",
    "WARN": "38;5;214",
    "STEALTH": "38;5;51",
    "ERROR": "38;5;196",
    "SUMMARY": _GOLD,
}
_MESSAGE_STYLES = {
    "FOUND": "38;5;46",
    "WARN": "38;5;214",
    "STEALTH": "38;5;51",
    "ERROR": "38;5;196",
    "SUMMARY": _GOLD,
}
_MODULE_STYLE = _GOLD
_MODULE_DONE_STYLE = "38;5;42"


def color_enabled(stream: TextIO) -> bool:
    """Honor REC_COLOR, NO_COLOR, and TTY detection for ANSI output."""
    mode = os.environ.get("REC_COLOR", "auto").strip().lower()
    if mode in {"never", "0", "false", "no", "off"}:
        return False
    if mode in {"always", "1", "true", "yes", "on"}:
        return True
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def ascii_text(value: object, limit: int | None = None) -> str:
    """Normalize external text to printable ASCII without decorative glyphs."""
    text = unicodedata.normalize("NFKD", str(value))
    text = text.encode("ascii", errors="ignore").decode("ascii")
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    if limit is not None and len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def safe_text(value: object, limit: int = 800) -> str:
    """Strip terminal controls, non-ASCII data, and bound external text."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = ascii_text(text, limit)
    return text


class Logger:
    def __init__(
        self,
        quiet: bool = False,
        stream: TextIO | None = None,
        color: bool | None = None,
    ) -> None:
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.color = color_enabled(self.stream) if color is None else color

    def _paint(self, style: str, text: str) -> str:
        if not self.color:
            return text
        return f"\x1b[{style}m{text}\x1b[0m"

    def _emit(self, level: str, message: str, message_style: str | None = None) -> None:
        cleaned = safe_text(message, 2000)
        tag = self._paint(_LEVEL_STYLES.get(level, "0"), f"[{level}]")
        style = message_style if message_style is not None else _MESSAGE_STYLES.get(level)
        body = self._paint(style, cleaned) if style else cleaned
        print(f"{tag} {body}", file=self.stream, flush=True)

    def _emit_plain(self, message: str, style: str | None = None) -> None:
        cleaned = safe_text(message, 2000)
        body = self._paint(style, cleaned) if style else cleaned
        print(body, file=self.stream, flush=True)

    def banner(self, target: str, mode: str, stealth: bool) -> None:
        if self.quiet:
            return
        self._emit_plain(
            "ReconEveryThings (recn) - reconnaissance framework", _GOLD
        )
        content = f"target={safe_text(target)} mode={mode} stealth={str(stealth).lower()}"
        self._emit_plain(content)
        self._emit_plain("Use only on assets you are authorized to assess.")

    def info(self, message: str) -> None:
        if not self.quiet:
            self._emit("INFO", message)

    def found(self, message: str) -> None:
        if not self.quiet:
            self._emit("FOUND", message)

    def warn(self, message: str) -> None:
        if not self.quiet:
            self._emit("WARN", message)

    def stealth(self, message: str) -> None:
        if not self.quiet:
            self._emit("STEALTH", message)

    def error(self, message: str) -> None:
        self._emit("ERROR", message)

    def summary(self, message: str) -> None:
        self._emit("SUMMARY", message)

    def module_start(self, name: str, index: int, total: int) -> None:
        if not self.quiet:
            label = safe_text(name).upper()
            self._emit("INFO", f"Module {index}/{total}: {label}", _MODULE_STYLE)

    def module_done(self, name: str, elapsed: float) -> None:
        if not self.quiet:
            label = safe_text(name).upper()
            self._emit(
                "INFO",
                f"Module complete: {label} ({elapsed:.2f}s)",
                _MODULE_DONE_STYLE,
            )
