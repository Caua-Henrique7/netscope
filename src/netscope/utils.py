"""FUnções de apoio: cores, controle de ritmo e progresso."""

from __future__ import annotations

import asyncio
import os
import sys
import time

_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return str(text)
    codes = ";".join(_CODES[style] for style in styles)
    return f"\033[{codes}m{text}\033[0m"


class RateLimiter:
    def __init__(self, rate: float | None):
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()


    async def acquire(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)


class Progress:
    def __init__(self, total: int, label: str, enabled: bool = True, stream=None):
        self.total = total
        self.label = label
        self.n = 0
        self.stream = stream or sys.stderr
        self.enabled = enabled and hasattr(self.stream, "isatty") and self.stream.isatty()
        self._last = 0.0


    def tick(self, step: int = 1) -> None:
        self.n += step
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self._last >= 0.2 or self.n >= self.total:
            self._last = now
            pct = 100 * self.n / self.total if self.total else 100
            self.stream.write(f"\r[*] {self.label}: {self.n}/{self.total} ({pct:3.0f}%)")
            self.stream.flush()


    def close(self) -> None:
        if self.enabled:
            self.stream.write("\r" + " " * 70 + "\r")
            self.stream.flush()


def safe_concurrency(requested: int) -> int:
    requested = max(1, int(requested))
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < target:
            for value in (target, 10240, 4096, 2048):
                if value <= soft:
                    break
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (value, hard))
                    break
                except (ValueError, OSError):
                    continue
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return max(1, min(requested, soft - 64))
    except Exception:
        return max(1, min(requested, 900))