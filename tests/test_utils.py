import asyncio
import time

from netscope.utils import Progress, RateLimiter, paint, safe_concurrency, use_color


def test_paint_disabled_returns_plain():
    assert paint("Olá", "red", enabled=False) == "Olá"


def test_paint_enabled_wraps():
    out = paint("oi", "green", enabled=True)
    assert "oi" in out and out.startswith("\033[") and out.endswith("\033[0m")


def test_paint_no_styles():
    assert paint("x", enabled=True) == "x"


def test_use_color_respects_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color() is False


def test_rate_limiter_interval():
    assert RateLimiter(None).interval == 0.0
    assert RateLimiter(0).interval == 0.0
    assert RateLimiter(100).interval == 0.01


def test_rate_limiter_spaces_calls():
    limiter = RateLimiter(50)

    async def run():
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(run())
    assert elapsed >= 0.06


def test_progress_counts_without_tty():
    progress = Progress(total=4, label="teste", enabled=False)
    progress.tick()
    progress.tick(3)
    progress.close()
    assert progress.n == 4


def test_safe_concurrency_bounds():
    assert safe_concurrency(100) <= 100
    assert safe_concurrency(1) == 1
    assert safe_concurrency(0) >= 1