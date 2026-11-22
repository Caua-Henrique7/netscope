"""Motor de varredura: descoberta de hosts e scan de portas TCP."""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import itertools
import random
import socket
import time
from collections.abc import Callable
from datetime import datetime, timezone

from . import __version__
from .ports import SERVICE_NAMES
from .utils import Progress, RateLimiter, safe_concurrency

DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 135, 139, 53, 8080, 21, 25)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def tcp_connect(ip: str, port: int, timeout: float) -> tuple[str, float | None]:
    for attempt in range(3):
        start = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except asyncio.TimeoutError:
            return "filtered", None
        except ConnectionRefusedError:
            return "closed", (time.monotonic() - start) * 1000
        except OSError as exc:
            if exc.errno in (errno.EMFILE, errno.ENFILE) and attempt < 2:
                await asyncio.sleep(0.25)
                continue
            return "filtered", None
        latency = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except Exception:
            pass
        return "open", latency
    return "filtered", None


async def discover(
    ips: list[str], timeout: float, concurrency: int, limiter: RateLimiter, progress: Progress
) -> dict[str, float]:
    alive: dict[str, float] = {}

    async def probe(ip: str, port: int) -> float | None:
        await limiter.acquire()
        state, latency = await tcp_connect(ip, port, timeout)
        return latency if state in ("open", "closed") else None

    async def host_alive(ip: str) -> float | None:
        tasks = [asyncio.ensure_future(probe(ip, port)) for port in DISCOVERY_PORTS]
        try:
            for future in asyncio.as_completed(tasks):
                latency = await future
                if latency is not None:
                    return latency
            return None
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    pending = iter(ips)

    async def worker() -> None:
        for ip in pending:
            latency = await host_alive(ip)
            if latency is not None:
                alive[ip] = latency
            progress.tick()

    workers = max(1, min(len(ips), max(1, concurrency // len(DISCOVERY_PORTS))))
    await asyncio.gather(*(worker() for _ in range(workers)))
    return alive


async def scan_ports(
    ips: list[str], ports: list[int], timeout: float, concurrency: int,
    limiter: RateLimiter, progress: Progress,
) -> dict[str, dict]:
    state: dict[str, dict] = {
        ip: {"open": {}, "closed": 0, "filtered": 0, "latency": None} for ip in ips
    }
    pairs = itertools.product(ports, ips)

    async def worker() -> None:
        for port, ip in pairs:
            await limiter.acquire()
            result, latency = await tcp_connect(ip, port, timeout)
            entry = state[ip]
            if result == "open":
                entry["open"][port] = latency
            else:
                entry[result] += 1
            if latency is not None and (entry["latency"] is None or latency < entry["latency"]):
                entry["latency"] = latency
            progress.tick()

    workers = max(1, min(concurrency, len(ports) * len(ips)))
    await asyncio.gather(*(worker() for _ in range(workers)))
    return state


async def _reverse_dns(ip: str, sem: asyncio.Semaphore) -> str | None:
    async with sem:
        loop = asyncio.get_running_loop()
        try:
            name, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), 2.0
            )
            return name
        except Exception:
            return None


async def run_scan(
    ips: list[str],
    ports: list[int],
    *,
    timeout: float = 1.5,
    concurrency: int = 256,
    rate: float | None = None,
    skip_discovery: bool = False,
    resolve_dns: bool = True,
    randomize: bool = True,
    show_progress: bool = True,
    log: Callable[[str], None] | None = None,
    meta: dict | None = None,
) -> dict:
    log = log or (lambda message: None)
    started = time.monotonic()
    started_at = _now()
    concurrency = safe_concurrency(concurrency)
    limiter = RateLimiter(rate)

    ports = list(ports)
    if randomize:
        random.shuffle(ports)

    if skip_discovery:
        alive: dict[str, float] = {}
        candidates = list(ips)
        log(f"[*] Pulando descoberta: tratando {len(ips)} endereço(s) como ativos")
    else:
        log(f"[*] Descobrindo hosts ({len(ips)} endereço(s))...")
        progress = Progress(len(ips), "descoberta", show_progress)
        alive = await discover(ips, timeout, concurrency, limiter, progress)
        progress.close()
        candidates = [ip for ip in ips if ip in alive]
        log(f"[+] {len(candidates)} host(s) ativo(s)")

    states: dict[str, dict] = {}
    if candidates:
        log(f"[*] Escaneando {len(ports)} porta(s) em {len(candidates)} host(s)...")
        progress = Progress(len(ports) * len(candidates), "portas", show_progress)
        states = await scan_ports(candidates, ports, timeout, concurrency, limiter, progress)
        progress.close()
        log(f"[+] {sum(len(s['open']) for s in states.values())} porta(s) aberta(s)")

    reported = [
        ip for ip in candidates
        if ip in alive or (ip in states and (states[ip]["open"] or states[ip]["closed"] > 0))
    ]

    hosts: dict[str, dict] = {}
    for ip in reported:
        entry = states.get(ip, {"open": {}, "closed": 0, "filtered": 0, "latency": None})
        latency = alive.get(ip, entry["latency"])
        hosts[ip] = {
            "ip": ip,
            "hostname": None,
            "latency_ms": round(latency, 2) if latency is not None else None,
            "ports": [
                {"port": port, "proto": "tcp", "state": "open",
                 "service": SERVICE_NAMES.get(port, "unknown")}
                for port in sorted(entry["open"])
            ],
            "closed": entry["closed"],
            "filtered": entry["filtered"],
        }

    if resolve_dns and hosts:
        sem = asyncio.Semaphore(32)
        names = await asyncio.gather(*(_reverse_dns(ip, sem) for ip in hosts))
        for ip, name in zip(hosts, names):
            hosts[ip]["hostname"] = name

    def ip_key(host: dict) -> tuple[int, int]:
        address = ipaddress.ip_address(host["ip"])
        return (address.version, int(address))

    host_list = sorted(hosts.values(), key=ip_key)
    result = {
        "tool": "netscope",
        "version": __version__,
        "started_at": started_at,
        "finished_at": _now(),
        "duration_s": round(time.monotonic() - started, 2),
        "stats": {
            "addresses_scanned": len(ips),
            "hosts_up": len(host_list),
            "open_ports": sum(len(host["ports"]) for host in host_list),
        },
        "hosts": host_list,
    }
    result.update(meta or {})
    return result