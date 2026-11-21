"""Interpretação de alvos de varredura."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable

MAX_TARGETS = 1 << 16

_FULL_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")
_SHORT_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def expand_target(token: str) -> list[str]:
    token = token.strip()
    if not token:
        return []

    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if network.num_addresses > MAX_TARGETS:
            raise ValueError(
                f"{token} expande para {network.num_addresses} endereços (máximo {MAX_TARGETS})"
            )
        if network.version == 4 and network.prefixlen < 31:
            return [str(host) for host in network.hosts()]
        return [str(addr) for addr in network]

    match = _FULL_RANGE.match(token)
    if match:
        start = ipaddress.IPv4Address(match.group(1))
        end = ipaddress.IPv4Address(match.group(2))
        if end < start:
            raise ValueError(f"intervalo inválido (fim antes do inicio): {token}")
        if int(end) - int(start) + 1 > MAX_TARGETS:
            raise ValueError(f"intervalo {token} é grande demais (máximo {MAX_TARGETS})")
        return [str(ipaddress.IPv4Address(value)) for value in range(int(start), int(end) + 1)]

    match = _SHORT_RANGE.match(token)
    if match:
        prefix = match.group(1)
        low = int(match.group(2))
        high = int(match.group(3))
        if not (0 <= low <= high <= 255):
            raise ValueError(f"intervalo inválido: {token}")
        ipaddress.IPv4Address(f"{prefix}{low}")
        return [f"{prefix}{value}" for value in range(low, high + 1)]

    try:
        return [str(ipaddress.ip_address(token))]
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(token, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"não foi possivel resolver o alvo '{token}': {exc}") from None

    addresses: list[str] = []
    for item in results:
        ip = item[4][0]
        if ip not in addresses:
            addresses.append(ip)
    return addresses


def parse_targets(tokens: Iterable[str], exclude: Iterable[str] = ()) -> list[str]:
    excluded: set[str] = set()
    for token in exclude:
        for part in token.split(","):
            excluded.update(expand_target(part))

    ordered: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        for part in token.split(","):
            for ip in expand_target(part):
                if ip not in seen and ip not in excluded:
                    seen.add(ip)
                    ordered.append(ip)
    return ordered