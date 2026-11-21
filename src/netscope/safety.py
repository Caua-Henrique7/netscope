"""Limites de escopo da varredura."""

from __future__ import annotations

import ipaddress

NOTICE = "Use apenas em redes e sistemas que você possuiu ou tem autorização por escrito para testar."


def is_internal(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def public_targets(ips: list[str]) -> list[str]:
    return [ip for ip in ips if not is_internal(ip)]


def enforce_scope(ips: list[str], allow_public: bool) -> None:
    if allow_public:
        return
    public = public_targets(ips)
    if public:
        sample = ", ".join(public[:3]) + (" ..." if len(public) > 3 else "")
        raise ValueError(
            f"recusando escanear {len(public)} endereço(s) publico(s) ({sample})."
            "Use --allow-public apenas se você tem autorização para testa-los."
        )