"""Impressões digitais de identidade de host: TLS, SSH e MAC."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct

_KEXINIT = 20
_ECDH_INIT = 30
_ECDH_REPLY = 31
_CLIENT_IDENT = b"SSH-2.0-netscope_0.1\r\n"

TLS_HINT_PORTS = (443, 465, 563, 636, 853, 989, 990, 993, 995, 2376, 4443, 5986, 8443, 9443)


def _tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except Exception:
        pass
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


async def tls_fingerprint(ip: str, port: int, timeout: float = 2.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_tls_context()), timeout
        )
    except Exception:
        return None
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    except Exception:
        der = None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except Exception:
            pass
    if not der:
        return None
    return "SHA256:" + hashlib.sha256(der).hexdigest()


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _ssh_name_list(names: str) -> bytes:
    return _ssh_string(names.encode("ascii"))


def _ssh_build_packet(payload: bytes) -> bytes:
    base = 5 + len(payload)
    pad = 8 - (base % 8)
    if pad < 4:
        pad += 8
    length = 1 + len(payload) + pad
    return struct.pack(">I", length) + struct.pack(">B", pad) + payload + b"\x00" * pad


def _ssh_kexinit_payload() -> bytes:
    payload = bytes([_KEXINIT]) + os.urandom(16)
    payload += _ssh_name_list("curve25519-sha256,curve25519-sha256@libssh.org")
    payload += _ssh_name_list("ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp256")
    payload += _ssh_name_list("aes128-ctr")
    payload += _ssh_name_list("aes128-ctr")
    payload += _ssh_name_list("hmac-sha2-256")
    payload += _ssh_name_list("hmac-sha2-256")
    payload += _ssh_name_list("none")
    payload += _ssh_name_list("none")
    payload += _ssh_name_list("")
    payload += _ssh_name_list("")
    payload += b"\x00"
    payload += struct.pack(">I", 0)
    return payload


async def _ssh_read_packet(reader: asyncio.StreamReader, timeout: float) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout)
    length = struct.unpack(">I", header)[0]
    if not (1 <= length <= 100000):
        raise ValueError("pacote SSH inválido")
    body = await asyncio.wait_for(reader.readexactly(length), timeout)
    pad = body[0]
    return body[1:len(body) - pad]


async def ssh_host_key_fingerprint(ip: str, port: int = 22, timeout: float = 3.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return None
    try:
        writer.write(_CLIENT_IDENT)
        await writer.drain()

        for _ in range(20):
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                return None
            if line.startswith(b"SSH-"):
                break
        else:
            return None

        writer.write(_ssh_build_packet(_ssh_kexinit_payload()))
        await writer.drain()
        for _ in range(5):
            payload = await _ssh_read_packet(reader, timeout)
            if payload and payload[0] == _KEXINIT:
                break
        else:
            return None

        writer.write(_ssh_build_packet(bytes([_ECDH_INIT]) + _ssh_string(os.urandom(32))))
        await writer.drain()
        for _ in range(5):
            payload = await _ssh_read_packet(reader, timeout)
            if payload and payload[0] == _ECDH_REPLY:
                break
        else:
            return None

        offset = 1
        key_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        host_key = payload[offset:offset + key_len]
        if len(host_key) != key_len or key_len == 0:
            return None
        digest = hashlib.sha256(host_key).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except Exception:
            pass


def mac_from_arp(ip: str, path: str = "/proc/net/arp") -> str | None:
    try:
        with open(path, encoding="ascii") as handle:
            next(handle, None)
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip:
                    mac = fields[3].lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except OSError:
        return None
    return None


async def collect_identity(ip: str, open_ports: list[int], timeout: float = 2.0) -> dict:
    identity: dict = {"tls": None, "ssh": None, "mac": None}

    if 22 in open_ports:
        identity["ssh"] = await ssh_host_key_fingerprint(ip, 22, timeout + 1.0)

    for port in open_ports:
        if port in TLS_HINT_PORTS:
            fingerprint = await tls_fingerprint(ip, port, timeout)
            if fingerprint:
                identity["tls"] = fingerprint
                break

    identity["mac"] = mac_from_arp(ip)
    return identity


def asset_key(identity: dict | None) -> str | None:
    if not identity:
        return None
    if identity.get("tls"):
        return f"tls:{identity['tls']}"
    if identity.get("ssh"):
        return f"ssh:{identity['ssh']}"
    if identity.get("mac"):
        return f"mac:{identity['mac']}"
    return None