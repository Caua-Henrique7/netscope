import asyncio
import hashlib
import base64
import ssl
import subprocess
import tempfile
from pathlib import Path

from netscope import identity
from netscope.identity import (
    asset_key,
    mac_from_arp,
    ssh_host_key_fingerprint,
    tls_fingerprint,
)


def _make_cert(directory: Path):
    cert, key = directory / "c.pem", directory / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=lab"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


def test_tls_fingerprint_matches_cert():
    tmp = tempfile.TemporaryDirectory()
    cert_path, key_path = _make_cert(Path(tmp.name))
    der = ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text())
    expected = "SHA256:" + hashlib.sha256(der).hexdigest()

    async def run():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0, ssl=context
        )
        port = server.sockets[0].getsockname()[1]
        try:
            return await tls_fingerprint("127.0.0.1", port, timeout=3.0)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(run()) == expected


def test_ssh_fingerprint_parses_host_key():
    host_key = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + b"K" * 32
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(host_key).digest()).decode().rstrip("=")

    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.readline(), 3.0)
            writer.write(b"SSH-2.0-FakeSSH\r\n")
            await writer.drain()
            await identity._ssh_read_packet(reader, 3.0)
            writer.write(identity._ssh_build_packet(identity._ssh_kexinit_payload()))
            await writer.drain()
            await identity._ssh_read_packet(reader, 3.0)
            reply = (bytes([identity._ECDH_REPLY])
                     + identity._ssh_string(host_key)
                     + identity._ssh_string(b"Q" * 32)
                     + identity._ssh_string(b"S" * 64))
            writer.write(identity._ssh_build_packet(reply))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await ssh_host_key_fingerprint("127.0.0.1", port, timeout=3.0)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(run()) == expected


def test_ssh_fingerprint_none_on_non_ssh():
    async def run():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await ssh_host_key_fingerprint("127.0.0.1", port, timeout=1.0)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(run()) is None


def test_mac_from_arp_parses(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.0.10     0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n"
        "192.168.0.20     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
    )
    assert mac_from_arp("192.168.0.10", str(arp)) == "aa:bb:cc:dd:ee:ff"
    assert mac_from_arp("192.168.0.20", str(arp)) is None
    assert mac_from_arp("192.168.0.99", str(arp)) is None
    assert mac_from_arp("192.168.0.10", "/caminho/inexistente") is None


def test_asset_key_priority():
    assert asset_key({"tls": "SHA256:a", "ssh": "SHA256:b", "mac": "x"}) == "tls:SHA256:a"
    assert asset_key({"tls": None, "ssh": "SHA256:b", "mac": "x"}) == "ssh:SHA256:b"
    assert asset_key({"tls": None, "ssh": None, "mac": "x"}) == "mac:x"
    assert asset_key({"tls": None, "ssh": None, "mac": None}) is None
    assert asset_key(None) is None