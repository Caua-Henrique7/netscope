import asyncio
import socket

from netscope.engine import run_scan


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _serve(port: int):
    return await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", port)


def test_scan_finds_open_and_ignores_closed():
    open_port = _free_port()
    closed_port = _free_port()

    async def run():
        server = await _serve(open_port)
        try:
            return await run_scan(
                ["127.0.0.1"], [open_port, closed_port],
                timeout=1.0, resolve_dns=False, show_progress=False,
            )
        finally:
            server.close()
            await server.wait_closed()

    scan = asyncio.run(run())
    assert scan["stats"]["hosts_up"] == 1
    ports = {p["port"]: p for p in scan["hosts"][0]["ports"]}
    assert open_port in ports
    assert closed_port not in ports
    assert ports[open_port]["proto"] == "tcp"
    assert "service" in ports[open_port]


def test_closed_port_means_host_up_zero_open():
    closed_port = _free_port()
    scan = asyncio.run(run_scan(
        ["127.0.0.1"], [closed_port], timeout=1.0, resolve_dns=False, show_progress=False,
    ))
    assert scan["stats"]["hosts_up"] == 1
    assert scan["stats"]["open_ports"] == 0
    assert scan["hosts"][0]["closed"] == 1


def test_skip_discovery_still_scans():
    open_port = _free_port()

    async def run():
        server = await _serve(open_port)
        try:
            return await run_scan(
                ["127.0.0.1"], [open_port],
                timeout=1.0, skip_discovery=True, resolve_dns=False, show_progress=False,
            )
        finally:
            server.close()
            await server.wait_closed()

    scan = asyncio.run(run())
    assert scan["stats"]["open_ports"] == 1


def test_meta_passthrough():
    closed_port = _free_port()
    scan = asyncio.run(run_scan(
        ["127.0.0.1"], [closed_port], timeout=1.0, resolve_dns=False, show_progress=False,
        meta={"name": "teste", "targets_input": ["127.0.0.1"]},
    ))
    assert scan["name"] == "teste"
    assert scan["targets_input"] == ["127.0.0.1"]
    assert scan["tool"] == "netscope"


def test_identity_collected_for_tls(monkeypatch):
    import ssl
    import subprocess
    import tempfile
    from pathlib import Path

    from netscope import identity as idmod

    tmp = tempfile.TemporaryDirectory()
    cert = Path(tmp.name) / "c.pem"
    key = Path(tmp.name) / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=lab"],
        check=True, capture_output=True, 
    )
    port = _free_port()
    monkeypatch.setattr(idmod, "TLS_HINT_PORTS", (port,))

    async def run():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", port, ssl=context
        )
        try:
            return await run_scan(
                ["127.0.0.1"], [port], timeout=2.0, resolve_dns=False, show_progress=False,
            )
        finally:
            server.close()
            await server.wait_closed()

    scan = asyncio.run(run())
    host = scan["hosts"][0]
    assert host["identity"]["tls"] and host["identity"]["tls"].startswith("SHA256:")
    assert host["asset_key"].startswith("tls:")


def test_identity_disabled_leaves_none():
    closed_port = _free_port()
    scan = asyncio.run(run_scan(
        ["127.0.0.1"], [closed_port], timeout=1.0, resolve_dns=False,
        show_progress=False, identity=False,
    ))
    host = scan["hosts"][0]
    assert host["identity"] is None
    assert host["asset_key"] is None