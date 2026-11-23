"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .engine import run_scan
from .ports import parse_ports
from .safety import NOTICE, enforce_scope
from .targets import parse_targets
from .utils import paint, use_color


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _read_target_file(path: str) -> list[str]:
    tokens: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                tokens.append(line)
    return tokens


def render_scan(scan: dict, color: bool = True) -> str:
    style = lambda text, *names: paint(text, *names, enabled=color)
    lines: list[str] = []

    for host in scan["hosts"]:
        title = host["ip"] + (f" ({host['hostname']})" if host.get("hostname") else "")
        latency = f"  {host['latency_ms']:.1f} ms" if host.get("latency_ms") is not None else ""
        lines.append("")
        lines.append(style(title, "bold", "green") + style(latency, "dim"))

        if not host["ports"]:
            lines.append(style(
                f"  sem portas abertas ({host['closed']} fechadas, {host['filtered']} filtradas)",
                "dim",
            ))
            continue

        rows = [(f"{rec['port']}/{rec['proto']}", rec["service"]) for rec in host["ports"]]
        width = max([len(row[0]) for row in rows] + [5])
        lines.append(style(f"  {'PORTA':<{width}}  SERVIÇO", "dim"))
        for column, service in rows:
            lines.append(f"  {column:<{width}}  {service}")

    stats = scan["stats"]
    lines.append("")
    lines.append(style(
        f"{stats['hosts_up']} host(s) ativo(s) de {stats['addresses_scanned']} endereço(s) | "
        f"{stats['open_ports']} porta(s) aberta(s) | {scan['duration_s']}s",
        "bold",
    ))
    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace) -> int:
    tokens = list(args.targets)
    if args.input_list:
        tokens += _read_target_file(args.input_list)
    if not tokens:
        raise ValueError("nenhum alvo informado (passe alvos ou use -iL ARQUIVO)")

    ips = parse_targets(tokens, args.exclude)
    if not ips:
        raise ValueError("lista de alvos vazia após as exclusões")
    enforce_scope(ips, args.allow_public)
    ports = parse_ports(args.ports)

    quiet = args.quiet
    log = (lambda message: None) if quiet else _log
    if not quiet:
        _log(f"[!] {NOTICE}")

    scan = asyncio.run(run_scan(
        ips, ports,
        timeout=args.timeout, concurrency=args.concurrency, rate=args.rate,
        skip_discovery=args.skip_discovery, resolve_dns=not args.no_dns,
        randomize=not args.no_randomize, show_progress=not quiet, log=log,
        meta={"name": args.name, "targets_input": tokens, "ports_spec": args.ports},
    ))
    print(render_scan(scan, color=use_color()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="Ferramenta de análise de redes. " + NOTICE,
    )
    parser.add_argument("--version", action="version", version=f"netscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="comando")

    scan = sub.add_parser("scan", help="descobre hosts e escaneia portas")
    scan.add_argument("targets", nargs="*", metavar="ALVO",
                      help="IP, CIDR (10.0.0.0/24), range (10.0.0.10-50) ou hostname")
    scan.add_argument("-iL", "--input-list", metavar="ARQUIVO",
                      help="lê os alvos de um arquivo (um por linha)")
    scan.add_argument("--exclude", action="append", default=[], metavar="ALVO",
                      help="alvos a ignorar")
    scan.add_argument("-p", "--ports", default="top",
                      help="'top' (padrão), 'full' ou uma lista/range como 22,80,8000-8100")
    scan.add_argument("-Pn", "--skip-discovery", action="store_true",
                      help="pula a descoberta e trata todo endereço como ativo")
    scan.add_argument("--timeout", type=float, default=1.5,
                      help="tempo limite de conexão em segundos (padrão 1.5)")
    scan.add_argument("-c", "--concurrency", type=int, default=256,
                      help="máximo de conexões em paralelo (padrão 256)")
    scan.add_argument("--rate", type=float, default=None, metavar="N",
                      help="máximo de tentativas de conexão por segundo")
    scan.add_argument("-n", "--no-dns", action="store_true",
                      help="não faz busca reversa de DNS")
    scan.add_argument("--no-randomize", action="store_true",
                      help="escaneia as portas em ordem, sem embaralhar")
    scan.add_argument("--allow-public", action="store_true",
                      help="permite escanear IP público (somente com autorização)")
    scan.add_argument("--name", help="rótulo para este scan")
    scan.add_argument("-q", "--quiet", action="store_true", help="sem mensagens de progresso")
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] interrompido", file=sys.stderr)
        return 130
    except (ValueError, LookupError, OSError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())