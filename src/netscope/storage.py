"""Histórico de scans em SQLite."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path


def default_db_path() -> Path:
    override = os.environ.get("NETSCOPE_DB")
    return Path(override) if override else Path.home() / ".netscope" / "netscope.db"


class Store:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                targets TEXT,
                ports_spec TEXT,
                hosts_up INTEGER,
                open_ports INTEGER,
                data TEXT NOT NULL
            )"""
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def save_scan(self, scan: dict) -> int:
        cursor = self.db.execute(
            """INSERT INTO scans (name, started_at, finished_at, targets, ports_spec,
                                  hosts_up, open_ports, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.get("name"),
                scan["started_at"],
                scan.get("finished_at"),
                " ".join(scan.get("targets_input", [])),
                scan.get("ports_spec"),
                scan["stats"]["hosts_up"],
                scan["stats"]["open_ports"],
                json.dumps(scan),
            ),
        )
        self.db.commit()
        scan["id"] = cursor.lastrowid
        return cursor.lastrowid

    def list_scans(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            """SELECT id, name, started_at, targets, ports_spec, hosts_up, open_ports
               FROM scans ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, ref: str | int) -> dict:
        token = str(ref).strip().lower()
        if token in ("last", "latest", "prev", "previous"):
            offset = 0 if token in ("last", "latest") else 1
            row = self.db.execute(
                "SELECT id, data FROM scans ORDER BY id DESC LIMIT 1 OFFSET ?", (offset,)
            ).fetchone()
        else:
            try:
                scan_id = int(token)
            except ValueError:
                raise LookupError(f"referência de scan inválida: '{ref}'") from None
            row = self.db.execute(
                "SELECT id, data FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()

        if row is None:
            raise LookupError(f"scan '{ref}' não encontrado")
        scan = json.loads(row["data"])
        scan["id"] = row["id"]
        return scan