"""Read access to the event store for one case.

A ``CaseStore`` is bound to the recording a case came from. Every query is limited
to that recording, so an investigation can never read another case's data, and the
recording's name (which states the attack technique) is never exposed.
"""

from __future__ import annotations

import ntpath
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import paths
from .corpus import SYSMON, open_store, unpack_fields
from .events import describe

POWERSHELL = "microsoft-windows-powershell/operational"

# Event kinds an investigator asks for, mapped to (channel, event ids).
KINDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "process": (SYSMON, (1,)),
    "network": (SYSMON, (3,)),
    "dns": (SYSMON, (22,)),
    "image_load": (SYSMON, (7,)),
    "remote_thread": (SYSMON, (8,)),
    "process_access": (SYSMON, (10,)),
    "file": (SYSMON, (11, 15, 23, 26, 2)),
    "registry": (SYSMON, (12, 13, 14)),
    "pipe": (SYSMON, (17, 18)),
    "wmi": (SYSMON, (19, 20, 21)),
    "powershell": (POWERSHELL, (4103, 4104)),
    "logon": ("security", (4624, 4625, 4648, 4672)),
    "service_or_task": ("security", (4697, 4698, 4699, 4700, 4701, 4702)),
    "account": ("security", (4720, 4722, 4724, 4728, 4732, 4756)),
    "share": ("security", (5140, 5145)),
}


@dataclass
class Event:
    id: int
    ts: str
    host: str
    channel: str
    eid: int
    pguid: str | None
    fields: dict[str, str]

    def line(self, limit: int = 220) -> str:
        return f"[E{self.id}] {self.ts[11:23]} {describe(self.channel, self.eid, self.fields, limit)}"

    def line_with_process(self, limit: int = 220) -> str:
        """The same line followed by the id of the process the event belongs to."""
        return self.line(limit) + (f"  process={self.pguid}" if self.pguid else "")


def _event(row: sqlite3.Row) -> Event:
    return Event(row["id"], row["ts"], row["host"], row["channel"], row["eid"], row["pguid"], unpack_fields(row["data"]))


class CaseStore:
    def __init__(self, capture: str, connection: sqlite3.Connection | None = None, path: Path | None = None):
        self.capture = capture
        self.connection = connection or open_store(path or paths.STORE_FILE)

    # ------------------------------------------------------------------ processes

    def process(self, pguid: str) -> dict | None:
        row = self.connection.execute("SELECT * FROM processes WHERE capture = ? AND pguid = ?", (self.capture, pguid.lower())).fetchone()
        return dict(row) if row else None

    def ancestors(self, pguid: str, limit: int = 8) -> list[dict]:
        chain, seen = [], {pguid.lower()}
        current = self.process(pguid)
        while current and current.get("parent_pguid") and len(chain) < limit:
            parent = self.process(current["parent_pguid"])
            if parent is None or parent["pguid"] in seen:
                break
            chain.append(parent)
            seen.add(parent["pguid"])
            current = parent
        return chain

    def children(self, pguid: str, limit: int = 25) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM processes WHERE capture = ? AND parent_pguid = ? ORDER BY first_seen LIMIT ?",
            (self.capture, pguid.lower(), limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def processes_by_image(self, image: str, host: str | None = None) -> list[dict]:
        """Processes whose program path ends with the given path or file name."""
        wanted = image.replace("/", "\\").strip().strip('"').lower()
        name = ntpath.basename(wanted)
        if not name:
            return []
        clause, args = "capture = ? AND lower(image) LIKE ?", [self.capture, "%" + name]
        if host:
            clause += " AND host = ?"
            args.append(host.lower())
        rows = [dict(r) for r in self.connection.execute(f"SELECT * FROM processes WHERE {clause}", args)]
        exact = [r for r in rows if (r["image"] or "").lower() == wanted]
        named = [r for r in rows if ntpath.basename((r["image"] or "").lower()) == name]
        return exact or named

    def creation_event(self, pguid: str) -> Event | None:
        record = self.process(pguid)
        if not record or not record.get("event_id"):
            return None
        return self.event(record["event_id"])

    # --------------------------------------------------------------------- events

    def event(self, event_id: int) -> Event | None:
        row = self.connection.execute("SELECT * FROM events WHERE id = ? AND capture = ?", (event_id, self.capture)).fetchone()
        return _event(row) if row else None

    def process_event_counts(self, pguid: str) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT channel, eid, COUNT(*) AS n FROM events WHERE capture = ? AND pguid = ? GROUP BY channel, eid",
            (self.capture, pguid.lower()),
        ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            for kind, (channel, ids) in KINDS.items():
                if row["channel"] == channel and row["eid"] in ids:
                    counts[kind] = counts.get(kind, 0) + row["n"]
        return counts

    def process_events(self, pguid: str, kind: str | None = None, limit: int = 30, offset: int = 0) -> tuple[list[Event], int]:
        clause, args = "capture = ? AND pguid = ?", [self.capture, pguid.lower()]
        if kind:
            channel, ids = KINDS[kind]
            clause += f" AND channel = ? AND eid IN ({','.join('?' * len(ids))})"
            args += [channel, *ids]
        total = self.connection.execute(f"SELECT COUNT(*) FROM events WHERE {clause}", args).fetchone()[0]
        rows = self.connection.execute(
            f"SELECT * FROM events WHERE {clause} ORDER BY id LIMIT ? OFFSET ?", [*args, limit, offset]
        ).fetchall()
        return [_event(r) for r in rows], total

    def window(self, host: str, start: str, end: str, kinds: list[str] | None = None) -> list[Event]:
        clause, args = "capture = ? AND host = ? AND ts >= ? AND ts <= ?", [self.capture, host.lower(), start, end]
        if kinds:
            parts = []
            for kind in kinds:
                channel, ids = KINDS[kind]
                parts.append(f"(channel = ? AND eid IN ({','.join('?' * len(ids))}))")
                args += [channel, *ids]
            clause += " AND (" + " OR ".join(parts) + ")"
        rows = self.connection.execute(f"SELECT * FROM events WHERE {clause} ORDER BY ts, id", args).fetchall()
        return [_event(r) for r in rows]

    def search(self, text: str, kinds: list[str] | None = None, host: str | None = None, limit: int = 30) -> tuple[list[Event], int]:
        """Case-insensitive substring search over event fields in this recording."""
        needle = text.lower()
        clause, args = "capture = ?", [self.capture]
        if host:
            clause += " AND host = ?"
            args.append(host.lower())
        if kinds:
            parts = []
            for kind in kinds:
                channel, ids = KINDS[kind]
                parts.append(f"(channel = ? AND eid IN ({','.join('?' * len(ids))}))")
                args += [channel, *ids]
            clause += " AND (" + " OR ".join(parts) + ")"
        found, total = [], 0
        for row in self.connection.execute(f"SELECT * FROM events WHERE {clause} ORDER BY id", args):
            event = _event(row)
            if any(needle in value.lower() for value in event.fields.values()):
                total += 1
                if len(found) < limit:
                    found.append(event)
        return found, total

    def hosts(self) -> list[str]:
        rows = self.connection.execute("SELECT DISTINCT host FROM events WHERE capture = ?", (self.capture,)).fetchall()
        return sorted(r[0] for r in rows)

    # ----------------------------------------------------------------- prevalence

    def seen_elsewhere(self, kind: str, value: str) -> tuple[int, int]:
        """In how many other recordings, and on how many distinct days, a value appears."""
        row = self.connection.execute(
            "SELECT COUNT(DISTINCT capture), COUNT(DISTINCT day) FROM seen WHERE kind = ? AND value = ? AND capture != ?",
            (kind, value.lower(), self.capture),
        ).fetchone()
        return row[0], row[1]

    def other_recordings(self) -> int:
        return self.connection.execute("SELECT COUNT(DISTINCT capture) FROM seen WHERE capture != ?", (self.capture,)).fetchone()[0]


def pair_key(parent_image: str | None, image: str | None) -> str | None:
    if not parent_image or not image:
        return None
    return f"{ntpath.basename(parent_image).lower()}>{ntpath.basename(image).lower()}"
