"""Turn the public Security Datasets captures into one queryable event store.

Each capture is a zip of Windows events (one JSON object per line) recorded while a
single attack technique was simulated in a lab. This module reads those files,
normalises timestamps and host names, and writes every event to SQLite.
"""

from __future__ import annotations

import io
import json
import sqlite3
import statistics
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

SYSMON = "microsoft-windows-sysmon/operational"

# Collector plumbing that says nothing about what happened on the host.
DROP_FIELDS = {
    "@version",
    "@timestamp",
    "SourceModuleType",
    "SourceModuleName",
    "port",
    "tags",
    "Keywords",
    "ProviderGuid",
    "OpcodeValue",
    "Opcode",
    "Version",
    "SeverityValue",
    "Severity",
    "EventReceivedTime",
    "EventTime",
    "TimeCreated",
    "UtcTime",
    "host",
    "Hostname",
    "Channel",
    "EventID",
    "ThreadID",
    "RecordNumber",
    "EventType",
    "Task",
    "Level",
    "SourceName",
    "Category",
    "AccountType",
    "UserID",
    "ERROR_EVT_UNRESOLVED",
    "ActivityID",
    "EventRecordID",
    "Correlation",
    "Execution",
    "Security",
    "TimeGenerated",
    "SystemTime",
}
MAX_FIELD_CHARS = 3000
# Bulky fields are shortened in the store. Detection always runs on the full text.
FIELD_CAPS = {"CallTrace": 400, "ContextInfo": 700, "Message": 1200, "Hashes": 200}
# On Sysmon records these describe the Sysmon service itself, not the process in the event.
SYSMON_SELF_FIELDS = {"AccountName", "Domain", "ExecutionProcessID"}


def _stored_fields(channel: str, fields: dict[str, str]) -> dict[str, str]:
    stored = {}
    for key, value in fields.items():
        if value == "-" or (channel == SYSMON and key in SYSMON_SELF_FIELDS):
            continue
        cap = FIELD_CAPS.get(key, MAX_FIELD_CHARS)
        stored[key] = value if len(value) <= cap else value[:cap] + " [truncated]"
    return stored


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    capture TEXT NOT NULL,
    ts TEXT NOT NULL,
    host TEXT NOT NULL,
    channel TEXT NOT NULL,
    eid INTEGER NOT NULL,
    pguid TEXT,
    image TEXT,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_pguid ON events (capture, pguid, eid);
CREATE INDEX IF NOT EXISTS ix_events_time ON events (capture, host, ts);
CREATE INDEX IF NOT EXISTS ix_events_eid ON events (capture, eid);
CREATE TABLE IF NOT EXISTS processes (
    capture TEXT NOT NULL,
    pguid TEXT NOT NULL,
    parent_pguid TEXT,
    event_id INTEGER,
    first_seen TEXT NOT NULL,
    host TEXT NOT NULL,
    pid TEXT,
    image TEXT,
    cmdline TEXT,
    user TEXT,
    integrity TEXT,
    PRIMARY KEY (capture, pguid)
);
CREATE INDEX IF NOT EXISTS ix_proc_parent ON processes (capture, parent_pguid);
CREATE TABLE IF NOT EXISTS prevalence (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    captures INTEGER NOT NULL,
    days INTEGER NOT NULL,
    PRIMARY KEY (kind, value)
);
"""


def iter_raw_events(archive: Path) -> Iterator[dict]:
    """Yield the JSON objects stored in a capture archive (.zip or .tar.gz)."""

    def lines(handle: io.BufferedIOBase) -> Iterator[dict]:
        for raw in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
            raw = raw.strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                yield parsed

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for name in sorted(zf.namelist()):
                if name.endswith(".json"):
                    with zf.open(name) as handle:
                        yield from lines(handle)
    else:
        with tarfile.open(archive) as tf:
            for member in sorted(tf.getmembers(), key=lambda m: m.name):
                if member.isfile() and member.name.endswith(".json"):
                    handle = tf.extractfile(member)
                    if handle is not None:
                        yield from lines(handle)


def _parse_time(text: object) -> datetime | None:
    if not text:
        return None
    value = str(text).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _wall_time(raw: dict) -> datetime | None:
    for key in ("TimeCreated", "EventTime", "@timestamp"):
        parsed = _parse_time(raw.get(key))
        if parsed is not None:
            return parsed
    return None


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def short_host(name: object) -> str:
    return str(name or "unknown").split(".")[0].lower()


def normalize_capture(raw_events: list[dict]) -> list[dict]:
    """Normalise one capture. Returns events sorted by time, each a flat dict.

    Sysmon records carry a true UTC timestamp. Other channels only carry the
    collector's local wall clock, so the offset between the two is measured on the
    Sysmon records and applied to everything else.
    """
    offsets = []
    for raw in raw_events:
        if str(raw.get("Channel", "")).lower() == SYSMON and raw.get("UtcTime"):
            utc, wall = _parse_time(raw["UtcTime"]), _wall_time(raw)
            if utc and wall:
                offsets.append((utc - wall).total_seconds())
        if len(offsets) >= 400:
            break
    # Round to the half hour: the residue is collection delay, not a time zone.
    offset = timedelta(seconds=round(statistics.median(offsets) / 1800) * 1800) if offsets else timedelta(0)

    events = []
    for raw in raw_events:
        channel = str(raw.get("Channel") or "").lower()
        try:
            eid = int(raw.get("EventID"))
        except (TypeError, ValueError):
            continue
        if not channel:
            continue
        moment = _parse_time(raw.get("UtcTime")) if channel == SYSMON else None
        if moment is None:
            wall = _wall_time(raw)
            if wall is None:
                continue
            moment = wall + offset

        fields = {}
        for key, value in raw.items():
            if key in DROP_FIELDS or value is None or isinstance(value, (dict, list)):
                continue
            text = str(value)
            if text == "" or (key == "Message" and (channel in (SYSMON, "security") or "ScriptBlockText" in raw or "Payload" in raw)):
                continue
            fields[key] = text
        events.append({"ts": _iso(moment), "host": short_host(raw.get("Hostname")), "channel": channel, "eid": eid, "fields": fields})
    events.sort(key=lambda e: e["ts"])
    return events


POWERSHELL_CHANNELS = ("microsoft-windows-powershell/operational", "windows powershell")


NULL_GUID = "{00000000-0000-0000-0000-000000000000}"


def clean_guid(guid: object) -> str | None:
    """Lower-case a process GUID; Sysmon's all-zero placeholder counts as unknown."""
    if not guid:
        return None
    value = str(guid).lower()
    return None if value == NULL_GUID else value


def process_guid(event: dict) -> str | None:
    fields = event["fields"]
    return clean_guid(fields.get("ProcessGuid") or fields.get("SourceProcessGuid") or fields.get("SourceProcessGUID"))


def collect_processes(events: list[dict]) -> dict[str, dict]:
    """Assemble what is known about every process GUID seen in a capture.

    A process that started before recording began has no creation event, but it
    still shows up as the parent of a later process or as the subject of a file,
    registry or network event. Those mentions are merged here so that process
    trees do not stop at the edge of the recording.
    """
    processes: dict[str, dict] = {}

    def note(guid: str | None, event: dict, **facts: str | None) -> dict | None:
        guid = clean_guid(guid)
        if not guid:
            return None
        record = processes.setdefault(
            guid,
            {
                "pguid": guid,
                "parent_pguid": None,
                "event_id": None,
                "first_seen": event["ts"],
                "host": event["host"],
                "pid": None,
                "image": None,
                "cmdline": None,
                "user": None,
                "integrity": None,
            },
        )
        for key, value in facts.items():
            if value and not record[key]:
                record[key] = value
        return record

    for event in events:
        if event["channel"] != SYSMON:
            continue
        f = event["fields"]
        if event["eid"] == 1:
            record = note(f.get("ProcessGuid"), event)
            if record is None:
                continue
            # The creation event is authoritative: overwrite anything inferred earlier.
            record.update(
                event_id=event["id"],
                first_seen=event["ts"],
                pid=f.get("ProcessId"),
                image=f.get("Image"),
                cmdline=f.get("CommandLine"),
                user=f.get("User"),
                integrity=f.get("IntegrityLevel"),
                parent_pguid=clean_guid(f.get("ParentProcessGuid")),
            )
            note(
                f.get("ParentProcessGuid"),
                event,
                pid=f.get("ParentProcessId"),
                image=f.get("ParentImage"),
                cmdline=f.get("ParentCommandLine"),
                user=f.get("ParentUser"),
            )
        elif event["eid"] in (8, 10):
            note(
                f.get("SourceProcessGuid") or f.get("SourceProcessGUID"),
                event,
                pid=f.get("SourceProcessId"),
                image=f.get("SourceImage"),
                user=f.get("SourceUser"),
            )
            note(
                f.get("TargetProcessGuid") or f.get("TargetProcessGUID"),
                event,
                pid=f.get("TargetProcessId"),
                image=f.get("TargetImage"),
                user=f.get("TargetUser"),
            )
        else:
            note(f.get("ProcessGuid"), event, pid=f.get("ProcessId"), image=f.get("Image"), user=f.get("User"))
    return processes


def attach_powershell_processes(events: list[dict], processes: dict[str, dict]) -> None:
    """Give PowerShell log records the GUID of the process that wrote them.

    PowerShell's own logs identify their host process only by PID. Matching that
    PID against the Sysmon process list lets script block text be read as part of
    a specific process's activity.
    """
    by_pid: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for record in processes.values():
        if record["pid"]:
            by_pid.setdefault((record["host"], record["pid"]), []).append((record["first_seen"], record["pguid"]))
    for candidates in by_pid.values():
        candidates.sort()
    for event in events:
        if event["channel"] not in POWERSHELL_CHANNELS:
            continue
        pid = event["fields"].get("ExecutionProcessID") or event["fields"].get("ProcessID")
        candidates = by_pid.get((event["host"], str(pid))) if pid else None
        if not candidates:
            continue
        started = [guid for seen, guid in candidates if seen <= event["ts"]]
        event["fields"]["ProcessGuid"] = started[-1] if started else candidates[0][1]


def pack_fields(fields: dict[str, str]) -> bytes:
    """Event fields are stored as compressed JSON; it cuts the store to about a third."""
    return zlib.compress(json.dumps(fields, separators=(",", ":")).encode("utf-8"), 6)


def unpack_fields(blob: bytes) -> dict[str, str]:
    return json.loads(zlib.decompress(blob).decode("utf-8"))


def open_store(path: Path | str) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    return connection


def create_store(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = open_store(path)
    connection.executescript(SCHEMA)
    return connection


def insert_capture(connection: sqlite3.Connection, capture: str, events: list[dict], processes: dict[str, dict]) -> None:
    """Write one prepared capture (events already carry their ``id``)."""
    rows = []
    for event in events:
        fields = event["fields"]
        image = fields.get("Image") or fields.get("SourceImage")
        stored = _stored_fields(event["channel"], fields)
        rows.append(
            (
                event["id"],
                capture,
                event["ts"],
                event["host"],
                event["channel"],
                event["eid"],
                process_guid(event),
                image,
                pack_fields(stored),
            )
        )
    connection.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)", rows)
    connection.executemany(
        "INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                capture,
                p["pguid"],
                p["parent_pguid"],
                p["event_id"],
                p["first_seen"],
                p["host"],
                p["pid"],
                p["image"],
                p["cmdline"],
                p["user"],
                p["integrity"],
            )
            for p in processes.values()
        ],
    )
    connection.commit()


def prepare_capture(archive: Path, first_id: int) -> tuple[list[dict], dict[str, dict]]:
    """Read, normalise and number one capture. Returns (events, processes)."""
    events = normalize_capture(list(iter_raw_events(archive)))
    for offset, event in enumerate(events):
        event["id"] = first_id + offset
    processes = collect_processes(events)
    attach_powershell_processes(events, processes)
    return events, processes
