"""The investigation tools the triage agent can call.

Each tool returns plain text. Events are shown as ``[E<number>] time description``
and every event number shown is recorded, so the evaluation can check that the
evidence an agent cites was really put in front of it.
"""

from __future__ import annotations

import json
import ntpath
import re
from datetime import datetime, timedelta
from functools import lru_cache

from . import paths
from .store import KINDS, CaseStore, Event, pair_key

MAX_LINES = 30

TOOL_SPECS = [
    {
        "name": "process_info",
        "description": (
            "Identity and family of a process: image, command line, user, integrity, start time, file "
            "metadata, its parent chain, its child processes, and how many events of each kind it has. "
            "Omit `process` for the process this case is about."
        ),
        "arguments": {"process": "optional process id in braces as printed after 'process=', or a program path"},
    },
    {
        "name": "process_events",
        "description": (
            "Events recorded for one process, oldest first. `kind` is one of: "
            + ", ".join(KINDS)
            + ". Omit `kind` for all kinds. Use `offset` to page."
        ),
        "arguments": {"process": "optional process id or program path", "kind": "optional event kind", "offset": "optional, default 0"},
    },
    {
        "name": "host_timeline",
        "description": (
            "What happened on a host around the time of the alert. Window is given in seconds relative to "
            "the first alert (defaults -30 to +30). Defaults to process creations; pass `kinds` for others."
        ),
        "arguments": {
            "host": "optional host name, defaults to the case host",
            "seconds_before": "optional integer, default 30, max 600",
            "seconds_after": "optional integer, default 30, max 600",
            "kinds": "optional list of event kinds",
            "contains": "optional text every returned event must contain",
        },
    },
    {
        "name": "search_events",
        "description": (
            "Case-insensitive text search across all hosts in this environment's recording, for following "
            "a file name, registry key, account, address or task name to wherever else it appears."
        ),
        "arguments": {
            "text": "text to find (at least 3 characters)",
            "kinds": "optional list of event kinds",
            "host": "optional host name",
        },
    },
    {
        "name": "get_event",
        "description": "Every field of one event, for reading a full command line, script block or call trace.",
        "arguments": {"event": "event number, e.g. E12345"},
    },
    {
        "name": "prevalence",
        "description": (
            "How common something is across the other recordings of this lab (different days and hosts): "
            "a program path, or a parent-to-child process pair. Common does not mean safe: the lab runs "
            "repeated attack simulations, so attacker tooling can be common too."
        ),
        "arguments": {
            "image": "optional full program path",
            "parent": "optional parent program name",
            "child": "optional child program name",
        },
    },
    {
        "name": "attack_technique",
        "description": "Name, tactic and short description of a MITRE ATT&CK technique.",
        "arguments": {"id": "technique id, e.g. T1003.001"},
    },
]


@lru_cache(maxsize=1)
def _attack() -> dict:
    with open(paths.ATTACK_FILE, encoding="utf-8") as handle:
        return json.load(handle)["techniques"]


def _clip(text: object, limit: int) -> str:
    value = " ".join(str(text if text is not None else "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _shift(ts: str, seconds: float) -> str:
    moment = datetime.strptime(ts[:23], "%Y-%m-%dT%H:%M:%S.%f") + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class ToolError(Exception):
    """The agent called a tool wrongly. The message is returned to the agent."""


class Toolbox:
    """Tools bound to one case. Records every call and every event shown."""

    def __init__(self, case: dict, store: CaseStore):
        self.case = case
        self.store = store
        self.calls: list[dict] = []
        self.shown_events: set[int] = {t["event_id"] for t in case.get("triggers", [])}

    # ------------------------------------------------------------------- helpers

    def _show(self, events: list[Event], limit: int = 220) -> list[str]:
        for event in events:
            self.shown_events.add(event.id)
        return [event.line(limit) for event in events]

    def _resolve(self, process: object) -> str:
        """Turn what the agent wrote into a process id.

        Models often name a process by its program path instead of its id. When
        that names exactly one process the call goes ahead; when it names several,
        the one that started closest to the alert is used. Either way the agent
        can read which process it got from the first line of the tool output.
        """
        if process in (None, "", "subject"):
            return self.case["pguid"]
        text = str(process)
        match = re.search(r"\{[0-9a-fA-F-]{36}\}", text)
        if match:
            return match.group(0).lower()
        candidates = self.store.processes_by_image(text, self.case["host"]) or self.store.processes_by_image(text)
        if not candidates:
            raise ToolError(
                f"no process with program {text!r} in this recording. Use a process id in braces, as printed "
                "after 'process=' in tool output, or omit `process` for the case process"
            )
        anchor = self.case["first_alert_ts"]
        candidates.sort(key=lambda record: abs(_seconds_between(anchor, record["first_seen"])))
        return candidates[0]["pguid"]

    def _kinds(self, kinds: object) -> list[str] | None:
        if kinds in (None, "", []):
            return None
        if isinstance(kinds, str):
            kinds = [k.strip() for k in kinds.split(",")]
        unknown = [k for k in kinds if k not in KINDS]
        if unknown:
            raise ToolError(f"unknown kind {unknown[0]!r}; valid kinds: {', '.join(KINDS)}")
        return list(kinds)

    @staticmethod
    def _describe_process(record: dict) -> str:
        name = ntpath.basename(record.get("image") or "unknown")
        command = _clip(record.get("cmdline") or record.get("image") or "", 260)
        started = record["first_seen"][11:19] if record.get("event_id") else "before recording"
        return f"{record['pguid']} {name} pid={record.get('pid')} user={record.get('user')} started={started} cmd: {command}"

    # --------------------------------------------------------------------- tools

    def process_info(self, process: object = None) -> str:
        pguid = self._resolve(process)
        record = self.store.process(pguid)
        if record is None:
            raise ToolError("no such process in this recording")
        lines = [f"Process {record['pguid']} on host {record['host']}"]
        lines.append(f"  image: {record.get('image')}")
        lines.append(f"  command line: {_clip(record.get('cmdline'), 900) or '(not recorded)'}")
        lines.append(f"  user: {record.get('user')}   integrity: {record.get('integrity')}   pid: {record.get('pid')}")
        creation = self.store.creation_event(pguid)
        if creation is not None:
            self.shown_events.add(creation.id)
            f = creation.fields
            lines.append(f"  started: {creation.ts} [E{creation.id}]   working directory: {f.get('CurrentDirectory')}")
            lines.append(
                f"  file: description={f.get('Description')!r} company={f.get('Company')!r} "
                f"original name={f.get('OriginalFileName')!r} hashes={_clip(f.get('Hashes'), 120)}"
            )
        else:
            lines.append("  started: before the recording began (no creation event)")
        ancestors = self.store.ancestors(pguid)
        lines.append("Parent chain (nearest first):" if ancestors else "Parent chain: not recorded")
        lines += ["  " + self._describe_process(a) for a in ancestors]
        children = self.store.children(pguid)
        lines.append(f"Child processes ({len(children)}{'+' if len(children) == 25 else ''}):")
        lines += ["  " + self._describe_process(c) for c in children[:15]]
        counts = self.store.process_event_counts(pguid)
        lines.append("Event counts: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
        return "\n".join(lines)

    def process_events(self, process: object = None, kind: object = None, offset: object = 0) -> str:
        pguid = self._resolve(process)
        kinds = self._kinds(kind)
        if kinds and len(kinds) > 1:
            raise ToolError("process_events takes a single kind")
        try:
            start = max(0, int(offset or 0))
        except (TypeError, ValueError) as error:
            raise ToolError("offset must be an integer") from error
        events, total = self.store.process_events(pguid, kinds[0] if kinds else None, 4000, 0)
        if not events:
            return f"No {kinds[0] + ' ' if kinds else ''}events recorded for this process."
        # Busy processes repeat themselves; identical events are folded into one line with a count.
        groups: dict[str, list] = {}
        for event in events:
            groups.setdefault(event.line().split(" ", 2)[2], []).append(event)
        ordered = list(groups.items())[start : start + MAX_LINES]
        if not ordered:
            return f"No more events; there are {len(groups)} distinct event(s)."
        record = self.store.process(pguid) or {}
        lines = [
            f"Process {pguid} ({ntpath.basename(record.get('image') or 'unknown')}): {total} event(s), {len(groups)} distinct; "
            f"showing distinct {start + 1} to {start + len(ordered)}"
        ]
        for text, members in ordered:
            first = members[0]
            self.shown_events.add(first.id)
            repeat = f"  (x{len(members)}, last at {members[-1].ts[11:19]})" if len(members) > 1 else ""
            lines.append(f"[E{first.id}] {first.ts[11:23]} {text}{repeat}")
        return "\n".join(lines)

    def host_timeline(
        self, host: object = None, seconds_before: object = 30, seconds_after: object = 30, kinds: object = None, contains: object = None
    ) -> str:
        try:
            before = min(600, max(0, int(seconds_before if seconds_before is not None else 30)))
            after = min(600, max(0, int(seconds_after if seconds_after is not None else 30)))
        except (TypeError, ValueError) as error:
            raise ToolError("seconds_before and seconds_after must be integers") from error
        target = str(host or self.case["host"]).split(".")[0].lower()
        if target not in self.store.hosts():
            raise ToolError(f"unknown host {target!r}; hosts in this recording: {', '.join(self.store.hosts())}")
        anchor = self.case["first_alert_ts"]
        events = self.store.window(target, _shift(anchor, -before), _shift(anchor, after), self._kinds(kinds) or ["process"])
        if contains:
            needle = str(contains).lower()
            events = [e for e in events if any(needle in v.lower() for v in e.fields.values())]
        header = f"{len(events)} event(s) on {target} from {before}s before to {after}s after the first alert ({anchor})"
        if len(events) > MAX_LINES:
            # Keep the events closest to the alert when there are too many to show.
            events = sorted(sorted(events, key=lambda e: abs(_seconds_between(anchor, e.ts)))[:MAX_LINES], key=lambda e: (e.ts, e.id))
            header += f"; showing the {MAX_LINES} closest to the alert"
        for event in events:
            self.shown_events.add(event.id)
        return "\n".join([header, *[event.line_with_process() for event in events]])

    def search_events(self, text: object = None, kinds: object = None, host: object = None) -> str:
        if not text or len(str(text).strip()) < 3:
            raise ToolError("text must be at least 3 characters")
        target = str(host).split(".")[0].lower() if host else None
        events, total = self.store.search(str(text).strip(), self._kinds(kinds), target, MAX_LINES)
        if not events:
            return "No events contain that text."
        lines = [f"{total} event(s) contain {str(text).strip()!r}; showing {len(events)}"]
        for event in events:
            self.shown_events.add(event.id)
            lines.append(f"{event.line()}  host={event.host} process={event.pguid}")
        return "\n".join(lines)

    def get_event(self, event: object = None) -> str:
        match = re.search(r"\d+", str(event or ""))
        if not match:
            raise ToolError("event must be an event number such as E12345")
        found = self.store.event(int(match.group(0)))
        if found is None:
            raise ToolError("no such event in this recording")
        self.shown_events.add(found.id)
        lines = [f"[E{found.id}] {found.ts} host={found.host} channel={found.channel} event_id={found.eid} process={found.pguid}"]
        lines += [f"  {key}: {_clip(value, 1500)}" for key, value in found.fields.items()]
        return "\n".join(lines)

    def prevalence(self, image: object = None, parent: object = None, child: object = None) -> str:
        total = self.store.other_recordings()
        lines = []
        if image:
            captures, days = self.store.seen_elsewhere("image", str(image))
            lines.append(f"Exact path {image}: seen in {captures} of {total} other recordings, on {days} distinct day(s).")
            name = ntpath.basename(str(image))
            captures, days = self.store.seen_elsewhere("name", name)
            lines.append(f"Any program named {name}: seen in {captures} of {total} other recordings, on {days} distinct day(s).")
        if parent and child:
            key = pair_key(str(parent), str(child))
            captures, days = self.store.seen_elsewhere("pair", key)
            lines.append(
                f"{ntpath.basename(str(parent))} starting {ntpath.basename(str(child))}: seen in {captures} of {total} "
                f"other recordings, on {days} distinct day(s)."
            )
        if not lines:
            raise ToolError("give `image`, or both `parent` and `child`")
        return "\n".join(lines)

    def attack_technique(self, id: object = None) -> str:
        key = str(id or "").strip().upper()
        entry = _attack().get(key)
        if entry is None:
            raise ToolError(f"unknown technique id {key!r}")
        return f"{key} {entry['name']} (tactics: {', '.join(entry['tactics'])}). {entry['description']}"

    # ------------------------------------------------------------------ dispatch

    def call(self, name: str, arguments: dict | None) -> str:
        """Run a tool by name. Errors come back as text so the agent can correct itself."""
        arguments = arguments if isinstance(arguments, dict) else {}
        record = {"tool": name, "arguments": arguments}
        try:
            if name not in {spec["name"] for spec in TOOL_SPECS}:
                raise ToolError(f"unknown tool {name!r}; tools: {', '.join(s['name'] for s in TOOL_SPECS)}")
            allowed = next(s for s in TOOL_SPECS if s["name"] == name)["arguments"]
            extra = [key for key in arguments if key not in allowed]
            if extra:
                raise ToolError(f"{name} does not take {extra[0]!r}; arguments: {', '.join(allowed) or 'none'}")
            repeated = [c for c in self.calls if c["tool"] == name and c["arguments"] == arguments]
            if len(repeated) >= 1 and not repeated[-1]["ok"]:
                raise ToolError("you already made this exact call and it failed the same way. Change the arguments or use another tool")
            if len(repeated) >= 2:
                raise ToolError("you have already made this exact call twice. Use what you learned, or try something different")
            output = getattr(self, name)(**arguments)
            record["ok"] = True
        except ToolError as error:
            output = f"ERROR: {error}"
            record["ok"] = False
        record["output_chars"] = len(output)
        self.calls.append(record)
        return output


def _seconds_between(first: str, second: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    return (datetime.strptime(second[:23], fmt) - datetime.strptime(first[:23], fmt)).total_seconds()
