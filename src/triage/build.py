"""Build the benchmark: event store, cases, labels.

    python -m triage build

reads the captures listed in ``benchmark/captures.yaml`` from ``data/otrf``, runs
the Sigma rules in ``data/sigma`` over them, groups the hits into cases, labels
the cases from ``benchmark/ground_truth.yaml`` and writes ``benchmark/cases.jsonl``.
"""

from __future__ import annotations

import json
import ntpath
import sqlite3
from collections import Counter
from pathlib import Path

import yaml

from . import paths
from .corpus import create_store, insert_capture, open_store, prepare_capture
from .detect import Detector, build_cases, load_rules
from .events import describe
from .labels import Labeler, UnlabeledCase

MAX_TRIGGERS = 12


def load_captures() -> dict:
    with open(paths.CAPTURES_FILE, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _prevalence_rows(capture: str, processes: dict[str, dict]) -> set[tuple[str, str, str, str]]:
    rows = set()
    for process in processes.values():
        image = process.get("image")
        if not image or "unknown process" in image:
            continue
        day = process["first_seen"][:10]
        rows.add(("image", image.lower(), capture, day))
        rows.add(("name", ntpath.basename(image).lower(), capture, day))
        parent = processes.get(process.get("parent_pguid") or "")
        if parent and parent.get("image"):
            pair = f"{ntpath.basename(parent['image']).lower()}>{ntpath.basename(image).lower()}"
            rows.add(("pair", pair, capture, day))
    return rows


def build_store_and_cases(log=print) -> tuple[list[dict], dict]:
    """Ingest every capture and detect. Returns (unlabeled cases, build statistics)."""
    config = load_captures()
    rules, skipped = load_rules(paths.SIGMA_DIR)
    detector = Detector(rules)
    log(f"compiled {len(rules)} Sigma rules ({sum(skipped.values())} skipped)")

    connection = create_store(paths.STORE_FILE)
    connection.execute(
        "CREATE TABLE seen (kind TEXT NOT NULL, value TEXT NOT NULL, capture TEXT NOT NULL, day TEXT NOT NULL,"
        " PRIMARY KEY (kind, value, capture, day))"
    )
    all_cases: list[dict] = []
    next_id, unattributed, fired = 1, 0, Counter()
    for entry in config["captures"]:
        archive = paths.OTRF_DIR / entry["path"]
        events, processes = prepare_capture(archive, next_id)
        next_id += len(events)
        by_id = {event["id"]: event for event in events}
        cases, missed = build_cases(entry["name"], events, detector)
        unattributed += missed
        for case in cases:
            subject = processes.get(case["pguid"], {})
            parent = processes.get(subject.get("parent_pguid") or "", {})
            case["split"] = entry["split"]
            case["subject"] = {
                "image": subject.get("image"),
                "command_line": subject.get("cmdline"),
                "user": subject.get("user"),
                "pid": subject.get("pid"),
                "integrity": subject.get("integrity"),
                "started": subject.get("first_seen") if subject.get("event_id") else None,
                "parent_image": parent.get("image"),
                "parent_command_line": parent.get("cmdline"),
            }
            triggers, seen_ids = [], set()
            for detection in case["detections"]:
                fired[detection["rule_id"]] += 1
                for event_id in detection["event_ids"]:
                    if event_id in seen_ids or len(triggers) >= MAX_TRIGGERS:
                        continue
                    seen_ids.add(event_id)
                    event = by_id[event_id]
                    triggers.append(
                        {"event_id": event_id, "ts": event["ts"], "what": describe(event["channel"], event["eid"], event["fields"])}
                    )
            case["triggers"] = sorted(triggers, key=lambda t: t["event_id"])
        all_cases.extend(cases)
        insert_capture(connection, entry["name"], events, processes)
        connection.executemany("INSERT OR IGNORE INTO seen VALUES (?,?,?,?)", list(_prevalence_rows(entry["name"], processes)))
        connection.commit()
        log(f"  {entry['name']}: {len(events)} events, {len(cases)} cases")
    connection.execute("CREATE INDEX ix_seen ON seen (kind, value)")
    connection.commit()
    connection.close()

    for number, case in enumerate(all_cases, start=1):
        case["case_id"] = f"C{number:04d}"
    stats = {
        "events": next_id - 1,
        "captures": len(config["captures"]),
        "rules_compiled": len(rules),
        "rules_skipped": dict(sorted(skipped.items())),
        "rules_fired": len(fired),
        "hits_without_process": unattributed,
        "otrf_commit": config["source"]["commit"],
        "sigma_commit": config["sigma"]["commit"],
    }
    paths.RAW_CASES_FILE.write_text("\n".join(json.dumps(c) for c in all_cases) + "\n", encoding="utf-8")
    return all_cases, stats


def load_processes(connection: sqlite3.Connection, capture: str) -> dict[str, dict]:
    rows = connection.execute("SELECT * FROM processes WHERE capture = ?", (capture,)).fetchall()
    return {row["pguid"]: dict(row) for row in rows}


def label_cases(cases: list[dict], strict: bool = True) -> tuple[list[dict], list[str]]:
    """Attach ground-truth labels. Returns (cases, descriptions of unlabeled cases)."""
    with open(paths.GROUND_TRUTH_FILE, encoding="utf-8") as handle:
        labeler = Labeler(yaml.safe_load(handle))
    connection = open_store(paths.STORE_FILE)
    unlabeled: list[str] = []
    cache: dict[str, tuple[dict, dict]] = {}
    for case in cases:
        if case["capture"] not in cache:
            processes = load_processes(connection, case["capture"])
            cache[case["capture"]] = (processes, labeler.footholds(case["capture"], processes))
        processes, footholds = cache[case["capture"]]
        try:
            verdict = labeler.label(case, processes, footholds)
        except UnlabeledCase as missing:
            unlabeled.append(str(missing))
            continue
        case["label"], case["label_basis"], case["label_reason"] = verdict.label, verdict.basis, verdict.reason
    connection.close()
    if unlabeled and strict:
        raise UnlabeledCase(f"{len(unlabeled)} cases have no ground-truth label:\n" + "\n".join(unlabeled))
    return cases, unlabeled


def write_cases(cases: list[dict], stats: dict | None = None) -> None:
    ordered = []
    for case in cases:
        ordered.append(
            {
                key: case[key]
                for key in (
                    "case_id",
                    "capture",
                    "split",
                    "host",
                    "pguid",
                    "first_alert_ts",
                    "max_level",
                    "subject",
                    "detections",
                    "triggers",
                    "label",
                    "label_basis",
                    "label_reason",
                )
            }
        )
    paths.CASES_FILE.write_text("\n".join(json.dumps(c, ensure_ascii=False) for c in ordered) + "\n", encoding="utf-8")
    if stats is not None:
        stats = dict(stats)
        stats["cases"] = len(ordered)
        stats["labels"] = dict(Counter(c["label"] for c in ordered))
        stats["cases_by_split"] = {split: dict(Counter(c["label"] for c in ordered if c["split"] == split)) for split in ("dev", "test")}
        paths.BUILD_INFO_FILE.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")


def load_cases(path: Path | None = None) -> list[dict]:
    with open(path or paths.CASES_FILE, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build(log=print) -> None:
    cases, stats = build_store_and_cases(log)
    cases, _ = label_cases(cases, strict=True)
    write_cases(cases, stats)
    log(f"wrote {len(cases)} cases to {paths.CASES_FILE}")
