"""Run Sigma rules over a capture and group the hits into triage cases."""

from __future__ import annotations

import glob
import os
from collections import defaultdict
from pathlib import Path

import yaml

from . import sigma
from .corpus import process_guid

# The rule folders of the SigmaHQ repository that are loaded. Deprecated,
# placeholder and unsupported folders are left out.
RULE_FOLDERS = ("rules/windows", "rules-threat-hunting/windows", "rules-emerging-threats")
ALERT_LEVELS = ("low", "medium", "high", "critical")
LEVEL_RANK = {level: rank for rank, level in enumerate(("informational",) + ALERT_LEVELS)}


def load_rules(sigma_root: Path) -> tuple[list[sigma.Rule], dict[str, int]]:
    """Compile every supported rule. Returns (rules, reasons_for_skipping)."""
    rules: list[sigma.Rule] = []
    skipped: dict[str, int] = defaultdict(int)
    for folder in RULE_FOLDERS:
        for path in sorted(glob.glob(str(sigma_root / folder / "**" / "*.yml"), recursive=True)):
            with open(path, encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            try:
                rule = sigma.compile_rule(doc, os.path.relpath(path, sigma_root).replace(os.sep, "/"))
            except sigma.UnsupportedRule as reason:
                skipped[str(reason)] += 1
                continue
            if rule.level not in ALERT_LEVELS:
                skipped["level informational"] += 1
                continue
            rules.append(rule)
    return rules, dict(skipped)


class Detector:
    def __init__(self, rules: list[sigma.Rule]):
        self.rules = rules
        self._index: dict[tuple[str, int | None], list[sigma.Rule]] = defaultdict(list)
        for rule in rules:
            for event_id in rule.event_ids or (None,):
                self._index[(rule.channel, event_id)].append(rule)

    def match(self, event: dict) -> list[sigma.Rule]:
        candidates = self._index.get((event["channel"], event["eid"]), []) + self._index.get((event["channel"], None), [])
        if not candidates:
            return []
        view = sigma.EventView({**event["fields"], "EventID": str(event["eid"])})
        return [rule for rule in candidates if rule.matches(view)]


def build_cases(capture: str, events: list[dict], detector: Detector) -> tuple[list[dict], int]:
    """Group rule hits by the process they are about.

    One case is one process on one host together with every rule that fired on
    it. Hits that cannot be tied to a process are counted and left out.
    """
    grouped: dict[tuple[str, str], dict] = {}
    unattributed = 0
    for event in events:
        rules = detector.match(event)
        if not rules:
            continue
        guid = process_guid(event)
        if guid is None:
            unattributed += len(rules)
            continue
        case = grouped.setdefault(
            (event["host"], guid),
            {"capture": capture, "host": event["host"], "pguid": guid, "first_alert_ts": event["ts"], "detections": {}},
        )
        for rule in rules:
            detection = case["detections"].setdefault(
                rule.id,
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "description": rule.description,
                    "techniques": rule.techniques,
                    "tactics": rule.tactics,
                    "known_false_positives": rule.falsepositives,
                    "author": rule.author,
                    "source": rule.path,
                    "event_ids": [],
                },
            )
            if len(detection["event_ids"]) < 5:
                detection["event_ids"].append(event["id"])
            detection["hits"] = detection.get("hits", 0) + 1
    cases = []
    for case in grouped.values():
        detections = sorted(case["detections"].values(), key=lambda d: (-LEVEL_RANK[d["level"]], d["title"]))
        case["detections"] = detections
        case["max_level"] = detections[0]["level"]
        cases.append(case)
    cases.sort(key=lambda c: (c["first_alert_ts"], c["pguid"]))
    return cases, unattributed
