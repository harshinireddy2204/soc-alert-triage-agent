"""Ground-truth labels for benchmark cases.

Labels are not stored as a bare list. They are derived from
``benchmark/ground_truth.yaml``, which records, for every capture, which processes
the simulated attacker controlled and why, plus an explicit decision for every
case that process ancestry alone cannot settle. The derivation runs each time the
benchmark is built, and the build fails if any case is left without a label.

Order of precedence for one case:

1. an explicit decision for that process in the capture's ``decisions``;
2. attacker lineage: the process is a foothold or descends from one;
3. a ``background`` pattern describing routine activity of the lab machines.
"""

from __future__ import annotations

import fnmatch
import ntpath
from dataclasses import dataclass

LABELS = ("malicious", "benign", "side_effect")


@dataclass
class Label:
    label: str
    basis: str
    reason: str


class UnlabeledCase(Exception):
    pass


def _glob(pattern: str, value: str | None) -> bool:
    return value is not None and fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _any_glob(patterns: list[str] | str, value: str | None) -> bool:
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(_glob(p, value) for p in patterns)


def process_matches(spec: dict, process: dict) -> bool:
    """Does a process record satisfy a matcher from the ground-truth file?"""
    for key, expected in spec.items():
        if key in ("why", "label", "id"):
            continue
        if key == "pguid":
            if process.get("pguid") != str(expected).lower():
                return False
        elif key == "pid":
            if str(process.get("pid")) != str(expected):
                return False
        elif key == "host":
            if process.get("host") != str(expected).lower():
                return False
        elif key in ("image", "cmdline", "user"):
            if not _any_glob(expected, process.get(key)):
                return False
        else:
            raise ValueError(f"unknown process matcher key {key!r}")
    return True


def ancestry(pguid: str, processes: dict[str, dict], limit: int = 40) -> list[dict]:
    """The process followed by its parents, nearest first."""
    chain, seen = [], set()
    current = processes.get(pguid)
    while current is not None and current["pguid"] not in seen and len(chain) < limit:
        chain.append(current)
        seen.add(current["pguid"])
        current = processes.get(current.get("parent_pguid") or "")
    return chain


class Labeler:
    def __init__(self, spec: dict):
        self.spec = spec
        self.signatures = spec.get("foothold_signatures") or []
        self.recurring = spec.get("recurring") or []
        self.captures = spec.get("captures") or {}

    def footholds(self, capture: str, processes: dict[str, dict]) -> dict[str, str]:
        """Map each attacker-controlled entry process in a capture to the reason it is one."""
        entry = self.captures.get(capture) or {}
        found: dict[str, str] = {}
        for process in processes.values():
            for spec in entry.get("footholds") or []:
                if process_matches(spec, process):
                    found[process["pguid"]] = spec["why"]
                    break
            else:
                for spec in self.signatures:
                    if process_matches({k: v for k, v in spec.items() if k != "id"}, process):
                        found[process["pguid"]] = spec["why"]
                        break
        return found

    def label(self, case: dict, processes: dict[str, dict], footholds: dict[str, str]) -> Label:
        entry = self.captures.get(case["capture"]) or {}
        chain = ancestry(case["pguid"], processes)
        subject = chain[0] if chain else {"pguid": case["pguid"], "host": case["host"]}

        for decision in entry.get("decisions") or []:
            if process_matches({k: v for k, v in decision.items() if k not in ("label", "why")}, subject):
                return Label(decision["label"], "reviewed", decision["why"])

        for depth, process in enumerate(chain):
            if process["pguid"] in footholds:
                why = footholds[process["pguid"]]
                if depth == 0:
                    return Label("malicious", "foothold", why)
                name = ntpath.basename(process.get("image") or "process")
                return Label("malicious", "lineage", f"Started by the attacker's {name} (PID {process.get('pid')}): {why}")

        titles = [d["title"] for d in case["detections"]]
        triggers = [t["what"] for t in case.get("triggers", [])]
        for pattern in self.recurring:
            match = pattern["match"]
            if "image" in match and not _any_glob(match["image"], subject.get("image")):
                continue
            if "cmdline" in match and not _any_glob(match["cmdline"], subject.get("cmdline")):
                continue
            if "user" in match and not _any_glob(match["user"], subject.get("user")):
                continue
            if "ancestor_image" in match and not any(_any_glob(match["ancestor_image"], p.get("image")) for p in chain):
                continue
            if "rules_all" in match and not all(_any_glob(match["rules_all"], t) for t in titles):
                continue
            if "triggers_all" in match and not (triggers and all(_any_glob(match["triggers_all"], t) for t in triggers)):
                continue
            return Label(pattern["label"], f"recurring:{pattern['id']}", pattern["why"])

        raise UnlabeledCase(
            f"{case['capture']} {case['host']} {subject.get('image')} pid={subject.get('pid')} pguid={case['pguid']} rules={titles}"
        )
