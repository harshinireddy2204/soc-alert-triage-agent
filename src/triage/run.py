"""Run a triage policy over benchmark cases and save one result line per case."""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .build import load_cases
from .corpus import open_store
from .store import CaseStore
from .tools import Toolbox

HIDDEN_FROM_AGENT = ("capture", "label", "label_basis", "label_reason", "split")


def public_view(case: dict) -> dict:
    """The case without anything that reveals the answer.

    The recording name states the attack technique and the label fields are the
    answer key, so policies never receive them.
    """
    return {key: value for key, value in case.items() if key not in HIDDEN_FROM_AGENT}


def select_cases(split: str = "test", limit: int | None = None, case_ids: list[str] | None = None) -> list[dict]:
    cases = load_cases()
    if case_ids:
        wanted = set(case_ids)
        cases = [c for c in cases if c["case_id"] in wanted]
    elif split != "all":
        cases = [c for c in cases if c["split"] == split]
    return cases[:limit] if limit else cases


def run_policy(policy, cases: list[dict], out_path: Path, resume: bool = True, log=print, store_path: Path | None = None) -> list[dict]:
    """Triage ``cases`` with ``policy``. Results are appended as they finish, so a
    long run can be interrupted and resumed."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done: dict[str, dict] = {}
    if resume and out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                done[record["case_id"]] = record
    elif out_path.exists():
        out_path.unlink()

    connection = open_store(store_path or paths.STORE_FILE)
    results = []
    with open(out_path, "a", encoding="utf-8") as handle:
        for number, case in enumerate(cases, start=1):
            if case["case_id"] in done:
                results.append(done[case["case_id"]])
                continue
            toolbox = Toolbox(public_view(case), CaseStore(case["capture"], connection))
            started = time.perf_counter()
            verdict, trace = policy.triage(public_view(case), toolbox)
            seconds = time.perf_counter() - started
            cited = verdict.evidence
            record = {
                "case_id": case["case_id"],
                "policy": policy.name,
                **verdict.to_dict(),
                "seconds": round(seconds, 3),
                "tool_calls": len(toolbox.calls),
                "tool_errors": sum(1 for call in toolbox.calls if not call["ok"]),
                "events_shown": len(toolbox.shown_events),
                "evidence_shown": [e for e in cited if e in toolbox.shown_events],
                "evidence_not_shown": [e for e in cited if e not in toolbox.shown_events],
                "input_tokens": trace.get("input_tokens", 0),
                "output_tokens": trace.get("output_tokens", 0),
                "invalid_replies": trace.get("invalid_replies", 0),
                "failure": trace.get("failure"),
                "steps": trace.get("steps", []),
            }
            if "signals" in trace:
                record["signals"] = trace["signals"]
                record["score"] = trace["score"]
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            results.append(record)
            outcome = "escalate" if verdict.escalate else verdict.verdict
            log(f"[{number}/{len(cases)}] {case['case_id']} {outcome} ({verdict.confidence:.2f}) {seconds:.1f}s")
    connection.close()
    return results


def load_results(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
