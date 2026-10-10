"""Combine two saved result files into layered policies and score them.

No model is run. This replays the verdicts already in results/<split>/ and asks:
what if the checklist decided first and the agent was only allowed to act on
what the checklist left over?

    python scripts/layered.py --agent ollama-qwen2.5-14b
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8") as handle:
        return {row["case_id"]: row for row in map(json.loads, handle) if row}


def decision(row: dict) -> str:
    return "escalate" if row["escalate"] else row["verdict"]


def policies(base: dict[str, dict], agent: dict[str, dict]) -> dict[str, callable]:
    def b(case_id: str) -> str:
        return decision(base[case_id])

    def a(case_id: str) -> str:
        return decision(agent[case_id])

    def handoff(case_id: str) -> str:
        return a(case_id) if b(case_id) == "escalate" else b(case_id)

    def raise_only(case_id: str) -> str:
        if b(case_id) != "escalate":
            return b(case_id)
        return "malicious" if a(case_id) == "malicious" else "escalate"

    def agreement(case_id: str) -> str:
        return b(case_id) if b(case_id) == a(case_id) else "escalate"

    return {
        "checklist alone": b,
        "agent alone": a,
        "checklist first, agent decides the rest": handoff,
        "checklist first, agent may only confirm an attack": raise_only,
        "act only when both agree": agreement,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", default="test")
    parser.add_argument("--base", default="scorecard")
    parser.add_argument("--agent", required=True, help="result file name without .jsonl")
    args = parser.parse_args()

    labels = {}
    with (ROOT / "benchmark" / "cases.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            case = json.loads(line)
            if case["label"] in ("malicious", "benign"):
                labels[case["case_id"]] = case["label"]

    results = ROOT / "results" / args.split
    base = load(results / f"{args.base}.jsonl")
    agent = load(results / f"{args.agent}.jsonl")
    scored = [c for c in labels if c in base and c in agent]
    attacks = sum(labels[c] == "malicious" for c in scored)
    benign = len(scored) - attacks

    print(f"{len(scored)} scored cases on the {args.split} split ({attacks} malicious, {benign} benign)\n")
    print("| Policy | Auto-resolved | Accuracy when it decides | Attacks auto-closed as benign | Benign auto-raised as attack |")
    print("|---|---|---|---|---|")
    for name, policy in policies(base, agent).items():
        tally = Counter((labels[c], policy(c)) for c in scored)
        decided = sum(n for (_, d), n in tally.items() if d != "escalate")
        right = tally[("malicious", "malicious")] + tally[("benign", "benign")]
        accuracy = f"{right / decided:.0%}" if decided else "n/a"
        print(
            f"| {name} | {decided / len(scored):.0%} | {accuracy} "
            f"| {tally[('malicious', 'benign')]} of {attacks} | {tally[('benign', 'malicious')]} of {benign} |"
        )


if __name__ == "__main__":
    main()
