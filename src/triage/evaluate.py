"""Score triage results against ground truth.

The numbers are organised around the decisions a team shipping a triage agent has
to make:

* Can its verdicts be trusted?            -> forced-choice accuracy, attack recall, false-alarm rate
* What happens when it acts on its own?   -> auto-resolved share, missed attacks, wrongly raised alarms
* Does it know when it does not know?     -> what escalation catches, and the accuracy/coverage curve
* Is its reasoning grounded?              -> whether cited evidence was really shown to it
* What does an investigation cost?        -> tool calls, tokens, seconds

Cases labeled ``side_effect`` are reported separately and never scored.
Confidence intervals come from resampling whole recordings, because cases from
the same recording are not independent.
"""

from __future__ import annotations

import random
from collections import defaultdict

SCORED = ("malicious", "benign")


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _core(rows: list[tuple[dict, dict]]) -> dict:
    """Metrics for (case, result) pairs. Every case must have a scored label."""
    n = len(rows)
    malicious = [(c, r) for c, r in rows if c["label"] == "malicious"]
    benign = [(c, r) for c, r in rows if c["label"] == "benign"]
    correct = [(c, r) for c, r in rows if r["verdict"] == c["label"]]
    auto = [(c, r) for c, r in rows if not r["escalate"]]
    escalated = [(c, r) for c, r in rows if r["escalate"]]
    auto_correct = [(c, r) for c, r in auto if r["verdict"] == c["label"]]
    missed = [(c, r) for c, r in auto if c["label"] == "malicious" and r["verdict"] == "benign"]
    false_alarms = [(c, r) for c, r in auto if c["label"] == "benign" and r["verdict"] == "malicious"]
    wrong_forced = [(c, r) for c, r in rows if r["verdict"] != c["label"]]
    escalated_wrong = [(c, r) for c, r in escalated if r["verdict"] != c["label"]]
    return {
        "cases": n,
        "malicious": len(malicious),
        "benign": len(benign),
        # If forced to decide every case
        "forced_accuracy": _rate(len(correct), n),
        "attack_recall": _rate(sum(1 for c, r in malicious if r["verdict"] == "malicious"), len(malicious)),
        "false_alarm_rate": _rate(sum(1 for c, r in benign if r["verdict"] == "malicious"), len(benign)),
        # As deployed, with escalation
        "auto_resolved": _rate(len(auto), n),
        "auto_accuracy": _rate(len(auto_correct), len(auto)),
        "missed_attacks": _rate(len(missed), len(malicious)),
        "benign_raised_as_attack": _rate(len(false_alarms), len(benign)),
        "auto_closed_benign": _rate(sum(1 for c, r in auto if c["label"] == "benign" and r["verdict"] == "benign"), len(benign)),
        "escalated": _rate(len(escalated), n),
        # Does escalation land on the cases it would have got wrong?
        "escalated_would_be_wrong": _rate(len(escalated_wrong), len(escalated)),
        "auto_would_be_wrong": _rate(len(auto) - len(auto_correct), len(auto)),
        "errors_caught_by_escalation": _rate(len(escalated_wrong), len(wrong_forced)),
        "missed_attack_count": len(missed),
        "false_alarm_count": len(false_alarms),
    }


def risk_coverage(rows: list[tuple[dict, dict]]) -> list[dict]:
    """Accuracy on the most-confident fraction of cases, for every fraction.

    Read it as: "if only the top X% most confident verdicts were acted on
    automatically, how accurate would they be?"
    """
    ranked = sorted(rows, key=lambda pair: -pair[1]["confidence"])
    points, correct = [], 0
    for index, (case, result) in enumerate(ranked, start=1):
        correct += result["verdict"] == case["label"]
        last_of_tie = index == len(ranked) or ranked[index][1]["confidence"] != result["confidence"]
        if last_of_tie:
            points.append({"coverage": index / len(ranked), "accuracy": correct / index, "confidence": result["confidence"]})
    return points


def area_under_risk_coverage(points: list[dict]) -> float | None:
    """Mean error over all coverage levels (lower is better; 0 means perfect ranking and accuracy)."""
    if not points:
        return None
    area, previous = 0.0, 0.0
    for point in points:
        area += (point["coverage"] - previous) * (1 - point["accuracy"])
        previous = point["coverage"]
    return area


def coverage_at_accuracy(points: list[dict], target: float) -> float:
    """Largest share of cases that can be auto-resolved while staying at or above ``target`` accuracy."""
    return max((p["coverage"] for p in points if p["accuracy"] >= target), default=0.0)


def _bootstrap(rows: list[tuple[dict, dict]], keys: tuple[str, ...], rounds: int = 1000, seed: int = 11) -> dict[str, list[float | None]]:
    by_capture: dict[str, list] = defaultdict(list)
    for pair in rows:
        by_capture[pair[0]["capture"]].append(pair)
    captures = sorted(by_capture)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {key: [] for key in keys}
    for _ in range(rounds):
        resampled = [pair for name in rng.choices(captures, k=len(captures)) for pair in by_capture[name]]
        metrics = _core(resampled)
        for key in keys:
            if metrics[key] is not None:
                samples[key].append(metrics[key])
    intervals = {}
    for key, values in samples.items():
        if len(values) < rounds * 0.9:
            intervals[key] = [None, None]
            continue
        values.sort()
        intervals[key] = [values[int(0.025 * len(values))], values[int(0.975 * len(values)) - 1]]
    return intervals


CI_KEYS = (
    "forced_accuracy",
    "attack_recall",
    "false_alarm_rate",
    "auto_resolved",
    "auto_accuracy",
    "missed_attacks",
    "benign_raised_as_attack",
)


def evaluate(cases: list[dict], results: list[dict], bootstrap_rounds: int = 1000) -> dict:
    by_id = {r["case_id"]: r for r in results}
    paired = [(c, by_id[c["case_id"]]) for c in cases if c["case_id"] in by_id]
    scored = [(c, r) for c, r in paired if c["label"] in SCORED]
    if not scored:
        raise ValueError("no scored cases have results")
    report = _core(scored)
    report["policy"] = scored[0][1]["policy"]
    report["confidence_intervals"] = _bootstrap(scored, CI_KEYS, bootstrap_rounds) if bootstrap_rounds else {}
    report["cases_without_result"] = sum(1 for c in cases if c["case_id"] not in by_id)

    curve = risk_coverage(scored)
    report["risk_coverage"] = curve
    report["area_under_risk_coverage"] = area_under_risk_coverage(curve)
    report["coverage_at_95_accuracy"] = coverage_at_accuracy(curve, 0.95)
    report["coverage_at_99_accuracy"] = coverage_at_accuracy(curve, 0.99)

    # Evidence
    cited = sum(len(r["evidence"]) for _, r in scored)
    not_shown = sum(len(r["evidence_not_shown"]) for _, r in scored)
    report["evidence"] = {
        "citations": cited,
        "citations_never_shown": not_shown,
        "citation_validity": _rate(cited - not_shown, cited),
        "verdicts_with_valid_citation": _rate(sum(1 for _, r in scored if r["evidence_shown"]), len(scored)),
    }

    # Cost
    count = len(scored)
    report["cost"] = {
        "mean_tool_calls": sum(r["tool_calls"] for _, r in scored) / count,
        "mean_seconds": sum(r["seconds"] for _, r in scored) / count,
        "mean_input_tokens": sum(r["input_tokens"] for _, r in scored) / count,
        "mean_output_tokens": sum(r["output_tokens"] for _, r in scored) / count,
        "failed_investigations": sum(1 for _, r in scored if r.get("failure")),
        "tool_errors": sum(r["tool_errors"] for _, r in scored),
    }

    # Where the errors are
    def breakdown(key_of) -> dict:
        groups: dict[str, list] = defaultdict(list)
        for pair in scored:
            groups[key_of(pair[0])].append(pair)
        return {
            name: {
                k: _core(rows)[k]
                for k in ("cases", "forced_accuracy", "auto_resolved", "auto_accuracy", "missed_attack_count", "false_alarm_count")
            }
            for name, rows in sorted(groups.items())
        }

    report["by_rule_severity"] = breakdown(lambda c: c["max_level"])
    report["by_label_basis"] = breakdown(lambda c: f"{c['label']}: {c['label_basis'].split(':')[0]}")

    side = [(c, r) for c, r in paired if c["label"] == "side_effect"]
    report["side_effect_cases"] = {
        "cases": len(side),
        "called_malicious": sum(1 for _, r in side if r["verdict"] == "malicious" and not r["escalate"]),
        "called_benign": sum(1 for _, r in side if r["verdict"] == "benign" and not r["escalate"]),
        "escalated": sum(1 for _, r in side if r["escalate"]),
    }
    report["errors"] = [
        {
            "case_id": c["case_id"],
            "truth": c["label"],
            "verdict": r["verdict"],
            "escalated": r["escalate"],
            "confidence": r["confidence"],
            "image": c["subject"].get("image"),
            "max_level": c["max_level"],
            "why_truth": c["label_reason"],
        }
        for c, r in scored
        if r["verdict"] != c["label"]
    ]
    return report
