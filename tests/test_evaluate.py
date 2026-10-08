from triage.evaluate import area_under_risk_coverage, coverage_at_accuracy, evaluate, risk_coverage


def case(i, label, capture="a"):
    return {
        "case_id": f"C{i}",
        "label": label,
        "capture": capture,
        "max_level": "high",
        "label_basis": "lineage",
        "label_reason": "r",
        "subject": {"image": "x.exe"},
    }


def result(i, verdict, confidence=0.9, escalate=False, cited=(1,), unseen=()):
    return {
        "case_id": f"C{i}",
        "policy": "p",
        "verdict": verdict,
        "confidence": confidence,
        "escalate": escalate,
        "evidence": list(cited) + list(unseen),
        "evidence_shown": list(cited),
        "evidence_not_shown": list(unseen),
        "tool_calls": 2,
        "tool_errors": 0,
        "seconds": 1.0,
        "input_tokens": 10,
        "output_tokens": 5,
        "failure": None,
    }


CASES = [
    case(1, "malicious"),
    case(2, "malicious"),
    case(3, "malicious", "b"),
    case(4, "benign", "b"),
    case(5, "benign", "b"),
    case(6, "side_effect", "b"),
]
RESULTS = [
    result(1, "malicious", 0.95),  # right, decided
    result(2, "benign", 0.9),  # wrong, decided: a missed attack
    result(3, "benign", 0.6, escalate=True),  # wrong, but escalated
    result(4, "benign", 0.8),  # right, decided
    result(5, "malicious", 0.7, unseen=(99,)),  # wrong, decided: a false alarm
    result(6, "benign", 0.9),  # side effect: never scored
]


def test_headline_numbers_by_hand():
    r = evaluate(CASES, RESULTS, bootstrap_rounds=0)
    assert (r["cases"], r["malicious"], r["benign"]) == (5, 3, 2)
    assert r["forced_accuracy"] == 2 / 5 and r["attack_recall"] == 1 / 3 and r["false_alarm_rate"] == 1 / 2
    assert r["auto_resolved"] == 4 / 5 and r["auto_accuracy"] == 2 / 4
    assert r["missed_attack_count"] == 1 and r["missed_attacks"] == 1 / 3
    assert r["false_alarm_count"] == 1 and r["benign_raised_as_attack"] == 1 / 2
    assert r["escalated_would_be_wrong"] == 1.0 and r["errors_caught_by_escalation"] == 1 / 3
    assert r["side_effect_cases"] == {"cases": 1, "called_malicious": 0, "called_benign": 1, "escalated": 0}
    assert r["evidence"]["citations"] == 6 and r["evidence"]["citations_never_shown"] == 1
    assert [e["case_id"] for e in r["errors"]] == ["C2", "C3", "C5"]


def test_accuracy_coverage_curve():
    pairs = [(c, r) for c, r in zip(CASES[:5], RESULTS[:5], strict=True)]
    curve = risk_coverage(pairs)
    assert curve[0] == {"coverage": 0.2, "accuracy": 1.0, "confidence": 0.95}
    assert curve[-1]["coverage"] == 1.0 and curve[-1]["accuracy"] == 0.4
    assert coverage_at_accuracy(curve, 0.95) == 0.2 and coverage_at_accuracy(curve, 0.3) == 1.0
    assert 0 < area_under_risk_coverage(curve) < 1


def test_intervals_resample_whole_recordings_and_missing_results_are_counted():
    r = evaluate(CASES, RESULTS[:4], bootstrap_rounds=200)
    assert r["cases_without_result"] == 2 and r["cases"] == 4
    low, high = r["confidence_intervals"]["forced_accuracy"]
    assert 0 <= low <= r["forced_accuracy"] <= high <= 1
