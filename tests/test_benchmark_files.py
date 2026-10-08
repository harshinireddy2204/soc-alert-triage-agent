"""Checks on the committed benchmark itself. These need no downloaded data."""

import json
from collections import Counter

import yaml

from triage import paths
from triage.agent import render_case
from triage.build import load_cases
from triage.labels import LABELS, Labeler
from triage.run import public_view

CASES = load_cases()
CAPTURES = yaml.safe_load(paths.CAPTURES_FILE.read_text(encoding="utf-8"))


def test_every_case_is_labeled_with_a_reason():
    assert len(CASES) > 300 and len({c["case_id"] for c in CASES}) == len(CASES)
    for case in CASES:
        assert case["label"] in LABELS and len(case["label_reason"]) > 20 and case["label_basis"]
        assert case["detections"] and case["triggers"]


def test_counts_match_the_build_record():
    info = json.loads(paths.BUILD_INFO_FILE.read_text(encoding="utf-8"))
    assert info["cases"] == len(CASES) and info["labels"] == dict(Counter(c["label"] for c in CASES))
    assert info["otrf_commit"] == CAPTURES["source"]["commit"] and info["sigma_commit"] == CAPTURES["sigma"]["commit"]


def test_split_is_by_recording_and_matches_the_capture_list():
    split_of = {c["name"]: c["split"] for c in CAPTURES["captures"]}
    assert all(split_of[case["capture"]] == case["split"] for case in CASES)
    assert {c["split"] for c in CASES} == {"dev", "test"}


def test_what_the_agent_is_shown_does_not_contain_the_answer():
    names = {c["name"] for c in CAPTURES["captures"]}
    for case in CASES:
        shown = render_case(public_view(case))
        assert case["capture"] not in shown or case["capture"] not in names or len(case["capture"]) < 6
        assert case["label_reason"] not in shown


def test_ground_truth_file_is_well_formed():
    spec = yaml.safe_load(paths.GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    Labeler(spec)
    known = {c["name"] for c in CAPTURES["captures"]}
    assert set(spec["captures"]) <= known
    for entry in spec["captures"].values():
        for item in (entry.get("footholds") or []) + (entry.get("decisions") or []):
            assert len(item["why"]) > 15
        for decision in entry.get("decisions") or []:
            assert decision["label"] in LABELS
