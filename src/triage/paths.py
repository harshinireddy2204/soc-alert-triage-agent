"""Where things live. Everything downloaded or generated goes under ``data/``."""

from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BENCHMARK = REPO / "benchmark"
RESULTS = REPO / "results"
DATA = Path(os.environ.get("TRIAGE_DATA", REPO / "data"))

CAPTURES_FILE = BENCHMARK / "captures.yaml"
GROUND_TRUTH_FILE = BENCHMARK / "ground_truth.yaml"
CASES_FILE = BENCHMARK / "cases.jsonl"
ATTACK_FILE = BENCHMARK / "attack_techniques.json"
BUILD_INFO_FILE = BENCHMARK / "build_info.json"

OTRF_DIR = DATA / "otrf"
SIGMA_DIR = DATA / "sigma"
STORE_FILE = DATA / "events.sqlite"
RAW_CASES_FILE = DATA / "cases_unlabeled.jsonl"
