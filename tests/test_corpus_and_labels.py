import pytest
from conftest import G_AGENT, G_SERVICES, G_SVCHOST, G_WHOAMI, raw_events

from triage import sigma
from triage.corpus import NULL_GUID, clean_guid, collect_processes, normalize_capture, pack_fields, unpack_fields
from triage.detect import Detector, build_cases
from triage.labels import Labeler, UnlabeledCase


def test_non_sysmon_times_are_shifted_onto_the_sysmon_clock(recording):
    logon = next(e for e in recording["events"] if e["channel"] == "security")
    # The collector clock is a day behind UTC in the fixture; the offset is measured and applied.
    assert logon["ts"] == "2024-01-01T09:59:50.000Z"
    assert recording["events"] == sorted(recording["events"], key=lambda e: e["ts"])
    assert all(e["host"] == "ws1" for e in recording["events"])


def test_processes_seen_only_as_parents_are_still_known(recording):
    processes = recording["processes"]
    assert processes[G_SERVICES]["image"].endswith("services.exe") and processes[G_SERVICES]["event_id"] is None
    assert processes[G_WHOAMI]["parent_pguid"] == G_AGENT and processes[G_WHOAMI]["event_id"] is not None
    assert processes[G_SVCHOST]["pid"] == "900"


def test_powershell_log_is_tied_to_its_process(recording):
    block = next(e for e in recording["events"] if e["eid"] == 4104)
    assert block["fields"]["ProcessGuid"] == G_AGENT


def test_null_guid_is_unknown_and_fields_round_trip():
    assert clean_guid(NULL_GUID) is None and clean_guid("{AB}") == "{ab}"
    assert unpack_fields(pack_fields({"a": "ü" * 50})) == {"a": "ü" * 50}
    raw = raw_events()
    raw[2]["ParentProcessGuid"] = NULL_GUID
    events = normalize_capture(raw)
    for i, e in enumerate(events):
        e["id"] = i
    assert collect_processes(events)[G_WHOAMI]["parent_pguid"] is None


def test_hits_are_grouped_into_one_case_per_process(recording):
    doc = {
        "title": "Whoami",
        "id": "w",
        "level": "low",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"s": {"Image|endswith": "\\whoami.exe"}, "condition": "s"},
    }
    enc = {
        "title": "Encoded",
        "id": "e",
        "level": "high",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"s": {"CommandLine|contains": " -enc "}, "condition": "s"},
    }
    net = {
        "title": "PS net",
        "id": "n",
        "level": "low",
        "logsource": {"product": "windows", "category": "network_connection"},
        "detection": {"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"},
    }
    cases, unattributed = build_cases("tiny", recording["events"], Detector([sigma.compile_rule(d) for d in (doc, enc, net)]))
    assert unattributed == 0 and len(cases) == 2
    agent = next(c for c in cases if c["pguid"] == G_AGENT)
    assert [d["title"] for d in agent["detections"]] == ["Encoded", "PS net"] and agent["max_level"] == "high"


SPEC = {
    "foothold_signatures": [{"id": "empire", "image": "*\\powershell.exe", "cmdline": ["*-noP -sta -w 1 -enc*"], "why": "Empire stager"}],
    "recurring": [
        {
            "id": "tasks",
            "label": "benign",
            "why": "Windows tasks",
            "match": {"image": "*\\svchost.exe", "rules_all": ["Scheduled Task*"], "triggers_all": ["*TaskCache\\Tree\\Microsoft*"]},
        }
    ],
    "captures": {"tiny": {"decisions": []}},
}


def _case(
    pguid,
    title="Scheduled Task Created - Registry",
    trigger="registry value set: HKLM\\..\\TaskCache\\Tree\\Microsoft\\Windows\\Defrag\\Index",
):
    return {"capture": "tiny", "host": "ws1", "pguid": pguid, "detections": [{"title": title}], "triggers": [{"what": trigger}]}


def test_label_precedence_decision_then_lineage_then_recurring(recording):
    processes = recording["processes"]
    labeler = Labeler(SPEC)
    footholds = labeler.footholds("tiny", processes)
    assert set(footholds) == {G_AGENT}
    assert labeler.label(_case(G_AGENT), processes, footholds).basis == "foothold"
    child = labeler.label(_case(G_WHOAMI), processes, footholds)
    assert (child.label, child.basis) == ("malicious", "lineage") and "4321" in child.reason
    assert labeler.label(_case(G_SVCHOST), processes, footholds).label == "benign"

    reviewed = Labeler(
        {
            **SPEC,
            "captures": {
                "tiny": {"decisions": [{"host": "ws1", "pid": 5000, "image": "*\\whoami.exe", "label": "benign", "why": "reviewed"}]}
            },
        }
    )
    assert reviewed.label(_case(G_WHOAMI), processes, footholds).basis == "reviewed"


def test_a_case_nothing_explains_fails_instead_of_defaulting(recording):
    labeler = Labeler(SPEC)
    with pytest.raises(UnlabeledCase):
        labeler.label(
            _case(G_SVCHOST, trigger="registry value set: HKLM\\..\\TaskCache\\Tree\\EvilTask\\Index"), recording["processes"], {}
        )
    with pytest.raises(UnlabeledCase):
        labeler.label(_case(G_SVCHOST, title="Something Else"), recording["processes"], {})
