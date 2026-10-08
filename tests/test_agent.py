import json

from conftest import G_AGENT

from triage.agent import LLMAgent, extract_json, parse_final, render_case
from triage.llm import ScriptedBackend
from triage.run import public_view, run_policy
from triage.tools import Toolbox


def tool(name, **arguments):
    return json.dumps({"thought": "look", "action": name, "arguments": arguments})


def final(**overrides):
    body = {
        "thought": "done",
        "action": "final",
        "verdict": "malicious",
        "confidence": 0.9,
        "escalate": False,
        "summary": "Child of an Empire stager.",
        "evidence": ["E104"],
        "technique": "T1033",
    }
    return json.dumps({**body, **overrides})


def test_tools_show_real_data_and_record_what_was_shown(case, recording):
    box = Toolbox(case, recording["store"])
    info = box.call("process_info", {})
    assert "whoami /user" in info and "-noP -sta -w 1 -enc" in info and "services.exe" in info
    parent = box.call("process_events", {"process": G_AGENT})
    assert "network connection to 10.10.10.5:80" in parent and "DownloadString" in parent
    assert "LogonType=3" in box.call("host_timeline", {"seconds_before": 60, "seconds_after": 5, "kinds": ["logon"]})
    assert "1 of 2 other recordings" in box.call("prevalence", {"parent": "powershell.exe", "child": "whoami.exe"})
    assert "System Owner/User Discovery" in box.call("attack_technique", {"id": "T1033"})
    found = box.call("search_events", {"text": "10.10.10.5"})
    assert "2 event(s)" in found
    assert box.shown_events == {100, 101, 102, 103, 104}


def test_tool_mistakes_come_back_as_text_not_exceptions(case, recording):
    box = Toolbox(case, recording["store"])
    for name, arguments in [
        ("nope", {}),
        ("process_events", {"kind": "bogus"}),
        ("get_event", {"event": "E999999"}),
        ("search_events", {"text": "a"}),
        ("process_info", {"process": "notaguid"}),
        ("host_timeline", {"host": "elsewhere"}),
        ("prevalence", {}),
        ("process_info", {"surprise": 1}),
    ]:
        assert box.call(name, arguments).startswith("ERROR:")
    assert all(not call["ok"] for call in box.calls)


def test_agent_investigates_then_decides(case, recording):
    backend = ScriptedBackend([tool("process_info"), tool("process_events", process=G_AGENT, kind="network"), final()])
    verdict, trace = LLMAgent(backend).triage(case, Toolbox(case, recording["store"]))
    assert (verdict.verdict, verdict.escalate, verdict.evidence, verdict.technique) == ("malicious", False, [104], "T1033")
    assert [s["action"] for s in trace["steps"]] == ["process_info", "process_events", "final"]
    assert "TOOL RESULT" in backend.seen[1][-1]["content"] and trace["failure"] is None


def test_agent_recovers_from_a_malformed_reply(case, recording):
    backend = ScriptedBackend(
        ["Sure! Let me look.", "```json\n" + final(confidence="high") + "\n```", final(escalate="true", confidence=0.6)]
    )
    verdict, trace = LLMAgent(backend).triage(case, Toolbox(case, recording["store"]))
    assert trace["invalid_replies"] == 2 and verdict.escalate is True and verdict.confidence == 0.6


def test_agent_that_never_answers_is_escalated_not_closed(case, recording):
    verdict, trace = LLMAgent(ScriptedBackend(lambda messages: "I cannot comply")).triage(case, Toolbox(case, recording["store"]))
    assert verdict.escalate and trace["failure"]
    looping = LLMAgent(ScriptedBackend(lambda messages: tool("process_info")), max_steps=3)
    verdict, trace = looping.triage(case, Toolbox(case, recording["store"]))
    assert verdict.escalate and "limit" in trace["failure"] and len(trace["steps"]) == 3


def test_parsing_helpers():
    assert extract_json('noise {"a": {"b": "}"}} trailing') == {"a": {"b": "}"}}
    assert extract_json("no json here") is None
    verdict = parse_final({"verdict": "Benign", "confidence": 2, "escalate": "no", "evidence": "E5, see also", "technique": "null"})
    assert (verdict.verdict, verdict.confidence, verdict.escalate, verdict.evidence, verdict.technique) == ("benign", 1.0, False, [5], None)


def test_the_agent_never_sees_the_answer(case, recording, tmp_path, monkeypatch):
    full = {**case, "capture": "tiny", "split": "test", "label": "malicious", "label_basis": "lineage", "label_reason": "SECRET-REASON"}
    assert set(public_view(full)) == set(case)
    backend = ScriptedBackend([tool("process_info"), final(evidence=["E104", "E424242"])])
    results = run_policy(
        LLMAgent(backend),
        [full],
        tmp_path / "out.jsonl",
        log=lambda *_: None,
        store_path=recording["store"].connection.execute("PRAGMA database_list").fetchone()[2],
    )
    prompt = json.dumps(backend.seen)
    assert "SECRET-REASON" not in prompt and "tiny" not in prompt and "lineage" not in prompt
    assert results[0]["evidence_shown"] == [104] and results[0]["evidence_not_shown"] == [424242]
    # A second call resumes from the saved file without asking the model again.
    again = run_policy(
        LLMAgent(ScriptedBackend([])),
        [full],
        tmp_path / "out.jsonl",
        log=lambda *_: None,
        store_path=recording["store"].connection.execute("PRAGMA database_list").fetchone()[2],
    )
    assert again[0]["verdict"] == "malicious"


def test_case_rendering_is_complete(case):
    text = render_case(case)
    assert "Local Accounts Discovery" in text and "[E104]" in text and "Admin activity" in text
