"""Triage policies that do not use a language model.

They exist to answer one question about the LLM agent: is it better than what a
team could ship without it? Three reference points:

* ``AlwaysEscalate``: every case goes to a human. Safe, and no help at all.
* ``SeverityRule``: trust the rule author's severity. This is what a queue sorted
  by severity effectively does.
* ``Scorecard``: a hand-written evidence checklist that uses the same
  investigation data the agent can reach. It is the honest "no AI" competitor.
"""

from __future__ import annotations

import math
import ntpath
import re

from .store import CaseStore
from .tools import Toolbox
from .verdict import Verdict

LEVEL_POINTS = {"low": 0.0, "medium": 1.0, "high": 2.0, "critical": 3.0}


class AlwaysEscalate:
    name = "always-escalate"

    def triage(self, case: dict, toolbox: Toolbox) -> tuple[Verdict, dict]:
        return Verdict("malicious", 0.5, True, "Policy: every case is reviewed by a human."), {"steps": []}


class SeverityRule:
    """Call it malicious when any rule that fired is rated high or critical."""

    name = "severity-rule"

    def triage(self, case: dict, toolbox: Toolbox) -> tuple[Verdict, dict]:
        level = case["max_level"]
        malicious = level in ("high", "critical")
        confidence = {"low": 0.75, "medium": 0.55, "high": 0.7, "critical": 0.9}[level]
        top = case["detections"][0]
        evidence = [t["event_id"] for t in case["triggers"][:3]]
        summary = f"Highest rule severity is {level} ({top['title']})."
        return Verdict("malicious" if malicious else "benign", confidence, False, summary, evidence), {"steps": []}


# --------------------------------------------------------------------- scorecard

USER_WRITABLE = re.compile(r"\\(users|programdata|temp|tmp|perflogs)\\", re.IGNORECASE)
MANAGEMENT_PATHS = re.compile(r"^c:\\(windowsazure|packages\\plugins|program files\\microsoft monitoring agent)\\", re.IGNORECASE)
SERVICE_ACCOUNTS = ("nt authority\\system", "nt authority\\local service", "nt authority\\network service")
SYSTEM_PARENTS = {"services.exe", "svchost.exe", "wininit.exe", "smss.exe", "system", "winlogon.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
REMOTE_EXEC_PARENTS = {
    "wmiprvse.exe",
    "wsmprovhost.exe",
    "services.exe",
    "w3wp.exe",
    "mshta.exe",
    "wscript.exe",
    "winword.exe",
    "excel.exe",
    "dllhost.exe",
    "scrcons.exe",
    "msbuild.exe",
    "regsvr32.exe",
}
QUIET_PROGRAMS = {
    "notepad.exe",
    "calc.exe",
    "regsvr32.exe",
    "mshta.exe",
    "rundll32.exe",
    "msbuild.exe",
    "installutil.exe",
    "wuauclt.exe",
    "excel.exe",
}
OBFUSCATED_COMMAND = re.compile(
    r"(-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{40,}|-w(in(dowstyle)?)?\s+(1|hidden)|frombase64string|downloadstring|"
    r"iex\s*\(|https?://|\\\\\.\\pipe\\|%comspec%)",
    re.IGNORECASE,
)

# Points per signal. Positive means "looks like an attacker", negative "looks routine".
WEIGHTS = {
    "rule_severity": 1.0,  # multiplied by LEVEL_POINTS of the highest rule
    "many_rules": 1.0,  # three or more different rules fired on the same process
    "obfuscated_command": 2.0,  # encoded or hidden PowerShell, download cradle, pipe redirection
    "user_writable_image": 2.0,  # program runs from a user-writable folder and is not Microsoft's
    "unsigned_module": 1.5,  # loaded an unsigned module from outside the .NET native image cache
    "shell_from_remote_exec": 2.0,  # a shell started by WMI, WinRM, a service, a web server or Office
    "remote_thread": 2.0,  # created a thread in another process
    "quiet_program_network": 1.5,  # a program that normally stays offline opened a connection
    "attacker_lineage_hint": 1.5,  # an ancestor has an obfuscated command line
    "management_agent": -4.0,  # the process or an ancestor lives in a known management-agent folder
    "system_service": -2.0,  # service account, System32 image, started by service infrastructure
    "microsoft_user_app": -1.0,  # signed Microsoft desktop software in the user's own session
}
# Thresholds were chosen on the dev split only, by a rule fixed in advance:
#   DECIDE_AT     the cut that maximises forced-choice accuracy on dev;
#   the band      the widest auto-resolve band that keeps dev auto-accuracy at 95% or more.
# See docs/methodology.md.
DECIDE_AT = 0.0
MALICIOUS_AT = 2.5
BENIGN_AT = -1.0


def scorecard_signals(case: dict, store: CaseStore) -> dict[str, float]:
    """Compute the checklist for one case. Each signal is 0 or a positive strength."""
    subject = case["subject"]
    image = subject.get("image") or ""
    name = ntpath.basename(image).lower()
    command = subject.get("command_line") or ""
    user = (subject.get("user") or "").lower()
    parent_name = ntpath.basename(subject.get("parent_image") or "").lower()
    ancestors = store.ancestors(case["pguid"])
    creation = store.creation_event(case["pguid"])
    company = (creation.fields.get("Company") if creation else "") or ""

    signals: dict[str, float] = {}
    signals["rule_severity"] = LEVEL_POINTS[case["max_level"]]
    signals["many_rules"] = 1.0 if len(case["detections"]) >= 3 else 0.0
    signals["obfuscated_command"] = 1.0 if OBFUSCATED_COMMAND.search(command) else 0.0
    signals["user_writable_image"] = 1.0 if USER_WRITABLE.search(image) and "microsoft" not in company.lower() else 0.0

    modules, _ = store.process_events(case["pguid"], "image_load", 400)
    signals["unsigned_module"] = (
        1.0
        if any(
            m.fields.get("Signed") == "false" and "\\assembly\\nativeimages" not in (m.fields.get("ImageLoaded") or "").lower()
            for m in modules
        )
        else 0.0
    )
    signals["shell_from_remote_exec"] = 1.0 if name in SHELLS and parent_name in REMOTE_EXEC_PARENTS else 0.0
    threads, _ = store.process_events(case["pguid"], "remote_thread", 5)
    signals["remote_thread"] = 1.0 if threads else 0.0
    connections, _ = store.process_events(case["pguid"], "network", 5)
    signals["quiet_program_network"] = 1.0 if connections and name in QUIET_PROGRAMS else 0.0
    signals["attacker_lineage_hint"] = 1.0 if any(OBFUSCATED_COMMAND.search(a.get("cmdline") or "") for a in ancestors) else 0.0

    family = [image] + [a.get("image") or "" for a in ancestors]
    signals["management_agent"] = (
        1.0 if any(MANAGEMENT_PATHS.search(path) or ntpath.basename(path).lower() == "monitoringhost.exe" for path in family) else 0.0
    )
    in_system32 = image.lower().startswith("c:\\windows\\system32\\") or name == "system"
    signals["system_service"] = (
        1.0
        if (
            (user in SERVICE_ACCOUNTS or not user)
            and in_system32
            and (parent_name in SYSTEM_PARENTS or not parent_name)
            and name not in SHELLS
        )
        else 0.0
    )
    signals["microsoft_user_app"] = (
        1.0
        if (
            "microsoft" in company.lower()
            and user not in SERVICE_ACCOUNTS
            and name not in SHELLS
            and not signals["obfuscated_command"]
            and parent_name in ("explorer.exe", "")
            and case["max_level"] in ("low", "medium")
        )
        else 0.0
    )
    return signals


class Scorecard:
    """A weighted checklist with an escalation band between two thresholds."""

    name = "scorecard"

    def __init__(
        self,
        malicious_at: float = MALICIOUS_AT,
        benign_at: float = BENIGN_AT,
        decide_at: float = DECIDE_AT,
        weights: dict[str, float] | None = None,
    ):
        self.malicious_at = malicious_at
        self.benign_at = benign_at
        self.decide_at = decide_at
        self.weights = weights or WEIGHTS

    def score(self, case: dict, store: CaseStore) -> tuple[float, dict[str, float]]:
        signals = scorecard_signals(case, store)
        return sum(self.weights[name] * value for name, value in signals.items()), signals

    def triage(self, case: dict, toolbox: Toolbox) -> tuple[Verdict, dict]:
        score, signals = self.score(case, toolbox.store)
        verdict = "malicious" if score >= self.decide_at else "benign"
        escalate = self.benign_at < score < self.malicious_at
        confidence = 0.5 + 0.5 * (1 - math.exp(-abs(score - self.decide_at) / 2.5))
        fired = [f"{name} ({self.weights[name] * value:+.1f})" for name, value in signals.items() if value]
        summary = f"Checklist score {score:+.1f}. Signals: {', '.join(fired) or 'none'}."
        evidence = [t["event_id"] for t in case["triggers"][:3]]
        return Verdict(verdict, confidence, escalate, summary, evidence), {"steps": [], "signals": signals, "score": score}
