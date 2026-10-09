"""The LLM triage agent: investigate with tools, then commit to a verdict.

The loop is deliberately plain. On every turn the model answers with one JSON
object: either a tool call or a final verdict. That protocol works with small
local models that do not support native function calling, and it keeps the
transcript readable.
"""

from __future__ import annotations

import json
import re

from .llm import Backend, BackendError
from .tools import TOOL_SPECS, Toolbox
from .verdict import Verdict

MAX_STEPS = 10
MAX_TOOL_OUTPUT_CHARS = 2800
# Windows paths and process ids tokenise badly (roughly 2.6 characters per token), and a
# server that receives more than its context window silently drops the oldest text, which
# is the instructions. The transcript is therefore trimmed well before that point.
CHARS_PER_TOKEN = 2.6
REPLY_RESERVE_TOKENS = 900
MAX_INVALID_REPLIES = 3
MAX_RULES_SHOWN = 6
MAX_TRIGGERS_SHOWN = 8
FINAL_ALIASES = {"final", "final_answer", "finalanswer", "finish", "answer", "verdict", "submit", "done", "conclude"}

SYSTEM_PROMPT = """You are a security operations analyst triaging one alert case from a Windows network.

A case is one process on one host, plus the detection rules that fired on it. Detection rules are \
written to catch attacker behaviour, but many of them also fire on normal system, administrative and \
management-agent activity. Your job is to work out which this is.

Decide whether the activity in the case is:
- "malicious": carried out by an attacker, or by a system component acting on an attacker's request \
(for example the Task Scheduler service registering a task an attacker created);
- "benign": normal operating system, management software or user activity.

How to work:
1. Investigate before deciding. Establish what the process is, what started it, what it did, and \
whether that fits a legitimate purpose on this host. Look at the parent chain and at neighbouring \
activity, not only at the event that fired.
2. A rule's severity is the rule author's guess, not evidence. High-severity rules fire on benign \
software and low-severity rules fire on real attacks.
3. A program being legitimate does not make its use legitimate. Attackers run built-in and \
administrative tools (whoami, net, reg, PsExec, PowerShell, schtasks) all the time. Judge by who ran \
it, what started it, and what that parent was doing. An encoded or hidden command line, a shell \
started by a service, by WMI or by a remote session, or a parent that itself looks wrong are reasons \
for suspicion that a familiar program name does not cancel.
4. Base every claim on events you have seen. Cite them by their numbers (E12345). Never cite an \
event you were not shown.
5. Use at most {max_steps} tool calls, fewer if the picture is already clear. The process details \
are already given to you below; do not ask for them again.

When to escalate to a human:
Set "escalate" to true when the evidence does not settle the question: you could not establish \
what started the process, the signals conflict, or your confidence is below about 0.8. \
A confidence of 0.9 or more means you have seen direct evidence, not that nothing looked odd. \
Do not escalate just to avoid deciding, and do not auto-close something you are unsure about. \
Always give your best-guess verdict even when escalating.

Tools:
{tools}

Reply with exactly one JSON object and nothing else.

To call a tool:
{{"thought": "<one or two sentences: what you know and what you need next>", "action": "<tool name>", "arguments": {{...}}}}

To finish:
{{"thought": "<your reasoning>", "action": "final", "verdict": "malicious" or "benign", \
"confidence": <number from 0.5 to 1.0>, "escalate": true or false, \
"summary": "<two to four sentences an analyst can act on>", \
"evidence": ["E123", "E456"], "technique": "<MITRE ATT&CK id or null>"}}"""


def render_tools() -> str:
    lines = []
    for spec in TOOL_SPECS:
        arguments = "; ".join(f"{name}: {meaning}" for name, meaning in spec["arguments"].items()) or "none"
        lines.append(f"- {spec['name']}: {spec['description']}\n  arguments: {arguments}")
    return "\n".join(lines)


def render_case(case: dict) -> str:
    """The alert as the analyst first sees it. Contains no ground truth."""
    subject = case["subject"]
    lines = [
        f"CASE {case['case_id']}",
        f"Host: {case['host']}",
        f"First alert: {case['first_alert_ts']}",
        "",
        "Process the case is about:",
        f"  id: {case['pguid']}",
        f"  image: {subject.get('image')}",
        f"  command line: {subject.get('command_line') or '(not recorded)'}",
        f"  user: {subject.get('user')}   integrity: {subject.get('integrity')}   pid: {subject.get('pid')}",
        f"  started: {subject.get('started') or 'before the recording began'}",
        f"  parent: {subject.get('parent_image') or '(not recorded)'}",
        "",
        f"Detection rules that fired ({len(case['detections'])}):",
    ]
    for detection in case["detections"][:MAX_RULES_SHOWN]:
        techniques = ", ".join(detection["techniques"]) or "none listed"
        false_positives = "; ".join(detection["known_false_positives"]) or "none listed"
        lines.append(f"- [{detection['level']}] {detection['title']} (ATT&CK: {techniques}; fired {detection.get('hits', 1)}x)")
        lines.append(f"    what it looks for: {detection['description'][:300]}")
        lines.append(f"    false positives the rule author expects: {false_positives[:200]}")
    if len(case["detections"]) > MAX_RULES_SHOWN:
        rest = ", ".join(f"[{d['level']}] {d['title']}" for d in case["detections"][MAX_RULES_SHOWN:])
        lines.append(f"- and {len(case['detections']) - MAX_RULES_SHOWN} more: {rest}")
    lines.append("")
    lines.append("Events that fired the rules:")
    for trigger in case["triggers"][:MAX_TRIGGERS_SHOWN]:
        lines.append(f"[E{trigger['event_id']}] {trigger['ts'][11:23]} {trigger['what']}")
    return "\n".join(lines)


def extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model reply, tolerating code fences and chatter."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    while start != -1:
        depth, in_string, escaped = 0, False, False
        for position in range(start, len(text)):
            char = text[position]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : position + 1])
                    except json.JSONDecodeError:
                        break
                    return parsed if isinstance(parsed, dict) else None
        start = text.find("{", start + 1)
    return None


def parse_event_ids(values: object) -> list[int]:
    if isinstance(values, (str, int)):
        values = [values]
    found: list[int] = []
    for value in values if isinstance(values, list) else []:
        match = re.search(r"\d+", str(value))
        if match and int(match.group(0)) not in found:
            found.append(int(match.group(0)))
    return found


def parse_final(action: dict) -> Verdict:
    verdict = str(action.get("verdict", "")).strip().lower()
    if verdict not in ("malicious", "benign"):
        raise ValueError('"verdict" must be "malicious" or "benign"')
    try:
        confidence = float(action.get("confidence"))
    except (TypeError, ValueError) as error:
        raise ValueError('"confidence" must be a number from 0.5 to 1.0') from error
    escalate = action.get("escalate")
    if isinstance(escalate, str):
        escalate = escalate.strip().lower() in ("true", "yes", "1")
    technique = action.get("technique")
    technique = str(technique).strip().upper() if technique and str(technique).lower() not in ("null", "none") else None
    return Verdict(
        verdict=verdict,
        confidence=max(0.5, min(1.0, confidence)),
        escalate=bool(escalate),
        summary=str(action.get("summary") or action.get("thought") or "").strip(),
        evidence=parse_event_ids(action.get("evidence")),
        technique=technique,
    )


def normalise_action(action: dict | None) -> dict | None:
    """Accept the common ways a model phrases a tool call or a final answer."""
    if not isinstance(action, dict):
        return None
    name = action.get("action") or action.get("tool") or action.get("name")
    if isinstance(name, dict):  # {"action": {"name": ..., "arguments": ...}}
        action = {**action, **name}
        name = name.get("name") or name.get("tool")
    if name is None and "verdict" in action:
        name = "final"
    if not isinstance(name, str):
        return None
    if name.strip().lower().replace(" ", "_") in FINAL_ALIASES:
        name = "final"
    arguments = action.get("arguments") or action.get("args") or action.get("parameters") or action.get("input") or {}
    return {**action, "action": name.strip(), "arguments": arguments if isinstance(arguments, dict) else {}}


def _trim(messages: list[dict], budget_chars: int) -> None:
    """Drop the oldest tool outputs once the transcript outgrows the context budget."""
    total = sum(len(m["content"]) for m in messages)
    for message in messages[2:-2]:
        if total <= budget_chars:
            return
        if message["role"] == "user" and message["content"].startswith("TOOL RESULT") and len(message["content"]) > 200:
            total -= len(message["content"])
            message["content"] = "TOOL RESULT\n[removed to save space; call the tool again if you still need it]"
            total += len(message["content"])


class LLMAgent:
    def __init__(self, backend: Backend, max_steps: int = MAX_STEPS, context_tokens: int = 8192):
        self.backend = backend
        self.max_steps = max_steps
        self.name = backend.name
        self.budget_chars = int((context_tokens - REPLY_RESERVE_TOKENS) * CHARS_PER_TOKEN)

    def triage(self, case: dict, toolbox: Toolbox) -> tuple[Verdict, dict]:
        """Run one investigation. Returns the verdict and a trace of how it was reached."""
        # Every analyst starts by looking at the process and its parents, so that lookup is
        # done up front instead of hoping the model asks for it.
        opening = toolbox.call("process_info", {})
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(max_steps=self.max_steps, tools=render_tools())},
            {
                "role": "user",
                "content": f"{render_case(case)}\n\nProcess details (process_info):\n{opening}\n\nInvestigate, then give your verdict.",
            },
        ]
        trace: dict = {"steps": [], "input_tokens": 0, "output_tokens": 0, "invalid_replies": 0, "failure": None, "rejected_replies": []}
        tool_calls = 0
        while True:
            _trim(messages, self.budget_chars)
            try:
                reply = self.backend.chat(messages)
            except BackendError as error:
                return self._give_up(trace, f"model backend failed: {error}")
            trace["input_tokens"] += reply.input_tokens
            trace["output_tokens"] += reply.output_tokens
            messages.append({"role": "assistant", "content": reply.text})

            action = normalise_action(extract_json(reply.text))
            problem = None
            if action is None:
                problem = (
                    'Your reply was not a JSON object with an "action". Reply with exactly one JSON object: '
                    'a tool call {"thought": ..., "action": "<tool name>", "arguments": {...}} or a final answer '
                    '{"thought": ..., "action": "final", "verdict": ..., "confidence": ..., "escalate": ..., '
                    '"summary": ..., "evidence": [...]}.'
                )
            elif action["action"] == "final":
                try:
                    verdict = parse_final(action)
                except ValueError as error:
                    problem = f"Your final answer was not valid: {error}. Send the corrected JSON object."
                else:
                    trace["steps"].append({"thought": str(action.get("thought", "")), "action": "final"})
                    return verdict, trace
            if problem is not None:
                trace["invalid_replies"] += 1
                trace["rejected_replies"].append(reply.text[:400])
                if trace["invalid_replies"] >= MAX_INVALID_REPLIES:
                    return self._give_up(trace, "the model did not produce a valid reply")
                messages.append({"role": "user", "content": problem})
                continue

            if tool_calls >= self.max_steps:
                messages.append(
                    {
                        "role": "user",
                        "content": "You have used all your tool calls. Reply now with your final "
                        'answer: one JSON object with "action": "final".',
                    }
                )
                tool_calls += 1
                if tool_calls > self.max_steps + 2:
                    return self._give_up(trace, "the model kept calling tools after the limit")
                continue
            tool_calls += 1
            output = toolbox.call(action["action"], action["arguments"])
            if len(output) > MAX_TOOL_OUTPUT_CHARS:
                output = output[:MAX_TOOL_OUTPUT_CHARS] + "\n[output cut; narrow the request to see more]"
            trace["steps"].append(
                {
                    "thought": str(action.get("thought", "")),
                    "action": action["action"],
                    "arguments": action["arguments"],
                    "output": output,
                }
            )
            remaining = self.max_steps - tool_calls
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"TOOL RESULT ({remaining} tool calls left)\n{output}\n\n"
                        'Reply with one JSON object: another tool call, or your final answer with "action": "final".'
                    ),
                }
            )

    @staticmethod
    def _give_up(trace: dict, reason: str) -> tuple[Verdict, dict]:
        """A broken investigation is handed to a human, never silently closed."""
        trace["failure"] = reason
        verdict = Verdict("malicious", 0.5, True, f"Investigation did not complete ({reason}); sent to a human.")
        return verdict, trace
