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
MAX_TOOL_OUTPUT_CHARS = 3500
TRANSCRIPT_BUDGET_CHARS = 22000
MAX_INVALID_REPLIES = 3

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
3. Base every claim on events you have seen. Cite them by their numbers (E12345). Never cite an \
event you were not shown.
4. Use at most {max_steps} tool calls, fewer if the picture is already clear.

When to escalate to a human:
Set "escalate" to true when the evidence does not settle the question: you could not establish \
what started the process, the signals conflict, or your confidence is below about 0.8. \
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
    for detection in case["detections"]:
        techniques = ", ".join(detection["techniques"]) or "none listed"
        false_positives = "; ".join(detection["known_false_positives"]) or "none listed"
        lines.append(f"- [{detection['level']}] {detection['title']} (ATT&CK: {techniques}; fired {detection.get('hits', 1)}x)")
        lines.append(f"    what it looks for: {detection['description'][:300]}")
        lines.append(f"    false positives the rule author expects: {false_positives[:200]}")
    lines.append("")
    lines.append("Events that fired the rules:")
    for trigger in case["triggers"]:
        lines.append(f"[E{trigger['event_id']}] {trigger['ts'][11:23]} {trigger['what']}")
    lines.append("")
    lines.append("Investigate, then give your verdict.")
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


def _trim(messages: list[dict]) -> None:
    """Drop the oldest tool outputs once the transcript outgrows the context budget."""
    total = sum(len(m["content"]) for m in messages)
    for message in messages[2:-2]:
        if total <= TRANSCRIPT_BUDGET_CHARS:
            return
        if message["role"] == "user" and message["content"].startswith("TOOL RESULT") and len(message["content"]) > 200:
            total -= len(message["content"])
            message["content"] = "TOOL RESULT\n[removed to save space; call the tool again if you still need it]"
            total += len(message["content"])


class LLMAgent:
    def __init__(self, backend: Backend, max_steps: int = MAX_STEPS):
        self.backend = backend
        self.max_steps = max_steps
        self.name = backend.name

    def triage(self, case: dict, toolbox: Toolbox) -> tuple[Verdict, dict]:
        """Run one investigation. Returns the verdict and a trace of how it was reached."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(max_steps=self.max_steps, tools=render_tools())},
            {"role": "user", "content": render_case(case)},
        ]
        trace: dict = {"steps": [], "input_tokens": 0, "output_tokens": 0, "invalid_replies": 0, "failure": None}
        tool_calls = 0
        while True:
            _trim(messages)
            try:
                reply = self.backend.chat(messages)
            except BackendError as error:
                return self._give_up(trace, f"model backend failed: {error}")
            trace["input_tokens"] += reply.input_tokens
            trace["output_tokens"] += reply.output_tokens
            messages.append({"role": "assistant", "content": reply.text})

            action = extract_json(reply.text)
            problem = None
            if action is None or "action" not in action:
                problem = 'Your reply was not a JSON object with an "action". Reply with exactly one JSON object.'
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
                if trace["invalid_replies"] >= MAX_INVALID_REPLIES:
                    return self._give_up(trace, "the model did not produce a valid reply")
                messages.append({"role": "user", "content": problem})
                continue

            if tool_calls >= self.max_steps:
                messages.append({"role": "user", "content": "You have used all your tool calls. Give your final answer now."})
                tool_calls += 1
                if tool_calls > self.max_steps + 2:
                    return self._give_up(trace, "the model kept calling tools after the limit")
                continue
            tool_calls += 1
            output = toolbox.call(str(action["action"]), action.get("arguments"))
            if len(output) > MAX_TOOL_OUTPUT_CHARS:
                output = output[:MAX_TOOL_OUTPUT_CHARS] + "\n[output cut; narrow the request to see more]"
            trace["steps"].append(
                {
                    "thought": str(action.get("thought", "")),
                    "action": str(action["action"]),
                    "arguments": action.get("arguments") or {},
                    "output": output,
                }
            )
            remaining = self.max_steps - tool_calls
            messages.append({"role": "user", "content": f"TOOL RESULT ({remaining} tool calls left)\n{output}"})

    @staticmethod
    def _give_up(trace: dict, reason: str) -> tuple[Verdict, dict]:
        """A broken investigation is handed to a human, never silently closed."""
        trace["failure"] = reason
        verdict = Verdict("malicious", 0.5, True, f"Investigation did not complete ({reason}); sent to a human.")
        return verdict, trace
