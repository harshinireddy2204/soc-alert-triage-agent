"""A small evaluator for the subset of the Sigma rule format this project needs.

It compiles a Sigma rule (https://sigmahq.io) into a Python predicate over a flat
event dictionary. It is not a full Sigma implementation: rules that use features
outside the supported subset raise ``UnsupportedRule`` and are skipped and counted,
never silently approximated.

Supported: field equality with wildcards, the modifiers ``contains``,
``startswith``, ``endswith``, ``all``, ``re``, ``cased``, ``base64``,
``base64offset``, ``utf16le``/``wide``, ``windash``, ``cidr``, ``exists``,
``fieldref``, ``gt``/``gte``/``lt``/``lte``, keyword searches, and conditions built
from ``and``/``or``/``not``, parentheses, ``1 of``/``all of`` with wildcards and
``them``.

Not supported: aggregation and correlation (``| count()`` and friends), the
``expand`` placeholder modifier, timeframe logic.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Event = dict[str, str]
Predicate = Callable[["EventView"], bool]


class UnsupportedRule(Exception):
    """The rule uses a Sigma feature this evaluator does not implement."""


class EventView:
    """An event plus lazily computed lower-cased views used during matching."""

    __slots__ = ("_blob", "_lower", "raw")

    def __init__(self, raw: Event):
        self.raw = raw
        self._lower: dict[str, str | None] = {}
        self._blob: str | None = None

    def get(self, name: str) -> str | None:
        value = self.raw.get(name)
        return None if value is None else str(value)

    def lower(self, name: str) -> str | None:
        try:
            return self._lower[name]
        except KeyError:
            value = self.raw.get(name)
            out = None if value is None else str(value).lower()
            self._lower[name] = out
            return out

    def blob(self) -> str:
        if self._blob is None:
            self._blob = "\n".join(str(v) for v in self.raw.values()).lower()
        return self._blob


# --------------------------------------------------------------------------- values


def _split_wildcards(value: str) -> tuple[bool, str]:
    """Return (has_wildcards, regex_or_literal) for a Sigma string value."""
    out: list[str] = []
    literal: list[str] = []
    has_wild = False
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            # A backslash escapes a wildcard or another backslash; "\\\\" is one backslash.
            out.append(re.escape(value[i + 1]))
            literal.append(value[i + 1])
            i += 2
            continue
        if ch == "*":
            has_wild = True
            out.append(".*")
        elif ch == "?":
            has_wild = True
            out.append(".")
        else:
            out.append(re.escape(ch))
            literal.append(ch)
        i += 1
    return has_wild, "".join(out) if has_wild else "".join(literal)


def _b64_offsets(data: bytes) -> list[str]:
    """The three encodings of ``data`` at each byte alignment, trimmed to the stable part."""
    start = (0, 2, 3)
    end = (None, -3, -2)
    variants = []
    for offset in range(3):
        encoded = base64.b64encode(b" " * offset + data).decode()
        tail = end[(len(data) + offset) % 3]
        variants.append(encoded[start[offset] : tail])
    return variants


_DASHES = ["-", "/", "\u2013", "\u2014", "\u2015"]  # hyphen, slash, en dash, em dash, horizontal bar


def _windash(value: str) -> list[str]:
    variants = {value}
    for dash in _DASHES[1:]:
        variants.add(re.sub(r"(^|\s)-", lambda m, d=dash: m.group(1) + d, value))
    return sorted(variants)


def _string_matcher(field_name: str, value: str, mode: str, cased: bool) -> Predicate:
    has_wild, compiled = _split_wildcards(value)
    if has_wild:
        pattern = {
            "contains": compiled,
            "startswith": "^" + compiled,
            "endswith": compiled + "$",
            "equals": "^" + compiled + "$",
        }[mode]
        regex = re.compile(pattern, re.DOTALL | (0 if cased else re.IGNORECASE))

        def match_regex(ev: EventView) -> bool:
            got = ev.get(field_name)
            return got is not None and regex.search(got) is not None

        return match_regex

    needle = compiled if cased else compiled.lower()
    getter = EventView.get if cased else EventView.lower

    if mode == "contains":
        return lambda ev: (got := getter(ev, field_name)) is not None and needle in got
    if mode == "startswith":
        return lambda ev: (got := getter(ev, field_name)) is not None and got.startswith(needle)
    if mode == "endswith":
        return lambda ev: (got := getter(ev, field_name)) is not None and got.endswith(needle)
    return lambda ev: getter(ev, field_name) == needle


def _to_float(text: str | None) -> float | None:
    if text is None:
        return None
    try:
        return float(int(text, 16)) if text.lower().startswith("0x") else float(text)
    except ValueError:
        return None


def _field_condition(key: str, raw_value: Any) -> Predicate:
    parts = key.split("|")
    field_name, modifiers = parts[0], parts[1:]
    if "expand" in modifiers:
        raise UnsupportedRule("expand modifier")

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    require_all = "all" in modifiers
    cased = "cased" in modifiers
    mode = "equals"
    for candidate in ("contains", "startswith", "endswith"):
        if candidate in modifiers:
            mode = candidate

    known = {
        "all",
        "cased",
        "contains",
        "startswith",
        "endswith",
        "re",
        "i",
        "m",
        "s",
        "base64",
        "base64offset",
        "utf16le",
        "utf16be",
        "utf16",
        "wide",
        "windash",
        "cidr",
        "exists",
        "fieldref",
        "gt",
        "gte",
        "lt",
        "lte",
    }
    unknown = set(modifiers) - known
    if unknown:
        raise UnsupportedRule("unknown modifier")

    matchers: list[Predicate] = []

    if "exists" in modifiers:
        want = bool(raw_value)
        return lambda ev: (ev.get(field_name) is not None) == want

    if "fieldref" in modifiers:
        for other in values:
            other_name = str(other)
            matchers.append(lambda ev, o=other_name: ev.lower(field_name) is not None and ev.lower(field_name) == ev.lower(o))
    elif "cidr" in modifiers:
        networks = [ipaddress.ip_network(str(v), strict=False) for v in values]

        def in_networks(ev: EventView, nets=networks) -> list[bool]:
            got = ev.get(field_name)
            try:
                address = ipaddress.ip_address(got) if got else None
            except ValueError:
                address = None
            return [address is not None and address.version == n.version and address in n for n in nets]

        if require_all:
            return lambda ev: all(in_networks(ev))
        return lambda ev: any(in_networks(ev))
    elif any(op in modifiers for op in ("gt", "gte", "lt", "lte")):
        op = next(o for o in ("gte", "lte", "gt", "lt") if o in modifiers)
        compare = {
            "gt": lambda a, b: a > b,
            "gte": lambda a, b: a >= b,
            "lt": lambda a, b: a < b,
            "lte": lambda a, b: a <= b,
        }[op]
        for v in values:
            bound = float(v)
            matchers.append(lambda ev, b=bound: (got := _to_float(ev.get(field_name))) is not None and compare(got, b))
    elif "re" in modifiers:
        flags = 0
        if "i" in modifiers:
            flags |= re.IGNORECASE
        if "m" in modifiers:
            flags |= re.MULTILINE
        if "s" in modifiers:
            flags |= re.DOTALL
        for v in values:
            try:
                regex = re.compile(str(v), flags)
            except re.error as exc:
                raise UnsupportedRule("invalid regular expression") from exc
            matchers.append(lambda ev, r=regex: (got := ev.get(field_name)) is not None and r.search(got) is not None)
    else:
        for v in values:
            if v is None or v == "":
                if v is None:
                    matchers.append(lambda ev: ev.get(field_name) in (None, "", "-"))
                else:
                    matchers.append(lambda ev: ev.get(field_name) == "")
                continue
            expanded = [str(v)]
            if "windash" in modifiers:
                expanded = [variant for text in expanded for variant in _windash(text)]
            if "base64" in modifiers or "base64offset" in modifiers:
                encoded: list[str] = []
                for text in expanded:
                    if "utf16le" in modifiers or "wide" in modifiers:
                        data = text.encode("utf-16-le")
                    elif "utf16be" in modifiers:
                        data = text.encode("utf-16-be")
                    elif "utf16" in modifiers:
                        data = text.encode("utf-16")
                    else:
                        data = text.encode()
                    if "base64offset" in modifiers:
                        encoded.extend(_b64_offsets(data))
                    else:
                        encoded.append(base64.b64encode(data).decode().rstrip("="))
                # Base64 text is case-sensitive and must not be treated as a wildcard pattern.
                options = [
                    (lambda ev, n=needle: (got := ev.get(field_name)) is not None and n in got)
                    if mode == "contains"
                    else (lambda ev, n=needle: ev.get(field_name) == n)
                    for needle in encoded
                ]
            else:
                options = [_string_matcher(field_name, text, mode, cased) for text in expanded]
            if len(options) == 1:
                matchers.append(options[0])
            else:
                matchers.append(lambda ev, opts=options: any(o(ev) for o in opts))

    if not matchers:
        return lambda ev: False
    if len(matchers) == 1:
        return matchers[0]
    if require_all:
        return lambda ev: all(m(ev) for m in matchers)
    return lambda ev: any(m(ev) for m in matchers)


def _keyword(value: Any) -> Predicate:
    has_wild, compiled = _split_wildcards(str(value))
    if has_wild:
        regex = re.compile(compiled, re.IGNORECASE | re.DOTALL)
        return lambda ev: regex.search(ev.blob()) is not None
    needle = compiled.lower()
    return lambda ev: needle in ev.blob()


def _search(definition: Any) -> Predicate:
    """Compile one named search identifier from the ``detection`` section."""
    if isinstance(definition, dict):
        conditions = [_field_condition(k, v) for k, v in definition.items()]
        return lambda ev: all(c(ev) for c in conditions)
    if isinstance(definition, list):
        options = [_search(item) if isinstance(item, (dict, list)) else _keyword(item) for item in definition]
        return lambda ev: any(o(ev) for o in options)
    return _keyword(definition)


# ------------------------------------------------------------------------ condition

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _compile_condition(text: str, searches: dict[str, Predicate]) -> Predicate:
    if "|" in text:
        raise UnsupportedRule("aggregation in condition")
    tokens = _TOKEN.findall(text)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def names_for(pattern: str) -> list[str]:
        if pattern == "them":
            return [n for n in searches if not n.startswith("_")]
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        return [n for n in searches if regex.match(n)]

    def parse_or() -> Predicate:
        left = parse_and()
        while peek() is not None and peek().lower() == "or":
            take()
            right = parse_and()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def parse_and() -> Predicate:
        left = parse_not()
        while peek() is not None and peek().lower() == "and":
            take()
            right = parse_not()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def parse_not() -> Predicate:
        if peek() is not None and peek().lower() == "not":
            take()
            inner = parse_not()
            return lambda ev: not inner(ev)
        return parse_atom()

    def parse_atom() -> Predicate:
        token = take()
        if token == "(":
            inner = parse_or()
            if take() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            return inner
        lowered = token.lower()
        if lowered in ("1", "all", "any") and peek() is not None and peek().lower() == "of":
            take()
            members = [searches[n] for n in names_for(take())]
            if not members:
                raise UnsupportedRule("quantifier matches no search identifier")
            if lowered == "all":
                return lambda ev: all(m(ev) for m in members)
            return lambda ev: any(m(ev) for m in members)
        if token not in searches:
            raise UnsupportedRule("condition names an undefined search")
        return searches[token]

    predicate = parse_or()
    if position != len(tokens):
        raise UnsupportedRule("trailing tokens in condition")
    return predicate


# ---------------------------------------------------------------------------- rules

# Sysmon event IDs for each Sigma log source category.
CATEGORY_EVENT_IDS: dict[str, tuple[int, ...]] = {
    "process_creation": (1,),
    "file_change": (2,),
    "network_connection": (3,),
    "driver_load": (6,),
    "image_load": (7,),
    "create_remote_thread": (8,),
    "raw_access_thread": (9,),
    "process_access": (10,),
    "file_event": (11,),
    "registry_add": (12,),
    "registry_delete": (12,),
    "registry_set": (13,),
    "registry_event": (12, 13, 14),
    "create_stream_hash": (15,),
    "pipe_created": (17, 18),
    "wmi_event": (19, 20, 21),
    "dns_query": (22,),
    "file_delete": (23, 26),
    "process_tampering": (25,),
}

SYSMON = "microsoft-windows-sysmon/operational"

# Windows event log channel for each Sigma log source service.
SERVICE_CHANNELS: dict[str, str] = {
    "security": "security",
    "system": "system",
    "application": "application",
    "sysmon": SYSMON,
    "powershell": "microsoft-windows-powershell/operational",
    "powershell-classic": "windows powershell",
    "taskscheduler": "microsoft-windows-taskscheduler/operational",
    "wmi": "microsoft-windows-wmi-activity/operational",
    "windefend": "microsoft-windows-windows defender/operational",
    "bits-client": "microsoft-windows-bits-client/operational",
    "firewall-as": "microsoft-windows-windows firewall with advanced security/firewall",
    "terminalservices-localsessionmanager": "microsoft-windows-terminalservices-localsessionmanager/operational",
    "smbclient-security": "microsoft-windows-smbclient/security",
    "dns-server": "dns server",
    "codeintegrity-operational": "microsoft-windows-codeintegrity/operational",
    "applocker": "microsoft-windows-applocker/exe and dll",
}

POWERSHELL_CATEGORIES = {"ps_script": 4104, "ps_module": 4103}


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    author: str
    tags: list[str]
    falsepositives: list[str]
    path: str
    channel: str
    event_ids: tuple[int, ...] | None
    predicate: Predicate = field(repr=False)

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique IDs from the rule tags, for example ``T1003.001``."""
        found = []
        for tag in self.tags:
            match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag.lower())
            if match:
                found.append(match.group(1).upper())
        return found

    @property
    def tactics(self) -> list[str]:
        return [
            t.split(".", 1)[1].replace("-", "_")
            for t in self.tags
            if t.lower().startswith("attack.") and not re.match(r"attack\.[tgs]\d", t.lower())
        ]

    def matches(self, event: EventView) -> bool:
        return self.predicate(event)


def compile_rule(doc: dict[str, Any], path: str = "") -> Rule:
    """Compile a parsed Sigma YAML document. Raises ``UnsupportedRule`` when it cannot."""
    logsource = doc.get("logsource") or {}
    if logsource.get("product") != "windows":
        raise UnsupportedRule("not a Windows rule")
    category = logsource.get("category")
    service = logsource.get("service")

    if category in CATEGORY_EVENT_IDS:
        channel, event_ids = SYSMON, CATEGORY_EVENT_IDS[category]
    elif category in POWERSHELL_CATEGORIES:
        channel, event_ids = SERVICE_CHANNELS["powershell"], (POWERSHELL_CATEGORIES[category],)
    elif category is None and service in SERVICE_CHANNELS:
        channel, event_ids = SERVICE_CHANNELS[service], None
    else:
        raise UnsupportedRule(f"log source this loader does not read: {category or service}")

    detection = dict(doc.get("detection") or {})
    condition = detection.pop("condition", None)
    detection.pop("timeframe", None)
    if condition is None:
        raise UnsupportedRule("no condition")
    searches = {name: _search(definition) for name, definition in detection.items()}
    if isinstance(condition, list):
        parts = [_compile_condition(str(c), searches) for c in condition]

        def predicate(ev: EventView) -> bool:
            return any(p(ev) for p in parts)

    else:
        predicate = _compile_condition(str(condition), searches)

    author = doc.get("author") or ""
    if isinstance(author, list):
        author = ", ".join(str(a) for a in author)
    return Rule(
        id=str(doc.get("id", "")),
        title=str(doc.get("title", "")),
        level=str(doc.get("level", "medium")),
        description=" ".join(str(doc.get("description", "")).split()),
        author=str(author),
        tags=[str(t) for t in doc.get("tags") or []],
        falsepositives=[str(f) for f in doc.get("falsepositives") or []],
        path=path,
        channel=channel,
        event_ids=event_ids,
        predicate=predicate,
    )
