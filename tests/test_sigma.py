import pytest

from triage import sigma


def rule(detection: dict, category: str = "process_creation") -> sigma.Rule:
    return sigma.compile_rule(
        {
            "title": "t",
            "id": "1",
            "level": "high",
            "tags": ["attack.t1003.001", "attack.credential-access"],
            "logsource": {"product": "windows", "category": category},
            "detection": detection,
        }
    )


def hit(r: sigma.Rule, **fields: str) -> bool:
    return r.matches(sigma.EventView(fields))


def test_equality_is_case_insensitive_and_wildcards_work():
    r = rule({"sel": {"Image": "*\\WHOAMI.exe"}, "condition": "sel"})
    assert hit(r, Image="C:\\Windows\\System32\\whoami.exe")
    assert not hit(r, Image="C:\\Windows\\System32\\whoami.exe.bak")
    assert not hit(r, CommandLine="whoami")


def test_contains_all_and_endswith_list():
    r = rule(
        {
            "a": {"CommandLine|contains|all": ["-enc", "hidden"]},
            "b": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
            "condition": "a and b",
        }
    )
    assert hit(r, CommandLine="x -ENC abc -w Hidden", Image="c:\\ps\\powershell.exe")
    assert not hit(r, CommandLine="x -enc abc", Image="c:\\ps\\powershell.exe")


def test_condition_logic_and_quantifiers():
    r = rule(
        {
            "sel_a": {"Image|endswith": "\\a.exe"},
            "sel_b": {"Image|endswith": "\\b.exe"},
            "filter_main": {"User|contains": "SYSTEM"},
            "condition": "1 of sel_* and not 1 of filter_*",
        }
    )
    assert hit(r, Image="c:\\a.exe", User="LAB\\alice")
    assert hit(r, Image="c:\\b.exe")
    assert not hit(r, Image="c:\\a.exe", User="NT AUTHORITY\\SYSTEM")
    all_of = rule({"s1": {"A": "1"}, "s2": {"B": "2"}, "condition": "all of them"})
    assert hit(all_of, A="1", B="2") and not hit(all_of, A="1")


def test_backslash_escaping_follows_the_sigma_spec():
    r = rule({"sel": {"TargetObject|contains": "\\\\Run\\\\"}, "condition": "sel"}, "registry_set")
    assert hit(r, TargetObject="HKLM\\Software\\Run\\Updater")
    literal_star = rule({"sel": {"CommandLine|contains": "a\\*b"}, "condition": "sel"})
    assert hit(literal_star, CommandLine="xx a*b yy") and not hit(literal_star, CommandLine="xx aQb yy")


def test_regex_cidr_numeric_and_null():
    assert hit(rule({"sel": {"CommandLine|re": "^cmd\\s+/c"}, "condition": "sel"}), CommandLine="cmd  /c dir")
    net = rule({"sel": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel"}, "network_connection")
    assert hit(net, DestinationIp="10.9.8.7") and not hit(net, DestinationIp="8.8.8.8") and not hit(net, DestinationIp="fe80::1")
    assert hit(rule({"sel": {"Port|gte": 1024}, "condition": "sel"}), Port="5985")
    missing = rule({"sel": {"Image|endswith": "\\x.exe"}, "f": {"CommandLine": None}, "condition": "sel and not f"})
    assert not hit(missing, Image="c:\\x.exe") and hit(missing, Image="c:\\x.exe", CommandLine="x")


def test_base64offset_and_windash():
    import base64

    r = rule({"sel": {"CommandLine|base64offset|contains": "DownloadString"}, "condition": "sel"})
    for prefix in ("", "a", "ab"):
        encoded = base64.b64encode((prefix + "IEX DownloadString('x')").encode()).decode()
        assert hit(r, CommandLine="powershell -enc " + encoded)
    dash = rule({"sel": {"CommandLine|windash|contains": " -accepteula"}, "condition": "sel"})
    assert hit(dash, CommandLine="psexec /accepteula") and hit(dash, CommandLine="psexec -accepteula")


def test_keywords_search_every_field():
    r = sigma.compile_rule(
        {
            "title": "k",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {"keywords": ["mimikatz", "sekurlsa*"], "condition": "keywords"},
        }
    )
    assert r.channel == "security" and r.event_ids is None
    assert hit(r, Anything="ran SEKURLSA::logonpasswords")


def test_metadata_and_log_source_mapping():
    r = rule({"sel": {"Image": "x"}, "condition": "sel"}, "process_access")
    assert r.event_ids == (10,) and r.channel == sigma.SYSMON
    assert r.techniques == ["T1003.001"] and r.tactics == ["credential_access"]


@pytest.mark.parametrize(
    "doc",
    [
        {"logsource": {"product": "linux", "category": "process_creation"}, "detection": {"s": {"a": "b"}, "condition": "s"}},
        {
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"s": {"a": "b"}, "condition": "s | count() > 5"},
        },
        {"logsource": {"product": "windows", "category": "process_creation"}, "detection": {"s": {"a|expand": "%x%"}, "condition": "s"}},
        {"logsource": {"product": "windows", "category": "no_such_category"}, "detection": {"s": {"a": "b"}, "condition": "s"}},
        {"logsource": {"product": "windows", "category": "process_creation"}, "detection": {"s": {"a": "b"}, "condition": "s and missing"}},
    ],
)
def test_unsupported_rules_are_refused_not_approximated(doc):
    with pytest.raises(sigma.UnsupportedRule):
        sigma.compile_rule(doc)
