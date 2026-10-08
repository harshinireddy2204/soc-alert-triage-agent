"""Readable one-line descriptions of Windows events.

The same wording is used in case files, in tool output shown to the agent and in
reports, so a person can follow exactly what the agent saw.
"""

from __future__ import annotations

SYSMON = "microsoft-windows-sysmon/operational"

SYSMON_NAMES = {
    1: "process created",
    2: "file creation time changed",
    3: "network connection",
    5: "process ended",
    6: "driver loaded",
    7: "image loaded",
    8: "remote thread created",
    9: "raw disk read",
    10: "process accessed",
    11: "file created",
    12: "registry key created or deleted",
    13: "registry value set",
    14: "registry key renamed",
    15: "file stream created",
    17: "named pipe created",
    18: "named pipe connected",
    19: "WMI filter registered",
    20: "WMI consumer registered",
    21: "WMI consumer bound to filter",
    22: "DNS query",
    23: "file deleted",
    25: "process image tampered",
    26: "file deleted",
    28: "file shredding blocked",
}


def _clip(text: object, limit: int) -> str:
    value = " ".join(str(text if text is not None else "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def describe(channel: str, eid: int, f: dict, limit: int = 220) -> str:
    """One line saying what an event records, with the fields an analyst reads first."""
    if channel == SYSMON:
        if eid == 1:
            text = f"process created: {f.get('CommandLine') or f.get('Image')} (parent {f.get('ParentImage')})"
        elif eid == 2:
            text = f"file creation time changed: {f.get('TargetFilename')} from {f.get('PreviousCreationUtcTime')} to {f.get('CreationUtcTime')}"
        elif eid == 3:
            host = f.get("DestinationHostname")
            text = (
                f"network connection to {f.get('DestinationIp')}:{f.get('DestinationPort')}"
                + (f" ({host})" if host and host != "-" else "")
                + f" from {f.get('SourceIp')}"
            )
        elif eid == 7:
            text = f"image loaded: {f.get('ImageLoaded')} (signed={f.get('Signed')}, signature={f.get('Signature')})"
        elif eid == 8:
            text = f"remote thread created in {f.get('TargetImage')} by {f.get('SourceImage')}"
        elif eid == 9:
            text = f"raw disk read of {f.get('Device')}"
        elif eid == 10:
            text = f"process accessed: {f.get('TargetImage')} with rights {f.get('GrantedAccess')} by {f.get('SourceImage')}"
        elif eid in (11, 15):
            text = f"file created: {f.get('TargetFilename')}"
        elif eid == 12:
            text = f"registry {f.get('EventType') or 'key event'}: {f.get('TargetObject')}"
        elif eid == 13:
            text = f"registry value set: {f.get('TargetObject')} = {_clip(f.get('Details'), 90)}"
        elif eid == 14:
            text = f"registry key renamed: {f.get('TargetObject')} to {f.get('NewName')}"
        elif eid in (17, 18):
            text = f"named pipe {'created' if eid == 17 else 'connected'}: {f.get('PipeName')}"
        elif eid in (19, 20, 21):
            detail = f.get("Query") or f.get("Destination") or f.get("Consumer") or f.get("Name")
            text = f"{SYSMON_NAMES[eid]}: {detail}"
        elif eid == 22:
            text = f"DNS query: {f.get('QueryName')} -> {_clip(f.get('QueryResults'), 60)}"
        elif eid in (23, 26):
            text = f"file deleted: {f.get('TargetFilename')}"
        elif eid == 28:
            text = f"file shredding blocked: {f.get('TargetFilename')}"
        else:
            text = SYSMON_NAMES.get(eid, f"sysmon event {eid}")
    elif channel.startswith("microsoft-windows-powershell"):
        body = f.get("ScriptBlockText") or f.get("Payload") or f.get("ContextInfo") or f.get("Message") or ""
        text = f"PowerShell {'script block' if eid == 4104 else 'command'}: {body}"
    elif channel == "windows powershell":
        text = f"PowerShell engine event {eid}: {f.get('Message') or f.get('HostApplication') or ''}"
    elif channel == "security":
        keys = (
            "SubjectUserName",
            "TargetUserName",
            "LogonType",
            "IpAddress",
            "ProcessName",
            "NewProcessName",
            "CommandLine",
            "ObjectName",
            "ShareName",
            "RelativeTargetName",
            "ServiceName",
            "ServiceFileName",
            "TaskName",
            "AccessMask",
            "PrivilegeList",
        )
        shown = ", ".join(f"{k}={_clip(f[k], 70)}" for k in keys if f.get(k) and f[k] != "-")
        text = f"security event {eid}: {shown}"
    else:
        shown = ", ".join(f"{k}={_clip(v, 60)}" for k, v in list(f.items())[:6])
        text = f"{channel} event {eid}: {shown}"
    return _clip(text, limit)
