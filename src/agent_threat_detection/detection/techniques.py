"""MITRE ATT&CK (Enterprise) and MITRE ATLAS techniques referenced by detectors and rules."""

from __future__ import annotations

from agent_threat_detection.domain.findings import Technique

_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "AML.TA0005": "Execution",
    "AML.TA0010": "Exfiltration",
}

# technique id -> (name, tactic id)
_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "TA0002"),
    "T1078": ("Valid Accounts", "TA0004"),
    "T1098": ("Account Manipulation", "TA0004"),
    "T1134": ("Access Token Manipulation", "TA0004"),
    "T1548": ("Abuse Elevation Control Mechanism", "TA0004"),
    "T1550": ("Use Alternate Authentication Material", "TA0008"),
    "T1552": ("Unsecured Credentials", "TA0006"),
    "T1562": ("Impair Defenses", "TA0005"),
    "T1213": ("Data from Information Repositories", "TA0009"),
    "T1530": ("Data from Cloud Storage", "TA0009"),
    "T1030": ("Data Transfer Size Limits", "TA0010"),
    "T1041": ("Exfiltration Over C2 Channel", "TA0010"),
    "T1048": ("Exfiltration Over Alternative Protocol", "TA0010"),
    "T1567": ("Exfiltration Over Web Service", "TA0010"),
    "AML.T0051": ("LLM Prompt Injection", "AML.TA0005"),
    "AML.T0053": ("LLM Plugin Compromise", "AML.TA0005"),
    "AML.T0057": ("LLM Data Leakage", "AML.TA0010"),
}


def technique(uid: str) -> Technique:
    name, tactic = _TECHNIQUES[uid]
    return Technique(uid=uid, name=name, tactic_uid=tactic, tactic_name=_TACTICS[tactic])


def from_tag(tag: str) -> Technique | None:
    """Translate a Sigma tag (``attack.t1567`` / ``atlas.aml.t0051``) into a technique."""
    lowered = tag.lower()
    if lowered.startswith("attack.t"):
        uid = lowered.removeprefix("attack.").upper().split(".")[0]
    elif lowered.startswith("atlas.aml.t"):
        uid = lowered.removeprefix("atlas.").upper()
    else:
        return None
    return technique(uid) if uid in _TECHNIQUES else None


def known(uid: str) -> bool:
    return uid in _TECHNIQUES
