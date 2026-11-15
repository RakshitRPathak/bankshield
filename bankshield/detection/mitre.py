"""MITRE ATT&CK (Enterprise / IaaS) techniques referenced by rules and detections."""

from __future__ import annotations

TACTIC_ORDER = ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
                "Lateral Movement", "Collection", "Exfiltration", "Impact"]

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1098.001": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "Persistence"},
    "T1098.004": {"name": "Account Manipulation: SSH Authorized Keys", "tactic": "Persistence"},
    "T1098.003": {"name": "Account Manipulation: Additional Cloud Roles", "tactic": "Privilege Escalation"},
    "T1562.008": {"name": "Impair Defenses: Disable or Modify Cloud Logs", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection"},
    "T1537": {"name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
}


def describe(tid: str) -> dict[str, str]:
    t = TECHNIQUES.get(tid, {"name": tid, "tactic": "Other"})
    return {"id": tid, **t}


def tactics(tids: list[str]) -> list[str]:
    seen = {TECHNIQUES[t]["tactic"] for t in tids if t in TECHNIQUES}
    return [t for t in TACTIC_ORDER if t in seen]
