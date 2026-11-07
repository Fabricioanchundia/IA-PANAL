"""Small, curated MITRE ATT&CK catalog for SSH honeypot activity, plus evidence rules.

The model may only cite techniques from this catalog; anything else is treated as a
hallucination and dropped. Rules map concrete evidence (commands, logins) to techniques.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# technique id -> (name, tactic)
CATALOG: dict[str, tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1222.002": ("File and Directory Permissions Modification: Linux", "Defense Evasion"),
}

COMMAND_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("T1082", re.compile(r"\b(uname|lscpu|nproc|hostname)\b|/proc/cpuinfo|free -m|os-release")),
    ("T1033", re.compile(r"\b(whoami|w|last)\b|(^|[;&|\s])id($|[;&|\s])")),
    ("T1057", re.compile(r"\b(ps|top)\b")),
    ("T1016", re.compile(r"\b(ifconfig|netstat|route)\b|\bip (a|addr|route)\b")),
    ("T1087.001", re.compile(r"/etc/(passwd|shadow)")),
    ("T1105", re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b")),
    ("T1496", re.compile(r"xmrig|minerd|stratum\+|cryptonight|monero|c3pool|nicehash", re.I)),
    ("T1098.004", re.compile(r"authorized_keys")),
    ("T1053.003", re.compile(r"crontab|/etc/cron")),
    ("T1070.003", re.compile(r"history -c|\.bash_history|HISTFILE")),
    ("T1222.002", re.compile(r"\bchmod\b")),
    ("T1098", re.compile(r"\b(passwd|chpasswd|usermod)\b")),
]


@dataclass(frozen=True)
class Evidence:
    technique: str
    reason: str


def evidence_for(failed_logins: int, successful_logins: int, commands: list[str]) -> list[Evidence]:
    """Techniques supported by concrete evidence in one session, in first-seen order."""
    found: dict[str, str] = {}
    if failed_logins == 0 and successful_logins == 0 and not commands:
        found["T1595"] = "connected without trying to log in"
    if failed_logins:
        found["T1110.001"] = f"{failed_logins} failed login attempt(s)"
    if successful_logins:
        found["T1078"] = "logged in with guessed credentials"
    if commands:
        found["T1059.004"] = f"{len(commands)} shell command(s)"
    for command in commands:
        for technique, pattern in COMMAND_RULES:
            if technique not in found and pattern.search(command):
                found[technique] = f"`{command[:80]}`"
    return [Evidence(t, r) for t, r in found.items()]
