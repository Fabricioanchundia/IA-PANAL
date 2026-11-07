"""Deterministic guardrails around the AI analyst.

The model's judgment is useful, but attacker-controlled text can steer it. These rules
run after the model and cannot be talked out of their decision:

1. Detect prompt-injection attempts in anything the attacker sent.
2. Never let severity drop below what the evidence supports.
3. Never call a session with shell activity a "scan" or "brute_force".
"""

from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Minimum severity implied by evidence-backed techniques.
SEVERITY_FLOOR = {
    "T1059.004": "medium",
    "T1070.003": "medium",
    "T1105": "high",
    "T1496": "high",
    "T1098": "high",
    "T1098.004": "high",
    "T1053.003": "high",
}

# Category implied by evidence, strongest first.
CATEGORY_FROM_EVIDENCE = [
    ("T1496", "cryptominer"),
    ("T1098.004", "persistence"),
    ("T1053.003", "persistence"),
    ("T1098", "persistence"),
    ("T1105", "malware_download"),
    ("T1059.004", "recon"),
]

INJECTION_PATTERNS = [
    r"ignor(e|a|ar)\b.{0,40}\b(instruc|previous|prior|above|anterior)",
    r"disregard\b.{0,40}\b(instruc|previous|prior|above|rules)",
    r"\byou are (now|an?)\b",
    r"\b(system|assistant|developer)\s*(prompt|message|:)",
    r"(classify|mark|rate|label|report|clasifica|marca)\W{0,3}(this|it|the|esta|la)?\W{0,3}"
    r"(session|sesi[oó]n|activity)?\W{0,3}(as|como)\b",
    r"\b(severity|severidad|category|categor[ií]a)\W{0,4}(low|none|baja|benign|scan)",
    r"\b(benign|harmless|authori[sz]ed|benigna|inofensiv)",
    r"\b(ai|llm|gpt|analyst|analista)\b.{0,30}\b(note|instruction|must|should|debe)",
    r"untrusted_session_data",
    r"\bDAN\b|jailbreak",
]
_INJECTION = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.IGNORECASE)


def detect_injection(texts: list[str]) -> list[str]:
    """Attacker strings that look like instructions aimed at an AI."""
    return [t for t in texts if t and _INJECTION.search(t)]


def apply_guardrails(
    result: dict[str, Any], evidence_ids: list[str], has_shell_activity: bool, injection: bool
) -> tuple[dict[str, Any], list[str]]:
    """Return (guarded result, human-readable list of overrides)."""
    guarded = dict(result)
    overrides: list[str] = []

    floor = "low"
    reasons = []
    for technique in evidence_ids:
        level = SEVERITY_FLOOR.get(technique)
        if level and SEVERITY_ORDER.index(level) > SEVERITY_ORDER.index(floor):
            floor = level
        if level:
            reasons.append(technique)
    if injection and SEVERITY_ORDER.index("high") > SEVERITY_ORDER.index(floor):
        floor, reasons = "high", [*reasons, "prompt injection attempt"]
    if SEVERITY_ORDER.index(guarded["severity"]) < SEVERITY_ORDER.index(floor):
        overrides.append(
            f"severity raised {guarded['severity']} -> {floor} (evidence: {', '.join(reasons)})"
        )
        guarded["severity"] = floor

    if has_shell_activity and guarded["category"] in ("scan", "brute_force"):
        new = next(c for t, c in CATEGORY_FROM_EVIDENCE if t in evidence_ids)
        overrides.append(f"category changed {guarded['category']} -> {new} (attacker had a shell)")
        guarded["category"] = new

    return guarded, overrides
