import json
import re
from pathlib import Path

import pytest

from panal.analyst import SAMPLES
from panal.ingest import load
from panal.publish import _tool, build_summary
from panal.sigma import load_rules

RULES = Path(__file__).parent.parent / "sigma" / "rules"


@pytest.fixture
def con(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "cowrie.json").write_text(SAMPLES.read_text())
    con = load(raw, tmp_path / "db.duckdb", ignore_ips=[])
    con.execute("CREATE TABLE ip_geo (ip VARCHAR, country_code VARCHAR)")
    con.execute("INSERT INTO ip_geo VALUES ('203.0.113.40', 'UA'), ('203.0.113.50', 'US')")
    return con


def test_summary_has_no_ips_or_session_ids(con) -> None:
    text = json.dumps(build_summary(con, load_rules(RULES)))

    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
    assert "demo-miner" not in text


def test_summary_aggregates(con) -> None:
    s = build_summary(con, load_rules(RULES))

    assert s["totals"]["sessions"] == 6
    assert s["totals"]["countries"] == 2
    by_code = {c["code"]: c for c in s["countries"]}
    assert by_code["UA"]["numeric"] == "804" and by_code["UA"]["name"] == "Ukraine"
    assert by_code["ZZ"]["name"] == "Unknown"
    assert {"label": "root", "count": 5} in s["top_usernames"]
    assert any(t["id"] == "T1496" for t in s["techniques"])
    assert s["totals"]["sigma_hits"] == 9


def test_tool_extraction() -> None:
    assert _tool("cd /tmp && wget http://x") == "cd"
    assert _tool("(crontab -l; echo x) | crontab -") == "crontab"
    assert _tool("/usr/bin/curl -s http://x") == "curl"
    assert _tool("") is None


def test_recent_feed_and_extras(con) -> None:
    def fake_llm(system, user, schema):
        return {
            "category": "cryptominer",
            "severity": "low",
            "techniques": [],
            "summary": "x",
            "recommendations": [],
        }

    from panal.analyst import analyze_session

    analyze_session(con, "demo-miner", fake_llm, "fake")
    s = build_summary(con, load_rules(RULES))

    assert len(s["recent"]) == 6 and s["recent"][0]["time"] >= s["recent"][-1]["time"]
    miner = next(r for r in s["recent"] if r["country_code"] == "UA")
    assert (miner["category"], miner["severity"], miner["by"]) == ("cryptominer", "high", "ai")
    scan = next(r for r in s["recent"] if r["category"] == "scan")
    assert scan["by"] == "rules" and scan["techniques"] == ["T1595"]
    inject = next(r for r in s["recent"] if r["injection"])
    assert inject["category"] == "pending_ai_review" and inject["severity"] == "high"
    assert s["funnel"] == {
        "connected": 6,
        "tried_login": 5,
        "got_shell": 4,
        "ran_commands": 4,
        "tried_download": 3,
    }
    assert s["clients"] == [{"label": "Go", "count": 6}]
    assert s["totals"]["ai_injection_attempts"] == 1
    assert s["reputation"] == [{"label": "Not checked", "count": 6}]


def test_client_family() -> None:
    from panal.publish import client_family

    assert client_family("SSH-2.0-ZGrab ZGrab SSH Survey") == "ZGrab"
    assert client_family("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3") == "OpenSSH"
    assert client_family("SSH-2.0-libssh_0.9.6") == "libssh"
    assert client_family(None) == "Unknown"


def test_serious_attacks_survive_many_scans(con, monkeypatch) -> None:
    import panal.publish as publish

    monkeypatch.setattr(publish, "RECENT_N", 1)
    s = build_summary(con, load_rules(RULES))

    assert any(r["severity"] == "high" for r in s["recent"])
    assert len(s["recent"]) <= 2  # newest session + newest serious one
