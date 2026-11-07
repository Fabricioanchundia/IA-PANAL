import json
from pathlib import Path

from panal.enrich import IOCS_SQL, enrich_geo, enrich_reputation, is_public, load_env, report
from panal.ingest import load

ATTACKER = "203.0.113.7"  # TEST-NET, not "global": use 8.8.8.8 style IPs for public ones
PUBLIC_A = "8.8.8.8"
PUBLIC_B = "1.1.1.1"


def _con(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    events = [
        {"eventid": "cowrie.session.connect", "session": "a", "src_ip": PUBLIC_A},
        {
            "eventid": "cowrie.login.failed",
            "session": "a",
            "src_ip": PUBLIC_A,
            "username": "root",
            "password": "x",
        },
        {
            "eventid": "cowrie.session.file_download",
            "session": "a",
            "src_ip": PUBLIC_A,
            "url": "http://bad.invalid/m",
            "shasum": "f" * 64,
        },
        {"eventid": "cowrie.session.connect", "session": "b", "src_ip": PUBLIC_B},
        {"eventid": "cowrie.session.connect", "session": "c", "src_ip": ATTACKER},
    ]
    lines = [
        json.dumps({**e, "timestamp": f"2026-11-07T20:00:{i:02d}Z"}) for i, e in enumerate(events)
    ]
    (raw / "cowrie.json").write_text("\n".join(lines) + "\n")
    return load(raw, tmp_path / "db.duckdb", ignore_ips=[])


def fake_geo(ip: str):
    return {
        "country_code": "US",
        "country": "United States",
        "city": "Columbus",
        "latitude": 40.0,
        "longitude": -83.0,
    }


def test_geo_skips_non_public_ips(tmp_path: Path) -> None:
    con = _con(tmp_path)

    assert enrich_geo(con, fake_geo) == 2
    assert con.execute("SELECT count(*) FROM ip_geo WHERE ip = ?", [ATTACKER]).fetchone() == (0,)


def test_reputation_is_cached_and_limited(tmp_path: Path) -> None:
    con = _con(tmp_path)
    calls: list[str] = []

    def fake_abuse(ip: str):
        calls.append(ip)
        return {
            "abuse_score": 100,
            "total_reports": 42,
            "isp": "x",
            "usage_type": "Data Center",
            "is_tor": False,
        }

    assert enrich_reputation(con, fake_abuse, max_lookups=1) == 1
    assert enrich_reputation(con, fake_abuse) == 1  # the other public IP
    assert enrich_reputation(con, fake_abuse) == 0  # both cached now
    assert sorted(calls) == [PUBLIC_B, PUBLIC_A]


def test_iocs_and_report(tmp_path: Path) -> None:
    con = _con(tmp_path)
    enrich_geo(con, fake_geo)
    con.execute(IOCS_SQL)

    text = report(con)

    assert "United States" in text
    assert "IOCs: 1 IPs, 1 URLs, 1 hashes" in text


def test_helpers(tmp_path: Path, monkeypatch) -> None:
    assert is_public(PUBLIC_A) and not is_public("10.0.0.1") and not is_public("nope")
    monkeypatch.delenv("PANAL_TEST_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("# comment\nPANAL_TEST_KEY='abc'\n")
    load_env(env)
    import os

    assert os.environ["PANAL_TEST_KEY"] == "abc"
