import json
from pathlib import Path

from panal.ingest import load, read_ignore_list, summary

ATTACKER = "203.0.113.7"
ME = "198.51.100.1"


def _event(eventid: str, session: str, src_ip: str, second: int, **fields: object) -> str:
    return json.dumps(
        {
            "eventid": eventid,
            "session": session,
            "src_ip": src_ip,
            "timestamp": f"2026-11-07T20:00:{second:02d}.000000Z",
            **fields,
        }
    )


def _write_logs(raw: Path) -> None:
    raw.mkdir()
    lines = [
        _event("cowrie.session.connect", "s1", ATTACKER, 0, src_port=5000, dst_port=2222),
        _event("cowrie.client.version", "s1", ATTACKER, 1, version="SSH-2.0-Go"),
        _event("cowrie.client.kex", "s1", ATTACKER, 1, hassh="abc", kexAlgs=["x", "y"]),
        _event("cowrie.login.failed", "s1", ATTACKER, 2, username="root", password="123456"),
        _event("cowrie.login.success", "s1", ATTACKER, 3, username="root", password="admin"),
        _event("cowrie.command.input", "s1", ATTACKER, 4, input="uname -a"),
        _event("cowrie.session.file_download.failed", "s1", ATTACKER, 5, url="http://x.invalid/m"),
        _event("cowrie.session.closed", "s1", ATTACKER, 6, duration_ms=6000),
        _event("cowrie.session.connect", "s2", ME, 10),
        _event("cowrie.login.success", "s2", ME, 11, username="root", password="hola123"),
    ]
    (raw / "cowrie.json").write_text("\n".join(lines) + "\n")


def test_builds_sessions_and_ignores_my_ip(tmp_path: Path) -> None:
    _write_logs(tmp_path / "raw")
    con = load(tmp_path / "raw", tmp_path / "panal.duckdb", ignore_ips=[ME])

    rows = con.execute(
        "SELECT session, failed_logins, successful_logins, commands, urls, hassh FROM sessions"
    ).fetchall()

    assert rows == [("s1", 1, 1, ["uname -a"], ["http://x.invalid/m"], "abc")]


def test_scanner_only_logs_still_load(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "cowrie.json").write_text(_event("cowrie.session.connect", "s1", ATTACKER, 0) + "\n")

    con = load(raw, tmp_path / "panal.duckdb", ignore_ips=[])

    assert "Sessions:               1" in summary(con)
    assert "(none yet)" in summary(con)


def test_ignore_list_skips_comments(tmp_path: Path) -> None:
    path = tmp_path / "ignore.txt"
    path.write_text("# my home\n198.51.100.1\n\n203.0.113.9  # university\n")

    assert read_ignore_list(path) == ["198.51.100.1", "203.0.113.9"]
