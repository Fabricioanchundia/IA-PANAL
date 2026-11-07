"""Load Cowrie JSON logs into DuckDB and group them into attack sessions.

Usage:
    uv run python -m panal.ingest
"""

from __future__ import annotations

import argparse
from pathlib import Path

import duckdb

RAW_DIR = Path("data/raw")
DB_PATH = Path("data/panal.duckdb")
IGNORE_FILE = Path("data/ignore_ips.txt")

# Explicit schema: Cowrie events have different fields, and a key that has not
# appeared yet (e.g. "password" before the first login) must still exist as NULL.
COLUMNS = {
    "eventid": "VARCHAR",
    "timestamp": "VARCHAR",
    "session": "VARCHAR",
    "src_ip": "VARCHAR",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "protocol": "VARCHAR",
    "username": "VARCHAR",
    "password": "VARCHAR",
    "input": "VARCHAR",
    "url": "VARCHAR",
    "shasum": "VARCHAR",
    "version": "VARCHAR",
    "hassh": "VARCHAR",
    "duration_ms": "BIGINT",
}

SESSIONS_SQL = """
CREATE OR REPLACE TABLE sessions AS
SELECT
    session,
    any_value(src_ip)                                                   AS src_ip,
    min(ts)                                                             AS started_at,
    max(ts)                                                             AS ended_at,
    any_value(version) FILTER (eventid = 'cowrie.client.version')       AS client_version,
    any_value(hassh) FILTER (eventid = 'cowrie.client.kex')             AS hassh,
    count(*) FILTER (eventid = 'cowrie.login.failed')                   AS failed_logins,
    count(*) FILTER (eventid = 'cowrie.login.success')                  AS successful_logins,
    list(username ORDER BY ts) FILTER (eventid LIKE 'cowrie.login.%')   AS usernames,
    list(password ORDER BY ts) FILTER (eventid LIKE 'cowrie.login.%')   AS passwords,
    list(input ORDER BY ts) FILTER (eventid = 'cowrie.command.input')   AS commands,
    list(url ORDER BY ts) FILTER (url IS NOT NULL)                      AS urls
FROM events
GROUP BY session
"""


def read_ignore_list(path: Path) -> list[str]:
    """IPs to exclude (your own tests). One per line; blank lines and # comments ignored."""
    if not path.exists():
        return []
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return [line for line in lines if line]


def load(raw_dir: Path, db_path: Path, ignore_ips: list[str]) -> duckdb.DuckDBPyConnection:
    """Rebuild the events and sessions tables from every cowrie.json* file in raw_dir."""
    files = sorted(str(p) for p in raw_dir.glob("cowrie.json*"))
    if not files:
        raise SystemExit(f"No cowrie.json* files in {raw_dir}. Run scripts/fetch_logs.sh first.")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    con.execute(
        """
        CREATE OR REPLACE TABLE events AS
        SELECT * EXCLUDE (timestamp), CAST(timestamp AS TIMESTAMPTZ) AS ts
        FROM read_json(?, format = 'newline_delimited', columns = ?, ignore_errors = true)
        WHERE eventid IS NOT NULL AND NOT list_contains(?::VARCHAR[], src_ip)
        """,
        [files, COLUMNS, ignore_ips],
    )
    con.execute(SESSIONS_SQL)
    return con


def summary(con: duckdb.DuckDBPyConnection) -> str:
    """Human-readable overview of what the honeypot saw."""
    total, ips, tried, owned = con.execute(
        """
        SELECT count(*), count(DISTINCT src_ip),
               count(*) FILTER (failed_logins + successful_logins > 0),
               count(*) FILTER (successful_logins > 0)
        FROM sessions
        """
    ).fetchone()
    lines = [
        f"Sessions:               {total}",
        f"Unique IPs:             {ips}",
        f"Sessions trying logins: {tried}",
        f"Sessions that got in:   {owned}",
    ]
    for title, column in (("Top passwords", "password"), ("Top commands", "input")):
        rows = con.execute(
            f"""
            SELECT {column}, count(*) AS n FROM events
            WHERE {column} IS NOT NULL
            GROUP BY 1 ORDER BY n DESC, 1 LIMIT 5
            """  # noqa: S608 - column comes from a fixed tuple, not user input
        ).fetchall()
        lines.append(f"\n{title}:")
        lines += [f"  {n:>5}  {value}" for value, n in rows] or ["  (none yet)"]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--ignore-file", type=Path, default=IGNORE_FILE)
    args = parser.parse_args()

    con = load(args.raw_dir, args.db, read_ignore_list(args.ignore_file))
    print(summary(con))


if __name__ == "__main__":
    main()
