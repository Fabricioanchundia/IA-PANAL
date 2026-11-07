"""Enrich attacker IPs with geolocation (DB-IP Lite) and reputation (AbuseIPDB).

Usage:
    uv run python -m panal.enrich

IP geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import duckdb
import maxminddb

DB_PATH = Path("data/panal.duckdb")
GEO_DB = Path("data/geo/dbip-city-lite.mmdb")
ENV_FILE = Path(".env")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_DAYS = 7  # re-check an IP's reputation at most once a week
MAX_LOOKUPS = 500  # AbuseIPDB free plan allows 1,000 checks per day

GeoLookup = Callable[[str], dict[str, Any] | None]
AbuseLookup = Callable[[str], dict[str, Any]]


def load_env(path: Path) -> None:
    """Minimal .env reader: KEY=value lines, # comments. Real env vars win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def mmdb_lookup(path: Path) -> GeoLookup:
    reader = maxminddb.open_database(str(path))

    def lookup(ip: str) -> dict[str, Any] | None:
        record = reader.get(ip)
        if not isinstance(record, dict):
            return None
        names = lambda key: (record.get(key) or {}).get("names", {})  # noqa: E731
        location = record.get("location") or {}
        return {
            "country_code": (record.get("country") or {}).get("iso_code"),
            "country": names("country").get("en"),
            "city": names("city").get("en"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
        }

    return lookup


def abuseipdb_lookup(api_key: str) -> AbuseLookup:
    def lookup(ip: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        request = urllib.request.Request(  # noqa: S310 - fixed https URL
            f"{ABUSEIPDB_URL}?{query}",
            headers={"Key": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            data = json.load(response)["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
        }

    return lookup


def enrich_geo(con: duckdb.DuckDBPyConnection, geo: GeoLookup) -> int:
    """Rebuild ip_geo for every attacker IP (local database, no limits)."""
    ips = [row[0] for row in con.execute("SELECT DISTINCT src_ip FROM sessions").fetchall()]
    con.execute(
        """
        CREATE OR REPLACE TABLE ip_geo (
            ip VARCHAR PRIMARY KEY, country_code VARCHAR, country VARCHAR,
            city VARCHAR, latitude DOUBLE, longitude DOUBLE)
        """
    )
    rows = []
    for ip in ips:
        info = geo(ip) if is_public(ip) else None
        if info:
            rows.append(
                [ip, *(info[k] for k in ("country_code", "country", "city"))]
                + [info["latitude"], info["longitude"]]
            )
    if rows:
        con.executemany("INSERT INTO ip_geo VALUES (?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def enrich_reputation(
    con: duckdb.DuckDBPyConnection, abuse: AbuseLookup, max_lookups: int = MAX_LOOKUPS
) -> int:
    """Check new or stale IPs on AbuseIPDB; results are cached in ip_reputation."""
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip VARCHAR PRIMARY KEY, abuse_score INTEGER, total_reports INTEGER,
            isp VARCHAR, usage_type VARCHAR, is_tor BOOLEAN, checked_at TIMESTAMPTZ)
        """
    )
    pending = con.execute(
        """
        SELECT DISTINCT s.src_ip FROM sessions s
        LEFT JOIN ip_reputation r ON r.ip = s.src_ip
        WHERE r.ip IS NULL OR r.checked_at < now() - to_days(?)
        ORDER BY 1
        """,
        [CACHE_DAYS],
    ).fetchall()
    checked = 0
    for (ip,) in pending:
        if checked >= max_lookups or not is_public(ip):
            continue
        info = abuse(ip)
        con.execute(
            "INSERT OR REPLACE INTO ip_reputation VALUES (?, ?, ?, ?, ?, ?, now())",
            [
                ip,
                info["abuse_score"],
                info["total_reports"],
                info["isp"],
                info["usage_type"],
                info["is_tor"],
            ],
        )
        checked += 1
    return checked


IOCS_SQL = """
CREATE OR REPLACE TABLE iocs AS
SELECT 'ip' AS type, s.src_ip AS value, min(s.started_at) AS first_seen,
       max(s.ended_at) AS last_seen, count(*) AS sessions
FROM sessions s
WHERE s.failed_logins + s.successful_logins > 0
GROUP BY 2
UNION ALL
SELECT 'url', url, min(ts), max(ts), count(DISTINCT session)
FROM events WHERE url IS NOT NULL GROUP BY 2
UNION ALL
SELECT 'sha256', shasum, min(ts), max(ts), count(DISTINCT session)
FROM events WHERE shasum IS NOT NULL GROUP BY 2
"""


def report(con: duckdb.DuckDBPyConnection) -> str:
    lines = ["Top countries (sessions):"]
    rows = con.execute(
        """
        SELECT coalesce(g.country, 'Unknown'), count(*) AS n
        FROM sessions s LEFT JOIN ip_geo g ON g.ip = s.src_ip
        GROUP BY 1 ORDER BY n DESC, 1 LIMIT 5
        """
    ).fetchall()
    lines += [f"  {n:>5}  {country}" for country, n in rows]

    has_rep = con.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = 'ip_reputation'"
    ).fetchone()[0]
    if has_rep:
        lines.append("\nMost reported IPs (AbuseIPDB score):")
        rows = con.execute(
            """
            SELECT abuse_score, total_reports, coalesce(usage_type, '?')
            FROM ip_reputation ORDER BY abuse_score DESC, total_reports DESC LIMIT 5
            """
        ).fetchall()
        lines += [f"  score {s:>3}  reports {r:>5}  {u}" for s, r, u in rows] or ["  (none)"]

    counts = dict(con.execute("SELECT type, count(*) FROM iocs GROUP BY 1").fetchall())
    lines.append(
        f"\nIOCs: {counts.get('ip', 0)} IPs, {counts.get('url', 0)} URLs, "
        f"{counts.get('sha256', 0)} hashes"
    )
    lines.append("\nIP geolocation by DB-IP (https://db-ip.com), CC BY 4.0")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--geo-db", type=Path, default=GEO_DB)
    parser.add_argument("--max-lookups", type=int, default=MAX_LOOKUPS)
    args = parser.parse_args()

    load_env(ENV_FILE)
    con = duckdb.connect(str(args.db))

    if args.geo_db.exists():
        print(f"Geolocated IPs: {enrich_geo(con, mmdb_lookup(args.geo_db))}")
    else:
        print(f"Skipping geolocation: {args.geo_db} not found (see README).")

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if api_key:
        checked = enrich_reputation(con, abuseipdb_lookup(api_key), args.max_lookups)
        print(f"AbuseIPDB checks: {checked}")
    else:
        print("Skipping reputation: ABUSEIPDB_API_KEY not set in .env")

    con.execute(IOCS_SQL)
    print()
    print(report(con))


if __name__ == "__main__":
    main()
