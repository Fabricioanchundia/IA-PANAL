"""Build the aggregated, privacy-safe dataset for the public dashboard (site/).

Only aggregates leave your laptop: counts per country, per day, per technique, per
Sigma rule, and the most common usernames, passwords and tools. No IP addresses,
no full commands (they can contain attacker URLs), no session IDs.

Usage:
    uv run python -m panal.publish            # from data/panal.duckdb
    uv run python -m panal.publish --demo     # from data/demo/demo.duckdb
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import pycountry

from panal.analyst import triage_without_llm
from panal.attack import CATALOG, evidence_for
from panal.guard import SEVERITY_FLOOR, SEVERITY_ORDER, detect_injection
from panal.sigma import load_rules, run

OUT = Path("site/data/summary.json")
TOP_N = 10
RECENT_N = 30
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _table_exists(con: duckdb.DuckDBPyConnection, name: str) -> bool:
    query = "SELECT count(*) FROM information_schema.tables WHERE table_name = ?"
    return con.execute(query, [name]).fetchone()[0] > 0


def _top(counter: Counter[str], n: int = TOP_N) -> list[dict[str, Any]]:
    return [{"label": k, "count": v} for k, v in counter.most_common(n)]


def _tool(command: str) -> str | None:
    """First program in a command line, e.g. 'cd /tmp && wget http://x' -> 'cd'."""
    word = command.strip().split(maxsplit=1)[0] if command.strip() else ""
    word = word.lstrip("(").split("/")[-1]
    return word if re.fullmatch(r"[A-Za-z0-9._+-]{1,24}", word) else None


def client_family(version: str | None) -> str:
    """'SSH-2.0-ZGrab ZGrab SSH Survey' -> 'ZGrab', 'SSH-2.0-OpenSSH_9.6' -> 'OpenSSH'."""
    if not version:
        return "Unknown"
    name = version.split("-", 2)[-1] if version.startswith("SSH-") else version
    name = re.split(r"[\s_/]", name.strip(), maxsplit=1)[0]
    name = re.sub(r"[^A-Za-z0-9.+-]", "", name)[:20]
    return name or "Unknown"


def _fallback_verdict(failed: int, ok: int, commands: list[str], urls: list[str]) -> dict[str, str]:
    """Verdict for sessions the AI analyst has not processed yet (rules only)."""
    facts = {"failed_logins": failed, "successful_logins": ok, "commands": commands, "urls": urls}
    quick = triage_without_llm(facts)
    if quick:
        return {"category": quick["category"], "severity": quick["severity"]}
    severity = "medium"
    for evidence in evidence_for(failed, ok, commands):
        floor = SEVERITY_FLOOR.get(evidence.technique, "low")
        if SEVERITY_ORDER.index(floor) > SEVERITY_ORDER.index(severity):
            severity = floor
    return {"category": "pending_ai_review", "severity": severity}


def _reputation_bucket(score: int | None) -> str:
    if score is None:
        return "Not checked"
    if score >= 50:
        return "Widely reported as malicious (score 50+)"
    if score > 0:
        return "Some abuse reports (score 1-49)"
    return "No reports or whitelisted scanner (score 0)"


def build_summary(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]]) -> dict[str, Any]:
    sessions = con.execute(
        """
        SELECT session, src_ip, strftime(started_at, '%Y-%m-%d'), failed_logins,
               successful_logins, coalesce(usernames, []), coalesce(passwords, []),
               coalesce(commands, []), strftime(started_at, '%Y-%m-%dT%H:%M:00Z'),
               client_version, coalesce(urls, [])
        FROM sessions
        ORDER BY started_at
        """
    ).fetchall()

    geo: dict[str, str] = {}
    if _table_exists(con, "ip_geo"):
        geo = dict(con.execute("SELECT ip, country_code FROM ip_geo").fetchall())

    countries: dict[str, dict[str, Any]] = {}
    daily: Counter[str] = Counter()
    usernames: Counter[str] = Counter()
    passwords: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    logins = with_shell = 0

    analyses: dict[str, tuple[Any, ...]] = {}
    if _table_exists(con, "analyses"):
        columns = {r[0] for r in con.execute("DESCRIBE analyses").fetchall()}
        injection_col = "injection" if "injection" in columns else "[]::VARCHAR[]"
        rows = con.execute(
            f"SELECT session, category, severity, {injection_col}, model FROM analyses"  # noqa: S608
        ).fetchall()
        analyses = {r[0]: r[1:] for r in rows}

    hourly: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    funnel = {
        "connected": 0,
        "tried_login": 0,
        "got_shell": 0,
        "ran_commands": 0,
        "tried_download": 0,
    }
    recent = []
    for sid, ip, day, failed, ok, users, pwds, commands, ts, version, urls in sessions:
        hourly[ts[:13]] += 1
        clients[client_family(version)] += 1
        funnel["connected"] += 1
        funnel["tried_login"] += bool(failed or ok)
        funnel["got_shell"] += bool(ok)
        funnel["ran_commands"] += bool(commands)
        funnel["tried_download"] += bool(urls)
        if sid in analyses:
            category, severity, injection, model = analyses[sid]
            by = "rules" if model == "rules" else "ai"
            verdict = {"category": category, "severity": severity, "by": by}
            injected = bool(injection)
        else:
            verdict = {**_fallback_verdict(failed, ok, commands, urls), "by": "rules"}
            injected = bool(detect_injection(commands + users + pwds))
        recent.append(
            {
                "time": ts,
                "country_code": geo.get(ip) or "ZZ",
                **verdict,
                "techniques": [e.technique for e in evidence_for(failed, ok, commands)],
                "client": client_family(version),
                "logins": failed + ok,
                "commands": len(commands),
                "injection": injected,
            }
        )

        code = geo.get(ip) or "ZZ"
        entry = countries.setdefault(code, {"sessions": 0, "ips": set()})
        entry["sessions"] += 1
        entry["ips"].add(ip)
        daily[day] += 1
        logins += failed + ok
        with_shell += bool(commands)
        usernames.update(u for u in users if u)
        passwords.update(p for p in pwds if p)
        tools.update(t for t in map(_tool, commands) if t)
        techniques.update(e.technique for e in evidence_for(failed, ok, commands))

    country_rows = []
    for code, entry in sorted(countries.items(), key=lambda kv: -kv[1]["sessions"]):
        info = pycountry.countries.get(alpha_2=code) if code != "ZZ" else None
        country_rows.append(
            {
                "code": code,
                "numeric": info.numeric if info else None,
                "name": getattr(info, "common_name", None) or (info.name if info else "Unknown"),
                "sessions": entry["sessions"],
                "ips": len(entry["ips"]),
            }
        )

    names = {c["code"]: c["name"] for c in country_rows}
    for item in recent:
        item["country"] = names.get(item["country_code"], "Unknown")
    categories = Counter(r["category"] for r in recent)
    injections = sum(r["injection"] for r in recent)
    newest = list(reversed(recent))
    # Keep the latest sessions plus the latest serious ones, so scans never push them out.
    keep = newest[:RECENT_N] + [r for r in newest if r["severity"] != "low"][:RECENT_N]
    recent = sorted({id(r): r for r in keep}.values(), key=lambda r: r["time"], reverse=True)

    reputation: Counter[str] = Counter()
    scores: dict[str, int] = {}
    if _table_exists(con, "ip_reputation"):
        scores = dict(con.execute("SELECT ip, abuse_score FROM ip_reputation").fetchall())
    for ip in {s[1] for s in sessions}:
        reputation[_reputation_bucket(scores.get(ip))] += 1

    hits = run(con, rules)
    sigma = Counter((h[1], h[2]) for h in hits)

    days = sorted(daily)
    summary = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "period": {"start": days[0] if days else None, "end": days[-1] if days else None},
        "last_attack_at": sessions[-1][8] if sessions else None,
        "totals": {
            "sessions": len(sessions),
            "unique_ips": len({s[1] for s in sessions}),
            "countries": len([c for c in countries if c != "ZZ"]),
            "login_attempts": logins,
            "sessions_with_shell": with_shell,
            "sigma_hits": len(hits),
            "ai_injection_attempts": injections,
        },
        "countries": country_rows,
        "daily": [{"date": d, "sessions": daily[d]} for d in days],
        "hourly": [{"hour": h, "sessions": hourly[h]} for h in sorted(hourly)],
        "funnel": funnel,
        "recent": recent,
        "clients": _top(clients),
        "reputation": _top(reputation),
        "top_usernames": _top(usernames),
        "top_passwords": _top(passwords),
        "top_tools": _top(tools),
        "techniques": [
            {"id": t, "name": CATALOG[t][0], "tactic": CATALOG[t][1], "sessions": n}
            for t, n in techniques.most_common()
        ],
        "categories": _top(categories, 20),
        "sigma": [
            {"title": title, "level": level, "hits": n} for (title, level), n in sigma.most_common()
        ],
    }
    leaked = _IP.findall(json.dumps(summary))
    if leaked:
        raise ValueError(f"Refusing to publish: IP-like values found {sorted(set(leaked))[:3]}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--db", type=Path, default=Path("data/panal.duckdb"))
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    db = Path("data/demo/demo.duckdb") if args.demo else args.db
    summary = build_summary(duckdb.connect(str(db)), load_rules())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    t = summary["totals"]
    print(
        f"Wrote {args.out}: {t['sessions']} sessions, {t['countries']} countries, "
        f"{t['sigma_hits']} Sigma hits (no IPs)."
    )


if __name__ == "__main__":
    main()
