"""Run the Sigma rules in sigma/rules against honeypot events stored in DuckDB.

A small Sigma evaluator for the subset these rules use: field modifiers contains,
startswith, endswith, re and all; keyword lists; and conditions with and/or/not,
parentheses and "1 of" / "all of" patterns. Matching is case-insensitive, as in Sigma.

Usage:
    uv run python -m panal.sigma            # data/panal.duckdb
    uv run python -m panal.sigma --demo     # data/demo/demo.duckdb (after analyst --demo)
"""

from __future__ import annotations

import argparse
import fnmatch
import re
from pathlib import Path
from typing import Any

import duckdb
import yaml

RULES_DIR = Path("sigma/rules")
KEYWORD_FIELDS = ("input", "username", "password", "url")
Event = dict[str, Any]


def load_rules(directory: Path = RULES_DIR) -> list[dict[str, Any]]:
    return [yaml.safe_load(p.read_text()) for p in sorted(directory.glob("*.yml"))]


def _value_matches(actual: str, expected: Any, modifiers: list[str]) -> bool:
    a, e = actual.lower(), str(expected).lower()
    if "re" in modifiers:
        return re.search(str(expected), actual, re.IGNORECASE) is not None
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return a == e


def _item_matches(event: Event, item: Any) -> bool:
    if isinstance(item, list):  # keyword list: any keyword anywhere in the text fields
        texts = [str(event[f]).lower() for f in KEYWORD_FIELDS if event.get(f)]
        return any(str(k).lower() in t for k in item for t in texts)
    for key, expected in item.items():  # field map: every field must match
        field, *modifiers = key.split("|")
        actual = event.get(field)
        if actual is None:
            return False
        values = expected if isinstance(expected, list) else [expected]
        check = all if "all" in modifiers else any
        if not check(_value_matches(str(actual), v, modifiers) for v in values):
            return False
    return True


def _evaluate(condition: str, results: dict[str, bool]) -> bool:
    tokens = re.findall(r"\(|\)|[\w*]+", condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def expr() -> bool:
        value = term()
        while peek() == "or":
            take()
            value = term() or value
        return value

    def term() -> bool:
        value = factor()
        while peek() == "and":
            take()
            value = factor() and value
        return value

    def factor() -> bool:
        tok = take()
        if tok == "not":
            return not factor()
        if tok == "(":
            value = expr()
            take()  # ")"
            return value
        if tok in ("1", "all") and peek() == "of":
            take()
            names = [n for n in results if fnmatch.fnmatch(n, take())]
            matches = [results[n] for n in names]
            return any(matches) if tok == "1" else bool(matches) and all(matches)
        return results[tok]

    return expr()


def matches(rule: dict[str, Any], event: Event) -> bool:
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    results = {name: _item_matches(event, item) for name, item in detection.items()}
    return _evaluate(condition, results)


def run(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    columns = ["session", "src_ip", "eventid", "input", "username", "password", "url"]
    rows = con.execute(
        f"SELECT {', '.join(columns)}, strftime(ts, '%Y-%m-%d %H:%M:%S') FROM events ORDER BY ts"  # noqa: S608
    ).fetchall()
    hits = []
    for row in rows:
        event = dict(zip(columns, row[:-1], strict=True))
        for rule in rules:
            if matches(rule, event):
                evidence = event["input"] or event["username"] or ""
                hits.append(
                    (
                        rule["id"],
                        rule["title"],
                        rule["level"],
                        event["session"],
                        event["src_ip"],
                        evidence[:200],
                        row[-1],
                    )
                )
    con.execute(
        """
        CREATE OR REPLACE TABLE sigma_hits (
            rule_id VARCHAR, title VARCHAR, level VARCHAR, session VARCHAR,
            src_ip VARCHAR, evidence VARCHAR, seen_at VARCHAR)
        """
    )
    if hits:
        con.executemany("INSERT INTO sigma_hits VALUES (?, ?, ?, ?, ?, ?, ?)", hits)
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--db", type=Path, default=Path("data/panal.duckdb"))
    args = parser.parse_args()

    db = Path("data/demo/demo.duckdb") if args.demo else args.db
    rules = load_rules()
    hits = run(duckdb.connect(str(db)), rules)
    print(f"{len(rules)} rules, {len(hits)} hits\n")
    for _, title, level, session, _, evidence, _ in hits:
        print(f"[{level.upper():<6}] {title}\n         {session}: {evidence[:90]}")


if __name__ == "__main__":
    main()
