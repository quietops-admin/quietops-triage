#!/usr/bin/env python3
"""hq.py — the QuietOps command center. Read-only status over a triage root.

Usage:
    python3 scripts/hq.py [--root ./data] [--scans N]

Shows: inbox queue, risk breakdown, the last scans, anything sitting in
review/ or quarantine/, and the latest audit events. Never writes anything;
opens the SQLite database in read-only mode.

This fills the reference made by commands.sh (`hq` alias).
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def q(db: Path, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    if not db.exists():
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def hr(title: str) -> None:
    print(f"\n── {title} " + "─" * max(1, 58 - len(title)))


def main() -> int:
    ap = argparse.ArgumentParser(description="QuietOps Triage HQ (read-only)")
    ap.add_argument("--root", type=Path, default=Path("data"),
                    help="triage root (default ./data)")
    ap.add_argument("--scans", type=int, default=12,
                    help="how many recent scans to show (default 12)")
    args = ap.parse_args()

    root = args.root.expanduser().resolve()
    if not root.exists():
        print(f"No triage root at {root} — run the triage first.", file=sys.stderr)
        return 1
    db = root / "logs" / "triage.db"

    print(f"QuietOps HQ — {root}")

    hr("inbox queue")
    inbox = sorted(p.name for p in (root / "inbox").iterdir()) \
        if (root / "inbox").exists() else []
    print(f"{len(inbox)} file(s) waiting" + (f": {', '.join(inbox[:10])}"
          if inbox else ""))

    hr("risk breakdown (all time)")
    rows = q(db, "SELECT risk, COUNT(*) AS n FROM scans GROUP BY risk ORDER BY n DESC")
    if rows:
        total = sum(r["n"] for r in rows)
        for r in rows:
            print(f"  {r['risk']:<18} {r['n']:>6}   ({100 * r['n'] / total:.0f}%)")
    else:
        print("  (no scans recorded yet)")

    hr("needs your eyes")
    for zone, hint in (("quarantine", "do not open — read the report"),
                       ("review", "verify flagged lines in a text editor")):
        d = root / zone
        items = sorted(p.name for p in d.iterdir()) if d.exists() else []
        print(f"  {zone}: {len(items)}" + (f"  — {hint}" if items else ""))

    hr(f"last {args.scans} scans")
    rows = q(db, "SELECT id, original_name, risk, destination, markdown_report "
                 "FROM scans ORDER BY id DESC LIMIT ?", (args.scans,))
    if rows:
        for r in rows:
            dest = Path(r["destination"]).parent.name if r["destination"] else "?"
            report = Path(r["markdown_report"]).name if r["markdown_report"] else "—"
            print(f"  #{r['id']:<4} {r['risk'].upper():<7} "
                  f"{(r['original_name'] or '?')[:36]:<36} → {dest:<10} "
                  f"report: {report}")
    else:
        print("  (none)")

    hr("recent audit events")
    log = root / "logs" / "events.jsonl"
    if log.exists():
        lines = log.read_text(encoding="utf-8", errors="replace") \
            .splitlines()[-8:]
        for line in lines:
            try:
                ev = json.loads(line)
                print(f"  {ev.get('timestamp', '?')[:19]}  "
                      f"{ev.get('event', '?'):<18} "
                      f"{(ev.get('name') or ev.get('original_name') or '')[:36]}")
            except json.JSONDecodeError:
                continue
    else:
        print("  (no events yet)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
