#!/usr/bin/env python3
"""Run all database audits (schema, migrations, operations, Postgres hardening) and merge them into one report. Read-only.

    python run_audit.py --root REPO [--pg-snapshot FILE] [--app-role NAME ...] [--format md|json|sarif] [--out FILE] [--strict] [--config FILE]

Never connects to a database, never runs migrations, never reads .env files. --pg-snapshot passes a file written by
assets/pg_snapshot.sql to audit_postgres.py for the live dbh.* checks.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.findings import Report

HERE = Path(__file__).resolve().parent
SCRIPTS = ("audit_schema.py", "audit_migrations.py", "audit_db_ops.py", "audit_postgres.py")


def run_json(script: str, root: str, config: str | None, extra: list[str] = ()) -> Report:
    cmd = [sys.executable, str(HERE / script), "--root", root, "--format", "json", *(["--config", config] if config else []), *extra]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if not res.stdout.strip().startswith("{"):
        r = Report(tool=script, root=root)
        r.skipped.append(f"{script} failed (exit {res.returncode}): {res.stderr.strip()[-300:]}")
        return r
    return Report.from_json(res.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--config")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--out")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--pg-snapshot", help="JSON-lines file from assets/pg_snapshot.sql (live dbh.* checks)")
    ap.add_argument("--app-role", action="append", default=[], help="The app's runtime database role (repeatable)")
    args = ap.parse_args()
    pg_extra = [*(["--snapshot", args.pg_snapshot] if args.pg_snapshot else []), *(x for r in args.app_role for x in ("--app-role", r))]
    merged = Report(tool="data-standards", root=str(Path(args.root).resolve()))
    for script in SCRIPTS:
        merged.merge(run_json(script, args.root, args.config, pg_extra if script == "audit_postgres.py" else []))
    merged.dedupe()
    text = merged.render(args.format)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(merged.findings)} findings)", file=sys.stderr)
    else:
        print(text)
    return 1 if args.strict and merged.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
