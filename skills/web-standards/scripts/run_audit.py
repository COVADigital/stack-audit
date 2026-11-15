#!/usr/bin/env python3
"""Run web-standards audits by phase and merge them into one report. Read-only.

    python run_audit.py --root APP --phase scope                 # stack profile + route inventory
    python run_audit.py --root APP --phase review [--changed]    # all static domain audits
    python run_audit.py --root APP --phase publish [--url URL]   # review + build-output checks (+ live headers)
    python run_audit.py --root APP --domain sec,a11y             # pick domains
    common: [--format md|json|sarif] [--out FILE] [--strict] [--config FILE] [--base REF]

Network: only `--url` (probe_headers) contacts anything. `--audit`, `--scan`, `--remote`
are passed through to audit_security / audit_git when given.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.findings import Report

HERE = Path(__file__).resolve().parent
DOMAINS = {
    "sec": "audit_security.py", "git": "audit_git.py", "a11y": "audit_a11y_i18n.py", "ren": "audit_rendering.py",
    "net": "audit_networking.py", "perf": "audit_performance.py", "cache": "audit_caching.py",
    "arch": "audit_architecture.py", "state": "audit_state.py",
}
PHASES = {
    "scope": ["ren"],
    "develop": list(DOMAINS),
    "review": list(DOMAINS),
    "publish": list(DOMAINS),
}


def run_one(domain: str, args) -> Report:
    script = HERE / DOMAINS[domain]
    cmd = [sys.executable, str(script), "--root", args.root, "--format", "json"]
    if args.changed and domain not in ("git",):
        cmd.append("--changed")
    if args.base:
        cmd += ["--base", args.base]
    if args.config:
        cmd += ["--config", args.config]
    if args.phase == "publish" and domain in ("sec", "perf"):
        cmd.append("--build")
    if domain == "sec" and args.audit:
        cmd.append("--audit")
    if domain == "git":
        if args.scan:
            cmd.append("--scan")
        if args.remote:
            cmd.append("--remote")
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode not in (0, 1) or not res.stdout.strip().startswith("{"):
        r = Report(tool=DOMAINS[domain], root=args.root)
        r.skipped.append(f"{DOMAINS[domain]} failed (exit {res.returncode}): {res.stderr.strip()[-300:]}")
        return r
    return Report.from_json(res.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--phase", choices=list(PHASES), default="review")
    ap.add_argument("--domain", help="Comma-separated subset: " + ",".join(DOMAINS))
    ap.add_argument("--changed", action="store_true")
    ap.add_argument("--base")
    ap.add_argument("--config")
    ap.add_argument("--url", help="Deployed URL for live header checks (publish)")
    ap.add_argument("--audit", action="store_true", help="npm/pnpm audit (network)")
    ap.add_argument("--scan", action="store_true", help="gitleaks history scan (local)")
    ap.add_argument("--remote", action="store_true", help="GitHub settings via gh api")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--out")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    domains = [d.strip() for d in args.domain.split(",")] if args.domain else PHASES[args.phase]
    unknown = [d for d in domains if d not in DOMAINS]
    if unknown:
        ap.error(f"unknown domain(s): {', '.join(unknown)}")
    merged = Report(tool=f"web-standards {args.phase}", root=str(Path(args.root).resolve()))
    stack = subprocess.run([sys.executable, str(HERE.parents[2] / "scripts" / "stack_profile.py"), "--root", args.root],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    if stack.returncode == 0:
        merged.appendix.append(stack.stdout.replace("# Stack profile", "## Stack profile", 1))
    with ThreadPoolExecutor(max_workers=4) as pool:
        for rep in pool.map(lambda d: run_one(d, args), domains):
            merged.merge(rep)
    if args.url:
        res = subprocess.run([sys.executable, str(HERE / "probe_headers.py"), "--url", args.url, "--format", "json"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
        if res.stdout.strip().startswith("{"):
            merged.merge(Report.from_json(res.stdout))
        else:
            merged.skipped.append(f"probe_headers failed: {res.stderr.strip()[-200:]}")
    elif args.phase == "publish":
        merged.skipped.append("Live header checks not run (pass --url <deployed-url>)")
    if args.phase == "scope":
        merged.findings = [f for f in merged.findings if f.rule in ("ren.01", "ren.09", "ren.03")]
    merged.dedupe()
    merged.meta["domains"] = domains
    text = merged.render(args.format)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(merged.findings)} findings)", file=sys.stderr)
    else:
        try:
            print(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")
    return 1 if args.strict and merged.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
