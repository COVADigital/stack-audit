#!/usr/bin/env python3
"""Run installed scanners and normalize their output (sup.01, sup.02, csec.05).

    python scan_image.py --dockerfile web/Dockerfile          # hadolint (local, no network)
    python scan_image.py --image myapp:local               # trivy or grype (downloads vulnerability DB: network)
    common: [--format md|json|sarif]

Never installs anything. Missing tools are reported with install links.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.findings import Report
from wclib.rules import RuleBook

SKILL = Path(__file__).resolve().parents[1]
INSTALL = {
    "hadolint": "https://github.com/hadolint/hadolint/releases (or: docker run --rm -i hadolint/hadolint < Dockerfile)",
    "trivy": "https://trivy.dev (install guide)",
    "grype": "https://github.com/anchore/grype#installation",
}


def run(cmd: list[str], timeout: int = 900) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def hadolint(path: str, rb: RuleBook, report: Report) -> None:
    exe = shutil.which("hadolint")
    if not exe:
        report.skipped.append(f"hadolint not installed: {INSTALL['hadolint']}")
        return
    _, out, err = run([exe, "--no-fail", "-f", "json", path])
    try:
        items = json.loads(out or "[]")
    except json.JSONDecodeError:
        report.skipped.append(f"hadolint output unreadable: {err[:200]}")
        return
    sev = {"error": "warn", "warning": "info", "info": "info", "style": "info"}
    for it in items:
        report.add(rb.make("sup.02", f"{it.get('code')}: {it.get('message')}", file=path, line=it.get("line"),
                           severity=sev.get(it.get("level"), "info")))


def trivy(image: str, rb: RuleBook, report: Report) -> bool:
    exe = shutil.which("trivy")
    if not exe:
        return False
    _, out, err = run([exe, "image", "--quiet", "--format", "json", "--scanners", "vuln,secret", "--severity", "HIGH,CRITICAL", image])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        report.skipped.append(f"trivy failed: {err[:200]}")
        return True
    vulns, secrets = [], []
    for res in data.get("Results") or []:
        vulns += [(v, res.get("Target")) for v in res.get("Vulnerabilities") or []]
        secrets += [(s, res.get("Target")) for s in res.get("Secrets") or []]
    summarize(image, [(v.get("VulnerabilityID"), v.get("Severity"), v.get("PkgName"), v.get("InstalledVersion"), v.get("FixedVersion"))
                      for v, _ in vulns], rb, report, "trivy")
    for s, target in secrets:
        report.add(rb.make("csec.05", f"trivy: secret ({s.get('RuleID')}) embedded in image layer: {target}", file=f"image:{image}",
                           fix_hint="Remove it from the build and rotate the credential"))
    return True


def grype(image: str, rb: RuleBook, report: Report) -> bool:
    exe = shutil.which("grype")
    if not exe:
        return False
    _, out, err = run([exe, image, "-o", "json", "--only-fixed"])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        report.skipped.append(f"grype failed: {err[:200]}")
        return True
    rows = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        if v.get("severity") in ("High", "Critical"):
            rows.append((v.get("id"), v.get("severity", "").upper(), a.get("name"), a.get("version"),
                         ", ".join((v.get("fix") or {}).get("versions") or [])))
    summarize(image, rows, rb, report, "grype")
    return True


def summarize(image: str, rows: list[tuple], rb: RuleBook, report: Report, tool: str) -> None:
    crit_fix = [r for r in rows if r[1] == "CRITICAL" and r[4]]
    high_fix = [r for r in rows if r[1] == "HIGH" and r[4]]
    if not rows:
        report.meta[f"{tool}"] = "no high/critical vulnerabilities"
        return
    top = ", ".join(f"{r[0]} ({r[2]} {r[3]} → {r[4] or 'no fix'})" for r in (crit_fix + high_fix + rows)[:8])
    report.add(rb.make("sup.01", f"{tool}: {len([r for r in rows if r[1] == 'CRITICAL'])} critical / {len([r for r in rows if r[1] == 'HIGH'])} high "
                       f"vulnerabilities ({len(crit_fix) + len(high_fix)} fixable). Top: {top}",
                       file=f"image:{image}", severity="error" if crit_fix else "warn",
                       fix_hint="Rebuild on an updated base image / bump the affected packages"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dockerfile", action="append", default=[])
    ap.add_argument("--image")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    args = ap.parse_args()
    if not args.dockerfile and not args.image:
        ap.error("give --dockerfile and/or --image")
    rb = RuleBook(SKILL)
    report = Report(tool="scan_image", root=args.image or ", ".join(args.dockerfile))
    for d in args.dockerfile:
        hadolint(d, rb, report)
    if args.image and not (trivy(args.image, rb, report) or grype(args.image, rb, report)):
        report.skipped.append(f"No image scanner installed: trivy ({INSTALL['trivy']}) or grype ({INSTALL['grype']})")
    print(report.render(args.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
