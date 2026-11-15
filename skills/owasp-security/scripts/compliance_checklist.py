#!/usr/bin/env python3
"""ASVS 5.0 self-assessment checklist (section level), pre-filled from audit findings. Read-only.

    python compliance_checklist.py --root APP [--level 1|2|3] [--evidence report.json ...] [--no-run]
                                   [--config FILE] [--format md|json] [--out FILE] [--clone PATH] [--data-dir DIR]

1. map_controls decides which ASVS 5.0 sections apply to the project.
2. Evidence: unless --no-run, runs web-standards `--phase review` and (if Docker files exist) container-standards
   `--phase build`. Both are local static audits: no network. Add more with --evidence (JSON from any run_audit.py,
   e.g. a publish run with --url).
3. Status per section: `not met` (error findings), `partial` (warn findings), else `not assessed`. A clean audit is
   never `met`: it lists which automated checks ran without findings, and a human or Claude finishes the assessment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.config import ConfigError, load_config
from wclib.controls import EVIDENCE, map_controls, rules_for_section
from wclib.findings import Report
from wclib.owasp import OwaspError, load_catalog, resolve_clone, resolve_data_dir
from wclib.rules import RuleBook
from wclib.walker import run_git

PLUGIN = Path(__file__).resolve().parents[3]
WEB = PLUGIN / "skills" / "web-standards"
CONTAINER = PLUGIN / "skills" / "container-standards"
CONTAINER_PREFIXES = ["img", "run", "cnet", "csec", "sup", "ops", "cool"]
ORDER = {"not met": 0, "partial": 1, "not assessed": 2}
DISCLAIMER = ("This is a self-assessment against OWASP ASVS 5.0 section-level mappings. It is not an audit, "
              "certification, or attestation of compliance.")


def run_audit(script: Path, root: str, phase: str, config: str | None) -> Report:
    cmd = [sys.executable, str(script), "--root", root, "--phase", phase, "--format", "json"]
    if config:
        cmd += ["--config", config]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if not res.stdout.strip().startswith("{"):
        r = Report(tool=script.parent.parent.name, root=root)
        r.skipped.append(f"{script.parent.parent.name} {phase} failed: {res.stderr.strip()[-200:]}")
        return r
    return Report.from_json(res.stdout)


def prefixes_run(rep: Report) -> set[str]:
    if rep.meta.get("domains"):
        return set(rep.meta["domains"])
    if rep.tool.startswith("container-standards"):
        return set(CONTAINER_PREFIXES)
    return {f.rule.split(".")[0] for f in rep.findings}


def rules_ran(prefixes: set[str], books: list[RuleBook]) -> set[str]:
    """Rules a static run actually checks (auto/heuristic) in the domains that ran."""
    out = set()
    for rb in books:
        for prefix in prefixes & set(rb.rules):
            out.update(f"{prefix}.{nn}" for nn, e in rb.rules[prefix].items() if e[0] in ("auto", "heuristic"))
    return out


def assess(cm, reports: list[Report], books: list[RuleBook], catalog: dict) -> list[dict]:
    findings = [f for r in reports for f in r.findings]
    ran: set[str] = set()
    for r in reports:
        ran |= rules_ran(prefixes_run(r), books)
    sheets = catalog["sheets"]
    rows = []
    for a in cm.asvs:
        row = {k: a[k] for k in ("code", "chapter", "chapter_title", "title", "applies", "reason")}
        guidance = []
        for sid in a["sheets"][:3]:
            s = sheets.get(sid)
            if s:
                guidance.append({"sheet": sid, "url": s.get("url"), "status": s["status"]})
        row["guidance"] = guidance
        if not a["applies"]:
            rows.append(row)
            continue
        hits = [f for f in findings if a["code"] in EVIDENCE.get(f.rule, ())]
        sev = {f.severity for f in hits}
        row["status"] = "not met" if "error" in sev else "partial" if "warn" in sev else "not assessed"
        row["findings"] = [{"rule": f.rule, "severity": f.severity, "confidence": f.confidence, "file": f.file,
                            "line": f.line, "message": f.message} for f in hits]
        hit_rules = {f.rule for f in hits}
        row["clean_checks"] = [r for r in rules_for_section(a["code"]) if r in ran and r not in hit_rules]
        rows.append(row)
    return rows


def _loc(f: dict) -> str:
    return f" {f['file']}:{f['line']}" if f.get("line") else (f" {f['file']}" if f.get("file") else "")


def to_markdown(rows, cm, level, sources, project_commit, catalog_commit) -> str:
    inscope = [r for r in rows if r["applies"]]
    counts = {s: sum(r["status"] == s for r in inscope) for s in ORDER}
    out = [f"# ASVS 5.0 Level {level} self-assessment (section level)", "",
           f"- **Project:** `{cm.root}`" + (f" @ `{project_commit[:10]}`" if project_commit else ""),
           f"- **Date:** {date.today().isoformat()}",
           f"- **Catalog:** OWASP Cheat Sheet Series @ `{(catalog_commit or '?')[:7]}` (ASVS 5.0 index)",
           "- **Assessor:** Claude (automated pre-fill; every `not assessed` row still needs review)",
           f"- **Evidence:** {', '.join(sources) or 'none'}",
           f"- **Level:** {level}. Section-level scope is the same for every level; requirement-level filtering "
           "needs the ASVS requirement text, which the cheat-sheet repo does not include.", "",
           "## Summary", "", "| Status | Sections |", "|---|---|"]
    out += [f"| {s} | {n} |" for s, n in counts.items()]
    out.append(f"| out of scope | {len(rows) - len(inscope)} |")
    gaps = sorted((r for r in inscope if r["status"] != "not assessed"),
                  key=lambda r: (ORDER[r["status"]], -len(r["findings"])))[:5]
    if gaps:
        out += ["", "**Top gaps:**", ""]
        for r in gaps:
            f = r["findings"][0]
            out.append(f"- **{r['code']} {r['title']}** ({r['status']}): `{f['rule']}` {f['message']}"
                       + (f" (+{len(r['findings']) - 1} more)" if len(r["findings"]) > 1 else ""))
    chapters: dict[str, list] = {}
    for r in inscope:
        chapters.setdefault(f"{r['chapter']} {r['chapter_title']}", []).append(r)
    for ch, items in chapters.items():
        out += ["", f"## {ch}", "", "| Section | Status | Evidence | Guidance |", "|---|---|---|---|"]
        for r in sorted(items, key=lambda r: ORDER[r["status"]]):
            ev = [f"`{f['rule']}` ({f['severity']}{'' if f['confidence'] == 'high' else ', verify'}){_loc(f)}"
                  for f in r["findings"][:4]]
            if len(r["findings"]) > 4:
                ev.append(f"+{len(r['findings']) - 4} more")
            if r["clean_checks"]:
                ev.append("automated checks with no findings: " + ", ".join(f"`{c}`" for c in r["clean_checks"]))
            ev = ev or ["no automated check: assess manually"]
            gd = [f"[{g['sheet']}]({g['url']})" if g["url"] else f"{g['sheet']} (*{g['status']}*)" for g in r["guidance"]]
            out.append(f"| {r['code']} {r['title']} | **{r['status']}** | {'<br>'.join(ev)} | {', '.join(gd) or '-'} |")
    out += ["", "## Out of scope", ""]
    out += [f"- {r['code']} {r['title']}: {r['reason']}" for r in rows if not r["applies"]]
    out += ["", "## Finishing the assessment", "",
            "Work through each `not assessed` row with `find_sheets.py --asvs <section>` and `read_section.py`, "
            "then record evidence (file:line, config value or attestation) as described in `references/compliance-method.md`. "
            "Runtime sections (V12 TLS, V3.4 headers on the live site) need `run_audit.py --phase publish --url <site>` "
            "evidence or an attestation.", "", f"> {DISCLAIMER}"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--level", type=int, choices=(1, 2, 3))
    ap.add_argument("--evidence", nargs="*", default=[], help="JSON reports from run_audit.py / audit_*.py")
    ap.add_argument("--no-run", action="store_true", help="Don't run the local audits; use --evidence only")
    ap.add_argument("--config")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--out")
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: --root is not a directory: {root}", file=sys.stderr)
        return 2
    try:
        config = load_config(root.resolve(), args.config)
        catalog = load_catalog(resolve_data_dir(args.data_dir), resolve_clone(args.clone))
    except (ConfigError, OwaspError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cm = map_controls(root, catalog)
    level = args.level or (config.get("asvs") or {}).get("level") or (2 if "auth" in cm.signals else 1)
    reports, sources = [], []
    for path in args.evidence:
        try:
            reports.append(Report.from_json(Path(path).read_text(encoding="utf-8")))
            sources.append(Path(path).name)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read evidence {path}: {exc}", file=sys.stderr)
            return 2
    if not args.no_run:
        reports.append(run_audit(WEB / "scripts" / "run_audit.py", str(root), "review", args.config))
        sources.append("web-standards review (static)")
        if cm.container_root:
            reports.append(run_audit(CONTAINER / "scripts" / "run_audit.py", cm.container_root, "build", args.config))
            sources.append("container-standards build (static)")
    books = [RuleBook(WEB), RuleBook(CONTAINER)]
    rows = assess(cm, reports, books, catalog)
    project_commit = (run_git(root.resolve(), "rev-parse", "HEAD") or "").strip() or None
    if args.format == "json":
        text = json.dumps({"level": level, "root": cm.root, "project_commit": project_commit,
                           "catalog_commit": cm.catalog_commit, "evidence": sources, "sections": rows,
                           "skipped": [s for r in reports for s in r.skipped], "disclaimer": DISCLAIMER}, indent=2)
    else:
        text = to_markdown(rows, cm, level, sources, project_commit, cm.catalog_commit)
        skipped = [s for r in reports for s in r.skipped]
        if skipped:
            text += "\n\n## Evidence gaps\n\n" + "\n".join(f"- {s}" for s in skipped)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(text.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
