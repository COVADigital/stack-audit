#!/usr/bin/env python3
"""Verify that OWASP citations point at sheets (and anchors) that exist in the catalog.

Checks, in the given files/directories (default: the plugin's skills/):
- rules.json files: OWASP sheet lists (entry[2]), optionally `Sheet#anchor`
- Markdown: rows of any "## OWASP mapping" table, inline `OWASP: Sheet[#anchor]`,
  and https://cheatsheetseries.owasp.org/cheatsheets/<Sheet>_Cheat_Sheet.html#anchor URLs
- JSON reports: any "owasp": [...] arrays of strings
- Markdown: ASVS 5.0 references (V3.3.1, V3.3) against the ASVS release JSON when installed

    python verify_citations.py [PATH ...] [--clone PATH] [--data-dir DIR] [--format md|json]

Exit 1 if any citation is broken (missing sheet or anchor); drafts are reported as info.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib import asvs
from wclib.findings import Finding, Report
from wclib.owasp import OwaspError, find_sheet, load_catalog, resolve_clone, resolve_data_dir

URL_RE = re.compile(r"cheatsheetseries\.owasp\.org/cheatsheets/([\w.-]+?)\.html(?:#([\w-]+))?")
INLINE_RE = re.compile(r"OWASP:\s*`?([A-Z][\w-]+)(?:#([\w-]+))?")
NAME_RE = re.compile(r"^([A-Za-z][\w-]*)(?:#([\w-]+))?$")


def citations_in_markdown(text: str) -> list[tuple[int, str, str | None]]:
    out = []
    lines = text.split("\n")
    in_table = False
    for n, line in enumerate(lines, 1):
        if line.startswith("## "):
            in_table = line.strip().lower() == "## owasp mapping"
            continue
        next_line = lines[n] if n < len(lines) else ""
        is_header_row = bool(re.match(r"^\|\s*:?-", next_line))
        if in_table and line.startswith("|") and not re.match(r"^\|\s*:?-", line) and not is_header_row:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2 and not cells[-1].lower().startswith("owasp"):
                for name in cells[-1].split(","):
                    m = NAME_RE.match(name.strip())
                    if m:
                        out.append((n, m.group(1), m.group(2)))
        for m in URL_RE.finditer(line):
            out.append((n, m.group(1), m.group(2)))
        for m in INLINE_RE.finditer(line):
            out.append((n, m.group(1), m.group(2)))
    return out


def citations_in_json(data, path_hint: str) -> list[tuple[int | None, str, str | None]]:
    out = []
    if isinstance(data, dict):
        rules = data.get("rules")
        if isinstance(rules, dict) and "files" in data:  # web-standards style rules.json
            for dom in rules.values():
                for entry in dom.values():
                    if isinstance(entry, list) and len(entry) > 2:
                        for name in entry[2]:
                            m = NAME_RE.match(name)
                            if m:
                                out.append((None, m.group(1), m.group(2)))
        for k, v in data.items():
            if k == "owasp" and isinstance(v, list):
                for name in v:
                    m = NAME_RE.match(str(name))
                    if m:
                        out.append((None, m.group(1), m.group(2)))
            elif isinstance(v, (dict, list)):
                out += citations_in_json(v, path_hint)
    elif isinstance(data, list):
        for item in data:
            out += citations_in_json(item, path_hint)
    return out


def collect(paths: list[Path]) -> list[Path]:
    files = []
    for p in paths:
        if p.is_dir():
            files += [f for f in p.rglob("*") if f.suffix in (".md", ".json") and "node_modules" not in f.parts]
        elif p.exists():
            files.append(p)
    return sorted(set(files))


def main() -> int:
    plugin_skills = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path, default=[plugin_skills])
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    ap.add_argument("--asvs", help="Path to the ASVS release JSON")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args()
    try:
        catalog = load_catalog(resolve_data_dir(args.data_dir), resolve_clone(args.clone))
    except OwaspError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = Report(tool="verify_citations", root=", ".join(str(p) for p in args.paths))
    asvs_data, asvs_note = asvs.try_load(args.asvs)
    checked = asvs_checked = 0
    for f in collect(args.paths):
        rel = str(f)
        if f.suffix == ".md":
            text = f.read_text(encoding="utf-8", errors="replace")
            cites = citations_in_markdown(text)
            for line, kind, ref in asvs.refs_in_text(text):
                asvs_checked += 1
                known = (asvs_data or {}).get("requirements" if kind == "req" else "sections", {})
                if asvs_data and ref not in known:
                    report.add(Finding("owasp.04", "error", f"ASVS {asvs.VERSION} {'requirement' if kind == 'req' else 'section'} "
                                       f"{ref} does not exist", file=rel, line=line,
                                       fix_hint="read_requirement.py --section V#.# lists the real IDs (4.x numbering differs)"))
        else:
            try:
                cites = citations_in_json(json.loads(f.read_text(encoding="utf-8")), rel)
            except json.JSONDecodeError:
                continue
        for line, name, anchor in cites:
            checked += 1
            sid = find_sheet(catalog, name)
            if not sid:
                report.add(Finding("owasp.01", "error", f"Cited OWASP sheet '{name}' does not exist in the catalog",
                                   file=rel, line=line, fix_hint="Use find_sheets.py to locate the right sheet id"))
                continue
            sheet = catalog["sheets"][sid]
            if anchor and not any(s["anchor"] == anchor for s in sheet["sections"]):
                report.add(Finding("owasp.02", "error", f"Anchor '#{anchor}' not found in {sid}",
                                   file=rel, line=line, fix_hint=f"read_section.py --sheet {sid} --list"))
            if sheet["status"] == "draft":
                report.add(Finding("owasp.03", "info", f"Cites draft sheet {sid} (not yet reviewed by OWASP)",
                                   file=rel, line=line))
    if asvs_checked and not asvs_data:
        report.add(Finding("owasp.05", "info", f"{asvs_checked} ASVS reference(s) not verified: {asvs_note}"))
    report.meta["citations_checked"] = checked
    report.meta["asvs_references_checked"] = asvs_checked if asvs_data else 0
    report.meta["catalog_commit"] = catalog["source"].get("commit")
    print(report.render(args.format))
    if args.format == "md":
        print(f"\n{checked} citation(s) checked against catalog @ {(catalog['source'].get('commit') or '?')[:7]}."
              + (f" {asvs_checked} ASVS {asvs.VERSION} reference(s) checked." if asvs_data and asvs_checked else ""))
    return 1 if report.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
