#!/usr/bin/env python3
"""Map a project to the OWASP guidance that applies to it (read-only, offline).

    python map_controls.py --root APP [--format md|json] [--clone PATH] [--data-dir DIR]

Detects stack signals (Next.js, auth library, ORM, uploads, webhooks, OAuth, JWT, AI/MCP, Docker, CI, ...)
and prints: applicable cheat sheets with the reason, ASVS 5.0 sections in / out of scope, and the
Top 10 2021 categories those sheets cover. Section level only: no ASVS requirement text.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.controls import map_controls
from wclib.owasp import OwaspError, load_catalog, resolve_clone, resolve_data_dir


def to_markdown(cm) -> str:
    out = [f"# OWASP control map: `{cm.root}`", ""]
    out.append(f"Catalog commit `{(cm.catalog_commit or '?')[:7]}`. ASVS **5.0** (section level), Top 10 **2021**.")
    out += ["", "## Signals", ""]
    out += [f"- **{k}**: {v}" for k, v in cm.signals.items()] or ["- none (no package.json?)"]
    if cm.container_root:
        out.append(f"- container audits root: `{cm.container_root}`")
    out += ["", "## Applicable cheat sheets", "", "| Sheet | Why | Link |", "|---|---|---|"]
    for s in cm.sheets:
        link = f"[published]({s['url']})" if s["url"] else f"*{s['status']}*"
        out.append(f"| `{s['id']}` | {'; '.join(s['reasons'])} | {link} |")
    out += ["", "## ASVS 5.0 sections", "", "| Section | Title | Scope | Why | Sheets |", "|---|---|---|---|---|"]
    for a in sorted(cm.asvs, key=lambda a: not a["applies"]):
        out.append(f"| {a['code']} | {a['title']} | {'in' if a['applies'] else 'out'} | {a['reason']} | "
                   f"{', '.join(a['sheets'][:3]) or '-'} |")
    out += ["", "## Top 10 2021 categories covered by the applicable sheets", ""]
    out += [f"- **{t['code']} {t['title']}**: {', '.join(t['sheets'])}" for t in cm.top10]
    out += ["", "Next: `compliance_checklist.py --root <app>` for an evidence-backed ASVS self-assessment."]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    args = ap.parse_args()
    if not Path(args.root).is_dir():
        print(f"error: --root is not a directory: {args.root}", file=sys.stderr)
        return 2
    try:
        catalog = load_catalog(resolve_data_dir(args.data_dir), resolve_clone(args.clone))
    except OwaspError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    cm = map_controls(args.root, catalog)
    text = json.dumps(asdict(cm), indent=2) if args.format == "json" else to_markdown(cm)
    sys.stdout.buffer.write(text.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
