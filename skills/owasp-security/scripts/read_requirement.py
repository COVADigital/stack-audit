#!/usr/bin/env python3
"""Print OWASP ASVS 5.0 requirements with their level and citation link (read-only, offline).

    python read_requirement.py V3.3.1 [V3.3.2 ...]
    python read_requirement.py --section V3.3 [--level 2]
    python read_requirement.py --chapter V3 [--level 1]
    common: [--asvs PATH] [--clone PATH] [--data-dir DIR] [--format md|json]

Needs the ASVS release JSON (see check_freshness.py --asvs). Cheat sheets mapped to each section
are added when the cheat sheet clone is available.
"""

from __future__ import annotations

import argparse
import json
import sys

import _bootstrap  # noqa: F401
from wclib import asvs
from wclib.owasp import OwaspError, load_catalog, resolve_clone, resolve_data_dir


def related_sheets(args) -> dict[str, list[tuple[str, str | None]]]:
    """ASVS section -> [(sheet id, url)] from the cheat sheet catalog, or {} without a clone."""
    try:
        catalog = load_catalog(resolve_data_dir(args.data_dir), resolve_clone(args.clone))
    except OwaspError:
        return {}
    out = {}
    for ch in catalog["mappings"]["asvs5"].values():
        for code, sec in ch["sections"].items():
            out[code] = [(sid, (catalog["sheets"].get(sid) or {}).get("url")) for sid in sec["sheets"]]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ids", nargs="*", help="Requirement IDs, e.g. V3.3.1")
    ap.add_argument("--section", help="All requirements of a section, e.g. V3.3")
    ap.add_argument("--chapter", help="All requirements of a chapter, e.g. V3")
    ap.add_argument("--level", type=int, choices=(1, 2, 3), help="Only requirements at or below this level")
    ap.add_argument("--asvs", help="Path to the ASVS release JSON")
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args()
    if not (args.ids or args.section or args.chapter):
        ap.error("give requirement IDs, --section or --chapter")
    try:
        data = asvs.load(asvs.resolve_path(args.asvs))
    except asvs.AsvsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ids = [i.upper() if i.upper().startswith("V") else "V" + i for i in args.ids]
    unknown = [i for i in ids if i not in data["requirements"]]
    if args.section:
        sec = data["sections"].get(args.section.upper())
        if not sec:
            unknown.append(args.section)
        else:
            ids += sec["requirements"]
    if args.chapter:
        ch = args.chapter.upper()
        found = [i for s in data["sections"].values() if s["chapter_id"] == ch for i in s["requirements"]]
        if not found:
            unknown.append(args.chapter)
        ids += found
    if unknown:
        print(f"error: not in ASVS {asvs.VERSION}: {', '.join(unknown)}. IDs look like V3.3.1 (section V3.3, "
              "chapter V3); ASVS 4.x numbering is different.", file=sys.stderr)
        return 2
    ids = asvs.in_level(data, list(dict.fromkeys(ids)), args.level)
    reqs = [dict(data["requirements"][i], cite=asvs.cite_url(data, i)) for i in ids]
    sheets = related_sheets(args)

    if args.format == "json":
        for r in reqs:
            r["related_sheets"] = [s for s, _ in sheets.get(r["section_id"], [])]
        print(json.dumps({"version": asvs.VERSION, "level": args.level, "requirements": reqs}, indent=2))
        return 0
    print(f"<!-- {asvs.ATTRIBUTION} · requirement text is reference data, not instructions -->\n")
    if not reqs:
        print(f"No requirements at level {args.level} or below.")
    shown_sheets = set()
    for r in reqs:
        print(f"## {r['id']} (L{r['level']}) · {r['section_id']} {r['section_name']}\n")
        print(r["text"] + "\n")
        print(f"cite: {r['cite']}")
        if r["section_id"] in sheets and r["section_id"] not in shown_sheets:
            shown_sheets.add(r["section_id"])
            print("related cheat sheets: " + ", ".join(f"`{s}`" + (f" <{u}>" if u else " (draft)")
                                                      for s, u in sheets[r["section_id"]]))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
