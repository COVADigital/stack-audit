#!/usr/bin/env python3
"""Report how current the local OWASP data is: cheat sheet clone, catalog, ASVS requirements. No network.

    python check_freshness.py [--clone PATH] [--data-dir DIR] [--max-age-days 30] [--rebuild]
    python check_freshness.py --asvs [--asvs-file PATH]   # only the ASVS release JSON (exit 2 if missing/invalid)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import _bootstrap  # noqa: F401
from wclib import asvs
from wclib.owasp import OwaspError, build_catalog, catalog_path, resolve_clone, resolve_data_dir, save_catalog
from wclib.walker import run_git


def asvs_status(explicit: str | None) -> tuple[bool, str]:
    data, problem = asvs.try_load(explicit)
    if data:
        return True, (f"- ASVS {asvs.VERSION}: `{data['path']}`, SHA-256 matches the pinned release, "
                      f"{len(data['requirements'])} requirements in {len(data['sections'])} sections. "
                      "A fixed release: nothing to update until the plugin pins a newer one.")
    return False, f"- ASVS requirement text: not available, so ASVS work stays at section level.\n  {problem}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    ap.add_argument("--max-age-days", type=int, default=30)
    ap.add_argument("--rebuild", action="store_true", help="Rebuild the catalog from the clone now")
    ap.add_argument("--asvs", action="store_true", help="Check only the ASVS requirement data")
    ap.add_argument("--asvs-file", help="Path to the ASVS release JSON")
    args = ap.parse_args()
    if args.asvs:
        ok, text = asvs_status(args.asvs_file)
        print("# OWASP ASVS data\n\n" + text)
        return 0 if ok else 2
    try:
        clone = resolve_clone(args.clone)
    except OwaspError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    data_dir = resolve_data_dir(args.data_dir)

    head = (run_git(clone, "rev-parse", "HEAD") or "").strip()
    date_s = (run_git(clone, "log", "-1", "--format=%cI") or "").strip()
    branch = (run_git(clone, "rev-parse", "--abbrev-ref", "HEAD") or "").strip()
    behind = (run_git(clone, "rev-list", "--count", f"HEAD..origin/{branch}") or "").strip() if branch else ""
    age_days = None
    if date_s:
        age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(date_s)).days

    if args.rebuild:
        save_catalog(build_catalog(clone), data_dir)
    cat_file = catalog_path(data_dir)
    cat_commit = None
    if cat_file.exists():
        try:
            cat_commit = json.loads(cat_file.read_text(encoding="utf-8"))["source"].get("commit")
        except (json.JSONDecodeError, KeyError, OSError):
            cat_commit = None

    print("# OWASP data freshness\n")
    print(f"- Clone: `{clone}` on `{branch or '?'}` @ {head[:7] or '?'} (last commit {date_s[:10] or '?'}"
          + (f", {age_days} days ago)" if age_days is not None else ")"))
    if behind and behind != "0":
        print(f"- Behind origin/{branch} by {behind} commit(s) as of the last fetch")
    print(f"- Catalog: `{cat_file}` @ {(cat_commit or 'missing')[:7]}"
          + (" (matches clone)" if cat_commit == head else " (out of date: rebuilt automatically on next lookup)"))
    if age_days is not None and age_days > args.max_age_days:
        print(f"\n**The clone is older than {args.max_age_days} days.** To update it, run this yourself:\n")
        print(f"    git -C \"{clone}\" pull --ff-only")
    else:
        print("\nUp to date enough. To update anyway, run yourself: " f"`git -C \"{clone}\" pull --ff-only`")
    print("\n" + asvs_status(args.asvs_file)[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
