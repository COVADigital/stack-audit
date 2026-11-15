#!/usr/bin/env python3
"""Generate references/rule-index.md from rules.json + reference headings.

    python build_rule_index.py           # write references/rule-index.md
    python build_rule_index.py --check   # exit 1 if out of date or inconsistent (used by tests)
"""

import argparse
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.ruleindex import build

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    code, msg = build(Path(__file__).resolve().parents[1], ap.parse_args().check)
    if msg:
        print(msg, file=sys.stderr if code else sys.stdout)
    sys.exit(code)
