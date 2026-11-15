#!/usr/bin/env python3
"""WCAG contrast checker (09-accessibility-i18n §06). Read-only.

    python contrast.py "#767676" "#ffffff"            # one pair (any CSS color syntax, incl. oklch())
    python contrast.py --root REPO                    # all fg/bg token pairs in CSS (light + dark)
"""

from __future__ import annotations

import argparse
import sys

import _bootstrap  # noqa: F401
from wclib.color import candidate_pairs, contrast, extract_tokens, parse_color, resolve_scope, resolve_value
from wclib.walker import Walker


def rate(ratio: float) -> str:
    if ratio >= 7:
        return "AAA"
    if ratio >= 4.5:
        return "AA"
    if ratio >= 3:
        return "AA large text / UI only"
    return "FAIL"


def scan(root: str) -> list[dict]:
    w = Walker(root)
    tokens = []
    for f in w.css_files():
        tokens += extract_tokens(f.read(), f.rel)
    results = []
    for scope in ("light", "dark"):
        if scope == "dark" and not any(t.scope == "dark" for t in tokens):
            continue
        table = resolve_scope(tokens, scope)
        for fg_k, bg_k in candidate_pairs(table):
            fg_v, fg_t = resolve_value(table, fg_k)
            bg_v, bg_t = resolve_value(table, bg_k)
            fg, bg = (parse_color(fg_v) if fg_v else None), (parse_color(bg_v) if bg_v else None)
            if not fg or not bg:
                continue
            results.append({
                "scope": scope, "fg": fg_k, "bg": bg_k, "fg_value": fg_v, "bg_value": bg_v,
                "ratio": round(contrast(fg, bg), 2), "translucent": fg.alpha < 1 or bg.alpha < 1,
                "file": fg_t.file, "line": fg_t.line,
            })
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("colors", nargs="*", help="Two colors: foreground background")
    ap.add_argument("--root")
    args = ap.parse_args()
    if len(args.colors) == 2:
        fg, bg = parse_color(args.colors[0]), parse_color(args.colors[1])
        if not fg or not bg:
            print("error: could not parse one of the colors", file=sys.stderr)
            return 2
        r = contrast(fg, bg)
        print(f"{args.colors[0]} on {args.colors[1]}: {r:.2f}:1 → {rate(r)} (normal text needs 4.5, large text/UI 3)")
        return 0
    if not args.root:
        ap.error("give two colors or --root")
    rows = scan(args.root)
    if not rows:
        print("No foreground/background token pairs found in CSS (:root / @theme / .dark).")
        return 0
    print("| Scope | Foreground | Background | Ratio | Rating | Where |\n|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: (x["scope"], x["ratio"])):
        note = " (translucent: verify on real backdrop)" if r["translucent"] else ""
        print(f"| {r['scope']} | `{r['fg']}` {r['fg_value']} | `{r['bg']}` {r['bg_value']} | {r['ratio']}:1 | {rate(r['ratio'])}{note} | {r['file']}:{r['line']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
