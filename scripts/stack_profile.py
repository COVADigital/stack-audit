#!/usr/bin/env python3
"""Print the detected stack profile of a project (read-only).

    python stack_profile.py --root path/to/repo [--format md|json]
"""

import argparse
import sys

import _bootstrap  # noqa: F401
from wclib.stack import detect_stack


def to_markdown(p) -> str:
    lines = [f"# Stack profile", "", f"- Root: `{p.root}`"]
    lines.append(f"- Package manager: {p.package_manager or 'unknown'}")
    if p.workspaces:
        lines.append(f"- Workspaces: {', '.join(p.workspaces)}")
    lines.append(f"- Router: app=`{p.router.get('app')}` pages=`{p.router.get('pages')}`")
    lines.append(f"- Request interceptor: `{p.request_interceptor}`")
    nc = p.next_config
    if nc:
        flags = [k for k in ("cacheComponents", "ppr", "reactCompiler", "productionBrowserSourceMaps", "headers") if nc.get(k)]
        lines.append(f"- {nc['file']}: output=`{nc.get('output')}` flags: {', '.join(flags) or 'none'}")
    lines += ["", "## Packages", "", "| Package | Declared | Installed | Major |", "|---|---|---|---|"]
    for name, info in sorted(p.packages.items()):
        lines.append(f"| {name} | {info['declared']} | {info['installed'] or '-'} | {info['major'] if info['major'] is not None else '-'} |")
    lines += ["", "## Categories", ""]
    lines += [f"- {k}: {v or '-'}" for k, v in p.categories.items()]
    lines += ["", "## Docker / CI", ""]
    lines.append(f"- Dockerfiles: {', '.join(p.docker['dockerfiles']) or '-'}; compose: {', '.join(p.docker['compose']) or '-'}; .dockerignore: {p.docker['dockerignore']}")
    lines.append(f"- GitHub Actions: {', '.join(p.ci['github_actions']) or '-'}; dependabot: {p.ci['dependabot']}; CODEOWNERS: {p.ci['codeowners']}; lighthouserc: {p.ci['lighthouserc']}")
    if p.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in p.notes]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args()
    profile = detect_stack(args.root)
    print(profile.to_json() if args.format == "json" else to_markdown(profile))
    return 0


if __name__ == "__main__":
    sys.exit(main())
