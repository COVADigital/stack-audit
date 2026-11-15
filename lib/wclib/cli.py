"""Shared CLI plumbing for audit scripts.

Exit codes: 0 = ran fine (findings may exist), 1 = --strict and error-severity
findings present, 2 = usage/config error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ConfigError, load_config
from .findings import Report
from .suppress import Suppressor
from .walker import Walker

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def build_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--root", default=".", help="Repository root to audit (default: current directory)")
    p.add_argument("--changed", action="store_true", help="Only audit files changed vs --base (git)")
    p.add_argument("--base", default=None, help="Base ref for --changed (default: origin/HEAD, origin/main, main)")
    p.add_argument("--files", nargs="+", default=None, metavar="PATH",
                   help="Only audit these files (relative to --root, or absolute inside it)")
    p.add_argument("--format", choices=("md", "json", "sarif"), default="md", help="Output format (default: md)")
    p.add_argument("--out", default=None, help="Write report to this file instead of stdout")
    p.add_argument("--strict", action="store_true", help="Exit 1 if error-severity findings remain")
    p.add_argument("--config", default=None, help="Path to stack-audit.config.json (default: <root>/stack-audit.config.json)")
    return p


class Context:
    """Everything an audit needs: resolved root, config, walker, suppressor."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = Path(args.root).resolve()
        if not self.root.is_dir():
            raise ConfigError(f"--root is not a directory: {self.root}")
        self.config = load_config(self.root, args.config)
        self.walker = Walker(
            self.root,
            ignore_paths=self.config.get("ignorePaths", []),
            changed_only=args.changed,
            base=args.base,
            only=self._only(args.files),
        )
        self.suppressor = Suppressor(self.root, self.config)

    def _only(self, files: list[str] | None) -> list[str] | None:
        if files is None:
            return None
        out = []
        for f in files:
            p = Path(f) if Path(f).is_absolute() else self.root / f
            try:
                out.append(p.resolve().relative_to(self.root).as_posix())
            except ValueError:
                raise ConfigError(f"--files: {f} is outside --root {self.root}") from None
        return out


def make_context(args: argparse.Namespace) -> Context:
    try:
        return Context(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def finish(report: Report, ctx: Context) -> int:
    """Apply suppressions, render, write, and return the exit code."""
    report.skipped.extend(n for n in ctx.walker.notes if n not in report.skipped)
    if ctx.config.get("_source"):
        report.meta.setdefault("config", ctx.config["_source"])
    ctx.suppressor.apply(report)
    text = report.render(ctx.args.format)
    if ctx.args.out:
        out = Path(ctx.args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out} ({len(report.findings)} findings)", file=sys.stderr)
    else:
        _safe_print(text)
    if ctx.args.strict and report.has_errors():
        return EXIT_FINDINGS
    return EXIT_OK


def _safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:  # Windows consoles with legacy code pages
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")
