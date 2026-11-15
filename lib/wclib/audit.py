"""Base class for domain audit scripts: file loading, finding helpers, CLI entry point."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from .cli import build_parser, finish, make_context
from .findings import Report
from .jsscan import JsFile, is_test_file
from .rules import RuleBook
from .stack import detect_stack


class Audit:
    tool = "audit"
    prefix = ""
    exts = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
    include_tests = False

    def __init__(self, ctx, rb: RuleBook, report: Report) -> None:
        self.ctx, self.rb, self.report, self.args = ctx, rb, report, ctx.args
        self.root: Path = ctx.root
        self.stack = detect_stack(ctx.root)
        self.files: list[JsFile] = []
        for sf in ctx.walker.files(exts=self.exts):
            if not self.include_tests and is_test_file(sf.rel):
                continue
            text = sf.read()
            if text:
                self.files.append(JsFile(sf.rel, text))
        self.by_rel = {f.rel: f for f in self.files}
        # App code only: excludes repo tooling (scripts/, tools/), test harnesses and config files.
        self.app_files = [f for f in self.files
                          if not re.search(r"(^|/)(scripts|tools|e2e|tests?|fixtures|mocks?)/|(^|/)[\w.-]+\.config\.[cm]?[jt]s$|(^|/)\.[\w-]+rc\.", f.rel)]

    # ------------------------------------------------------------------ helpers
    def add(self, rule: str, msg: str, f: JsFile | None = None, offset: int | None = None, **kw) -> None:
        file = f.rel if f else kw.pop("file", None)
        line = f.line_of(offset) if (f is not None and offset is not None) else kw.pop("line", None)
        snippet = f.snippet(offset) if (f is not None and offset is not None) else None
        self.report.add(self.rb.make(rule, msg, file=file, line=line, snippet=snippet, **kw))

    def read(self, rel: str) -> str:
        p = self.root / rel
        try:
            return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        except OSError:
            return ""

    @property
    def is_next(self) -> bool:
        return self.stack.has("next")

    def finish_not_checked(self, ran: set[str] = frozenset()) -> None:
        self.report.not_checked += self.rb.not_checked(self.prefix, ran=set(ran))

    def run(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    # ------------------------------------------------------------------ entry point
    @classmethod
    def add_arguments(cls, parser) -> None:
        """Override to add script-specific flags."""

    @classmethod
    def main(cls, skill_dir: Path, description: str) -> int:
        ap = build_parser(description)
        cls.add_arguments(ap)
        args = ap.parse_args()
        ctx = make_context(args)
        report = Report(tool=cls.tool, root=str(ctx.root))
        cls(ctx, RuleBook(skill_dir), report).run()
        return finish(report, ctx)


def run_main(cls, file: str, doc: str) -> None:
    skill_dir = Path(file).resolve().parents[1]
    sys.exit(cls.main(skill_dir, (doc or "").strip().splitlines()[0]))
