"""Suppressions.

Inline (on the finding's line or the line directly above it):

    // stack-audit-ignore sec.01 -- sanitized by DOMPurify in lib/html.ts
    # stack-audit-ignore cnet.02 -- bound to the private network interface only
    {/* stack-audit-ignore a11y.07 -- decorative, alt set by CMS */}

Several rules: `stack-audit-ignore sec.01,sec.14 -- reason`. Domain wildcard: `sec.*`.
A suppression with no reason after `--` does not suppress anything and is
reported as `meta.01` instead.

Config (`stack-audit.config.json`):  "ignore": { "sec.01": ["src/legacy/**"] }
"""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Finding, Report
from .textutil import any_glob

_INLINE = re.compile(
    r"stack-audit-ignore\s+(?P<rules>[a-z0-9]+\.(?:\*|[0-9]{2})(?:\s*,\s*[a-z0-9]+\.(?:\*|[0-9]{2}))*)"
    r"(?:\s*--\s*(?P<reason>.*?))?\s*(?:\*/\s*\}?|-->)?\s*$",
    re.IGNORECASE,
)


def _rule_matches(rule: str, pattern: str) -> bool:
    if pattern.endswith(".*"):
        return rule.split(".", 1)[0] == pattern[:-2]
    return rule == pattern


def parse_inline(line: str) -> tuple[list[str], str | None] | None:
    m = _INLINE.search(line)
    if not m:
        return None
    rules = [r.strip().lower() for r in m.group("rules").split(",")]
    reason = (m.group("reason") or "").strip() or None
    return rules, reason


class Suppressor:
    def __init__(self, root: str | Path, config: dict) -> None:
        self.root = Path(root)
        self.config_ignores: dict[str, list[str]] = config.get("ignore", {}) or {}
        self._line_cache: dict[str, list[str]] = {}

    def _lines(self, rel: str) -> list[str]:
        if rel not in self._line_cache:
            try:
                text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            self._line_cache[rel] = text.split("\n")
        return self._line_cache[rel]

    def _config_suppressed(self, f: Finding) -> bool:
        if not f.file:
            return False
        for pattern, globs in self.config_ignores.items():
            if _rule_matches(f.rule, pattern.lower()) and any_glob(f.file, globs):
                return True
        return False

    def _inline(self, f: Finding) -> tuple[bool, Finding | None]:
        """Returns (suppressed, meta_finding_if_reasonless)."""
        if not f.file or not f.line:
            return False, None
        lines = self._lines(f.file)
        for ln in (f.line, f.line - 1):
            if 1 <= ln <= len(lines):
                parsed = parse_inline(lines[ln - 1])
                if parsed and any(_rule_matches(f.rule, p) for p in parsed[0]):
                    rules, reason = parsed
                    if reason:
                        return True, None
                    return False, Finding(
                        rule="meta.01",
                        severity="warn",
                        message=f"stack-audit-ignore for {', '.join(rules)} has no reason; suppression ignored",
                        file=f.file,
                        line=ln,
                        fix_hint="Add a reason: `stack-audit-ignore <rule> -- <why this is safe>`",
                    )
        return False, None

    def apply(self, report: Report) -> Report:
        kept: list[Finding] = []
        metas: list[Finding] = []
        for f in report.findings:
            if f.rule.startswith("meta."):
                kept.append(f)
                continue
            if self._config_suppressed(f):
                report.suppressed += 1
                continue
            suppressed, meta = self._inline(f)
            if suppressed:
                report.suppressed += 1
                continue
            if meta:
                metas.append(meta)
            kept.append(f)
        report.findings = kept + metas
        report.dedupe()
        return report
