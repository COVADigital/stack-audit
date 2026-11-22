"""Rule metadata (rules.json) -> Findings with default severity, reference link and OWASP sheets."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .findings import Finding

CHECK_NOT_RUN = {"manual": "needs judgment", "live": "needs a live target: --url, --remote or --snapshot", "build": "needs --build",
                 "tool": "delegated to another tool"}


class RuleBook:
    def __init__(self, skill_dir: str | Path) -> None:
        skill_dir = Path(skill_dir)
        meta = json.loads((skill_dir / "rules.json").read_text(encoding="utf-8"))
        self.files: dict[str, str] = meta["files"]
        self.rules: dict[str, dict[str, list]] = meta["rules"]
        self._titles: dict[str, str] = {}
        refs = skill_dir / "references"
        for prefix, fname in self.files.items():
            path = refs / fname
            if path.exists():
                for nn, title in re.findall(r"^## (\d{2})\. (.+?)\s*$", path.read_text(encoding="utf-8"), re.M):
                    self._titles[f"{prefix}.{nn}"] = title

    def entry(self, rule: str) -> list:
        prefix, nn = rule.split(".", 1)
        try:
            return self.rules[prefix][nn]
        except KeyError as exc:
            raise KeyError(f"unknown rule {rule}: add it to rules.json") from exc

    def title(self, rule: str) -> str:
        return self._titles.get(rule, rule)

    def ref(self, rule: str) -> str:
        prefix, nn = rule.split(".", 1)
        title = self._titles.get(rule)
        if not title:
            return f"references/{self.files.get(prefix, '?')}"
        slug = re.sub(r"\s+", "-", re.sub(r"[^\w\s-]", "", f"{nn}. {title}".lower()).strip())
        return f"references/{self.files[prefix]}#{slug}"

    def make(self, rule: str, message: str, *, file: str | None = None, line: int | None = None,
             severity: str | None = None, confidence: str | None = None, fix_hint: str | None = None,
             snippet: str | None = None) -> Finding:
        e = self.entry(rule)
        check = e[0]
        conf = confidence or ("medium" if check == "heuristic" else "high")
        return Finding(
            rule=rule, severity=severity or e[1], message=message, file=file, line=line,
            confidence=conf, fix_hint=fix_hint, ref=self.ref(rule),
            owasp=list(e[2]) if len(e) > 2 else [], snippet=snippet,
        )

    def not_checked(self, prefix: str, *, ran: set[str] = frozenset()) -> list[str]:
        """Rules in `prefix` this run could not verify (manual, plus live/build/tool unless in `ran`)."""
        out = []
        for nn, e in sorted(self.rules.get(prefix, {}).items()):
            check = e[0]
            if check in CHECK_NOT_RUN and check not in ran:
                out.append(f"`{prefix}.{nn}` {self.title(f'{prefix}.{nn}')} ({CHECK_NOT_RUN[check]})")
        return out
