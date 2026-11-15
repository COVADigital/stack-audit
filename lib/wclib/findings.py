"""Finding and Report model plus JSON / Markdown / SARIF writers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable

SEVERITIES = ("error", "warn", "info")
CONFIDENCES = ("high", "medium", "low")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_SARIF_LEVEL = {"error": "error", "warn": "warning", "info": "note"}

# Rule-ID prefix -> human domain name (shared across the three skills).
DOMAINS = {
    "git": "Git security",
    "ren": "Rendering",
    "perf": "Performance",
    "state": "State management",
    "net": "Networking",
    "cache": "Caching",
    "arch": "Architecture",
    "sec": "Security",
    "a11y": "Accessibility & i18n",
    "img": "Image build",
    "run": "Runtime hardening",
    "cnet": "Container network exposure",
    "csec": "Container secrets",
    "host": "Docker host",
    "sup": "Supply chain",
    "ops": "Data & operations",
    "cool": "Coolify",
    "owasp": "OWASP",
    "meta": "Audit meta",
}


def domain_of(rule: str) -> str:
    return rule.split(".", 1)[0] if "." in rule else rule


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    confidence: str = "high"
    fix_hint: str | None = None
    ref: str | None = None
    owasp: list[str] = field(default_factory=list)
    snippet: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r} for {self.rule}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"invalid confidence {self.confidence!r} for {self.rule}")
        if self.file:
            self.file = self.file.replace("\\", "/")

    @property
    def domain(self) -> str:
        return domain_of(self.rule)

    @property
    def location(self) -> str:
        if not self.file:
            return "(project)"
        return f"{self.file}:{self.line}" if self.line else self.file

    def fingerprint(self) -> str:
        raw = f"{self.rule}|{self.file}|{self.line}|{self.message}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["domain"] = self.domain
        d["fingerprint"] = self.fingerprint()
        return {k: v for k, v in d.items() if v not in (None, [], "")}


@dataclass
class Report:
    tool: str
    root: str
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)       # e.g. "gitleaks not found"
    not_checked: list[str] = field(default_factory=list)   # judgment-only rules for this phase
    suppressed: int = 0
    meta: dict = field(default_factory=dict)
    appendix: list[str] = field(default_factory=list)  # extra Markdown blocks (e.g. route inventory)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def merge(self, other: "Report") -> None:
        self.extend(other.findings)
        self.skipped.extend(s for s in other.skipped if s not in self.skipped)
        self.not_checked.extend(s for s in other.not_checked if s not in self.not_checked)
        self.suppressed += other.suppressed
        self.appendix.extend(other.appendix)

    def dedupe(self) -> None:
        seen: set[str] = set()
        unique = []
        for f in self.findings:
            fp = f.fingerprint()
            if fp not in seen:
                seen.add(fp)
                unique.append(f)
        self.findings = unique

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (_SEV_RANK[f.severity], f.domain, f.file or "", f.line or 0, f.rule),
        )

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def has_errors(self) -> bool:
        return any(f.severity == "error" for f in self.findings)

    # ------------------------------------------------------------------ writers

    def to_json(self) -> str:
        payload = {
            "tool": self.tool,
            "root": self.root,
            "generated": _now(),
            "counts": self.counts(),
            "suppressed": self.suppressed,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "skipped": self.skipped,
            "not_checked": self.not_checked,
            "meta": self.meta,
            "appendix": self.appendix,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "Report":
        data = json.loads(text)
        r = cls(tool=data.get("tool", "?"), root=data.get("root", ""), skipped=data.get("skipped", []),
                not_checked=data.get("not_checked", []), suppressed=data.get("suppressed", 0),
                meta=data.get("meta", {}), appendix=data.get("appendix", []))
        keep = {"rule", "severity", "message", "file", "line", "confidence", "fix_hint", "ref", "owasp", "snippet"}
        for f in data.get("findings", []):
            r.add(Finding(**{k: v for k, v in f.items() if k in keep}))
        return r

    def to_markdown(self) -> str:
        out: list[str] = []
        c = self.counts()
        out.append(f"# {self.tool} report")
        out.append("")
        out.append(f"- Root: `{self.root}`")
        out.append(f"- Generated: {_now()}")
        out.append(
            f"- Findings: **{c['error']} error**, **{c['warn']} warn**, {c['info']} info"
            + (f" · {self.suppressed} suppressed" if self.suppressed else "")
        )
        out.append("")

        if self.findings:
            out.append("## Summary by domain")
            out.append("")
            out.append("| Domain | error | warn | info |")
            out.append("|---|---|---|---|")
            by_domain: dict[str, dict[str, int]] = {}
            for f in self.findings:
                row = by_domain.setdefault(f.domain, {s: 0 for s in SEVERITIES})
                row[f.severity] += 1
            for dom in sorted(by_domain):
                row = by_domain[dom]
                name = DOMAINS.get(dom, dom)
                out.append(f"| {name} | {row['error']} | {row['warn']} | {row['info']} |")
            out.append("")

            for sev in SEVERITIES:
                group = [f for f in self.sorted_findings() if f.severity == sev]
                if not group:
                    continue
                out.append(f"## {sev.capitalize()} ({len(group)})")
                out.append("")
                for f in group:
                    conf = "" if f.confidence == "high" else f" _(confidence: {f.confidence})_"
                    out.append(f"- **`{f.rule}`** `{f.location}` {_md_escape(f.message)}{conf}")
                    if f.fix_hint:
                        out.append(f"  - Fix: {_md_escape(f.fix_hint)}")
                    refs = ([f.ref] if f.ref else []) + [f"OWASP: {o}" for o in f.owasp]
                    if refs:
                        out.append(f"  - Ref: {'; '.join(refs)}")
                out.append("")
        else:
            out.append("No findings.")
            out.append("")

        for block in self.appendix:
            out.append(block.rstrip())
            out.append("")
        if self.skipped:
            out.append("## Skipped checks")
            out.append("")
            out.extend(f"- {s}" for s in self.skipped)
            out.append("")
        if self.not_checked:
            out.append("## Not checked automatically (needs human judgment)")
            out.append("")
            out.extend(f"- {s}" for s in self.not_checked)
            out.append("")
        return "\n".join(out)

    def to_sarif(self) -> str:
        rules: dict[str, dict] = {}
        results = []
        for f in self.sorted_findings():
            if f.rule not in rules:
                rule = {"id": f.rule, "shortDescription": {"text": f.message[:200]}}
                if f.ref and f.ref.startswith("http"):
                    rule["helpUri"] = f.ref
                rules[f.rule] = rule
            result: dict = {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message + (f" Fix: {f.fix_hint}" if f.fix_hint else "")},
                "partialFingerprints": {"wcFingerprint": f.fingerprint()},
            }
            if f.file:
                loc: dict = {"artifactLocation": {"uri": f.file}}
                if f.line:
                    loc["region"] = {"startLine": f.line}
                result["locations"] = [{"physicalLocation": loc}]
            results.append(result)
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": self.tool, "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def render(self, fmt: str) -> str:
        if fmt == "json":
            return self.to_json()
        if fmt == "sarif":
            return self.to_sarif()
        if fmt == "md":
            return self.to_markdown()
        raise ValueError(f"unknown format {fmt!r}")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
