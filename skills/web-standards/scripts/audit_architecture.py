#!/usr/bin/env python3
"""Architecture audit (rules arch.*, 07-architecture.md). Read-only.

    python audit_architecture.py --root APP [--changed] [--format md|json|sarif] [--strict]

Builds an import graph (relative imports + tsconfig `paths`), ignores type-only imports,
and reports cycles (Tarjan SCC), cross-feature deep imports, and layering violations.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import PurePosixPath

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile
from wclib.walker import repo_paths

IMPORT_RE = re.compile(
    r"""^\s*(?:import|export)\s+(type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?['"]([^'"]+)['"]|"""
    r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)|\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.M,
)
RESOLVE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
COLOR_LITERAL = re.compile(r"(?<![\w-])#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b|\brgba?\(\s*\d|\bhsla?\(\s*\d")
TW_ARBITRARY = re.compile(r"(?<![\w-])(?:bg|text|border|from|to|via|fill|stroke|ring|outline|shadow|decoration)-\[(?:#|rgb|hsl)[^\]]*\]|"
                          r"(?<![\w-])-?(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|space-[xy]|w|h|top|left|right|bottom|text)-\[\d+(?:\.\d+)?px\]")
DOMAIN_DIRS = re.compile(r"(^|/)(domain|core|rules|business|logic|use-?cases|application)/")
VENDOR_SDK = re.compile(r"^(react|react-dom|next(/.*)?|stripe|@sanity/.+|drizzle-orm(/.*)?|@prisma/client|better-auth(/.*)?|@aws-sdk/.+|resend|@vercel/.+)$")
ENV_IGNORE = {"NODE_ENV", "NEXT_RUNTIME", "CI", "VERCEL", "VERCEL_ENV", "VERCEL_URL", "PORT", "HOSTNAME", "TZ", "npm_package_version",
              "NEXT_PHASE", "PWD", "HOME", "DEBUG", "NODE_OPTIONS", "NEXT_TELEMETRY_DISABLED"}


def strip_jsonc(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:\"'])//[^\n]*", r"\1", text)
    return re.sub(r",(\s*[}\]])", r"\1", text)


class ArchitectureAudit(Audit):
    tool = "audit_architecture"
    prefix = "arch"

    # ------------------------------------------------------------- import graph
    def load_paths(self) -> tuple[str, dict[str, list[str]]]:
        for name in ("tsconfig.json", "jsconfig.json"):
            p = self.root / name
            if p.exists():
                try:
                    cfg = json.loads(strip_jsonc(p.read_text(encoding="utf-8")))
                except json.JSONDecodeError:
                    continue
                co = cfg.get("compilerOptions") or {}
                return co.get("baseUrl", "."), co.get("paths") or {}
        return ".", {}

    def resolve(self, importer: str, spec: str) -> str | None:
        cands = []
        if spec.startswith("."):
            cands.append(str(PurePosixPath(importer).parent / spec))
        else:
            for pattern, targets in self.paths.items():
                if pattern.endswith("/*") and spec.startswith(pattern[:-1]):
                    rest = spec[len(pattern) - 1:]
                    cands += [str(PurePosixPath(self.base_url) / t.replace("*", rest)) for t in targets]
                elif pattern == spec:
                    cands += [str(PurePosixPath(self.base_url) / t) for t in targets]
        for c in cands:
            c = str(PurePosixPath(c)).replace("\\", "/")
            parts = []
            for seg in c.split("/"):  # normalise ./ and ../
                if seg in ("", "."):
                    continue
                if seg == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(seg)
            c = "/".join(parts)
            if c in self.fileset:
                return c
            for ext in RESOLVE_EXTS:
                if c + ext in self.fileset:
                    return c + ext
            for ext in RESOLVE_EXTS:
                if f"{c}/index{ext}" in self.fileset:
                    return f"{c}/index{ext}"
        return None

    def build_graph(self) -> None:
        self.base_url, self.paths = self.load_paths()
        self.fileset = {f.rel for f in self.files}
        self.graph: dict[str, set[str]] = {f.rel: set() for f in self.files}
        self.edges: list[tuple[str, str, str, int]] = []  # importer, target, spec, offset
        for f in self.files:
            for m in IMPORT_RE.finditer(f.code):
                type_only = bool(m.group(1))
                spec = m.group(2) or m.group(3) or m.group(4)
                if not spec:
                    continue
                target = self.resolve(f.rel, spec)
                if target:
                    self.edges.append((f.rel, target, spec, m.start()))
                    if not type_only and m.group(3) is None:  # dynamic import() doesn't create a load-time cycle
                        self.graph[f.rel].add(target)

    def cycles(self) -> list[list[str]]:
        index, low, on, stack, out = {}, {}, set(), [], []
        counter = [0]
        sys.setrecursionlimit(max(10000, len(self.graph) * 4))

        def strong(v: str) -> None:
            index[v] = low[v] = counter[0]
            counter[0] += 1
            stack.append(v)
            on.add(v)
            for w in self.graph.get(v, ()):
                if w not in index:
                    strong(w)
                    low[v] = min(low[v], low[w])
                elif w in on:
                    low[v] = min(low[v], index[w])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    out.append(sorted(comp))

        for v in list(self.graph):
            if v not in index:
                strong(v)
        return out

    def boundaries(self) -> None:
        froot = self.ctx.config.get("features", {}).get("root", "src/features").strip("/")
        if not any(r.startswith(froot + "/") for r in self.fileset):
            froot = next((d for d in ("src/features", "features", "src/modules", "modules") if any(r.startswith(d + "/") for r in self.fileset)), froot)
        # Enforce public-API imports only if the repo uses the convention (some feature has an index file).
        uses_index = any(re.fullmatch(rf"{re.escape(froot)}/[^/]+/index\.[cm]?[jt]sx?", r) for r in self.fileset)
        if any(r.startswith(froot + "/") for r in self.fileset) and not uses_index:
            self.report.skipped.append(f"arch.08: features under {froot}/ have no index files, so public-API imports aren't enforced")
        app_rels = {f.rel for f in self.app_files}
        for importer, target, spec, off in self.edges:
            f = self.by_rel[importer]
            if importer not in app_rels:
                continue
            if uses_index and target.startswith(froot + "/"):
                feature = target[len(froot) + 1:].split("/")[0]
                inside = importer.startswith(f"{froot}/{feature}/")
                public = re.fullmatch(rf"{re.escape(froot)}/{re.escape(feature)}/index\.[cm]?[jt]sx?", target)
                if not inside and not public and "/" in target[len(froot) + 1:]:
                    self.add("arch.08", f"Deep import into feature '{feature}' ({spec}) bypasses its public index", f, off,
                             confidence="medium", fix_hint=f"Export it from {froot}/{feature}/index.ts and import from the feature root")
            if re.search(r"(^|/)components/ui/", importer) and (target.startswith(froot + "/") or "/app/" in "/" + target):
                self.add("arch.03", f"Design-system component imports app/feature code ({spec})", f, off,
                         fix_hint="Lower layers never import higher ones: pass data/handlers in via props")
        for f in self.files:
            if DOMAIN_DIRS.search(f.rel):
                for m in IMPORT_RE.finditer(f.code):
                    spec = m.group(2) or m.group(3) or m.group(4) or ""
                    if VENDOR_SDK.match(spec) and not m.group(1):
                        self.add("arch.16", f"Domain/business module imports framework/vendor '{spec}'", f, m.start(),
                                 fix_hint="Keep domain logic pure TypeScript; wrap vendors in adapters injected from outside")

    # ------------------------------------------------------------- other checks
    def components(self, f: JsFile) -> None:
        if not f.rel.endswith((".tsx", ".jsx")):
            return
        limit = int(self.ctx.config["budgets"]["componentMaxLines"])
        lines = f.text.count("\n") + 1
        if lines > limit * 2 and not re.search(r"(^|/)components/ui/", f.rel):
            self.add("arch.01", f"{lines} lines (guideline: split around {limit})", f, 0, severity="info",
                     fix_hint="Extract sub-components and hooks; one job per component")
        if re.search(r"(^|/)components/ui/|(theme|tokens?|colors?|opengraph|og-image|icon|manifest|email)", f.rel, re.I):
            return  # the design system / theme files are where tokens and raw values belong

        def in_prose(pos: int) -> bool:
            """True if pos sits inside a quoted string of 4+ words (e.g. "Use a hex color like #1a2b3c")."""
            start = f.text.rfind("\n", 0, pos) + 1
            end = f.text.find("\n", pos)
            line = f.text[start: end if end != -1 else len(f.text)]
            col = pos - start
            return any(q.start() < col < q.end() and q.group(2).count(" ") >= 3
                       for q in re.finditer(r"(['\"`])(.*?)\1", line))

        colors = [m for m in COLOR_LITERAL.finditer(f.code) if not in_prose(m.start())]
        arbitrary = list(TW_ARBITRARY.finditer(f.code))
        hits = colors + arbitrary
        if hits:
            self.add("arch.02", f"{len(hits)} hard-coded color/spacing value(s) instead of design tokens", f, hits[0].start(),
                     confidence="medium", fix_hint="Define tokens in @theme (Tailwind 4) / CSS variables and use the utilities")

    def routes_thin(self, f: JsFile) -> None:
        if not re.search(r"(^|/)(page|route)\.[jt]sx?$", f.rel):
            return
        if re.search(r"\bdb\s*\.\s*(select|insert|update|delete|query|execute|transaction)\b", f.code_nostr):
            self.add("arch.09", "Route file queries the database directly (business logic in the route)", f,
                     f.code_nostr.find("db"), severity="info", fix_hint="Call a feature service / DAL; keep routes thin")
        elif f.text.count("\n") > 250:
            self.add("arch.09", f"Route file is {f.text.count(chr(10))} lines (keep routes thin)", f, 0, severity="info")
        if re.search(r"from\s+['\"](drizzle-orm|postgres|pg|@/lib/db|~/lib/db|@/db)['\"]", f.code) and f.directive != "client" \
                and not re.search(r"(^|/)(health|healthz|ready|readyz|status|live|livez)/", f.rel):
            self.add("arch.21", "Route imports the DB client directly instead of going through a data access layer", f, 0,
                     severity="info", confidence="low", fix_hint="lib/dal/*: auth check + query in one server-only module")

    def registries(self, f: JsFile) -> None:
        # Only component lookups rendered from data (Capitalized names); typed Record lookups of plain values are skipped.
        for m in re.finditer(r"const\s+([A-Z]\w*)\s*=\s*(\w+)\s*\[\s*[\w.]*\b(_?type|kind|blockType)\b[^\]]*\]", f.code_nostr):
            name = m.group(1)
            after = f.code_nostr[m.end(): m.end() + 300]
            if not re.search(rf"if\s*\(\s*!\s*{name}\b|{name}\s*\?|{name}\s*&&|\?\?|{name}\s*===?\s*undefined", after):
                self.add("arch.14", f"Config-driven lookup `{name}` has no fallback for unknown types", f, m.start(), confidence="low",
                         fix_hint="return C ? <C … /> : null (and log unknown block types)")

    def docs_and_env(self) -> None:
        places = repo_paths(self.root)
        readme = next((b / n for b in places for n in ("README.md", "readme.md", "README") if (b / n).exists()), None)
        if not readme:
            self.add("arch.20", "No README", fix_hint="Setup, scripts, environment variables, architecture")
        else:
            text = readme.read_text(encoding="utf-8", errors="replace").lower()
            missing = [k for k, pat in (("setup", r"setup|install|getting started|quick ?start"), ("scripts", r"scripts|commands|npm run|pnpm"),
                                        ("environment", r"environment|\.env|env var"), ("architecture", r"architecture|structure|overview"))
                       if not re.search(pat, text)]
            if missing:
                self.add("arch.20", f"README lacks: {', '.join(missing)}", file=str(readme.relative_to(places[-1]) if len(places) > 1 else readme.name),
                         severity="info")
        used = set()
        for f in self.app_files:
            used |= set(re.findall(r"process\.env\.([A-Z][A-Z0-9_]+)", f.code))
            used |= set(re.findall(r"process\.env\[\s*['\"]([A-Z][A-Z0-9_]+)['\"]\s*\]", f.code))
            if re.search(r"(^|/)env\.[cm]?[jt]s$", f.rel):  # zod/t3 env schemas: keys of the schema
                used |= set(re.findall(r"^\s*([A-Z][A-Z0-9_]{2,})\s*:", f.code, re.M))
        used -= ENV_IGNORE
        if not used:
            return
        example = next((b / n for b in places for n in (".env.example", ".env.sample", ".env.template", ".env.local.example") if (b / n).exists()), None)
        if not example:
            self.add("arch.20", f"No .env.example while code reads {len(used)} environment variable(s)",
                     fix_hint="Commit .env.example with placeholder values only")
            return
        documented = set(re.findall(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=", example.read_text(encoding="utf-8", errors="replace"), re.M))
        missing = sorted(used - documented)
        if missing:
            self.add("arch.20", f"{len(missing)} env var(s) used in code but missing from {example.name}: {', '.join(missing[:12])}",
                     file=example.name, fix_hint="Document every variable (placeholder values only)")

    def codeowners(self) -> None:
        for b in repo_paths(self.root):
            for rel in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
                p = b / rel
                if p.exists():
                    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        path = line.split("#", 1)[0].split()
                        if path and not any(ch in path[0] for ch in "*?") and not (b / path[0].lstrip("/")).exists():
                            self.add("arch.17", f"CODEOWNERS entry '{path[0]}' matches no path", file=rel, line=n, severity="info")
                    return

    def run(self) -> None:
        self.build_graph()
        for comp in self.cycles():
            members = comp[:6]
            f = self.by_rel[comp[0]]
            self.add("arch.18", f"Import cycle between {len(comp)} modules: {' ↔ '.join(members)}{' …' if len(comp) > 6 else ''}",
                     f, 0, fix_hint="Extract the shared piece into a lower-level module; check with `npx madge --circular`")
        self.boundaries()
        for f in self.files:
            self.components(f)
            self.routes_thin(f)
            self.registries(f)
        self.docs_and_env()
        self.codeowners()
        self.report.meta["modules"] = len(self.graph)
        self.report.meta["import_edges"] = len(self.edges)
        self.finish_not_checked()


if __name__ == "__main__":
    run_main(ArchitectureAudit, __file__, __doc__)
