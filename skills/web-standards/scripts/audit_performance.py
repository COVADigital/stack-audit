#!/usr/bin/env python3
"""Performance audit (rules perf.*, 03-performance.md). Read-only.

    python audit_performance.py --root APP [--changed] [--format md|json|sarif] [--strict]
                                [--build]   per-route initial JS (gzip) from .next build output vs budget
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile, find_calls, tags

HEAVY = ("chart.js", "react-chartjs-2", "recharts", "@nivo/", "mapbox-gl", "maplibre-gl", "leaflet", "react-leaflet", "three",
         "@react-three/fiber", "@monaco-editor/react", "monaco-editor", "@tiptap/", "pdfjs-dist", "react-pdf", "xlsx", "exceljs",
         "@codemirror/", "quill", "react-quill", "lottie-web", "lottie-react", "video.js", "hls.js", "emoji-mart", "plotly.js",
         "react-plotly.js", "@uiw/react-md-editor", "firebase", "@ffmpeg/ffmpeg", "highlight.js", "prismjs", "shiki")
RUM = re.compile(r"useReportWebVitals|from\s+['\"]web-vitals['\"]|@vercel/speed-insights|@sentry/nextjs|posthog|@datadog/browser-rum|plausible|cloudflareinsights", re.I)


class PerformanceAudit(Audit):
    tool = "audit_performance"
    prefix = "perf"

    @classmethod
    def add_arguments(cls, parser) -> None:
        parser.add_argument("--build", action="store_true", help="Measure per-route initial JS from .next (after next build)")

    def images(self, f: JsFile) -> None:
        major = self.stack.next_major or 0
        static_imports = set(re.findall(r"import\s+(\w+)\s+from\s+['\"][^'\"]+\.(?:png|jpe?g|webp|avif|gif|svg)['\"]", f.code))
        for t in tags(f, {"Image", "img", "video", "iframe"}):
            if t.has_spread:
                continue
            if t.name == "Image":
                if major >= 16 and t.has("priority"):
                    self.add("perf.02", "`priority` is deprecated in Next.js 16: use `preload` (or fetchPriority=\"high\")", f, t.start,
                             severity="info")
                if t.has("preload", "priority") and t.has("loading", "fetchPriority"):
                    self.add("perf.02", "Don't combine preload/priority with loading or fetchPriority", f, t.start)
                if t.literal("loading") == "lazy" and t.has("preload", "priority"):
                    self.add("perf.02", "Image is both lazy and preloaded", f, t.start)
                src = t.attr("src")
                is_static = isinstance(src, str) and re.fullmatch(r"\{\s*(\w+)\s*\}", src) and re.fullmatch(r"\{\s*(\w+)\s*\}", src).group(1) in static_imports
                if not t.has("fill") and not (t.has("width") and t.has("height")) and not is_static:
                    self.add("perf.04", "next/image without width/height (or fill)", f, t.start,
                             fix_hint="Give intrinsic width/height, use fill inside a sized container, or a static import")
                if t.has("fill") and not t.has("sizes"):
                    self.add("perf.09", "next/image with fill but no sizes (downloads a viewport-wide image)", f, t.start,
                             severity="info", fix_hint="sizes=\"(max-width: 768px) 100vw, 50vw\"")
            elif t.name == "img":
                cls = str(t.attr("className") or t.attr("class") or "")
                style = str(t.attr("style") or "")
                if not (t.has("width") and t.has("height")) and not re.search(r"aspect-|size-|h-\d|w-\d", cls) and "aspect" not in style:
                    self.add("perf.04", "<img> without width/height or aspect-ratio (layout shift)", f, t.start)
                if self.is_next and f.rel.endswith((".tsx", ".jsx")) and not re.search(r"\.svg|data:|blob:|\bqr|\bavatar", str(t.attr("src")), re.I):
                    self.add("perf.09", "Raw <img> instead of next/image (no resizing / modern formats)", f, t.start, severity="info")
            elif t.name in ("video", "iframe"):
                cls = str(t.attr("className") or t.attr("class") or "")
                if not (t.has("width") and t.has("height")) and not re.search(r"aspect-|absolute\s+inset-0|h-full|size-full", cls):
                    self.add("perf.04", f"<{t.name}> without dimensions or aspect-ratio", f, t.start, severity="info", confidence="medium")
                if t.name == "iframe" and not t.has("loading"):
                    self.add("perf.08", "<iframe> without loading=\"lazy\"", f, t.start, severity="info")

    def imports(self, f: JsFile) -> None:
        client = f.directive == "client"
        for m in re.finditer(r"^\s*import\s+(?!type\b)([^;]*?)\s+from\s+['\"]([^'\"]+)['\"]", f.code, re.M):
            what, mod = m.group(1), m.group(2)
            if mod == "lodash":
                self.add("perf.07", "import from 'lodash' pulls the whole library", f, m.start(),
                         fix_hint="import debounce from 'lodash-es/debounce' (or a native alternative)")
            if mod in ("moment", "moment-timezone"):
                self.add("perf.07", f"'{mod}' is large and not tree-shakeable", f, m.start(), fix_hint="Use Intl / date-fns / Temporal")
            if what.startswith("* as") and re.match(r"(lucide-react|react-icons|@heroicons|@tabler/icons-react|@phosphor-icons)", mod):
                self.add("perf.07", f"Namespace import from icon library '{mod}' defeats tree shaking", f, m.start())
            if client and any(mod == h or mod.startswith(h) for h in HEAVY):
                self.add("perf.06", f"Heavy library '{mod}' statically imported in a Client Component", f, m.start(),
                         fix_hint="Load it with next/dynamic (or import() on demand) so it isn't in the initial bundle")
        for m in re.finditer(r"fonts\.googleapis\.com", f.code):
            self.add("perf.10", "Google Fonts loaded from fonts.googleapis.com (render-blocking, extra origin)", f, m.start(),
                     fix_hint="Use next/font (self-hosted, preloaded, size-adjusted fallback)")
            break
        for off, args in find_calls(f, r"\.addEventListener", nostr=False):
            ev = re.match(r"\s*['\"](scroll|touchstart|touchmove|wheel)['\"]", args)
            if ev and "passive" not in args:
                self.add("perf.14", f"'{ev.group(1)}' listener without {{ passive: true }}", f, off, severity="info")

    def fonts(self) -> None:
        families = set()
        for f in self.files:
            m = re.search(r"import\s*\{([^}]+)\}\s*from\s*['\"]next/font/google['\"]", f.code)
            if m:
                families |= {x.strip() for x in m.group(1).split(",") if x.strip()}
        if len(families) > 2:
            self.add("perf.10", f"{len(families)} font families loaded ({', '.join(sorted(families))}): budget is 2",
                     severity="info", fix_hint="Limit to two families and use variable fonts")
        for sf in self.ctx.walker.css_files():
            text = sf.read()
            if "fonts.googleapis.com" in text:
                self.add("perf.10", "CSS @import of Google Fonts (render-blocking)", file=sf.rel, fix_hint="Use next/font")

    def project(self) -> None:
        code = "\n".join(f.code for f in self.files)
        if self.is_next and not RUM.search(code):
            self.add("perf.20", "No real-user monitoring of Web Vitals (useReportWebVitals, Speed Insights, Sentry, …)",
                     fix_hint="Report LCP/INP/CLS per route from real users (assets: 03-performance §20)")
        if self.is_next and not self.stack.ci.get("lighthouserc"):
            self.add("perf.19", "No Lighthouse CI config (lighthouserc.*)", fix_hint="Copy assets/lighthouserc.json and run `npx @lhci/cli autorun` in CI")
            self.add("perf.18", "No performance budget committed to the repo", severity="warn", fix_hint="Budgets live in lighthouserc assertions (or budget.json) and fail CI")
        if self.stack.next_config.get("reactCompiler"):
            manual = sum(len(re.findall(r"\buse(Memo|Callback)\s*\(|\bmemo\s*\(", f.code_nostr)) for f in self.files)
            if manual:
                self.add("perf.15", f"React Compiler is on and {manual} manual useMemo/useCallback/memo call(s) exist",
                         severity="info", fix_hint="Fine to keep; for new code rely on the compiler and memoize only for precise control")

    # ------------------------------------------------------------- build budget
    def build_budget(self) -> None:
        nxt = self.root / ".next"
        bm_path = nxt / "build-manifest.json"
        if not bm_path.exists():
            self.report.skipped.append("--build: .next/build-manifest.json not found (run `next build` first)")
            return
        bm = json.loads(bm_path.read_text(encoding="utf-8"))
        root_files = list(bm.get("rootMainFiles") or [])
        cache: dict[str, int] = {}

        def gz(rel: str) -> int:
            if rel not in cache:
                p = nxt / rel.lstrip("/").removeprefix("_next/")
                try:
                    cache[rel] = len(gzip.compress(p.read_bytes(), 6))
                except OSError:
                    cache[rel] = 0
            return cache[rel]

        shared = sum(gz(r) for r in root_files)
        budget_kb = self.ctx.config["budgets"]["initialJsGzipKb"]
        rows = []
        for man in (nxt / "server" / "app").rglob("*_client-reference-manifest.js"):
            text = man.read_text(encoding="utf-8", errors="replace")
            route_m = re.search(r"__RSC_MANIFEST\[\"([^\"]+)\"\]", text)
            entry_m = re.search(r"\"entryJSFiles\"\s*:\s*(\{.*?\})\s*\}\s*;?\s*$", text, re.S)
            if not route_m or not entry_m:
                continue
            try:
                entries = json.loads(entry_m.group(1))
            except json.JSONDecodeError:
                continue
            chunks = set(root_files)
            for files in entries.values():
                chunks |= set(files)
            total = sum(gz(c) for c in chunks)
            route = route_m.group(1)
            if route.endswith("/page"):
                route = route[: -len("/page")] or "/"
            if "/_" in route or route.startswith("/_"):
                continue
            rows.append((route, total))
        if not rows:
            self.report.skipped.append("--build: no per-route client manifests found (unsupported build layout)")
            return
        rows.sort(key=lambda r: -r[1])
        from wclib.nextapp import PRIVATE_SEGMENTS
        over = [(r, t) for r, t in rows if t / 1024 > budget_kb]
        public = [(r, t) for r, t in over if not PRIVATE_SEGMENTS.search(r)]
        private = [(r, t) for r, t in over if PRIVATE_SEGMENTS.search(r)]
        hint = "Analyze with `npx next experimental-analyze`; dynamic-import heavy client parts; push 'use client' down"
        for group, sev, label in ((public, "error", "public"), (private, "warn", "signed-in/admin")):
            if group:
                worst = ", ".join(f"`{r}` {t / 1024:.0f} KB" for r, t in group[:5])
                self.add("perf.18", f"{len(group)} {label} route(s) exceed the {budget_kb} KB gzipped initial-JS budget: {worst}"
                         + (" …" if len(group) > 5 else ""), file=".next", severity=sev, fix_hint=hint)
        md = ["## Initial JS per route (gzip, from .next)", "",
              f"Shared runtime (rootMainFiles): **{shared / 1024:.0f} KB** · budget per route: {budget_kb} KB", "",
              "| Route | Initial JS (gzip) |", "|---|---|"]
        md += [f"| `{r}` | {t / 1024:.0f} KB{' ⚠' if t / 1024 > budget_kb else ''} |" for r, t in rows[:25]]
        self.report.appendix.append("\n".join(md))
        self.report.meta["initial_js_kb_max"] = round(rows[0][1] / 1024, 1)

    def run(self) -> None:
        for f in self.files:
            if f.jsx:
                self.images(f)
            self.imports(f)
        self.fonts()
        self.project()
        ran = set()
        if self.args.build:
            self.build_budget()
            ran.add("build")
        self.finish_not_checked(ran)


if __name__ == "__main__":
    run_main(PerformanceAudit, __file__, __doc__)
