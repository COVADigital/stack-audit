#!/usr/bin/env python3
"""Rendering audit + route inventory (rules ren.*, 02-rendering.md). Read-only.

    python audit_rendering.py --root APP [--changed] [--format md|json|sarif] [--strict]

The Markdown report ends with a route inventory: every page/route with its inferred
rendering strategy and the signals behind it (cacheComponents-aware).
"""

from __future__ import annotations

import re

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile, find_calls, functions, match_close
from wclib.nextapp import chain_files, nearest, routes, special_files

REQUEST_APIS = re.compile(r"\bawait\s+(cookies|headers|connection|draftMode)\s*\(|\bawait\s+(props\.)?searchParams\b|searchParams\s*[:}]")
BROWSER_ONLY = re.compile(r"\b(window\.|document\.|localStorage\.|sessionStorage\.|navigator\.)|\bnew Date\(\s*\)|\bDate\.now\(\)|\bMath\.random\(\)")
HOOK_OR_EVENT = re.compile(r"\buse[A-Z]\w*\s*\(|\bon[A-Z]\w*\s*=\s*\{|\bcreateContext\s*\(|\bwindow\b|\bdocument\b|\blocalStorage\b|\bnavigator\b|\buseActionState\b|forwardRef|\baddEventListener\b")


class RenderingAudit(Audit):
    tool = "audit_rendering"
    prefix = "ren"

    # ------------------------------------------------------------- inventory
    def inventory(self) -> None:
        app = self.stack.router.get("app")
        files = self.ctx.walker.all_files()
        rts = routes(files, app)
        specials = special_files(files)
        cc = self.stack.cache_components
        rows = []
        any_error = any("error" in v for v in specials.values())
        for r in rts:
            f = self.by_rel.get(r.file) or JsFile(r.file, self.read(r.file))
            code = f.code
            signals = []
            if "generateStaticParams" in code:
                signals.append("generateStaticParams")
            if re.search(r"['\"]use cache(: \w+)?['\"]", code):
                signals.append("'use cache'")
            if REQUEST_APIS.search(code):
                signals.append("request APIs")
            m_dyn = re.search(r"export\s+const\s+(dynamic|revalidate|fetchCache|runtime)\s*=\s*([^;\n]+)", code)
            for m in re.finditer(r"export\s+const\s+(dynamic|revalidate|fetchCache|runtime)\s*=\s*([^;\n]+)", code):
                signals.append(f"{m.group(1)}={m.group(2).strip()}")
            client = f.directive == "client"
            if client:
                signals.append("'use client'")
            if r.kind == "route":
                strategy = "route handler (dynamic by default)" if cc else "route handler"
            elif cc:
                if "request APIs" in signals:
                    strategy = "request-time (dynamic)"
                elif "'use cache'" in signals:
                    strategy = "cached ('use cache')"
                elif "generateStaticParams" in signals:
                    strategy = "prerendered per param"
                else:
                    strategy = "static shell / PPR"
            else:
                if any(s.startswith("dynamic='force-dynamic'") or s.startswith('dynamic="force-dynamic"') for s in signals) or "request APIs" in signals:
                    strategy = "SSR (dynamic)"
                elif any(s.startswith("revalidate=") for s in signals):
                    strategy = "ISR"
                elif "generateStaticParams" in signals:
                    strategy = "SSG (params)"
                else:
                    strategy = "static"
            meta = bool(re.search(r"export\s+(const\s+metadata\b|(async\s+)?function\s+generateMetadata)", code)) or any(
                re.search(r"export\s+(const\s+metadata\b|(async\s+)?function\s+generateMetadata)", self.read(lf))
                for lf in chain_files(r, specials, "layout"))
            loading = nearest(r, specials, "loading")
            error = nearest(r, specials, "error")
            rows.append((r, strategy, signals, meta, loading, error, f))
            self.route_checks(r, f, client, meta, loading, error, any_error)
        if rows:
            md = ["## Route inventory", "", f"Caching model: **{'Cache Components' if cc else 'legacy'}** · {len(rows)} routes", "",
                  "| Route | Kind | Strategy | Signals | Metadata | loading / error |", "|---|---|---|---|---|---|"]
            for r, strategy, signals, meta, loading, error, _ in rows:
                meta_cell = "n/a" if r.kind == "route" else ("yes" if meta else "no")
                md.append(f"| `{r.url}` | {r.kind} | {strategy} | {', '.join(signals) or '-'} | "
                          f"{meta_cell} | {'✓' if loading else '–'} / {'✓' if error else '–'} |")
            md += ["", "_Strategy is inferred from the page file only: request-time reads inside child components "
                       "(e.g. a session check in a layout or component) make the route dynamic too. Confirm with `next build` output._"]
            self.report.appendix.append("\n".join(md))
            self.report.meta["routes"] = len(rows)
        if app:
            root_files = set(files)
            if not any(x in root_files for x in (f"{app}/global-error.tsx", f"{app}/global-error.jsx", f"{app}/global-error.js")):
                self.add("ren.19", "No app/global-error.tsx (root layout failures show the default error page)", severity="info",
                         file=app, fix_hint="Add a Client Component global-error.tsx with its own <html>/<body>")
            public_pages = [r for r, *_ in rows if r.kind == "page" and not r.private]
            has_sitemap = any(x.startswith(f"{app}/sitemap.") for x in root_files) or (self.root / "public" / "sitemap.xml").exists()
            has_robots = any(x.startswith(f"{app}/robots.") for x in root_files) or (self.root / "public" / "robots.txt").exists()
            if public_pages and not has_sitemap:
                self.add("ren.18", "No sitemap (app/sitemap.ts) for public pages", severity="info", file=app)
            if public_pages and not has_robots:
                self.add("ren.18", "No robots (app/robots.ts)", severity="info", file=app)

    def route_checks(self, r, f: JsFile, client: bool, meta: bool, loading, error, any_error: bool) -> None:
        if r.kind == "page" and client:
            self.add("ren.06", f"page `{r.url}` is a Client Component: the whole route ships as client JS", f, 0,
                     fix_hint="Keep the page a Server Component; push 'use client' down to the interactive leaves")
        if r.kind == "page" and not meta and not r.private:
            self.add("ren.18", f"Public page `{r.url}` has no metadata (page or parent layouts)", f, 0,
                     fix_hint="export const metadata, or generateMetadata for dynamic routes")
        if r.kind == "page" and not client:
            body_awaits = re.search(r"export\s+default\s+async\s+function[\s\S]*?\bawait\s+(?!params\b|props\.params\b|searchParams\b|props\.searchParams\b)", f.code)
            # With Cache Components, Next.js fails the build for uncached data outside <Suspense>: skip there.
            if body_awaits and not loading and "<Suspense" not in f.code and not self.stack.cache_components:
                self.add("ren.04", f"`{r.url}` awaits data with no loading.tsx or <Suspense> boundary (blocks the whole page)",
                         f, body_awaits.start(), fix_hint="Add loading.tsx or wrap the slow part in <Suspense fallback>")
            if body_awaits and not error and not any_error:
                self.add("ren.19", f"`{r.url}` fetches data but no error.tsx exists in its segment chain", f, 0,
                         severity="info", fix_hint="Add an error.tsx boundary ('use client') next to data-fetching segments")

    # ------------------------------------------------------------- per file
    def segment_config(self, f: JsFile) -> None:
        cc = self.stack.cache_components
        for m in re.finditer(r"export\s+const\s+(dynamic|revalidate|fetchCache)\s*=", f.code):
            if cc:
                self.add("ren.01", f"`export const {m.group(1)}` is not supported with cacheComponents (build error)", f, m.start(),
                         severity="error", fix_hint="Delete it; use 'use cache' + cacheLife, or connection() for request-time")
        for m in re.finditer(r"export\s+const\s+runtime\s*=\s*['\"]edge['\"]", f.code):
            if cc:
                self.add("ren.09", "runtime = 'edge' is not supported with Cache Components", f, m.start(), severity="error")
        if re.search(r"(^|/)error\.(tsx|jsx|js)$", f.rel) and f.directive != "client":
            self.add("ren.19", "error.tsx must be a Client Component ('use client')", f, 0, severity="error")

    def revalidation(self, f: JsFile) -> None:
        major = self.stack.next_major or 0
        for off, args in find_calls(f, r"\brevalidateTag", nostr=False):
            if major >= 16 and "," not in args:
                self.add("ren.03", "revalidateTag(tag) without a cacheLife profile (deprecated in Next.js 16)", f, off,
                         fix_hint="revalidateTag(tag, 'max') for SWR, or updateTag(tag) in a Server Action for read-your-writes")
        if self.stack.cache_components:
            for m in re.finditer(r"\bunstable_cache\s*\(", f.code_nostr):
                self.add("ren.03", "unstable_cache in a Cache Components app: use 'use cache' + cacheTag + cacheLife", f, m.start(), severity="info")
        if re.search(r"\bupdateTag\s*\(", f.code_nostr):
            in_action = f.directive == "server" or "'use server'" in f.code or '"use server"' in f.code
            if not in_action:
                m = re.search(r"\bupdateTag\s*\(", f.code_nostr)
                self.add("ren.03", "updateTag is only allowed in Server Actions", f, m.start(), severity="error",
                         fix_hint="Use revalidateTag(tag, 'max') in route handlers / webhooks")

    def client_boundaries(self, f: JsFile) -> None:
        if f.directive != "client":
            for off, args in find_calls(f, r"\bdynamic", nostr=False):
                if re.search(r"ssr\s*:\s*false", args):
                    self.add("ren.16", "next/dynamic with ssr:false outside a Client Component (not allowed)", f, off,
                             fix_hint="Move this into a 'use client' file")
            return
        if re.search(r"(^|/)layout\.(tsx|jsx)$", f.rel):
            self.add("ren.06", "layout is a Client Component: every child route hydrates through it", f, 0,
                     fix_hint="Keep layouts as Server Components; extract interactive parts")
        wraps_client_lib = re.search(r"from\s+['\"](radix-ui|@radix-ui/[\w-]+|@base-ui[\w/-]*|vaul|cmdk|sonner|react-day-picker|"
                                     r"embla-carousel-react|input-otp|react-resizable-panels|recharts|@headlessui/react|motion/react|framer-motion)['\"]", f.code)
        if not HOOK_OR_EVENT.search(f.code_nostr) and re.search(r"<[A-Za-z]", f.code) and not wraps_client_lib \
                and not re.search(r"(^|/)components/ui/", f.rel):
            self.add("ren.08", "'use client' file uses no hooks, events, or browser APIs: it may not need to be a Client Component",
                     f, 0, fix_hint="Remove 'use client' if nothing interactive is inside (smaller bundle)")
        self.hydration(f)

    def hydration(self, f: JsFile) -> None:
        """Browser-only/non-deterministic values read during render of a client component."""
        hay = f.code_nostr
        for fn in functions(f):
            if not (fn.name[:1].isupper() or fn.name == "default"):
                continue
            body_start, body_end = fn.body_start, fn.body_end
            nested = self.nested_function_ranges(hay, body_start, body_end)
            for m in BROWSER_ONLY.finditer(hay, body_start, body_end):
                pos = m.start()
                if any(a < pos < b for a, b in nested):
                    continue  # inside a callback / handler / effect: not render-time
                window = hay[max(0, pos - 200):pos]
                if "typeof window" in window or "typeof document" in window:
                    continue
                if re.search(r"\b(useEffect|useLayoutEffect)\s*\(\s*\(\s*\)\s*=>\s*$", window):
                    continue
                self.add("ren.05", f"`{m.group(0).strip('(').strip('.')}` read during render of client component `{fn.name}` (hydration mismatch / server crash)",
                         f, pos, confidence="medium",
                         fix_hint="Read it in useEffect (or behind a mounted flag); for dates pass a server value as a prop")
                break  # one per component

    @staticmethod
    def nested_function_ranges(hay: str, start: int, end: int) -> list[tuple[int, int]]:
        """Ranges of nested functions inside a component body (arrow block/expression bodies,
        function declarations). Arrows passed straight to useState/useMemo/useRef run during
        render, so they are not excluded."""
        ranges = []
        for m in re.finditer(r"=>", hay[start:end]):
            arrow = start + m.start()
            head = hay[max(start, arrow - 120):arrow]
            if re.search(r"\b(useState|useMemo|useRef|useReducer)\s*\(\s*(\([^()]*\)|\w+)?\s*$", head):
                continue
            j = arrow + 2
            while j < end and hay[j] in " \t\r\n":
                j += 1
            if j < end and hay[j] == "{":
                close = match_close(hay, j)
                if close != -1:
                    ranges.append((arrow, close))
                continue
            depth, k = 0, j  # expression body: until , ; or an unmatched closer
            while k < end:
                c = hay[k]
                if c in "([{":
                    depth += 1
                elif c in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif c in ",;" and depth == 0:
                    break
                k += 1
            ranges.append((arrow, k))
        for m in re.finditer(r"\bfunction\b[^{;]*\{", hay[start:end]):
            brace = start + m.end() - 1
            close = match_close(hay, brace)
            if close != -1:
                ranges.append((brace, close))
        return ranges

    def keys(self, f: JsFile) -> None:
        for m in re.finditer(r"\.map\(\s*\(\s*[\w{}\s,]+?,\s*(\w+)\s*\)\s*=>", f.code_nostr):
            idx = m.group(1)
            window = f.code[m.end(): m.end() + 900]
            km = re.search(r"\bkey\s*=\s*\{\s*(" + re.escape(idx) + r"|`[^`]*\$\{\s*" + re.escape(idx) + r"\s*\}[^`]*`|String\(\s*" + re.escape(idx) + r"\s*\))\s*\}", window)
            if km:
                # Interactive/stateful rows are where index keys break; static text lists are low risk.
                stateful = re.search(r"<(input|select|textarea)|\buse[A-Z]\w*\(|onChange|draggable|sortable|dnd|useSortable|contentEditable",
                                     window[km.start(): km.start() + 160])
                self.add("ren.13", f"Array index `{idx}` used as a React key (state/DOM mix-ups when items reorder)", f, m.end() + km.start(),
                         severity="warn" if stateful else "info",
                         fix_hint="Use a stable id from the data; index keys are only safe for static, never-reordered lists")

    def css_motion(self) -> None:
        for sf in self.ctx.walker.css_files():
            text = sf.read()
            for m in re.finditer(r"transition(?:-property)?\s*:\s*[^;{}]*\b(top|left|right|bottom|width|height|margin[\w-]*|padding[\w-]*)\b", text):
                self.add("ren.11", f"Transition on layout property `{m.group(1)}` (reflow every frame)", file=sf.rel,
                         line=text.count("\n", 0, m.start()) + 1, fix_hint="Animate transform/opacity instead")
                break
        for f in self.files:
            for m in re.finditer(r"transition-\[(width|height|top|left|margin|padding)[^\]]*\]", f.code):
                self.add("ren.11", f"Tailwind transition on layout property `{m.group(1)}`", f, m.start(), fix_hint="Prefer transform/opacity")
                break
            for m in re.finditer(r"\b(forEach|for)\b[\s\S]{0,40}\{([\s\S]{0,400}?)\}", f.code_nostr):
                body = m.group(2)
                if re.search(r"offset(Width|Height|Top|Left)|getBoundingClientRect|client(Width|Height)", body) and ".style." in body:
                    self.add("ren.14", "Loop reads layout and writes styles (layout thrashing)", f, m.start(),
                             fix_hint="Batch reads first, then write inside requestAnimationFrame")
                    break

    def run(self) -> None:
        if not self.is_next:
            self.report.skipped.append("Not a Next.js project: route/caching checks skipped")
        for f in self.files:
            self.segment_config(f)
            self.revalidation(f)
            self.keys(f)
            if f.jsx:
                self.client_boundaries(f)
        if self.is_next:
            if self.stack.request_interceptor and "middleware." in self.stack.request_interceptor and (self.stack.next_major or 0) >= 16:
                self.add("ren.09", f"{self.stack.request_interceptor} on Next.js 16: rename to proxy.ts (middleware is deprecated)",
                         severity="info", file=self.stack.request_interceptor, fix_hint="npx @next/codemod@latest upgrade 16")
            self.inventory()
        self.css_motion()
        self.finish_not_checked()


if __name__ == "__main__":
    run_main(RenderingAudit, __file__, __doc__)
