#!/usr/bin/env python3
"""Caching audit, static part (rules cache.*, 06-caching.md). Read-only.
Live header checks are in probe_headers.py (needs --url).

    python audit_caching.py --root APP [--changed] [--format md|json|sarif] [--strict]
"""

from __future__ import annotations

import json
import re

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile, functions

REQUEST_API_IN_CACHE = re.compile(r"\b(cookies|headers|draftMode)\s*\(|\bauth\s*\(\s*\)|getSession\s*\(|auth\.api\.getSession|getServerSession\s*\(")
SW_NAMES = re.compile(r"(^|/)(sw|service-worker|serviceworker|worker)\.(js|ts|mjs)$")


class CachingAudit(Audit):
    tool = "audit_caching"
    prefix = "cache"

    def cached_functions(self, f: JsFile) -> None:
        file_cached = bool(re.match(r"""\s*['"]use cache['"]""", f.code.lstrip()))
        for fn in functions(f):
            head = f.code[fn.body_start: fn.body_start + 60]
            m = re.match(r"""\s*['"]use cache(?::\s*(\w+))?['"]""", head)
            if not (m or file_cached):
                continue
            kind = m.group(1) if m else None
            if kind == "private":
                continue
            body = fn.body(f)
            api = REQUEST_API_IN_CACHE.search(body)
            if api:
                self.add("cache.15", f"`{fn.name}` reads request data ({api.group(0).strip('(')}) inside 'use cache'", f, fn.start,
                         fix_hint="Read cookies()/headers()/session outside and pass values as arguments, or use 'use cache: private'")
            if not re.search(r"\bcacheTag\s*\(", body) and not re.search(r"\bcacheLife\s*\(", body):
                self.add("cache.15", f"`{fn.name}` uses 'use cache' with no cacheTag or cacheLife (can't be invalidated deliberately)",
                         f, fn.start, severity="info", fix_hint="cacheLife('<profile>') + cacheTag('<entity>-<id>')")

    def query_keys(self, f: JsFile) -> None:
        for m in re.finditer(r"queryKey\s*:\s*\[\s*['\"](me|user|account|profile|session|cart|orders?|settings|notifications)['\"]\s*\]", f.code):
            self.add("cache.15", f"Query key ['{m.group(1)}'] has no user id: data can leak between accounts on the same device",
                     f, m.start(), severity="warn", confidence="low", fix_hint="Include the user id: ['me', userId]")

    def service_worker(self) -> None:
        for sf in self.ctx.walker.all_files():
            if not SW_NAMES.search(sf) or "node_modules" in sf:
                continue
            text = self.read(sf)
            if "addEventListener" not in text and "self." not in text:
                continue
            if re.search(r"addEventListener\(\s*['\"]fetch['\"]", text) and not re.search(r"workbox|serwist", text, re.I):
                self.add("cache.02", "Hand-written service worker fetch handler (use Serwist/Workbox; keep a kill switch)", file=sf,
                         severity="info")
            for m in re.finditer(r"caches\.open\(\s*['\"]([^'\"]+)['\"]", text):
                if not re.search(r"\d", m.group(1)):
                    self.add("cache.03", f"Cache name '{m.group(1)}' has no version", file=sf, severity="info",
                             fix_hint="Version cache names (app-v3) and delete old ones in activate")
            if "caches.open" in text and "caches.delete" not in text and "serwist" not in text.lower():
                self.add("cache.13", "Service worker never deletes old caches", file=sf, severity="info")

    def manifest(self) -> None:
        app = self.stack.router.get("app") or ""
        cands = [f"{app}/manifest.ts", f"{app}/manifest.json", "public/manifest.webmanifest", "public/manifest.json", "public/site.webmanifest"]
        rel = next((c for c in cands if (self.root / c).exists()), None)
        if not rel:
            return
        text = self.read(rel)
        if "512" not in text:
            self.add("cache.10", "Web app manifest has no 512px icon", file=rel, severity="info")
        if "maskable" not in text:
            self.add("cache.10", "Web app manifest has no maskable icon", file=rel, severity="info")

    def chunk_errors(self) -> None:
        app = self.stack.router.get("app")
        if not app:
            return
        errs = [f for f in self.files if re.search(r"(^|/)(global-)?error\.(tsx|jsx|js)$", f.rel)]
        if errs and not any(re.search(r"ChunkLoadError|Loading chunk|location\.reload|router\.refresh", f.code) for f in errs):
            self.add("cache.16", "Error boundaries don't handle ChunkLoadError (users on an old deploy get stuck)", file=errs[0].rel,
                     severity="info", fix_hint="Detect ChunkLoadError in error.tsx/global-error.tsx and offer a reload")

    def storage(self, f: JsFile) -> None:
        if re.search(r"indexedDB\.open|openDB\(|caches\.open\(|\.put\(", f.code_nostr) and re.search(r"indexedDB|openDB|caches\.", f.code_nostr) \
                and "QuotaExceededError" not in f.code:
            m = re.search(r"indexedDB\.open|openDB\(|caches\.open\(", f.code_nostr)
            if m:
                self.add("cache.17", "Browser storage writes without QuotaExceededError handling", f, m.start(), confidence="low")

    def run(self) -> None:
        for f in self.files:
            self.cached_functions(f)
            self.query_keys(f)
            self.storage(f)
        self.service_worker()
        self.manifest()
        self.chunk_errors()
        self.report.not_checked.append("`cache.01` `cache.07` `cache.08` `cache.09` live headers: run probe_headers.py --url <deployed-url>")
        self.report.not_checked.append("`cache.05` localStorage tokens are checked by audit_security (sec.07)")
        self.finish_not_checked()


if __name__ == "__main__":
    run_main(CachingAudit, __file__, __doc__)
