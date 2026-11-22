#!/usr/bin/env python3
"""Networking audit (rules net.*, 05-networking.md). Read-only.

    python audit_networking.py --root APP [--changed] [--format md|json|sarif] [--strict]
"""

from __future__ import annotations

import re

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile, find_calls, functions

PARSE = re.compile(r"\.(parse|safeParse|parseAsync|safeParseAsync)\s*\(|\bvalidate\w*\s*\(|\bparse[A-Z]\w*\s*\(|\bv\.parse\(|\bassert\w*\s*\(")
RATE_LIMIT = re.compile(r"ratelimit|rateLimit|rate_limit|limiter|throttle", re.I)
SENSITIVE_PATH = re.compile(r"(^|/)(auth|login|signin|sign-in|signup|sign-up|register|reset|forgot|password|contact|newsletter|subscribe|ai|chat|completion|upload|invite|otp|verify)(/|\.|-|$)", re.I)


class NetworkingAudit(Audit):
    tool = "audit_networking"
    prefix = "net"

    def fetch_hygiene(self, f: JsFile) -> None:
        calls = find_calls(f, r"(?<![\w.$])fetch", nostr=False)
        no_signal = [off for off, args in calls
                     if "signal" not in args and "keepalive" not in args and not re.match(r"\s*\)?$", args)]
        if no_signal:
            self.add("net.18", f"{len(no_signal)} fetch() call(s) without a timeout/abort signal", f, no_signal[0],
                     fix_hint="{ signal: AbortSignal.timeout(10_000) } (combine with a user signal via AbortSignal.any)")
        for m in re.finditer(r"(?:const|let)\s+(\w+)\s*=\s*await\s+fetch\s*\(", f.code_nostr):
            var = m.group(1)
            after = f.code[m.end(): m.end() + 1200]
            use = re.search(rf"\b{var}\.(json|text|blob|arrayBuffer)\s*\(", after)
            if use and not re.search(rf"\b{var}\.(ok|status)\b|!\s*{var}\.ok|ensureOk|assertOk|throwIfNot", after[: use.start()]):
                self.add("net.17", f"`{var}.{use.group(1)}()` used without checking `{var}.ok` (fetch doesn't throw on 4xx/5xx)",
                         f, m.start(), fix_hint="if (!res.ok) throw new HttpError(res.status, …); then validate the body with a schema")
        for m in re.finditer(r"fetch\s*\([^;]*?\)\s*\.then\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\1\.json\(\)", f.code_nostr):
            self.add("net.17", "fetch().then(r => r.json()) without checking r.ok", f, m.start())
        if f.directive != "client":
            for m in re.finditer(r"catch\s*\(\s*(\w+)[^)]*\)\s*\{", f.code):
                var, block = m.group(1), f.code[m.end(): m.end() + 600].split("catch", 1)[0]
                leak = re.search(rf"(?:Response|NextResponse)\.json\s*\([^;]*\b{var}\b(?:\.(?:message|detail|hint|stack|cause))?"
                                 rf"|return\s*\{{[^;}}]*\b{var}\.(?:message|detail|hint|stack)", block)
                if leak and not re.search(r"console\.|logger\.|log\(|captureException", block[: leak.start()] + "x") or \
                        leak and re.search(rf"\b{var}\b(?:\.(?:message|detail|hint|stack|cause))?\s*[,}})]", leak.group(0)):
                    self.add("net.17", f"Raw error `{var}` returned to the client: database errors reveal tables, columns and SQL "
                                       "(error-based injection)", f, m.end() + leak.start(), severity="warn", confidence="medium",
                             fix_hint="Log the error server-side; return a generic message and an error id")

    def effects(self, f: JsFile) -> None:
        for off, args in find_calls(f, r"\buseEffect", nostr=False):
            # Only a problem when the result feeds state (races / setState after unmount); fire-and-forget beacons are fine.
            if re.search(r"(?<![\w.$])fetch\s*\(", args) and re.search(r"\bset[A-Z]\w*\b|\bdispatch\s*\(", args) \
                    and not re.search(r"AbortController|signal|ignore\s*=|cancelled|canceled|active\s*=", args):
                self.add("net.11", "useEffect fetches without cancellation (races and setState after unmount)", f, off,
                         fix_hint="AbortController in the effect + abort() in the cleanup, or move data fetching to RSC / TanStack Query")

    def loops(self, f: JsFile) -> None:
        for m in re.finditer(r"\bfor\s*\((?:const|let)\s+[^)]*\b(of|in)\b[^)]*\)\s*\{", f.code_nostr):
            body_end = f.code_nostr.find("}", m.end())
            body = f.code[m.end(): m.end() + 600]
            if re.search(r"\bawait\s+(db|tx|prisma|sql|client)\b[\w.]*\s*[.(`]|\bawait\s+\w*(Repo|repository|service)\.\w+\(", body):
                self.add("net.12", "Awaited database call inside a loop (N+1 queries)", f, m.start(), confidence="medium",
                         fix_hint="Fetch in one query (inArray / join) or batch with a DataLoader")
        for m in re.finditer(r"\.forEach\s*\(\s*async\b", f.code_nostr):
            self.add("net.12", "forEach(async …) does not await its callbacks (unhandled, unordered requests)", f, m.start(),
                     fix_hint="Use for…of with await, or await Promise.all(items.map(async …))")

    def handlers(self, f: JsFile) -> None:
        is_route = re.search(r"(^|/)route\.[cm]?[jt]sx?$", f.rel) is not None
        is_actions = f.directive == "server"
        if not (is_route or is_actions):
            return
        for fn in functions(f):
            body = fn.body(f)
            method = fn.name.upper() if is_route and fn.name.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} else None
            if is_route and method in {"POST", "PUT", "PATCH", "DELETE"}:
                if re.search(r"\.(json|formData)\s*\(\s*\)", body) and not PARSE.search(body):
                    self.add("net.19", f"{method} handler reads the request body without schema validation", f, fn.start,
                             fix_hint="Parse with the shared Zod contract: Schema.parse(await req.json())")
            if is_route and method == "GET" and re.search(r"(Response|NextResponse)\.json\(|new\s+Response\(", body) \
                    and not re.search(r"Cache-Control", body + f.code[:fn.start]) and "revalidate" not in f.code:
                self.add("net.02", "GET handler response has no explicit Cache-Control", f, fn.start, severity="info",
                         fix_hint="Set Cache-Control intentionally (private, no-store for user data; s-maxage + SWR for public)")
            params = f.code[fn.start: fn.body_start]
            typed_params = re.findall(r"(\w+)\s*:\s*([\w<>\[\]|. ]+?)\s*[,)=]", params)
            # `input: unknown` / FormData signal "validated downstream" (the service parses it)
            all_unknown = typed_params and all(t.strip() in ("unknown", "FormData") for _, t in typed_params)
            if is_actions and fn.exported and typed_params and not all_unknown and not PARSE.search(body) \
                    and not re.search(r"\brun\w*\s*\(|\bwith\w*\s*\(|\baction\w*\s*\(", body):
                self.add("net.19", f"Server Action `{fn.name}` uses its arguments without schema validation (arguments come from the client)",
                         f, fn.start, confidence="low", fix_hint="Validate every argument (Zod) before use; treat ids as untrusted selectors")
        if is_route or is_actions:
            sensitive = SENSITIVE_PATH.search(f.rel)
            better_auth_route = re.search(r"api/auth/\[\.\.\.\w+\]", f.rel) and self.stack.categories.get("auth") == "better-auth"
            if sensitive and not better_auth_route and not RATE_LIMIT.search(f.code) and not RATE_LIMIT.search(self.proxy_text):
                self.add("net.15", f"Sensitive endpoint without rate limiting ({sensitive.group(2)})", f, 0,
                         fix_hint="Rate-limit by IP/user (e.g. @upstash/ratelimit, Better Auth rateLimit) and return 429 + Retry-After")

    def streams(self, f: JsFile) -> None:
        for off, args in find_calls(f, r"new\s+ReadableStream", nostr=False):
            start = re.search(r"start\s*\([^)]*\)\s*\{", args)
            if start and re.search(r"return\s*\(\s*\)\s*=>|return\s+function", args) and "cancel" not in args:
                self.add("net.08", "ReadableStream start() returns a cleanup function: it is ignored (put cleanup in cancel())", f, off,
                         fix_hint="cancel() { clearInterval(id) }")

    def retries(self, f: JsFile) -> None:
        for m in re.finditer(r"\b(retries|maxRetries|attempt)\b", f.code_nostr):
            window = f.code[max(0, m.start() - 300): m.start() + 900]
            if re.search(r"method\s*:\s*['\"]POST['\"]", window) and re.search(r"(?<![\w.$])fetch\s*\(", window) \
                    and not re.search(r"idempotency|Idempotency-Key", window, re.I):
                self.add("net.09", "Retry logic around a POST without an idempotency key (replays can double-submit)", f, m.start(),
                         confidence="low", fix_hint="Send an Idempotency-Key header, or retry only idempotent methods")
                break

    def run(self) -> None:
        ic = self.stack.request_interceptor
        self.proxy_text = self.read(ic) if ic else ""
        for f in self.app_files:
            self.fetch_hygiene(f)
            self.effects(f)
            self.loops(f)
            self.handlers(f)
            self.streams(f)
            self.retries(f)
        self.report.not_checked.append("`net.14` CORS is checked by audit_security (sec.04)")
        self.finish_not_checked()


if __name__ == "__main__":
    run_main(NetworkingAudit, __file__, __doc__)
