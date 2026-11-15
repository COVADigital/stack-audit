#!/usr/bin/env python3
"""State management audit (rules state.*, 04-state-management.md). Read-only, heuristic.

    python audit_state.py --root APP [--changed] [--format md|json|sarif] [--strict]
"""

from __future__ import annotations

import re
from collections import defaultdict

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.jsscan import JsFile, find_calls, functions

INVALIDATE = re.compile(r"revalidate(Path|Tag)\s*\(|updateTag\s*\(|\brefresh\s*\(|redirect\s*\(|invalidate\w*\s*\(|evict\w*\s*\(|expire\w*\s*\(|setQueryData\s*\(|refetch\w*\s*\(")
DB_WRITE = re.compile(r"\.(insert|update|delete|upsert)\s*\(|\bservice\.\w*(create|update|delete|save|remove|set)\w*\s*\(", re.I)
URL_STATE_NAMES = re.compile(r"^(page|pageIndex|filter|filters|sort|sortBy|order|tab|activeTab|query|search|searchTerm|q|category|view)$")


class StateAudit(Audit):
    tool = "audit_state"
    prefix = "state"

    def state_vars(self, f: JsFile) -> dict[str, str]:
        return {m.group(1): m.group(2) for m in re.finditer(r"const\s*\[\s*(\w+)\s*,\s*(set\w+)\s*\]\s*=\s*(?:React\.)?useState\b", f.code_nostr)}

    def per_file(self, f: JsFile) -> None:
        sv = self.state_vars(f)
        setters = set(sv.values())
        # state.05: server data fetched by hand into useState
        for off, args in find_calls(f, r"\buseEffect", nostr=False):
            # setter called (setX(data)) or passed by reference (.then(setX))
            if re.search(r"(?<![\w.$])fetch\s*\(|axios\.|\.get\(", args) and any(re.search(rf"\b{s}\b", args) for s in setters):
                self.add("state.05", "Server data fetched in useEffect into useState (no caching, dedupe, or revalidation)", f, off,
                         fix_hint="Fetch in a Server Component, or use TanStack Query / SWR")
            body = args.split("=>", 1)[-1]
            calls = re.findall(r"\b(set\w+)\s*\(", body)
            if calls and set(calls) <= setters and len(re.findall(r";|\n\s*\S", body.strip("{} \n"))) <= 2 \
                    and not re.search(r"fetch|then|await|addEventListener|setTimeout|setInterval|subscribe|localStorage|window", body):
                self.add("state.08", f"Effect only copies other state into `{calls[0]}` (derived state stored twice)", f, off,
                         fix_hint="Compute it during render (useMemo only if profiling shows a cost)")
        # state.09: mutating state in place
        for name in sv:
            for m in re.finditer(rf"\b{re.escape(name)}\.(push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)\s*\(", f.code_nostr):
                self.add("state.09", f"`{name}.{m.group(1)}()` mutates React state in place (no re-render / stale UI)", f, m.start(),
                         fix_hint="Copy first: setX([...x, item]) / x.toSorted() / x.toSpliced()")
            for m in re.finditer(rf"\b{re.escape(name)}(\.\w+)+\s*=(?!=)", f.code_nostr):
                self.add("state.09", f"Property assignment on state `{name}`", f, m.start(), fix_hint="setX(prev => ({ ...prev, field }))")
                break
        # state.13: shareable UI state held in useState on list/page components
        url_like = [n for n in sv if URL_STATE_NAMES.match(n)]
        if url_like and re.search(r"(^|/)(app|features|components)/", f.rel) and f.directive == "client":
            self.add("state.13", f"Shareable UI state in useState ({', '.join(url_like)}): users can't bookmark or share it", f, 0,
                     fix_hint="Keep it in the URL (useSearchParams + router, or nuqs)")
        # state.14: boolean status clusters
        flags = [n for n in sv if re.match(r"is(Loading|Error|Success|Submitting|Pending|Fetching|Saving|Done|Failed)$", n)]
        if len(flags) >= 3:
            self.add("state.14", f"{len(flags)} status booleans ({', '.join(flags)}) allow impossible combinations", f, 0,
                     fix_hint="One discriminated union: { status: 'idle' | 'loading' | 'success' | 'error' }")
        # state.17: whole-store subscriptions (Zustand)
        stores = set(re.findall(r"(?:export\s+)?const\s+(use\w+)\s*=\s*create(?:<[^>]*>)?\s*\(", f.code_nostr))
        self.stores |= stores
        # state.11: TanStack mutations without invalidation
        for off, args in find_calls(f, r"\buseMutation", nostr=False):
            if not re.search(r"invalidateQueries|setQueryData|refetch|resetQueries|onSettled", args):
                self.add("state.11", "useMutation without invalidating or updating the affected queries", f, off,
                         fix_hint="onSuccess/onSettled: queryClient.invalidateQueries({ queryKey: [...] })")
        # state.11: Server Actions writing data without cache invalidation
        if f.directive == "server":
            for fn in functions(f):
                body = fn.body(f)
                if fn.exported and DB_WRITE.search(body) and not INVALIDATE.search(body) and not INVALIDATE.search(f.code_nostr[:fn.start]):
                    returns_fresh = re.search(r"return\s+[\w.]*(list|get|find|load|fetch)\w*\s*\(", body, re.I)
                    self.add("state.11", f"Server Action `{fn.name}` writes data but invalidates no cache (stale pages if this data is cached)",
                             f, fn.start, severity="info" if returns_fresh else None,
                             confidence="low" if returns_fresh else "medium",
                             fix_hint="updateTag(tag) for read-your-writes, or revalidatePath / revalidateTag(tag, 'max')")
        # state.12: forms without schema resolver
        for off, args in find_calls(f, r"\buseForm", nostr=False):
            if args.strip() and "resolver" not in args:
                self.add("state.12", "useForm without a schema resolver (client and server validation drift apart)", f, off,
                         severity="info", fix_hint="resolver: zodResolver(SharedSchema), reusing the server-side schema")
        # state.18: persisted stores without a version
        for off, args in find_calls(f, r"\bpersist", nostr=False):
            if re.search(r"\bname\s*:", args) and not re.search(r"\bversion\s*:", args):
                self.add("state.18", "Persisted store without a schema version (old shapes break after deploys)", f, off,
                         severity="info", fix_hint="Add version + migrate")
        for m in re.finditer(r"queryKey\s*:\s*(\[[^\]]*\])", f.code):
            self.query_keys[re.sub(r"\s+", "", m.group(1))].append((f, m.start()))

    def run(self) -> None:
        self.stores: set[str] = set()
        self.query_keys: dict[str, list] = defaultdict(list)
        for f in self.files:
            self.per_file(f)
        for f in self.files:
            for store in self.stores:
                for m in re.finditer(rf"\b{store}\s*\(\s*\)", f.code_nostr):
                    self.add("state.17", f"`{store}()` subscribes to the whole store (re-renders on every change)", f, m.start(),
                             fix_hint=f"Select a slice: {store}(s => s.items.length); use useShallow for several fields")
                for m in re.finditer(rf"\b{store}\s*\(\s*\(?\s*\w+\s*\)?\s*=>\s*\(\s*\{{", f.code_nostr):
                    if "useShallow" not in f.code:
                        self.add("state.17", f"`{store}` selector returns a new object each time (re-renders always)", f, m.start(),
                                 fix_hint="Wrap the selector in useShallow()")
        for key, uses in self.query_keys.items():
            files = {u[0].rel for u in uses}
            if len(files) >= 3 and key.startswith(("['", '["')):
                f, off = uses[0]
                self.add("state.06", f"Query key {key} repeated literally in {len(files)} files", f, off,
                         fix_hint="Create a key factory per feature (productKeys.detail(id))")
        code_all = "\n".join(f.code for f in self.files)
        if re.search(r"\b(logout|signOut|sign_out)\b", code_all) and not re.search(r"BroadcastChannel|addEventListener\(\s*['\"]storage", code_all) \
                and self.stack.categories.get("auth") not in ("better-auth", "next-auth", "@clerk/nextjs"):
            self.add("state.19", "Logout exists but other tabs aren't notified (BroadcastChannel / storage event)", severity="info",
                     confidence="low", fix_hint="Broadcast logout so every tab drops the session UI")
        self.finish_not_checked()


if __name__ == "__main__":
    run_main(StateAudit, __file__, __doc__)
