"""Project stack -> applicable OWASP sheets, ASVS 5.0 sections and Top 10 2021 categories.

Also holds the rule -> ASVS evidence map that compliance_checklist.py uses. Read-only, offline.
Mappings are section-level (the cheat-sheet repo has no ASVS requirement text).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .stack import detect_stack
from .walker import Walker, git_toplevel

# id -> (label, deps (exact or "prefix/"), code regex, path regex, sheets)
SIGNALS: dict[str, tuple] = {
    "web": ("React / Next.js web app", {"next", "react"}, None, None,
            ["Nextjs_Security", "Cross_Site_Scripting_Prevention", "Content_Security_Policy", "HTTP_Headers",
             "Secrets_Management", "NPM_Security", "JavaScript_and_TypeScript_Security", "Nodejs_Security",
             "Prototype_Pollution_Prevention", "React_Security", "Input_Validation", "Error_Handling", "Logging"]),
    "auth": ("user accounts / sessions", {"better-auth", "next-auth", "@auth/core", "@clerk/nextjs", "lucia", "@supabase/ssr",
                                          "passport", "iron-session", "@kinde-oss/kinde-auth-nextjs"}, None, None,
             ["Authentication", "Session_Management", "Authorization", "Insecure_Direct_Object_Reference_Prevention",
              "Cross-Site_Request_Forgery_Prevention", "Password_Storage", "Multifactor_Authentication",
              "Credential_Stuffing_Prevention", "Forgot_Password", "Passkey_Security"]),
    "oauth_client": ("OAuth / OIDC sign-in", {"arctic", "openid-client"},
                     r"\bsocialProviders\b|\bgenericOAuth\b|\b(Google|GitHub|Discord|Apple)Provider\b", None, ["OAuth2"]),
    "oauth_server": ("OAuth / OIDC provider role", {"oidc-provider", "@openauthjs/openauth"},
                     r"\boidcProvider\s*\(|\boauthProvider\s*\(", None, ["OAuth2"]),
    "jwt": ("self-contained tokens (JWT)", {"jose", "jsonwebtoken"}, r"\bjwtVerify\s*\(|\bjwt\.(verify|sign)\s*\(", None,
            ["JSON_Web_Token"]),
    "db": ("SQL / document database", {"drizzle-orm", "prisma", "@prisma/client", "pg", "postgres", "mysql2", "kysely",
                                       "typeorm", "better-sqlite3", "@neondatabase/serverless", "mongoose", "mongodb"}, None, None,
           ["SQL_Injection_Prevention", "Query_Parameterization", "Database_Security", "Mass_Assignment"]),
    "multi_tenant": ("multi-tenant / organizations", set(), r"\b(tenantId|organizationId|orgId)\b|\borganization\s*\(", None,
                     ["Multi_Tenant_Security"]),
    "uploads": ("file uploads", {"multer", "formidable", "busboy", "uploadthing", "@vercel/blob", "@aws-sdk/client-s3"},
                r"type=[\"']file[\"']|\.get\([\"']file[\"']\)|\binstanceof\s+File\b|createPresignedPost", None, ["File_Upload"]),
    "webhooks": ("incoming webhooks", {"svix"}, r"\bconstructEvent\s*\(|\bisValidSignature\s*\(",
                 r"(^|/)webhooks?(/|$)", ["Webhook_Security"]),
    "cms": ("headless CMS content", {"next-sanity", "@sanity/client", "sanity", "contentful", "@payloadcms/next"}, None, None,
            ["Webhook_Security", "Web_Cache_Security", "Third_Party_Javascript_Management"]),
    "payments": ("payments", {"stripe", "@stripe/stripe-js", "@lemonsqueezy/lemonsqueezy.js", "@paypal/"}, None, None,
                 ["Third_Party_Payment_Gateway_Integration", "Transaction_Authorization"]),
    "redirects": ("redirects to user-supplied targets", set(), r"\b(returnTo|callbackUrl|redirectTo|next)\b[^\n]{0,40}searchParams|searchParams[^\n]{0,60}\bredirect\(",
                  None, ["Unvalidated_Redirects_and_Forwards"]),
    "graphql": ("GraphQL API", {"graphql", "@apollo/server", "@apollo/client", "urql", "graphql-yoga"}, None, None, ["GraphQL"]),
    "websocket": ("WebSockets / realtime", {"ws", "socket.io", "socket.io-client", "partysocket", "pusher", "ably"},
                  r"\bnew\s+WebSocket\s*\(", None, ["WebSocket_Security"]),
    "webrtc": ("WebRTC", {"simple-peer", "livekit-client", "livekit-server-sdk", "mediasoup", "peerjs"}, r"\bRTCPeerConnection\b",
               None, []),
    "ai": ("LLM / AI features", {"ai", "@ai-sdk/", "openai", "@anthropic-ai/sdk", "langchain", "@langchain/", "@google/genai", "ollama"},
           None, None, ["LLM_Prompt_Injection_Prevention", "AI_Agent_Security", "Secure_Coding_with_AI"]),
    "rag": ("vector search / RAG", {"@pinecone-database/", "chromadb", "@qdrant/", "pgvector", "weaviate-client"}, None, None,
            ["RAG_Security"]),
    "mcp": ("MCP server or client", {"@modelcontextprotocol/sdk", "mcp-handler", "@vercel/mcp-adapter"}, None, r"(^|/)\.mcp\.json$",
            ["MCP_Security"]),
    "docker": ("Docker / Compose", set(), None, None,
               ["Docker_Security", "NodeJS_Docker", "Network_Segmentation", "Infrastructure_as_Code_Security"]),
    "ci": ("CI/CD pipeline", set(), None, r"(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.yml$",
           ["GitHub_Actions_Security", "CI_CD_Security", "Software_Supply_Chain_Security",
            "Vulnerable_Dependency_Management", "Dependency_Graph_SBOM"]),
}

# ASVS sections that only apply with a signal; every other section of the catalog applies to any web app.
GATED: dict[str, tuple[str, ...]] = {
    "V3": ("web",), "V4.3": ("graphql",), "V4.4": ("websocket",), "V5": ("uploads",),
    "V6": ("auth",), "V7": ("auth",), "V8": ("auth", "multi_tenant"), "V9": ("jwt", "oauth_server"),
    "V10.1": ("oauth_client", "oauth_server"), "V10.2": ("oauth_client",), "V10.5": ("oauth_client",),
    "V10.3": ("oauth_server",), "V10.4": ("oauth_server",), "V10.6": ("oauth_server",), "V10.7": ("oauth_server",),
    "V17": ("webrtc",),
}
NOT_APPLICABLE = {"V1.4": "memory-unsafe / unmanaged code: not applicable to a JavaScript/TypeScript app"}

# rule -> ASVS 5.0 sections it gives automated evidence for. Container rules follow OWASP's own
# IndexASVS mapping (Docker_Security -> V13.2). Rules with no defensible ASVS section are left out.
EVIDENCE: dict[str, tuple[str, ...]] = {
    "sec.01": ("V1.2", "V1.3", "V3.2"), "sec.02": ("V3.5",), "sec.03": ("V3.4",), "sec.04": ("V3.4",), "sec.05": ("V3.4",),
    "sec.06": ("V3.3",), "sec.07": ("V14.3", "V7.2"), "sec.08": ("V10.2",), "sec.09": ("V9.1",), "sec.10": ("V1.2", "V1.3", "V2.2"),
    "sec.11": ("V15.2",), "sec.12": ("V3.6",), "sec.13": ("V12.2", "V3.4"), "sec.14": ("V3.2",), "sec.15": ("V3.4",),
    "sec.16": ("V13.3", "V14.2"), "sec.17": ("V8.2", "V8.3", "V6.3"), "sec.18": ("V7.3",), "sec.19": ("V3.4",),
    "sec.20": ("V3.6",), "sec.21": ("V1.3",), "sec.22": ("V3.7",), "sec.23": ("V11.5",),
    "net.02": ("V14.2",), "net.14": ("V3.4",), "net.15": ("V2.4",), "net.17": ("V16.5",), "net.19": ("V2.2", "V4.1"),
    "net.21": ("V8.3", "V2.2"), "state.12": ("V2.2",), "state.18": ("V14.3",), "cache.05": ("V14.3",),
    "cache.08": ("V14.2",), "cache.15": ("V14.2", "V8.2"), "arch.21": ("V14.2",),
    "git.04": ("V13.3",), "git.05": ("V13.3",), "git.08": ("V15.2",), "git.09": ("V15.2",), "git.11": ("V13.3",),
    "img.01": ("V15.2",), "img.02": ("V13.2",), "img.04": ("V15.2",), "sup.01": ("V15.2",), "sup.05": ("V15.2",),
    "run.01": ("V13.2",), "run.03": ("V13.2",), "run.04": ("V13.2",), "run.05": ("V13.2",), "run.08": ("V13.2",),
    "run.09": ("V13.2",), "cnet.01": ("V13.2",), "cnet.02": ("V13.2",), "cnet.03": ("V13.2",),
    "csec.01": ("V13.3",), "csec.02": ("V13.3",), "csec.03": ("V13.3",), "csec.04": ("V13.3",), "csec.05": ("V13.3",),
    "csec.06": ("V13.3",), "csec.07": ("V13.2",), "host.02": ("V13.2",), "host.06": ("V13.2",), "cool.01": ("V13.2",), "cool.02": ("V13.2",),
    "cool.04": ("V13.3",), "cool.05": ("V13.2",),
    "dbs.06": ("V11.4",), "dbo.03": ("V12.3",), "dbo.04": ("V13.2",),
}


def rules_for_section(section: str) -> list[str]:
    return sorted(r for r, secs in EVIDENCE.items() if section in secs)


# (rule, message pattern or None, ASVS 5.0 requirements) where a matching finding shows that exact requirement is
# not satisfied. Hand-checked against the requirement text; leave a rule out when it only relates to a section.
# Left out on purpose: sec.07 (V14.3.3 allows session tokens in browser storage), run.* (no single requirement).
REQUIREMENT_EVIDENCE: list[tuple[str, str | None, tuple[str, ...]]] = [
    ("sec.01", r"dangerouslySetInnerHTML with a non-sanitized", ("V1.3.1",)),
    ("sec.01", r"DOM HTML sink", ("V3.2.2",)),
    ("sec.01", r"eval / new Function", ("V1.3.2",)),
    ("sec.01", r"javascript: URLs", ("V1.2.2",)),
    ("sec.01", r"JSON-LD", ("V1.2.3",)),
    ("sec.02", None, ("V3.5.3",)),
    ("sec.03", r"No Content-Security-Policy|No enforced Content-Security-Policy|unsafe-inline|unsafe-eval", ("V3.4.3",)),
    ("sec.04", None, ("V3.4.2",)),
    ("sec.05", None, ("V3.4.6",)),
    ("sec.06", r"\bSecure\b", ("V3.3.1",)),
    ("sec.06", r"SameSite", ("V3.3.2",)),
    ("sec.06", r"HttpOnly", ("V3.3.4",)),
    ("sec.09", r"decodes without verifying", ("V9.1.1",)),
    ("sec.09", r"algorithms", ("V9.1.2",)),
    ("sec.10", r"SQL|sql\.raw", ("V1.2.4",)),
    ("sec.10", r"Shell command", ("V1.2.5",)),
    ("sec.11", r"vulnerabilities in dependencies", ("V15.2.1",)),
    ("sec.12", None, ("V3.6.1",)),
    ("sec.13", r"HSTS|Strict-Transport-Security", ("V3.4.1",)),
    ("sec.16", r"Hard-coded|found in the client bundle|NEXT_PUBLIC_ ships", ("V13.3.1",)),
    ("sec.17", None, ("V8.2.1",)),
    ("sec.19", r"HSTS|Strict-Transport-Security", ("V3.4.1",)),
    ("sec.19", r"nosniff", ("V3.4.4",)),
    ("sec.19", r"Referrer-Policy", ("V3.4.5",)),
    ("sec.21", None, ("V1.3.6",)),
    ("sec.22", None, ("V3.7.2",)),
    ("sec.23", None, ("V11.5.1",)),
    ("net.15", None, ("V2.4.1",)),
    ("net.19", None, ("V2.2.1",)),
    ("cache.08", r"sets a cookie", ("V14.2.2",)),
    ("csec.01", None, ("V13.3.1",)),
    ("csec.04", None, ("V13.3.1",)),
    ("csec.05", None, ("V13.3.1",)),
    ("csec.07", None, ("V13.2.1",)),
    ("sup.01", None, ("V15.2.1",)),
    ("dbs.06", None, ("V11.4.2",)),
    ("dbo.03", r"disables SSL", ("V12.3.1",)),
    ("dbo.03", r"certificate verification", ("V12.3.2",)),
    ("dbo.04", None, ("V13.2.2",)),
]


def requirements_for_finding(rule: str, message: str) -> set[str]:
    return {r for ru, pat, reqs in REQUIREMENT_EVIDENCE if ru == rule and (pat is None or re.search(pat, message))
            for r in reqs}


def rules_for_requirement(req: str) -> list[str]:
    return sorted({ru for ru, _, reqs in REQUIREMENT_EVIDENCE if req in reqs})


@dataclass
class ControlMap:
    root: str
    signals: dict[str, str] = field(default_factory=dict)  # id -> reason
    sheets: list[dict] = field(default_factory=list)  # {id, reasons, status, url}
    asvs: list[dict] = field(default_factory=list)  # {code, chapter, title, applies, reason, sheets}
    top10: list[dict] = field(default_factory=list)  # {code, title, sheets}
    container_root: str | None = None
    catalog_commit: str | None = None


def _deps(root: Path) -> set[str]:
    names: set[str] = set()
    for pj in [root / "package.json", *root.glob("*/package.json"), *root.glob("packages/*/package.json"),
               *root.glob("apps/*/package.json")]:
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for key in ("dependencies", "devDependencies"):
            names.update((data.get(key) or {}).keys())
    return names


def _dep_hit(deps: set[str], wanted: set[str]) -> str | None:
    for w in sorted(wanted):
        if w.endswith("/"):
            hit = next((d for d in sorted(deps) if d.startswith(w)), None)
            if hit:
                return hit
        elif w in deps:
            return w
    return None


def detect_signals(root: str | Path) -> tuple[dict[str, str], str | None]:
    """Returns ({signal: reason}, container_root)."""
    root = Path(root).resolve()
    stack = detect_stack(root)
    deps = _deps(root)
    walker = Walker(root)
    paths = walker.all_files()
    top = git_toplevel(root)
    if top and Path(top).resolve() != root:
        paths = paths + [p for p in Walker(top).all_files() if re.search(r"(^|/)\.github/|(^|/)\.mcp\.json$|\.gitlab-ci", p)]
    code_files = [f for f in walker.js_files() if not re.search(r"(^|/)(tests?|e2e|__tests__|fixtures)/|\.(test|spec)\.", f.rel)]
    texts: dict[str, str] = {}

    def code_hit(rx: str) -> str | None:
        pat = re.compile(rx)
        for f in code_files:
            if f.rel not in texts:
                try:
                    texts[f.rel] = f.read()[:400_000]
                except OSError:
                    texts[f.rel] = ""
            m = pat.search(texts[f.rel])
            if m:
                return f"`{m.group(0)[:40].strip()}` in {f.rel}"
        return None

    found: dict[str, str] = {}
    for sid, (_label, wanted, code_rx, path_rx, _sheets) in SIGNALS.items():
        reason = None
        dep = _dep_hit(deps, wanted)
        if dep:
            reason = f"dependency `{dep}`"
        if not reason and path_rx:
            p = next((p for p in paths if re.search(path_rx, p)), None)
            reason = f"path `{p}`" if p else None
        if not reason and code_rx:
            reason = code_hit(code_rx)
        if reason:
            found[sid] = reason
    if stack.docker.get("dockerfiles") or stack.docker.get("compose"):
        found["docker"] = "files: " + ", ".join((stack.docker.get("dockerfiles") or []) + (stack.docker.get("compose") or []))
    if stack.ci.get("github_actions") and "ci" not in found:
        found["ci"] = "GitHub Actions workflows"
    # Compose files usually sit at the repo root even when the app is in a subfolder.
    container_root = str(Path(top).resolve() if top else root) if "docker" in found else None
    return found, container_root


def map_controls(root: str | Path, catalog: dict) -> ControlMap:
    signals, container_root = detect_signals(root)
    cm = ControlMap(root=str(Path(root).resolve()), signals=signals, container_root=container_root,
                    catalog_commit=(catalog.get("source") or {}).get("commit"))
    sheets_cat = catalog["sheets"]
    reasons: dict[str, list[str]] = {}
    for sid in signals:
        for sheet in SIGNALS[sid][4]:
            reasons.setdefault(sheet, []).append(SIGNALS[sid][0])
    for sheet, why in reasons.items():
        s = sheets_cat.get(sheet)
        cm.sheets.append({"id": sheet, "reasons": why, "status": s["status"] if s else "missing",
                          "url": s.get("url") if s else None, "title": s["title"] if s else sheet})
    cm.sheets.sort(key=lambda s: -len(s["reasons"]))  # stable: keeps SIGNALS order within a tie
    applicable = set(reasons)

    for chapter, ch in catalog["mappings"]["asvs5"].items():
        for code, sec in ch["sections"].items():
            gate = GATED.get(code) or GATED.get(chapter)
            if code in NOT_APPLICABLE:
                applies, reason = False, NOT_APPLICABLE[code]
            elif gate:
                hit = [g for g in gate if g in signals]
                applies = bool(hit)
                reason = (f"{SIGNALS[hit[0]][0]} ({signals[hit[0]]})" if hit
                          else "no " + " / ".join(SIGNALS[g][0] for g in gate) + " detected")
            else:
                applies, reason = True, "applies to any web application"
            ordered = sorted(sec["sheets"], key=lambda s: s not in applicable)
            cm.asvs.append({"code": code, "chapter": chapter, "chapter_title": ch["title"], "title": sec["title"],
                            "applies": applies, "reason": reason, "sheets": ordered})

    for code, cat in catalog["mappings"]["top10_2021"].items():
        overlap = [s for s in cat["sheets"] if s in applicable]
        if overlap:
            cm.top10.append({"code": code, "title": cat["title"], "sheets": overlap})
    return cm
