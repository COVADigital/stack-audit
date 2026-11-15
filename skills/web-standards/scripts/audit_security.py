#!/usr/bin/env python3
"""Frontend/web security audit (rules sec.*, 08-security.md). Read-only.

    python audit_security.py --root REPO [--changed] [--format md|json|sarif] [--strict]
                             [--build]   also scan .next/static for leaked secrets (run after `next build`)
                             [--audit]   run `npm/pnpm/yarn audit --json` (contacts the package registry)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.cli import build_parser, finish, make_context
from wclib.findings import Report
from wclib.jsscan import JsFile, Tag, find_calls, functions, is_test_file, tags
from wclib.rules import RuleBook
from wclib.stack import detect_stack
from wclib.walker import repo_paths

SKILL = Path(__file__).resolve().parents[1]

SANITIZERS = re.compile(r"sanitize|DOMPurify|purify|sanitizeHtml|xss\(|escapeHtml|marked\.parse|toHTML|renderToStaticMarkup")
SESSION_COOKIE = re.compile(r"sess|auth|token|jwt|sid|refresh|access|login|credential", re.I)
TOKEN_KEY = re.compile(r"token|jwt|auth|session|refresh|access_?key|secret|password|credential", re.I)
SECRET_ENV_HARD = re.compile(r"SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|(^|_)SK(_|$)|DATABASE_URL|WEBHOOK_SECRET")
SECRET_ENV_SOFT = re.compile(r"(^|_)(TOKEN|API_KEY|KEY)$")
PUBLIC_OK = re.compile(r"PUBLISHABLE|PUBLIC_KEY|SITE_KEY|PROJECT_ID|DATASET|_URL$|_ID$|ANALYTICS|POSTHOG|SENTRY_DSN|MEASUREMENT")
AUTH_CALL = re.compile(
    r"\b(auth|getSession|getServerSession|verifySession|requireUser|requireAuth|requireSession|currentUser|getCurrentUser|"
    r"getUser|validateRequest|withAuth|assertAuth|checkAuth|authorize|getAuth)\s*\(|auth\.api\.getSession|session\s*=|session\?\.|session\.user"
)
DB_WRITE = re.compile(r"\.(insert|update|delete|upsert|create|createMany|updateMany|deleteMany)\s*\(|db\.execute|\bsql`\s*(INSERT|UPDATE|DELETE)", re.I)
HARD_SECRETS = [
    (re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "Stripe live secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bpostgres(?:ql)?://[^\s:'\"@/]+:[^\s@'\"/]{3,}@(?!localhost|127\.0\.0\.1|db\b|postgres\b)[^\s'\"]+"), "database URL with password"),
    (re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}"), "API secret key (OpenAI/Anthropic style)"),
]
SECRET_SCAN_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".toml", ".env", ".sh", ".py"}
RATE_LIMIT_HINT = re.compile(r"ratelimit|rateLimit|rate_limit|limiter|Ratelimit", re.I)
REDIRECT_CALL = r"(?:(?<![\w$.])(?:redirect|permanentRedirect)|\b(?:NextResponse|Response)\.redirect|\blocation\.(?:assign|replace))"
REQUEST_SOURCE = re.compile(r"searchParams|nextUrl|formData\(|req\.url|request\.url|req\.query|useSearchParams")
REDIRECT_TARGET = re.compile(r"searchParams\.get\(|\b(next|returnTo|returnUrl|redirectTo|redirectUrl|redirect_uri|callbackUrl|"
                             r"continue|dest|destination|target|goto)\b")
REDIRECT_GUARD = re.compile(r"safe|isRelative|isLocal|startsWith\(\s*['\"]/|allow(ed)?(List|Hosts?|Origins?)|ALLOWED|"
                            r"\.origin\s*[!=]==|\.host(name)?\s*[!=]==", re.I)
SECRET_VALUE_NAME = re.compile(r"token|secret|nonce|salt|otp|passw|api_?key|session_?id|reset|invite|csrf|verif", re.I)


class SecurityAudit:
    def __init__(self, ctx, rb: RuleBook, report: Report) -> None:
        self.ctx, self.rb, self.report = ctx, rb, report
        self.stack = detect_stack(ctx.root)
        self.files: list[JsFile] = []
        for sf in ctx.walker.js_files():
            if is_test_file(sf.rel):
                continue
            text = sf.read()
            if text:
                self.files.append(JsFile(sf.rel, text))
        self.html_files = [JsFile(sf.rel, sf.read()) for sf in ctx.walker.files(exts={".html", ".htm"})]
        self.all_code = "\n".join(f.code for f in self.files)

    def add(self, rule, msg, f: JsFile | None = None, offset: int | None = None, **kw):
        line = f.line_of(offset) if (f and offset is not None) else kw.pop("line", None)
        self.report.add(self.rb.make(rule, msg, file=f.rel if f else kw.pop("file", None), line=line,
                                     snippet=f.snippet(offset) if (f and offset is not None) else None, **kw))

    # ------------------------------------------------------------- sec.01 XSS sinks
    def xss(self, f: JsFile) -> None:
        for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:", f.code):
            value = f.code[m.end(): m.end() + 300].split("}}", 1)[0]
            if re.fullmatch(r"\s*(['\"`])[^$]*\1\s*", value):
                continue  # static literal
            if SANITIZERS.search(value):
                continue
            if "JSON.stringify" in value:
                if "<" not in value and not re.search(r"replace\(\s*/<", value):
                    self.add("sec.01", "JSON-LD via dangerouslySetInnerHTML without escaping `<` (a `</script>` in data breaks out)",
                             f, m.start(), severity="warn", confidence="medium",
                             fix_hint="JSON.stringify(data).replace(/</g, '\\\\u003c')")
                continue
            self.add("sec.01", "dangerouslySetInnerHTML with a non-sanitized value", f, m.start(), confidence="medium",
                     fix_hint="Render as text, or sanitize with DOMPurify (isomorphic-dompurify on the server); Portable Text for Sanity")
        for m in re.finditer(r"\.(innerHTML|outerHTML)\s*=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\.write(ln)?\s*\(", f.code_nostr):
            self.add("sec.01", f"DOM HTML sink `{m.group(0).strip(' =(')}`", f, m.start(), severity="warn", confidence="medium",
                     fix_hint="Use textContent / React rendering, or sanitize first")
        for m in re.finditer(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(", f.code_nostr):
            self.add("sec.01", "eval / new Function executes strings as code", f, m.start(),
                     fix_hint="Remove dynamic code execution; parse data with JSON.parse or a schema")
        if f.jsx or f.rel.endswith((".html", ".htm")):
            for t in tags(f, {"a", "Link", "iframe"}):
                href = t.attr("href") if t.name != "iframe" else t.attr("src")
                # Only names that suggest user-supplied URLs; `item.href` from static nav config is not flagged.
                if isinstance(href, str) and href.startswith("{") \
                        and re.search(r"(user|profile|website|redirect|returnTo|callback|\.url\b|Url\b)", href) \
                        and not re.search(r"^\{\s*[`'\"]/", href) and not re.search(r"safe|sanitize|isHttp|new URL", f.code, re.I):
                    self.add("sec.01", f"`{t.name}` URL from data without a scheme check (javascript: URLs execute)", f, t.start,
                             severity="info", confidence="low", fix_hint="Allow only http(s): (or relative) URLs before rendering")

    # ------------------------------------------------------------- sec.02 / sec.17 / sec.21 handlers & actions
    def handlers_and_actions(self, f: JsFile) -> None:
        is_route = re.search(r"(^|/)route\.[cm]?[jt]sx?$", f.rel) is not None
        file_server = f.directive == "server"
        if not (is_route or file_server or "use server" in f.code):
            return
        for fn in functions(f):
            body = fn.body(f)
            method = fn.name.upper() if is_route and fn.name.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} else None
            is_action = (file_server and fn.exported) or fn.has_use_server
            if is_route and method == "GET" and DB_WRITE.search(body) and not re.search(r"cron|webhook|revalidate", f.rel, re.I):
                self.add("sec.02", "GET route handler writes data (state change on GET enables CSRF via links/prefetch)", f, fn.start,
                         fix_hint="Move the write to POST/PUT/DELETE (or a Server Action)")
            # Auth via a wrapper that hands the callback an authenticated identity, e.g. run("x", async (userId) => …)
            wrapped_auth = re.search(r"\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?async\s*\(\s*\{?\s*(userId|user|session|actor|viewer|ctx|auth)\b", body)
            if (method in {"POST", "PUT", "PATCH", "DELETE"} or is_action) and DB_WRITE.search(body) \
                    and not AUTH_CALL.search(body) and not wrapped_auth \
                    and not re.search(r"webhook|cron|public|signup|register|contact|newsletter", f.rel, re.I) \
                    and not re.search(r"verify(Signature|Webhook)|svix|stripe\.webhooks", body):
                kind = "Server Action" if is_action else f"{method} handler"
                self.add("sec.17", f"{kind} `{fn.name}` writes data without an authentication check in its body",
                         f, fn.start, confidence="medium",
                         fix_hint="Authenticate, validate, and authorize inside the action/handler (pages don't protect actions)")
            if (is_route or is_action) and re.search(r"\bfetch\s*\(", body) \
                    and re.search(r"searchParams\.get\(|\.json\(\)|formData\.get\(|params\.|input\.|body\.", body) \
                    and re.search(r"fetch\s*\(\s*(?:new URL\()?\s*(url|target|href|link|src|input|body|params|data)\b", body, re.I) \
                    and not re.search(r"allow(ed)?(List|Hosts?)|ALLOWED|\.hostname\s*(===|!==|in)|isAllowed", body):
                self.add("sec.21", f"`{fn.name}` fetches a URL derived from request input without a host allow-list (SSRF)",
                         f, fn.start, confidence="low",
                         fix_hint="Allow-list hosts/schemes, refuse redirects, block private IP ranges, set a timeout")

    # ------------------------------------------------------------- sec.22 open redirects
    def open_redirects(self, f: JsFile) -> None:
        if not REQUEST_SOURCE.search(f.code) or REDIRECT_GUARD.search(f.code):
            return
        hits = [(off, a) for off, a in find_calls(f, REDIRECT_CALL)]
        hits += [(m.start(), m.group(1)) for m in re.finditer(r"\blocation\.href\s*=(?!=)\s*([^;\n]+)", f.code)]
        for off, args in hits:
            # A literal or template that starts with "/" (not "//") stays on this site.
            if re.match(r"\s*(?:new URL\(\s*)?['\"`]/(?!/)", args) or not REDIRECT_TARGET.search(args):
                continue
            self.add("sec.22", "Redirect target comes from the request without a same-site check (open redirect)", f, off,
                     confidence="low", fix_hint="Allow only relative paths starting with a single '/', or map to an allow-list")

    # ------------------------------------------------------------- sec.23 predictable random values
    def weak_random(self, f: JsFile) -> None:
        funcs = functions(f)
        for m in re.finditer(r"\bMath\.random\s*\(", f.code_nostr):
            line_start = f.code.rfind("\n", 0, m.start()) + 1
            stmt = f.code[line_start:m.start()]
            fn = next((fn for fn in funcs if fn.body_start <= m.start() < fn.body_end), None)
            if SECRET_VALUE_NAME.search(stmt) or (fn and SECRET_VALUE_NAME.search(fn.name)):
                self.add("sec.23", "Math.random() used for a value that must not be guessable", f, m.start(), confidence="medium",
                         fix_hint="crypto.randomUUID() or crypto.getRandomValues() (node:crypto randomBytes on the server)")

    # ------------------------------------------------------------- sec.06 / sec.07 cookies & storage
    def cookies_and_storage(self, f: JsFile) -> None:
        # Also `const store = await cookies(); store.set(...)` (the usual Next 15+/16 form).
        aliases = set(re.findall(r"\b(\w+)\s*=\s*(?:await\s+)?cookies\(\)", f.code))
        alias_rx = "|".join(rf"\b{re.escape(a)}" for a in sorted(aliases))
        for off, args in find_calls(f, rf"(?:cookies\(\)\)|cookieStore|cookies|\.cookies{'|' + alias_rx if alias_rx else ''})\.set", nostr=False):
            name_m = re.match(r"\s*(['\"`])([^'\"`]+)\1", args) or re.search(r"name\s*:\s*(['\"`])([^'\"`]+)\1", args)
            name = name_m.group(2) if name_m else ""
            if not SESSION_COOKIE.search(name):
                continue
            missing = [k for k, pat in (("httpOnly", r"httpOnly\s*:\s*true"), ("secure", r"secure\s*:\s*(?!false)"),
                                        ("sameSite", r"sameSite\s*:")) if not re.search(pat, args)]
            if missing:
                self.add("sec.06", f"Session-like cookie '{name}' set without {', '.join(missing)}", f, off,
                         fix_hint="{ httpOnly: true, secure: true, sameSite: 'lax', path: '/' } (prefer the __Host- prefix)")
        for m in re.finditer(r"Set-Cookie['\"]?\s*[,:]\s*[`'\"]([^`'\"]*)", f.code):
            val = m.group(1)
            if SESSION_COOKIE.search(val.split("=", 1)[0]) and not all(x in val.lower() for x in ("httponly", "secure", "samesite")):
                self.add("sec.06", "Session-like Set-Cookie header missing HttpOnly/Secure/SameSite", f, m.start())
        for off, args in find_calls(f, r"\b(?:localStorage|sessionStorage|window\.localStorage)\.setItem", nostr=False):
            key = re.match(r"\s*(['\"`])([^'\"`]+)\1", args)
            if key and TOKEN_KEY.search(key.group(2)):
                self.add("sec.07", f"Auth token stored in Web Storage ('{key.group(2)}'): readable by any XSS", f, off,
                         fix_hint="Keep tokens in HttpOnly cookies (BFF / server session)")
        for m in re.finditer(r"persist\s*\(", f.code_nostr):
            window = f.code[m.start(): m.start() + 1500]
            if re.search(r"\b(token|accessToken|refreshToken|jwt|password|secret)\s*:", window):
                self.add("sec.07", "Persisted client store appears to contain tokens/secrets", f, m.start(), confidence="medium",
                         fix_hint="Exclude credentials via partialize, or keep them server-side")

    # ------------------------------------------------------------- sec.08 / sec.09 OAuth & JWT
    def oauth_jwt(self, f: JsFile) -> None:
        for m in re.finditer(r"response_type=code", f.code):
            window = f.code[max(0, m.start() - 400): m.start() + 600]
            if "code_challenge" not in window:
                self.add("sec.08", "Hand-built OAuth authorization URL without PKCE (code_challenge)", f, m.start(),
                         fix_hint="Use PKCE with S256 and validate state; prefer Better Auth / Auth.js / oidc-client-ts")
            elif "code_challenge_method=plain" in window:
                self.add("sec.08", "PKCE uses the 'plain' method", f, m.start(), fix_hint="Use code_challenge_method=S256")
            if "state=" not in window:
                self.add("sec.08", "Hand-built OAuth URL without a state parameter", f, m.start())
        server_side = f.directive != "client"
        for m in re.finditer(r"\b(jwtDecode|jwt_decode|decodeJwt|jwt\.decode)\s*\(", f.code_nostr):
            if server_side:
                self.add("sec.09", f"`{m.group(1)}` decodes without verifying; don't use it for authorization", f, m.start(),
                         severity="warn", confidence="medium", fix_hint="Use jwtVerify (jose) with pinned algorithms, issuer, audience")
        for off, args in find_calls(f, r"\bjwt\.verify", nostr=False):
            if "algorithms" not in args:
                self.add("sec.09", "jwt.verify without an `algorithms` allow-list", f, off, confidence="medium",
                         fix_hint="Pass { algorithms: ['RS256'] } (never accept 'none')")
        for m in re.finditer(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", f.code, re.I):
            self.add("sec.09", "JWT algorithms allow 'none'", f, m.start())

    # ------------------------------------------------------------- sec.10 injection
    def injection(self, f: JsFile) -> None:
        for off, args in find_calls(f, r"\bsql\.raw", nostr=False):
            if not re.fullmatch(r"\s*(['\"])[^'\"]*\1\s*", args):
                self.add("sec.10", "sql.raw() with a non-literal argument", f, off,
                         fix_hint="Use the sql`` tag (parameterized) or an allow-listed identifier")
        for m in re.finditer(r"(?<![\w$])(?:query|execute|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*`([^`]*\$\{[^`]*)`", f.code):
            if re.search(r"\b(select|insert|update|delete|where|from)\b", m.group(1), re.I):
                self.add("sec.10", "SQL built with template-string interpolation", f, m.start(), confidence="medium",
                         fix_hint="Use parameterized queries (Drizzle sql`` tag / query builder)")
        for m in re.finditer(r"(['\"])\s*(SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*\1\s*\+", f.code, re.I):
            self.add("sec.10", "SQL built with string concatenation", f, m.start(), confidence="medium",
                     fix_hint="Use parameterized queries")
        for m in re.finditer(r"\b(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{", f.code):
            self.add("sec.10", "Shell command built with template interpolation (command injection)", f, m.start(),
                     confidence="medium", fix_hint="Use execFile/spawn with an argument array and validated input")

    # ------------------------------------------------------------- sec.12 / sec.14 / sec.20 markup
    def markup(self, f: JsFile) -> list[tuple[str, int, str]]:
        third_party = []
        if not f.jsx and not f.rel.endswith((".html", ".htm")):
            return third_party
        for t in tags(f, {"script", "Script", "link", "iframe"}):
            src = t.literal("src") or (t.literal("href") if t.name == "link" else None)
            if t.name in ("script", "Script") and src and src.startswith(("http://", "https://", "//")):
                third_party.append((src, t.start, f.rel))
                if t.name == "script" and not t.has("integrity"):
                    self.add("sec.12", f"Third-party <script> without integrity (SRI): {src[:80]}", f, t.start,
                             fix_hint="Add integrity + crossorigin, or self-host the file")
            if t.name == "link" and src and src.startswith(("http://", "https://")) and "stylesheet" in str(t.attr("rel")) \
                    and "fonts.googleapis.com" not in src and not t.has("integrity"):
                self.add("sec.12", f"Third-party stylesheet without integrity (SRI): {src[:80]}", f, t.start)
            if t.name == "iframe":
                src_v = t.attr("src")
                dynamic = isinstance(src_v, str) and src_v.startswith("{")
                sandbox = t.literal("sandbox")
                if dynamic and not t.has("sandbox"):
                    self.add("sec.14", "<iframe> with a dynamic src and no sandbox", f, t.start,
                             fix_hint="Start with sandbox=\"\" and add only the permissions the embed needs")
                if sandbox and "allow-scripts" in sandbox and "allow-same-origin" in sandbox and dynamic:
                    self.add("sec.14", "sandbox combines allow-scripts and allow-same-origin for dynamic content", f, t.start)
        return third_party

    # ------------------------------------------------------------- sec.16 secrets
    def secrets_in_code(self, f: JsFile) -> None:
        for m in re.finditer(r"process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)", f.code):
            name = m.group(1)[len("NEXT_PUBLIC_"):]
            if SECRET_ENV_HARD.search(name):
                self.add("sec.16", f"`{m.group(1)}` looks secret but NEXT_PUBLIC_ ships it to every browser", f, m.start(),
                         fix_hint="Drop the NEXT_PUBLIC_ prefix and use it only in server code")
            elif SECRET_ENV_SOFT.search(name) and not PUBLIC_OK.search(name):
                self.add("sec.16", f"`{m.group(1)}` is public: confirm this key is meant to be exposed", f, m.start(),
                         severity="warn", confidence="low")
        if f.directive == "client":
            for m in re.finditer(r"process\.env\.(?!NEXT_PUBLIC_|NODE_ENV\b)([A-Z0-9_]+)", f.code):
                self.add("sec.16", f"Client Component reads server env `{m.group(1)}` (undefined in the browser; secret misuse risk)",
                         f, m.start(), severity="warn", fix_hint="Read it on the server and pass only what the UI needs")
        reads_secret = re.search(r"process\.env\.(?!NEXT_PUBLIC_)[A-Z0-9_]*(SECRET|PRIVATE|TOKEN|PASSWORD|DATABASE_URL|_KEY)\b", f.code)
        if reads_secret and f.directive is None and "server-only" not in f.code \
                and re.search(r"(^|/)(lib|server|utils|services|dal|data)/", f.rel) and not re.search(r"(config|env)\.[cm]?[jt]s$", f.rel):
            self.add("sec.16", "Module reads a server secret but doesn't import 'server-only'", f, reads_secret.start(),
                     severity="info", fix_hint="Add `import 'server-only'` so a client import fails the build")

    def hardcoded_secrets(self) -> None:
        for sf in self.ctx.walker.all_files():
            p = Path(sf)
            if p.suffix.lower() not in SECRET_SCAN_EXTS and not p.name.startswith(".env"):
                continue
            if p.name.endswith((".example", ".sample", ".template")) or "lock" in p.name:
                continue
            try:
                text = (self.ctx.root / sf).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(text) > 1_500_000:
                continue
            for pat, label in HARD_SECRETS:
                for m in pat.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    self.report.add(self.rb.make("sec.16", f"Hard-coded {label} in source", file=sf, line=line,
                                                 fix_hint="Remove it, rotate the credential, and load it from the environment"))
                    break

    def build_output(self) -> None:
        static = self.ctx.root / ".next" / "static"
        if not static.is_dir():
            self.report.skipped.append("--build: .next/static not found (run `next build` first)")
            return
        pats = HARD_SECRETS + [(re.compile(r"sk_test_[0-9A-Za-z]{16,}"), "Stripe test secret key")]
        for p in static.rglob("*.js"):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pat, label in pats:
                if pat.search(text):
                    self.report.add(self.rb.make("sec.16", f"{label} found in the client bundle",
                                                 file=p.relative_to(self.ctx.root).as_posix(),
                                                 fix_hint="Find the import that pulls it into client code; rotate the credential"))

    # ------------------------------------------------------------- headers / CSP / config (project level)
    def project_config(self) -> None:
        nc_name = self.stack.next_config.get("file")
        nc_text = (self.ctx.root / nc_name).read_text(encoding="utf-8", errors="replace") if nc_name else ""
        interceptor = self.stack.request_interceptor
        ic_text = (self.ctx.root / interceptor).read_text(encoding="utf-8", errors="replace") if interceptor else ""
        header_src = nc_text + "\n" + ic_text + "\n" + self.all_code
        is_next = self.stack.has("next")
        if is_next and self.stack.next_config.get("productionBrowserSourceMaps"):
            self.report.add(self.rb.make("sec.16", "productionBrowserSourceMaps: true publishes your source", file=nc_name,
                                         severity="warn", fix_hint="Turn it off, or upload maps privately to your error tracker"))
        if not is_next:
            return
        csp = re.search(r"Content-Security-Policy(?!-Report)", header_src)
        csp_ro = "Content-Security-Policy-Report-Only" in header_src
        if not csp and not csp_ro:
            self.report.add(self.rb.make("sec.03", "No Content-Security-Policy found in next.config, proxy, or code",
                                         fix_hint="Start with a Report-Only CSP (assets/proxy.csp.ts), then enforce",
                                         confidence="medium"))
        for m in re.finditer(r"'unsafe-eval'", header_src):
            line_text = header_src[header_src.rfind("\n", 0, m.start()) + 1: header_src.find("\n", m.start())]
            if not re.search(r"isDev|development|NODE_ENV", line_text):
                self.report.add(self.rb.make("sec.03", "CSP allows 'unsafe-eval' in production", severity="warn",
                                             file=interceptor or nc_name))
                break
        for m in re.finditer(r"script-src([^;\"'`]*(?:'[^']*'[^;\"'`]*)*)", header_src):
            directive = m.group(1)
            if "'unsafe-inline'" in directive and not re.search(r"'nonce-|'sha(256|384|512)-|'strict-dynamic'", directive):
                self.report.add(self.rb.make("sec.03", "CSP script-src allows 'unsafe-inline' without a nonce or hash (XSS protection lost)",
                                             severity="warn", file=interceptor or nc_name,
                                             fix_hint="Use a nonce (proxy.ts) or hashes; keep 'unsafe-inline' only as a fallback alongside them"))
                break
        if "nonce-" in header_src and (re.search(r"generateStaticParams|'use cache'|\"use cache\"", self.all_code)):
            self.report.add(self.rb.make("sec.03", "Nonce CSP with static/cached routes: nonce pages must render dynamically",
                                         severity="info", file=interceptor,
                                         fix_hint="Exclude static routes from the nonce matcher, or use a hash-based CSP there"))
        checks = [
            ("sec.19", r"Strict-Transport-Security", "HSTS (Strict-Transport-Security)"),
            ("sec.19", r"X-Content-Type-Options", "X-Content-Type-Options: nosniff"),
            ("sec.19", r"Referrer-Policy", "Referrer-Policy"),
            ("sec.15", r"Permissions-Policy", "Permissions-Policy"),
            ("sec.05", r"X-Frame-Options|frame-ancestors", "framing protection (frame-ancestors / X-Frame-Options)"),
        ]
        for rule, pat, label in checks:
            if not re.search(pat, header_src):
                self.report.add(self.rb.make(rule, f"No {label} header configured in the app", file=nc_name,
                                             confidence="medium",
                                             fix_hint="Add it in next.config headers() (assets/security-headers.next.config.ts) "
                                                      "unless your host/proxy sets it; verify on the deployed URL"))
        if "interest-cohort" in header_src:
            self.report.add(self.rb.make("sec.15", "Permissions-Policy still lists obsolete `interest-cohort`", severity="info",
                                         file=nc_name))

    def cors(self, f: JsFile) -> None:
        wildcard = re.search(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]", f.code)
        creds = re.search(r"Access-Control-Allow-Credentials['\"]?\s*[,:]\s*['\"]?true", f.code)
        if wildcard and creds:
            self.add("sec.04", "CORS allows any origin (*) together with credentials", f, wildcard.start(),
                     fix_hint="Use an explicit origin allow-list and Vary: Origin")
        reflect = re.search(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*(?:req|request)\.headers\.get\(\s*['\"]origin", f.code, re.I)
        if reflect and not re.search(r"ALLOWED|allow(ed)?(List|Origins)|\.includes\(\s*origin|\.has\(\s*origin", f.code):
            self.add("sec.04", "CORS reflects the request Origin without an allow-list check", f, reflect.start(),
                     confidence="medium", fix_hint="Check the origin against an allow-list before echoing it")

    def dependencies(self, run_audit: bool) -> None:
        pm = self.stack.package_manager
        lock = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock", "bun": "bun.lock"}.get(pm or "")
        if self.stack.has_package_json and not lock:
            self.report.add(self.rb.make("sec.11", "No lockfile: installs are not reproducible", file="package.json",
                                         severity="warn", fix_hint="Commit the lockfile; use `npm ci` in CI"))
        elif lock and self.ctx.walker.git and not self.ctx.walker.tracked(lock):
            self.report.add(self.rb.make("sec.11", f"{lock} exists but is not committed", file=lock, severity="warn"))
        wf_dir = next((b / ".github" / "workflows" for b in repo_paths(self.ctx.root)
                       if (b / ".github" / "workflows").is_dir()), None)
        if wf_dir:
            for wf in sorted(wf_dir.glob("*.y*ml")):
                text = wf.read_text(encoding="utf-8", errors="replace")
                for m in re.finditer(r"^\s*(?:-\s*)?run:\s*.*\b(npm install|npm i\b|pnpm install(?!.*frozen)|yarn install(?!.*(immutable|frozen)))", text, re.M):
                    self.report.add(self.rb.make("sec.11", "CI installs without a frozen lockfile",
                                                 file=f".github/workflows/{wf.name}", line=text.count("\n", 0, m.start()) + 1,
                                                 severity="warn", fix_hint="npm ci / pnpm install --frozen-lockfile / yarn install --immutable"))
        if not run_audit:
            self.report.skipped.append("Dependency vulnerability audit not run (pass --audit; contacts the registry)")
            return
        cmd = {"pnpm": ["pnpm", "audit", "--json"], "yarn": ["yarn", "npm", "audit", "--json"]}.get(pm or "", ["npm", "audit", "--json"])
        try:
            res = subprocess.run(cmd, cwd=self.ctx.root, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=180, shell=sys.platform == "win32")
            data = json.loads(res.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            self.report.skipped.append(f"{' '.join(cmd)} failed: {exc}")
            return
        vulns = (data.get("metadata") or {}).get("vulnerabilities") or {}
        high, crit = vulns.get("high", 0), vulns.get("critical", 0)
        if high or crit:
            self.report.add(self.rb.make("sec.11", f"{crit} critical and {high} high vulnerabilities in dependencies ({' '.join(cmd)})",
                                         file=lock or "package.json", fix_hint="Update or replace the affected packages"))

    def run(self, args) -> None:
        third_party = []
        for f in self.files:
            self.xss(f)
            self.handlers_and_actions(f)
            self.cookies_and_storage(f)
            self.oauth_jwt(f)
            self.injection(f)
            self.cors(f)
            self.secrets_in_code(f)
            self.open_redirects(f)
            self.weak_random(f)
            third_party += self.markup(f)
        for f in self.html_files:
            self.xss(f)
            third_party += self.markup(f)
        self.hardcoded_secrets()
        self.project_config()
        self.dependencies(args.audit)
        if args.build:
            self.build_output()
        origins = sorted({re.sub(r"^(https?:)?//([^/]+).*", r"\2", s) for s, _, _ in third_party})
        if origins:
            budget = self.ctx.config["budgets"]["maxThirdPartyScripts"]
            sev = "warn" if len(origins) > budget else "info"
            self.report.add(self.rb.make("sec.20", f"{len(origins)} third-party script origin(s): {', '.join(origins)} (budget {budget})",
                                         severity=sev, fix_hint="Inventory each with an owner and purpose; load lazily; allow in CSP"))
        ran = {"build"} if args.build else set()
        self.report.not_checked += self.rb.not_checked("sec", ran=ran)
        self.report.not_checked.append("`sec.17` ownership/IDOR checks per resource (heuristics only find missing auth calls)")


def main() -> int:
    ap = build_parser(__doc__.splitlines()[0])
    ap.add_argument("--build", action="store_true", help="Scan .next/static for secrets (after next build)")
    ap.add_argument("--audit", action="store_true", help="Run the package manager's audit (network)")
    args = ap.parse_args()
    ctx = make_context(args)
    report = Report(tool="audit_security", root=str(ctx.root))
    SecurityAudit(ctx, RuleBook(SKILL), report).run(args)
    return finish(report, ctx)


if __name__ == "__main__":
    sys.exit(main())
