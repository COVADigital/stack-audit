"""Fixture tests for audit_security, audit_git, audit_a11y_i18n and contrast.

Each check has a BAD snippet that must be flagged and a GOOD counterpart that must not.
"""

import json
import subprocess
import sys
import unittest

from helpers import PLUGIN_ROOT, TempRepo
from wclib.color import contrast, extract_tokens, parse_color, resolve_scope, resolve_value

SCRIPTS = PLUGIN_ROOT / "skills" / "web-standards" / "scripts"
PKG = json.dumps({"name": "app", "dependencies": {"next": "16.1.0", "react": "19.2.0", "framer-motion": "12.0.0"}})


class AuditCase(TempRepo):
    script = ""

    def run_audit(self, *extra):
        res = subprocess.run([sys.executable, str(SCRIPTS / self.script), "--root", str(self.dir), "--format", "json", *extra],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertIn(res.returncode, (0, 1), res.stderr)
        return json.loads(res.stdout)

    def rules_in(self, data, file_part=None):
        return {f["rule"] for f in data["findings"] if file_part is None or file_part in (f.get("file") or "")}

    def messages(self, data, rule):
        return [f["message"] for f in data["findings"] if f["rule"] == rule]


# ============================================================================ security

class SecurityAuditTests(AuditCase):
    script = "audit_security.py"

    def setUp(self):
        super().setUp()
        self.write("package.json", PKG)

    def test_xss(self):
        self.write("app/bad.tsx", """
export function C({ html, site }) {
  el.innerHTML = html;
  const f = eval(code);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}""")
        self.write("app/good.tsx", """
import DOMPurify from 'isomorphic-dompurify';
export function C({ html }) {
  // eval(x) in a comment is fine
  const s = "eval(x) in a string is fine";
  return <>
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
    <div dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld).replace(/</g, '\\\\u003c') }} />
  </>;
}""")
        d = self.run_audit()
        self.assertEqual(len([f for f in d["findings"] if f["rule"] == "sec.01" and "bad.tsx" in f["file"]]), 3)
        self.assertNotIn("sec.01", self.rules_in(d, "good.tsx"))

    def test_cookies_storage_jwt(self):
        self.write("app/actions/bad.ts", """
'use server';
import { cookies } from 'next/headers';
export async function login(t: string) {
  (await cookies()).set('session', t, { path: '/' });
}
localStorage.setItem('access_token', t);
const claims = jwtDecode(token);
jwt.verify(token, key);
""")
        self.write("app/actions/good.ts", """
'use server';
import { cookies } from 'next/headers';
export async function setTheme(v: string) {
  const store = await cookies();
  store.set('theme', v);
  store.set('session', t, { httpOnly: true, secure: true, sameSite: 'lax' });
}
localStorage.setItem('theme', 'dark');
jwt.verify(token, key, { algorithms: ['RS256'] });
""")
        # Found by the M7 eval: the `const store = await cookies(); store.set(...)` form was missed.
        self.write("app/api/session/route.ts", """
import { cookies } from 'next/headers'
export async function POST() {
  const store = await cookies()
  store.set('sid', crypto.randomUUID(), { path: '/' })
}
""")
        d = self.run_audit()
        bad = self.rules_in(d, "bad.ts")
        self.assertTrue({"sec.06", "sec.07", "sec.09"} <= bad, bad)
        self.assertIn("sec.06", self.rules_in(d, "session/route.ts"))
        self.assertFalse({"sec.06", "sec.07", "sec.09"} & self.rules_in(d, "good.ts"))

    def test_server_action_without_auth(self):
        self.write("app/actions/bad.ts", """
'use server';
export async function deletePost(id: string) {
  await db.delete(posts).where(eq(posts.id, id));
}""")
        self.write("app/actions/good.ts", """
'use server';
export async function deletePost(id: string) {
  const session = await auth();
  if (!session) throw new Error('Unauthorized');
  await db.delete(posts).where(eq(posts.id, id));
}""")
        self.write("app/api/items/route.ts", """
export async function GET() {
  await db.insert(visits).values({});
  return Response.json({});
}""")
        d = self.run_audit()
        self.assertIn("sec.17", self.rules_in(d, "actions/bad.ts"))
        self.assertNotIn("sec.17", self.rules_in(d, "actions/good.ts"))
        self.assertIn("sec.02", self.rules_in(d, "route.ts"))

    def test_sql_and_shell_injection(self):
        self.write("lib/bad.ts", """
await db.execute(sql.raw(userInput));
await client.query(`SELECT * FROM users WHERE email = '${email}'`);
const q = "SELECT * FROM t WHERE id = " + id;
exec(`convert ${file} out.png`);
await db.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);
await prisma.$executeRawUnsafe(`DELETE FROM t WHERE id = ${id}`);
""")
        self.write("lib/good.ts", """
await db.execute(sql`SELECT * FROM users WHERE email = ${email}`);
await db.select().from(users).where(eq(users.email, email));
""")
        d = self.run_audit()
        self.assertEqual(len(self.messages(d, "sec.10")), 6)
        self.assertNotIn("sec.10", self.rules_in(d, "good.ts"))

    def test_ssrf(self):
        self.write("app/api/proxy/route.ts", """
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get('target');
  return fetch(url);
}""")
        self.write("app/api/safe/route.ts", """
const ALLOWED = new Set(['api.example.com']);
export async function GET(req: Request) {
  const url = new URL(new URL(req.url).searchParams.get('target'));
  if (!ALLOWED.has(url.hostname)) return new Response(null, { status: 400 });
  return fetch(url);
}""")
        d = self.run_audit()
        self.assertIn("sec.21", self.rules_in(d, "proxy/route.ts"))
        self.assertNotIn("sec.21", self.rules_in(d, "safe/route.ts"))

    def test_open_redirect(self):
        self.write("app/login/page.tsx", """
import { redirect } from 'next/navigation';
export default async function Page({ searchParams }) {
  const { next } = await searchParams;
  if (next) redirect(next);
}""")
        self.write("app/api/leave/route.ts", """
export function GET(req) {
  return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('to')));
}""")
        self.write("app/ok/page.tsx", """
export default async function Page({ searchParams }) {
  const { next } = await searchParams;
  redirect(`/posts/${next}`);
  redirect('/login');
}""")
        self.write("app/guarded/page.tsx", """
const safeNext = (n) => (n?.startsWith('/') && !n.startsWith('//') ? n : '/');
export default async function Page({ searchParams }) {
  const { next } = await searchParams;
  redirect(safeNext(next));
}""")
        d = self.run_audit()
        self.assertIn("sec.22", self.rules_in(d, "login/page.tsx"))
        self.assertIn("sec.22", self.rules_in(d, "leave/route.ts"))
        self.assertNotIn("sec.22", self.rules_in(d, "ok/page.tsx"))
        self.assertNotIn("sec.22", self.rules_in(d, "guarded/page.tsx"))

    def test_weak_random(self):
        self.write("lib/bad.ts", """
const resetToken = Math.random().toString(36).slice(2);
export function makeInviteCode() { return Math.random().toString(36); }
""")
        self.write("lib/good.ts", """
const delay = base * (0.5 + Math.random());
export function shuffle(a) { return a.sort(() => Math.random() - 0.5); }
const token = crypto.randomUUID();
""")
        d = self.run_audit()
        self.assertEqual(len([f for f in d["findings"] if f["rule"] == "sec.23" and "bad.ts" in f["file"]]), 2)
        self.assertNotIn("sec.23", self.rules_in(d, "good.ts"))

    def test_lockfile_and_ci_install(self):
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npm install\n")
        d = self.run_audit()
        msgs = self.messages(d, "sec.11")
        self.assertTrue(any("No lockfile" in m for m in msgs), msgs)
        self.assertTrue(any("frozen lockfile" in m for m in msgs), msgs)
        self.write("package-lock.json", "{}")
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npm ci\n")
        self.assertEqual(self.messages(self.run_audit(), "sec.11"), [])

    def test_secrets(self):
        self.write("app/client.tsx", """'use client';
export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
export const s = process.env.STRIPE_SECRET_KEY;
export const ok = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;
""")
        self.write("lib/config.ts", "export const key = 'sk_live_" + "a" * 24 + "';\n")
        d = self.run_audit()
        msgs = " ".join(self.messages(d, "sec.16"))
        self.assertIn("NEXT_PUBLIC_STRIPE_SECRET_KEY", msgs)
        self.assertIn("STRIPE_SECRET_KEY", msgs)
        self.assertIn("Stripe live secret key", msgs)
        self.assertNotIn("PUBLISHABLE", msgs)

    def test_headers_and_cors_project_level(self):
        self.write("next.config.ts", "export default { async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }] } }")
        self.write("app/api/x/route.ts", """
export async function GET() {
  return new Response('x', { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' } });
}""")
        d = self.run_audit()
        rules = self.rules_in(d)
        self.assertTrue({"sec.03", "sec.19", "sec.15", "sec.05", "sec.04"} <= rules, rules)
        self.assertFalse(any("X-Content-Type-Options" in m for m in self.messages(d, "sec.19")))

    def test_markup_and_oauth(self):
        self.write("app/layout.tsx", """
export default function L({ children, embed }) {
  return <html lang="en"><body>
    <script src="https://cdn.example.com/lib.js"></script>
    <iframe src={embed.url} title="x" />
    {children}
  </body></html>;
}
const u = `${AUTH}?response_type=code&client_id=${id}`;
""")
        d = self.run_audit()
        rules = self.rules_in(d, "layout.tsx")
        self.assertTrue({"sec.12", "sec.14", "sec.08"} <= rules, rules)
        self.assertIn("sec.20", self.rules_in(d))

    def test_not_checked_and_suppression(self):
        self.write("app/x.tsx", "export const C = ({h}) => <div dangerouslySetInnerHTML={{ __html: h }} /> // stack-audit-ignore sec.01 -- trusted CMS HTML sanitized at ingest\n")
        d = self.run_audit()
        self.assertNotIn("sec.01", self.rules_in(d, "x.tsx"))
        self.assertEqual(d["suppressed"], 1)
        self.assertTrue(any("sec.13" in n for n in d["not_checked"]))


# ============================================================================ git

class GitAuditTests(AuditCase):
    script = "audit_git.py"

    def test_bad_repo(self):
        self.init_git()
        self.write("package.json", PKG)
        self.write(".gitignore", "node_modules\n")
        self.write(".env", "SECRET=1")
        self.write(".github/workflows/ci.yml", """name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
      - run: echo ${{ secrets.TOKEN }}
""")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        d = self.run_audit()
        rules = self.rules_in(d)
        self.assertTrue({"git.04", "git.05", "git.08", "git.09", "git.11", "git.03"} <= rules, rules)
        self.assertTrue(any("Secret-like file is tracked" in m for m in self.messages(d, "git.04")))
        self.assertTrue(any("pull_request_target" in m for m in self.messages(d, "git.08")))

    def test_signing_and_merged_branches(self):
        self.init_git()
        self.write("a.txt", "x")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        self.git("branch", "feat-done")
        d = self.run_audit()
        self.assertTrue(any("signing is not enabled" in m for m in self.messages(d, "git.01")))
        self.assertTrue(any("feat-done" in m for m in self.messages(d, "git.10")))
        self.git("config", "commit.gpgsign", "true")
        self.git("branch", "-d", "feat-done")
        d = self.run_audit()
        self.assertFalse(any("signing is not enabled" in m for m in self.messages(d, "git.01")))
        self.assertEqual(self.messages(d, "git.10"), [])

    def test_remote_branch_protection(self):
        import importlib.util
        from wclib.cli import build_parser, make_context
        from wclib.findings import Report
        from wclib.rules import RuleBook
        sys.path.insert(0, str(SCRIPTS))
        try:
            spec = importlib.util.spec_from_file_location("audit_git_under_test", SCRIPTS / "audit_git.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            sys.path.remove(str(SCRIPTS))
        self.init_git()
        self.git("remote", "add", "origin", "https://github.com/acme/app.git")
        ctx = make_context(build_parser("t").parse_args(["--root", str(self.dir)]))

        def remote(rules, protection):
            def fake_gh(*args):  # stands in for the gh CLI: no network, no auth
                ep = args[1]
                if ep == "repos/acme/app":
                    return 0, json.dumps({"default_branch": "main", "delete_branch_on_merge": True})
                if ep.endswith("/protection"):
                    return protection
                if "/rules/branches/" in ep:
                    return rules
                return 1, "not found"
            mod.gh = fake_gh
            report = Report(tool="t", root=str(self.dir))
            mod.GitAudit(ctx, RuleBook(SCRIPTS.parent), report).remote()
            return [f.message for f in report.findings if f.rule == "git.02"]

        self.assertTrue(any("no ruleset or branch protection" in m for m in remote((0, "[]"), (1, "Not Found"))))
        self.assertTrue(any("Force-pushes" in m for m in remote((0, json.dumps([{"type": "deletion"}])), (1, ""))))
        protected = json.dumps([{"type": "non_fast_forward"},
                                {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}])
        self.assertEqual(remote((0, protected), (1, "")), [])

    def test_good_repo(self):
        self.init_git()
        self.write("package.json", PKG)
        self.write(".gitignore", ".env\n.env.*\n!.env.example\nnode_modules/\n.next/\n*.pem\n")
        self.write(".env.example", "SECRET=changeme")
        self.write(".pre-commit-config.yaml", "repos:\n  - repo: https://github.com/gitleaks/gitleaks\n    hooks:\n      - id: gitleaks\n")
        self.write(".github/CODEOWNERS", "* @owner\n")
        self.write(".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n  - package-ecosystem: github-actions\n")
        self.write(".github/workflows/ci.yml", """name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4
      - uses: gitleaks/gitleaks-action@0123456789abcdef0123456789abcdef01234567
      - run: npm ci
""")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        d = self.run_audit()
        rules = self.rules_in(d)
        self.assertFalse({"git.03", "git.04", "git.05", "git.08", "git.09", "git.11"} & rules, d["findings"])


# ============================================================================ a11y

class A11yAuditTests(AuditCase):
    script = "audit_a11y_i18n.py"

    def setUp(self):
        super().setUp()
        self.write("package.json", PKG)

    def test_i18n_rtl_plurals_live_regions(self):
        self.write("package.json", json.dumps({"dependencies": {"next": "16.1.0", "react": "19.2.0", "next-intl": "4.0.0"}}))
        self.write("messages/en.json", '{"hi": "Hi"}')
        self.write("messages/ar.json", '{"hi": "مرحبا"}')
        self.write("app/[locale]/page.tsx", 'export default function P() { return <main className="ml-4 text-left">x</main>; }\n')
        self.write("app/[locale]/about/page.tsx", 'export default function P() { return <main className="ms-4 text-start">x</main>; }\n')
        self.write("app/globals.css", ".card { margin-left: 4px; }\n")
        self.write("components/Toast.tsx", 'export function Toast({ msg }) { return <div className="toast">{msg}</div>; }\n')
        self.write("components/notification-region.tsx",
                   'export function N({ msg }) { return <div role="status" aria-live="polite">{msg}</div>; }\n')
        self.write("components/Count.tsx", "export const Count = ({ n }) => <span>{`${n} item${n === 1 ? '' : 's'}`}</span>;\n")
        d = self.run_audit()
        self.assertIn("a11y.16", self.rules_in(d, "[locale]/page.tsx"))
        self.assertNotIn("a11y.16", self.rules_in(d, "about/page.tsx"))
        self.assertIn("a11y.16", self.rules_in(d, "globals.css"))
        self.assertIn("a11y.11", self.rules_in(d, "Toast.tsx"))
        self.assertNotIn("a11y.11", self.rules_in(d, "notification-region.tsx"))
        self.assertIn("a11y.18", self.rules_in(d, "Count.tsx"))
        self.assertIn("a11y.19", self.rules_in(d))
        # Found by this test: alternates in a .ts helper (no JSX) used to be ignored.
        self.write("lib/seo.ts", "export const alternates = { languages: { en: '/en', ar: '/ar' } };\n"
                   "export const meta = { alternates: { languages: { en: '/en' } } };\n")
        self.assertNotIn("a11y.19", self.rules_in(self.run_audit()))

    def test_bad_markup(self):
        self.write("app/page.tsx", """
export default function Page() {
  return <div>
    <nav>Links</nav>
    <h1>Title</h1><h3>Skipped</h3>
    <div onClick={go}>Buy</div>
    <a onClick={go}>More</a>
    <button onClick={close}><XIcon /></button>
    <img src="/a.jpg" />
    <input type="email" placeholder="Email" />
    <span tabIndex={3}>x</span>
    <input className="outline-none" aria-label="q" />
    <p>{d.toLocaleDateString()}</p>
  </div>;
}""")
        self.write("app/globals.css", ".btn:focus { outline: none; }\n@keyframes spin { to { transform: rotate(1turn) } }\n")
        self.write("app/layout.tsx", "export default function L({children}) { return <html><body>{children}</body></html> }")
        d = self.run_audit()
        rules = self.rules_in(d)
        for r in ("a11y.01", "a11y.03", "a11y.05", "a11y.07", "a11y.08", "a11y.09", "a11y.10", "a11y.15", "a11y.17"):
            self.assertIn(r, rules, r)
        self.assertTrue(any("<html> without lang" in m for m in self.messages(d, "a11y.15")))

    def test_good_markup(self):
        self.write("app/page.tsx", """
export default function Page() {
  return <main id="main">
    <a href="#main" className="skip-link">Skip to main content</a>
    <nav aria-label="Main">Links</nav>
    <h1>Title</h1><h2>Next</h2>
    <button type="button" onClick={go}>Buy</button>
    <button aria-label="Close" onClick={close}><XIcon aria-hidden /></button>
    <img src="/a.jpg" alt="" />
    <label htmlFor="email">Email</label>
    <input id="email" type="email" autoComplete="email" />
    <label>Name <input name="n" /></label>
    <input className="outline-none focus-visible:ring-2" aria-label="q" />
    <p>{new Intl.DateTimeFormat('en-US').format(d)}</p>
  </main>;
}""")
        self.write("app/globals.css", ".btn:focus:not(:focus-visible) { outline: none; }\n.btn:focus-visible { outline: 3px solid; }\n@media (prefers-reduced-motion: reduce) { * { animation: none } }\n@keyframes spin {}\n")
        self.write("app/layout.tsx", "export default function L({children}) { return <html lang=\"en\"><body>{children}</body></html> }")
        d = self.run_audit()
        rules = self.rules_in(d)
        self.assertFalse({"a11y.01", "a11y.03", "a11y.05", "a11y.07", "a11y.08", "a11y.09", "a11y.10", "a11y.15", "a11y.17"} & rules,
                         [f for f in d["findings"]])

    def test_contrast_and_messages(self):
        self.write("app/globals.css", """
@import "tailwindcss";
:root { --background: #ffffff; --foreground: #777777; --muted: oklch(0.97 0 0); --muted-foreground: oklch(0.556 0 0); }
.dark { --background: #0b0b0b; --foreground: #f5f5f5; }
@theme inline { --color-background: var(--background); --color-foreground: var(--foreground); }
""")
        self.write("messages/en.json", json.dumps({"cart": {"items": "{count, plural, one {# item} other {# items}}", "title": "Cart"}}))
        self.write("messages/es.json", json.dumps({"cart": {"items": "{count, plural, one {# artículo}}"}}))
        d = self.run_audit()
        contrast_msgs = self.messages(d, "a11y.06")
        self.assertTrue(any("[light] `foreground` on `background`" in m for m in contrast_msgs), contrast_msgs)
        self.assertFalse(any("[dark] `foreground`" in m for m in contrast_msgs), contrast_msgs)
        msgs20 = " ".join(self.messages(d, "a11y.20"))
        self.assertIn("missing 1 key(s): cart.title", msgs20)
        self.assertIn("without an `other` case: es:cart.items", msgs20)


class DogfoodRegressionTests(AuditCase):
    """False positives / gaps found while dogfooding real repos (2026-11-14)."""

    def test_a11y_patterns_not_flagged(self):
        self.script = "audit_a11y_i18n.py"
        self.write("package.json", PKG)
        self.write("app/form.tsx", """
import { Dialog as DialogPrimitive } from "radix-ui";
export function F({ item }) {
  const id = fieldId(item.id);
  return <div>
    <p ref={statusRef} tabIndex={-1} role="status" className="outline-none">Saved</p>
    <DialogPrimitive.Content className="fixed inset-0 z-50 outline-none" />
    <Label htmlFor={id}>Choice</Label>
    <select id={id} className="outline-none focus-visible:ring-3" />
    <input ref={file} type="file" hidden onChange={upload} />
  </div>;
}""")
        self.write("app/dashboard/page.tsx", """
export default async function Page() {
  if (!data) {
    return <main><h1>Analytics</h1><p>No data</p></main>;
  }
  return <main><h1>Analytics</h1><Chart /></main>;
}""")
        d = self.run_audit()
        rules = self.rules_in(d)
        self.assertFalse({"a11y.03", "a11y.08", "a11y.12"} & rules, d["findings"])
        self.assertFalse(any("<h1>" in m for m in self.messages(d, "a11y.01")))

    def test_a11y_still_flags_real_cases(self):
        self.script = "audit_a11y_i18n.py"
        self.write("package.json", PKG)
        self.write("app/x.tsx", """
export const X = () => <div>
  <button className="outline-none">Go</button>
  <Label htmlFor={a}>A</Label><input id={b} />
</div>;""")
        d = self.run_audit()
        self.assertIn("a11y.03", self.rules_in(d))
        self.assertIn("a11y.08", self.rules_in(d))

    def test_wrapped_server_action_auth(self):
        self.script = "audit_security.py"
        self.write("package.json", PKG)
        self.write("features/actions.ts", """
'use server';
export async function deleteThing(id: string) {
  return run("deleteThing", async (userId) => {
    await service.deleteThing(userId, id);
  });
}""")
        d = self.run_audit()
        self.assertNotIn("sec.17", self.rules_in(d))

    def test_csp_unsafe_inline_and_html_files(self):
        self.script = "audit_security.py"
        self.write("package.json", PKG)
        self.write("next.config.ts", """export default { async headers() { return [{ source: '/(.*)', headers: [
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'" }] }] } }""")
        self.write("public/legacy.html", '<html lang="en"><script src="https://cdn.example.com/x.js"></script></html>')
        d = self.run_audit()
        self.assertTrue(any("unsafe-inline" in m for m in self.messages(d, "sec.03")))
        self.assertIn("sec.12", self.rules_in(d, "legacy.html"))

    def test_html_lowercase_attributes(self):
        self.script = "audit_a11y_i18n.py"
        self.write("index.html", '<html lang="en"><body><main><div onclick="go()">Buy</div><span tabindex="2">x</span></main></body></html>')
        d = self.run_audit()
        self.assertIn("a11y.01", self.rules_in(d))
        self.assertIn("a11y.03", self.rules_in(d))

    def test_git_reads_repo_root_for_app_subfolder(self):
        self.script = "audit_git.py"
        self.init_git()
        self.write(".gitignore", ".env\n.env.*\nnode_modules/\n.next/\n*.pem\n")
        self.write(".github/CODEOWNERS", "* @owner\n")
        self.write(".github/dependabot.yml", "updates:\n  - package-ecosystem: npm\n")
        self.write("web/package.json", PKG)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        res = subprocess.run([sys.executable, str(SCRIPTS / "audit_git.py"), "--root", str(self.dir / "web"), "--format", "json"],
                             capture_output=True, text=True, encoding="utf-8")
        d = json.loads(res.stdout)
        rules = self.rules_in(d)
        self.assertNotIn("git.03", rules)
        self.assertFalse(any("does not cover" in m for m in self.messages(d, "git.04")), d["findings"])
        self.assertFalse(any("No Dependabot" in m for m in self.messages(d, "git.09")))

    def test_git_non_repo_only_gitignore(self):
        self.script = "audit_git.py"
        self.write("index.html", "<html></html>")
        d = self.run_audit()
        self.assertEqual(self.rules_in(d), {"git.04"})
        self.assertTrue(any("Not a git repository" in s for s in d["skipped"]))


class ColorTests(unittest.TestCase):
    def test_reference_ratios(self):
        self.assertAlmostEqual(contrast(parse_color("#767676"), parse_color("#fff")), 4.54, places=2)
        self.assertAlmostEqual(contrast(parse_color("#777"), parse_color("white")), 4.48, places=2)
        self.assertAlmostEqual(contrast(parse_color("rgb(0 0 0)"), parse_color("rgba(255,255,255,1)")), 21.0, places=1)
        self.assertGreater(contrast(parse_color("oklch(0.145 0 0)"), parse_color("oklch(1 0 0)")), 19)
        self.assertAlmostEqual(parse_color("#ffffff80").alpha, 0.5, places=2)
        self.assertIsNone(parse_color("var(--x)"))
        self.assertIsNone(parse_color("transparent"))

    def test_token_resolution_dark_inherits(self):
        css = ":root { --bg: #fff; --fg: #111; --accent: var(--fg); }\n[data-theme='dark'] { --bg: #000; }\n"
        toks = extract_tokens(css, "a.css")
        light, dark = resolve_scope(toks, "light"), resolve_scope(toks, "dark")
        self.assertEqual(resolve_value(light, "accent")[0], "#111")
        self.assertEqual(resolve_value(dark, "bg")[0], "#000")
        self.assertEqual(resolve_value(dark, "fg")[0], "#111")


if __name__ == "__main__":
    unittest.main()
