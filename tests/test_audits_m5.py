"""Fixture tests for M5 scripts: rendering, networking, state, performance, caching,
architecture, probe_headers (local server only) and run_audit."""

import gzip
import http.server
import json
import subprocess
import sys
import threading
import unittest

from helpers import PLUGIN_ROOT, TempRepo

SCRIPTS = PLUGIN_ROOT / "skills" / "web-standards" / "scripts"
PKG16 = json.dumps({"name": "app", "dependencies": {"next": "16.4.0", "react": "19.2.0", "zustand": "5.0.0"}})


class Case(TempRepo):
    script = ""

    def setUp(self):
        super().setUp()
        self.write("package.json", PKG16)

    def run_audit(self, *extra, script=None):
        res = subprocess.run([sys.executable, str(SCRIPTS / (script or self.script)), "--root", str(self.dir), "--format", "json", *extra],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertIn(res.returncode, (0, 1), res.stderr)
        return json.loads(res.stdout)

    def rules(self, d, part=None):
        return {f["rule"] for f in d["findings"] if part is None or part in (f.get("file") or "")}

    def msgs(self, d, rule):
        return [f["message"] for f in d["findings"] if f["rule"] == rule]


class RenderingTests(Case):
    script = "audit_rendering.py"

    def test_cache_components_and_revalidation(self):
        self.write("next.config.ts", "export default { cacheComponents: true }")
        self.write("app/blog/page.tsx", "export const revalidate = 3600;\nexport const metadata = { title: 'Blog' };\nexport default function P(){ return <h1>Blog</h1> }")
        self.write("app/api/hook/route.ts", "import { revalidateTag, updateTag } from 'next/cache';\nexport async function POST(){ revalidateTag('posts'); updateTag('x'); return Response.json({}) }")
        self.write("app/good/page.tsx", "export const metadata = {};\nexport default function P(){ return null }\n")
        self.write("app/hook2/route.ts", "export async function POST(){ revalidateTag('posts', 'max'); return Response.json({}) }")
        d = self.run_audit()
        self.assertTrue(any("not supported with cacheComponents" in m for m in self.msgs(d, "ren.01")))
        r3 = " ".join(self.msgs(d, "ren.03"))
        self.assertIn("without a cacheLife profile", r3)
        self.assertIn("only allowed in Server Actions", r3)
        self.assertNotIn("ren.03", self.rules(d, "hook2"))
        inv = "\n".join(d["appendix"])
        self.assertIn("Route inventory", inv)
        self.assertIn("`/blog`", inv)
        self.assertIn("Cache Components", inv)

    def test_hydration_keys_and_client_boundaries(self):
        self.write("app/clock.tsx", """'use client';
import { useEffect, useState } from 'react';
export function Clock() {
  const now = new Date().toLocaleTimeString();
  return <p>{now}</p>;
}
export function Safe() {
  const [t, setT] = useState<string | null>(null);
  useEffect(() => { setT(new Date().toLocaleTimeString()); }, []);
  return <button onClick={() => setT(String(Date.now()))}>{t}</button>;
}
export function List({ rows }) {
  return <ul>{rows.map((r, i) => <li key={i}><input defaultValue={r} onChange={x} /></li>)}</ul>;
}
""")
        self.write("app/static.tsx", "'use client';\nexport function Plain() { return <p>hi</p>; }\n")
        self.write("components/ui/dialog.tsx", "'use client';\nimport { Dialog as P } from 'radix-ui';\nexport const D = (p) => <P.Root {...p} />;\n")
        self.write("app/server.tsx", "import dynamic from 'next/dynamic';\nconst C = dynamic(() => import('./c'), { ssr: false });\n")
        d = self.run_audit()
        r5 = [f for f in d["findings"] if f["rule"] == "ren.05"]
        self.assertEqual(len(r5), 1)
        self.assertIn("Clock", r5[0]["message"])
        self.assertTrue(any(f["rule"] == "ren.13" and f["severity"] == "warn" for f in d["findings"]))
        self.assertIn("ren.08", self.rules(d, "static.tsx"))
        self.assertNotIn("ren.08", self.rules(d, "components/ui"))
        self.assertIn("ren.16", self.rules(d, "server.tsx"))


class NetworkingTests(Case):
    script = "audit_networking.py"

    def test_fetch_effects_loops_handlers(self):
        self.write("app/c.tsx", """'use client';
export function C() {
  useEffect(() => { fetch('/api/x').then(r => r.json()).then(setData); }, []);
  useEffect(() => { fetch('/api/beacon', { method: 'POST', keepalive: true }); }, []);
}""")
        self.write("lib/api.ts", """
export async function get() {
  const res = await fetch(url);
  return res.json();
}
export async function ok() {
  const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}
for (const id of ids) { await db.select().from(t).where(eq(t.id, id)); }
items.forEach(async (i) => { await save(i); });
""")
        self.write("app/api/items/route.ts", "export async function POST(req: Request) { const b = await req.json(); return Response.json(b); }")
        self.write("app/api/ok/route.ts", "export async function POST(req: Request) { const b = Item.parse(await req.json()); return Response.json(b); }")
        self.write("app/actions/a.ts", "'use server';\nexport async function rename(id: string, name: string) { await db.update(t).set({ name }); }\nexport async function safe(input: unknown) { await service.do(input); }\n")
        self.write("scripts/tool.mjs", "await fetch('http://localhost')\n")
        d = self.run_audit()
        self.assertIn("net.11", self.rules(d, "c.tsx"))
        self.assertEqual(len([f for f in d["findings"] if f["rule"] == "net.11"]), 1)  # beacon not flagged
        self.assertIn("net.17", self.rules(d, "api.ts"))
        self.assertEqual(len([m for m in self.msgs(d, "net.17") if "res.json" in m]), 1)
        self.assertEqual(len(self.msgs(d, "net.12")), 2)
        self.assertIn("net.19", self.rules(d, "items/route.ts"))
        self.assertNotIn("net.19", self.rules(d, "ok/route.ts"))
        n19 = self.msgs(d, "net.19")
        self.assertTrue(any("rename" in m for m in n19))
        self.assertFalse(any("`safe`" in m for m in n19))
        self.assertNotIn("net.18", self.rules(d, "scripts/"))


class StateTests(Case):
    script = "audit_state.py"

    def test_state_patterns(self):
        self.write("app/list.tsx", """'use client';
import { create } from 'zustand';
export const useCart = create((set) => ({ items: [] }));
export function L() {
  const [items, setItems] = useState([]);
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [isError, setIsError] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [total, setTotal] = useState(0);
  useEffect(() => { fetch('/api').then(r => r.json()).then(setItems); }, []);
  useEffect(() => { setTotal(items.length); }, [items]);
  items.push(1);
  const cart = useCart();
  const both = useCart((s) => ({ a: s.a, b: s.b }));
}""")
        self.write("app/actions.ts", "'use server';\nexport async function save(x) { await db.insert(t).values(x); }\nexport async function ok(x) { await db.insert(t).values(x); updateTag('t'); }\n")
        d = self.run_audit()
        for r in ("state.05", "state.08", "state.09", "state.13", "state.14", "state.17", "state.11"):
            self.assertIn(r, self.rules(d), r)
        s11 = self.msgs(d, "state.11")
        self.assertTrue(any("`save`" in m for m in s11))
        self.assertFalse(any("`ok`" in m for m in s11))
        self.assertEqual(len(self.msgs(d, "state.17")), 2)

    def test_persist_without_version(self):
        self.write("app/store.ts", """
export const a = create(persist((set) => ({}), { name: 'cart' }));
export const b = create(persist((set) => ({}), { name: 'prefs', version: 2, migrate }));
""")
        self.assertEqual(len(self.msgs(self.run_audit(), "state.18")), 1)


class PerformanceTests(Case):
    script = "audit_performance.py"

    def test_static_checks(self):
        self.write("app/c.tsx", """'use client';
import _ from 'lodash';
import moment from 'moment';
import { Chart } from 'chart.js';
import Image from 'next/image';
export const C = () => <>
  <Image src="/a.jpg" alt="" priority />
  <Image src="/b.jpg" alt="" width={10} height={10} preload fetchPriority="high" />
  <img src="/c.jpg" alt="" />
  <iframe src="https://x" title="x" />
</>;
window.addEventListener('scroll', onScroll);
""")
        d = self.run_audit()
        rules = self.rules(d)
        for r in ("perf.02", "perf.04", "perf.06", "perf.07", "perf.08", "perf.09", "perf.14", "perf.20"):
            self.assertIn(r, rules, r)
        self.assertTrue(any("deprecated in Next.js 16" in m for m in self.msgs(d, "perf.02")))

    def test_build_budget(self):
        big = ("function a(){return " + "Math.random()*" * 40000 + "1}").encode()  # incompressible-ish
        self.write(".next/build-manifest.json", json.dumps({"rootMainFiles": ["static/chunks/main.js"]}))
        (self.dir / ".next/static/chunks").mkdir(parents=True, exist_ok=True)
        (self.dir / ".next/static/chunks/main.js").write_bytes(b"x" * 1000)
        import os
        (self.dir / ".next/static/chunks/big.js").write_bytes(os.urandom(200_000))
        self.write(".next/server/app/page_client-reference-manifest.js",
                   'globalThis.__RSC_MANIFEST["/page"] = {"entryJSFiles":{"[project]/src/app/page":["static/chunks/big.js"]}};')
        self.write(".next/server/app/dashboard/page_client-reference-manifest.js",
                   'globalThis.__RSC_MANIFEST["/dashboard/page"] = {"entryJSFiles":{"[project]/src/app/dashboard/page":["static/chunks/big.js"]}};')
        d = self.run_audit("--build")
        p18 = [f for f in d["findings"] if f["rule"] == "perf.18" and "exceed" in f["message"]]
        self.assertEqual({f["severity"] for f in p18}, {"error", "warn"})  # public = error, dashboard = warn
        self.assertIn("Initial JS per route", "\n".join(d["appendix"]))


class CachingTests(Case):
    script = "audit_caching.py"

    def test_use_cache_rules(self):
        self.write("lib/data.ts", """
import { cookies } from 'next/headers';
export async function bad() { 'use cache'; const c = await cookies(); return c; }
export async function untagged() { 'use cache'; return 1; }
export async function good(id: string) { 'use cache'; cacheTag(`x-${id}`); cacheLife('hours'); return id; }
export async function priv() { 'use cache: private'; const c = await cookies(); cacheLife({ stale: 60 }); return c; }
""")
        self.write("app/q.tsx", "useQuery({ queryKey: ['me'], queryFn })\n")
        d = self.run_audit()
        m = " ".join(self.msgs(d, "cache.15"))
        self.assertIn("`bad` reads request data", m)
        self.assertIn("`untagged`", m)
        self.assertNotIn("`good`", m)
        self.assertNotIn("`priv`", m)
        self.assertIn("['me']", m)


class ArchitectureTests(Case):
    script = "audit_architecture.py"

    def test_cycles_boundaries_env(self):
        self.write("tsconfig.json", '{ // comment\n "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] }, }, }')
        self.write("src/a.ts", "import { b } from './b';\nexport const a = 1;")
        self.write("src/b.ts", "import { a } from '@/a';\nexport const b = 2;")
        self.write("src/t1.ts", "import type { T2 } from './t2';\nexport type T1 = 1;")
        self.write("src/t2.ts", "import type { T1 } from './t1';\nexport type T2 = 2;")
        self.write("src/features/cart/index.ts", "export * from './store';")
        self.write("src/features/cart/store.ts", "export const s = 1;")
        self.write("src/features/checkout/x.ts", "import { s } from '@/features/cart/store';\nimport { s as t } from '@/features/cart';")
        self.write("src/components/ui/button.tsx", "import { s } from '@/features/cart';\nexport const B = () => <button className='bg-[#ff0000] p-[13px]' />;")
        self.write("src/components/Card.tsx", "export const C = () => <div style={{ color: '#ff0000' }} title=\"Use a hex color like #1a2b3c here\" />;")
        self.write("src/domain/pricing.ts", "import Stripe from 'stripe';\nexport const p = 1;")
        self.write("src/lib/env.ts", "export const env = { API_URL: process.env.API_URL, SECRET_KEY: process.env.SECRET_KEY };")
        self.write(".env.example", "API_URL=http://localhost\n")
        d = self.run_audit()
        cyc = self.msgs(d, "arch.18")
        self.assertEqual(len(cyc), 1)
        self.assertIn("src/a.ts", cyc[0])
        self.assertEqual(len(self.msgs(d, "arch.08")), 1)
        self.assertIn("arch.03", self.rules(d, "components/ui"))
        self.assertIn("arch.16", self.rules(d, "domain/"))
        self.assertTrue(any("SECRET_KEY" in m for m in self.msgs(d, "arch.20")))
        a02 = [f for f in d["findings"] if f["rule"] == "arch.02"]
        self.assertEqual([f["file"] for f in a02], ["src/components/Card.tsx"])
        self.assertIn("1 hard-coded", a02[0]["message"])  # the prose example is ignored

    def test_no_feature_index_skips_boundaries(self):
        self.write("src/features/a/x.ts", "export const x = 1;")
        self.write("src/features/b/y.ts", "import { x } from '../a/x';")
        d = self.run_audit()
        self.assertNotIn("arch.08", self.rules(d))
        self.assertTrue(any("arch.08" in s for s in d["skipped"]))


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/_next/static/"):
            body = gzip.compress(b"console.log(1);" * 200)
            self.send_response(200)
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Encoding", "gzip")
        else:
            body = b"<html><script src=\"/_next/static/chunks/app.js\"></script>" + b"x" * 3000 + b"</html>"
            self.send_response(200)
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("X-Powered-By", "Next.js")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProbeAndOrchestratorTests(Case):
    def test_probe_headers_local_server(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            res = subprocess.run([sys.executable, str(SCRIPTS / "probe_headers.py"), "--url", url, "--format", "json"],
                                 capture_output=True, text=True, encoding="utf-8", timeout=60)
            d = json.loads(res.stdout)
        finally:
            srv.shutdown()
        rules = {f["rule"] for f in d["findings"]}
        for r in ("cache.09", "cache.01", "perf.13", "sec.19", "sec.15", "sec.03", "sec.05"):
            self.assertIn(r, rules, r)
        self.assertTrue(any("immutable" in f["message"] for f in d["findings"] if f["rule"] == "cache.01"))

    def test_run_audit_merges_domains(self):
        self.write("app/page.tsx", "export default function P(){ return <div onClick={go}>x</div> }")
        self.write("lib/x.ts", "localStorage.setItem('token', t);")
        res = subprocess.run([sys.executable, str(SCRIPTS / "run_audit.py"), "--root", str(self.dir), "--domain", "sec,a11y,ren",
                              "--format", "json"], capture_output=True, text=True, encoding="utf-8", timeout=300)
        d = json.loads(res.stdout)
        rules = {f["rule"] for f in d["findings"]}
        self.assertIn("sec.07", rules)
        self.assertIn("a11y.01", rules)
        self.assertEqual(d["meta"]["domains"], ["sec", "a11y", "ren"])
        self.assertTrue(any("Stack profile" in a for a in d["appendix"]))


if __name__ == "__main__":
    unittest.main()
