#!/usr/bin/env python3
"""Audit database workflow and operations: push vs migrate, CI checks, SSL, roles, pools, seeds. Read-only.

    python audit_db_ops.py --root REPO [--files PATH ...] [--format md|json|sarif] [--strict]

Covers dbo.01–06. Reads package.json, CI workflows, Dockerfiles, compose files, .env.example (never .env files)
and source code. Connection strings are never printed: only hosts, user roles and settings.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.containers import DEV_FILE
from wclib.jsscan import functions
from wclib.walker import repo_paths

PG_URL = re.compile(r"postgres(?:ql)?://(?:([^:@/\s'\"`]+)(?::[^@\s'\"`]*)?@)?([^:/?\s'\"`]+)[^\s'\"`]*")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}
EXAMPLE_ENV = re.compile(r"(^|/)\.env\.(example|sample|template|dist)$")
COMPOSE = re.compile(r"(^|/)(docker-)?compose([.-][\w.-]+)?\.ya?ml$")
DOCKERFILE = re.compile(r"(^|/)(Dockerfile|Containerfile)(\.[\w.-]+)?$")
DB_CLIENT = re.compile(r"\b(?:postgres\s*\(|new\s+(?:Pool|Client)\s*\(|neon\s*\(|drizzle\s*\()")
SEED_FILE = re.compile(r"(^|/)(seeds?|fixtures)(/[^/]+|[.-][^/]*)?\.(ts|js|mjs|cjs)$", re.I)
PROD_GUARD = re.compile(r"NODE_ENV|production|ALLOW_SEED|SEED_ALLOW|--force|isProd|IS_PROD|VERCEL_ENV|APP_ENV")
RISKY_SCRIPT_NAME = re.compile(r"deploy|start|release|prod|postinstall|prestart|build|ci\b|migrate")


def is_local(host: str) -> bool:
    return host.lower() in LOCAL_HOSTS or "." not in host  # single-label names: Docker service names (db, postgres)


class DbOpsAudit(Audit):
    tool = "data-standards ops"
    prefix = "dbo"

    def run(self) -> None:
        self.pkg = self.package_json()
        deps = {**self.pkg.get("dependencies", {}), **self.pkg.get("devDependencies", {})}
        self.uses_drizzle = any(d in deps for d in ("drizzle-kit", "drizzle-orm"))
        files = self.ctx.walker.all_files()
        self.push_and_check(files)
        self.connection_strings(files)
        self.pools_and_seeds()
        if not self.uses_drizzle and not self.report.findings:
            self.report.skipped.append("No drizzle-kit/drizzle-orm dependency: push/migrate checks did not apply")
        self.finish_not_checked()

    def package_json(self) -> dict:
        p = self.root / "package.json"
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
        except ValueError:
            return {}

    # ------------------------------------------------------------- dbo.01 / dbo.02
    def push_and_check(self, files: list[str]) -> None:
        scripts: dict[str, str] = self.pkg.get("scripts", {}) or {}
        push_scripts = {n for n, cmd in scripts.items() if "drizzle-kit push" in str(cmd)}
        check_scripts = {n for n, cmd in scripts.items() if "drizzle-kit check" in str(cmd)}
        uses_push = re.compile(r"drizzle-kit\s+push" + "".join(rf"|\brun\s+{re.escape(n)}\b" for n in push_scripts))
        for name, cmd in scripts.items():
            if RISKY_SCRIPT_NAME.search(name) and "drizzle-kit push" in str(cmd):
                self.add("dbo.01", f"package.json script `{name}` runs drizzle-kit push", file="package.json",
                         fix_hint="drizzle-kit generate in development, drizzle-kit migrate when deploying")
        workflows = [b / ".github" / "workflows" for b in repo_paths(self.root)]
        ci_text = []
        for wf_dir in workflows:
            if not wf_dir.is_dir():
                continue
            for wf in sorted(wf_dir.glob("*.y*ml")):
                text = wf.read_text(encoding="utf-8", errors="replace")
                ci_text.append(text)
                if m := uses_push.search(text):
                    self.add("dbo.01", "CI workflow runs drizzle-kit push", file=f".github/workflows/{wf.name}",
                             line=text.count("\n", 0, m.start()) + 1, fix_hint="Apply migrations with drizzle-kit migrate")
        for rel in files:
            if DOCKERFILE.search(rel):
                text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
                if m := uses_push.search(text):
                    self.add("dbo.01", "Dockerfile runs drizzle-kit push", file=rel, line=text.count("\n", 0, m.start()) + 1,
                             fix_hint="Run drizzle-kit migrate as a release step, not push")
        if self.uses_drizzle and ci_text:
            joined = "\n".join(ci_text)
            if "drizzle-kit check" not in joined and not any(re.search(rf"\brun\s+{re.escape(n)}\b", joined) for n in check_scripts):
                self.add("dbo.02", "CI doesn't run drizzle-kit check on migration history", file=".github/workflows",
                         fix_hint="Add a step: npx drizzle-kit check")

    # ------------------------------------------------------------- dbo.03 / dbo.04
    def connection_strings(self, files: list[str]) -> None:
        for rel in files:
            name = PurePosixPath(rel).name
            if not (EXAMPLE_ENV.search(rel) or COMPOSE.search(rel) or re.match(r"drizzle\.config\.", name)
                    or re.search(r"\.(ts|js|mjs|cjs)$", rel)):
                continue
            if re.search(r"(^|/)\.env($|\.local$|\.production$|\.development$)", rel):
                continue  # real env files are never read
            text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            for m in PG_URL.finditer(text):
                user, host = m.group(1), m.group(2)
                line = text.count("\n", 0, m.start()) + 1
                if "${" in host or host.startswith("$"):
                    continue
                if re.search(r"[?&](sslmode=disable|ssl=false)\b", m.group(0)) and not is_local(host):
                    self.add("dbo.03", f"Connection to remote host `{host}` disables SSL", file=rel, line=line,
                             fix_hint="sslmode=require (or verify-full with the provider's CA)")
                # Local development examples commonly use the superuser; deployment compose files and remote hosts shouldn't.
                deploy_compose = COMPOSE.search(rel) and not DEV_FILE.search(name)
                if user == "postgres" and (deploy_compose or not is_local(host)):
                    self.add("dbo.04", "Connection string uses the `postgres` superuser", file=rel, line=line,
                             fix_hint="Create a dedicated app role with access to its own schema only")
            if re.search(r"\.(ts|js|mjs|cjs)$", rel):
                for m in re.finditer(r"rejectUnauthorized\s*:\s*false", text):
                    self.add("dbo.03", "SSL certificate verification is turned off (rejectUnauthorized: false)", file=rel,
                             line=text.count("\n", 0, m.start()) + 1, severity="info",
                             fix_hint="Verify the server certificate: pass the provider's CA instead")

    # ------------------------------------------------------------- dbo.05 / dbo.06
    def pools_and_seeds(self) -> None:
        for f in self.files:
            if not DB_CLIENT.search(f.code_nostr):
                continue
            route = re.search(r"(^|/)(route|page|layout)\.[jt]sx?$", f.rel) is not None
            for fn in functions(f):
                handler = (route and (fn.exported or fn.name.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"})) \
                    or fn.has_use_server or (f.directive == "server" and fn.exported)
                body = f.code_nostr[fn.body_start: fn.body_end]
                if handler and (m := DB_CLIENT.search(body)):
                    self.add("dbo.05", f"`{fn.name or 'handler'}` creates a database client on every call", f, fn.body_start + m.start(),
                             fix_hint="Create the client once in lib/db.ts (module scope) and import it")
        for f in self.files:
            if SEED_FILE.search(f.rel) and re.search(r"\.insert\s*\(|INSERT\s+INTO", f.code, re.I) and not PROD_GUARD.search(f.code):
                self.add("dbo.06", "Seed script has no guard against running in production", f, 0,
                         fix_hint="if (process.env.NODE_ENV === 'production') throw new Error('refusing to seed production')")


if __name__ == "__main__":
    run_main(DbOpsAudit, __file__, __doc__)
