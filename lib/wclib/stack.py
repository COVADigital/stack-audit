"""Project stack detection.

Produces a JSON-serialisable profile that audit scripts use to switch rules on
and off (e.g. Next >= 16 -> proxy.ts / preload / revalidateTag(tag, profile);
cacheComponents -> 'use cache' advice instead of segment config).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .textutil import mask_js
from .walker import repo_paths

# package name -> profile key
TRACKED_PACKAGES = {
    "next": "next",
    "react": "react",
    "react-dom": "react-dom",
    "typescript": "typescript",
    "zod": "zod",
    "tailwindcss": "tailwindcss",
    "drizzle-orm": "drizzle-orm",
    "prisma": "prisma",
    "@prisma/client": "@prisma/client",
    "better-auth": "better-auth",
    "next-auth": "next-auth",
    "@auth/core": "@auth/core",
    "@clerk/nextjs": "@clerk/nextjs",
    "next-intl": "next-intl",
    "next-i18next": "next-i18next",
    "react-i18next": "react-i18next",
    "@lingui/core": "@lingui/core",
    "@tanstack/react-query": "@tanstack/react-query",
    "swr": "swr",
    "zustand": "zustand",
    "jotai": "jotai",
    "@reduxjs/toolkit": "@reduxjs/toolkit",
    "xstate": "xstate",
    "nuqs": "nuqs",
    "react-hook-form": "react-hook-form",
    "sanity": "sanity",
    "next-sanity": "next-sanity",
    "@serwist/next": "@serwist/next",
    "next-pwa": "next-pwa",
    "framer-motion": "framer-motion",
    "motion": "motion",
    "gsap": "gsap",
    "three": "three",
    "@upstash/ratelimit": "@upstash/ratelimit",
    "isomorphic-dompurify": "isomorphic-dompurify",
    "dompurify": "dompurify",
    "babel-plugin-react-compiler": "babel-plugin-react-compiler",
    "eslint": "eslint",
    "@playwright/test": "@playwright/test",
    "@axe-core/playwright": "@axe-core/playwright",
    "web-vitals": "web-vitals",
    "@vercel/speed-insights": "@vercel/speed-insights",
    "@sentry/nextjs": "@sentry/nextjs",
}

CATEGORIES = {
    "orm": ["drizzle-orm", "@prisma/client", "prisma"],
    "auth": ["better-auth", "next-auth", "@auth/core", "@clerk/nextjs"],
    "i18n": ["next-intl", "next-i18next", "react-i18next", "@lingui/core"],
    "serverState": ["@tanstack/react-query", "swr"],
    "clientState": ["zustand", "jotai", "@reduxjs/toolkit", "xstate"],
    "cms": ["next-sanity", "sanity"],
    "pwa": ["@serwist/next", "next-pwa"],
    "motion": ["motion", "framer-motion", "gsap"],
    "rum": ["web-vitals", "@vercel/speed-insights", "@sentry/nextjs"],
}

NEXT_CONFIG_NAMES = ("next.config.ts", "next.config.mjs", "next.config.js", "next.config.cjs", "next.config.mts")


@dataclass
class PackageInfo:
    name: str
    declared: str | None = None
    installed: str | None = None
    dev: bool = False

    @property
    def version(self) -> str | None:
        return self.installed or _clean_range(self.declared)

    @property
    def major(self) -> int | None:
        return major_of(self.version)


@dataclass
class StackProfile:
    root: str
    has_package_json: bool = False
    package_manager: str | None = None
    workspaces: list[str] = field(default_factory=list)
    packages: dict[str, dict] = field(default_factory=dict)
    categories: dict[str, str | None] = field(default_factory=dict)
    router: dict[str, str | None] = field(default_factory=dict)
    next_config: dict = field(default_factory=dict)
    request_interceptor: str | None = None  # proxy.ts | middleware.ts | None
    docker: dict = field(default_factory=dict)
    ci: dict = field(default_factory=dict)
    git: bool = False
    notes: list[str] = field(default_factory=list)

    # convenience accessors used by rules -------------------------------
    def major(self, pkg: str) -> int | None:
        info = self.packages.get(pkg)
        return major_of(info.get("version")) if info else None

    def has(self, pkg: str) -> bool:
        return pkg in self.packages

    @property
    def next_major(self) -> int | None:
        return self.major("next")

    @property
    def cache_components(self) -> bool:
        return bool(self.next_config.get("cacheComponents"))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _clean_range(spec: str | None) -> str | None:
    if not spec:
        return None
    if spec.startswith(("workspace:", "file:", "link:", "git", "http", "npm:")) or spec in ("*", "latest"):
        return None
    m = re.search(r"\d+(?:\.\d+){0,2}", spec)
    return m.group(0) if m else None


def major_of(version: str | None) -> int | None:
    if not version:
        return None
    m = re.match(r"\s*v?(\d+)", version)
    return int(m.group(1)) if m else None


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _installed_from_lock(root: Path, pm: str | None, names: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    if pm == "npm":
        lock = _read_json(root / "package-lock.json") or {}
        pkgs = lock.get("packages", {})
        for n in names:
            entry = pkgs.get(f"node_modules/{n}")
            if isinstance(entry, dict) and entry.get("version"):
                found[n] = entry["version"]
    elif pm == "pnpm":
        try:
            text = (root / "pnpm-lock.yaml").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return found
        for n in names:
            # importers section: "      next:\n        specifier: ^16\n        version: 16.1.0(...)"
            m = re.search(
                rf"^\s+'?{re.escape(n)}'?:\s*\n\s+specifier:.*\n\s+version:\s*'?([0-9][^\s('\"]*)",
                text, re.M,
            )
            if m:
                found[n] = m.group(1)
    elif pm == "yarn":
        try:
            text = (root / "yarn.lock").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return found
        for n in names:
            m = re.search(rf'^"?{re.escape(n)}@[^\n]*:\s*\n\s+version:?\s+"?([0-9][^"\s]*)', text, re.M)
            if m:
                found[n] = m.group(1)
    elif pm == "bun":
        pass  # bun.lockb is binary; bun.lock (text) parsing not needed for v1
    return found


def _installed_from_node_modules(root: Path, names: list[str]) -> dict[str, str]:
    found = {}
    for n in names:
        pj = _read_json(root / "node_modules" / n / "package.json")
        if pj and pj.get("version"):
            found[n] = pj["version"]
    return found


def _detect_pm(root: Path) -> str | None:
    for fname, pm in (
        ("pnpm-lock.yaml", "pnpm"), ("package-lock.json", "npm"), ("yarn.lock", "yarn"),
        ("bun.lock", "bun"), ("bun.lockb", "bun"),
    ):
        if (root / fname).exists():
            return pm
    return None


def _flag(pattern: str, text: str) -> bool:
    return re.search(pattern, text) is not None


def _parse_next_config(root: Path) -> dict:
    for name in NEXT_CONFIG_NAMES:
        path = root / name
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text = mask_js(raw, comments=True, strings=False, jsx=False)
            out_m = re.search(r"\boutput\s*:\s*['\"](\w+)['\"]", text)
            return {
                "file": name,
                "cacheComponents": _flag(r"\bcacheComponents\s*:\s*true\b", text),
                "ppr": _flag(r"\bppr\s*:\s*(true|['\"]incremental['\"])", text),
                "reactCompiler": _flag(r"\breactCompiler\s*:\s*(true|\{)", text),
                "output": out_m.group(1) if out_m else None,
                "productionBrowserSourceMaps": _flag(r"\bproductionBrowserSourceMaps\s*:\s*true\b", text),
                "headers": _flag(r"\b(async\s+)?headers\s*\(\s*\)|\bheaders\s*:", text),
                "images": _flag(r"\bimages\s*:", text),
                "poweredByHeaderDisabled": _flag(r"\bpoweredByHeader\s*:\s*false\b", text),
                "eslintKey": _flag(r"\beslint\s*:\s*\{", text),
            }
    return {}


def _first_existing(root: Path, candidates: list[str]) -> str | None:
    for c in candidates:
        if (root / c).exists():
            return c
    return None


def detect_stack(root: str | Path) -> StackProfile:
    root = Path(root).resolve()
    prof = StackProfile(root=str(root))
    prof.git = (root / ".git").exists()
    pm = _detect_pm(root)
    prof.package_manager = pm

    pkg = _read_json(root / "package.json")
    if pkg is not None:
        prof.has_package_json = True
        ws = pkg.get("workspaces")
        if isinstance(ws, dict):
            ws = ws.get("packages")
        if isinstance(ws, list):
            prof.workspaces = [w for w in ws if isinstance(w, str)]
        if (root / "pnpm-workspace.yaml").exists():
            try:
                pw = (root / "pnpm-workspace.yaml").read_text(encoding="utf-8")
                prof.workspaces += re.findall(r"^\s*-\s*['\"]?([^'\"\n]+)['\"]?\s*$", pw, re.M)
            except OSError:
                pass

        infos: dict[str, PackageInfo] = {}
        for section, dev in (("dependencies", False), ("devDependencies", True), ("peerDependencies", False)):
            for name, spec in (pkg.get(section) or {}).items():
                if name in TRACKED_PACKAGES and name not in infos:
                    infos[name] = PackageInfo(name=name, declared=str(spec), dev=dev)

        names = list(infos)
        installed = _installed_from_node_modules(root, names)
        missing = [n for n in names if n not in installed]
        if missing:
            installed.update(_installed_from_lock(root, pm, missing))
        for n, v in installed.items():
            infos[n].installed = v

        for n, info in infos.items():
            prof.packages[n] = {
                "declared": info.declared,
                "installed": info.installed,
                "version": info.version,
                "major": info.major,
                "dev": info.dev,
            }
        if prof.workspaces and not infos.get("next"):
            prof.notes.append(
                "Monorepo detected and no 'next' dependency at root: run against each app directory (e.g. apps/web)."
            )
        scripts = pkg.get("scripts") or {}
        if any("next lint" in str(v) for v in scripts.values()):
            prof.notes.append("package.json script uses `next lint` (removed in Next.js 16).")
    else:
        prof.notes.append("No package.json at root.")

    for cat, pkgs in CATEGORIES.items():
        prof.categories[cat] = next((p for p in pkgs if p in prof.packages), None)

    app_dir = _first_existing(root, ["src/app", "app"])
    pages_dir = _first_existing(root, ["src/pages", "pages"])
    prof.router = {"app": app_dir, "pages": pages_dir}
    prof.next_config = _parse_next_config(root)

    proxy = _first_existing(root, ["proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"])
    middleware = _first_existing(root, ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"])
    prof.request_interceptor = proxy or middleware
    if middleware and (prof.next_major or 0) >= 16:
        prof.notes.append(f"{middleware} on Next.js {prof.next_major}: renamed to proxy.ts in Next.js 16 (middleware is deprecated).")

    dockerfiles = sorted(p.name for p in root.glob("Dockerfile*") if p.is_file())
    dockerfiles += sorted(
        p.relative_to(root).as_posix() for p in root.glob("*/Dockerfile*") if p.is_file() and "node_modules" not in p.parts
    )
    compose = sorted(
        p.name for pat in ("compose*.yaml", "compose*.yml", "docker-compose*.yaml", "docker-compose*.yml")
        for p in root.glob(pat) if p.is_file()
    )
    prof.docker = {
        "dockerfiles": dockerfiles,
        "compose": compose,
        "dockerignore": (root / ".dockerignore").exists(),
    }
    places = repo_paths(root)  # app dir, plus the git toplevel in monorepos
    if len(places) > 1:
        prof.notes.append(f"App is inside a larger git repo ({places[1]}): repo-level files are read from there too.")

    def any_exists(*rels: str) -> bool:
        return any((b / r).exists() for b in places for r in rels)

    workflows_dir = next((b / ".github" / "workflows" for b in places if (b / ".github" / "workflows").is_dir()), None)
    prof.ci = {
        "github_actions": sorted(p.name for p in workflows_dir.glob("*.y*ml")) if workflows_dir else [],
        "dependabot": any_exists(".github/dependabot.yml", ".github/dependabot.yaml"),
        "codeowners": any_exists(".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"),
        "lighthouserc": any_exists("lighthouserc.json", "lighthouserc.js", ".lighthouserc.json", "lighthouserc.cjs"),
    }
    if not compose:
        prof.docker["compose"] = sorted(
            p.relative_to(places[-1]).as_posix() if len(places) > 1 else p.name
            for b in places[1:] for pat in ("compose*.yaml", "compose*.yml", "docker-compose*.yaml", "docker-compose*.yml")
            for p in b.glob(pat) if p.is_file()
        )
    return prof
