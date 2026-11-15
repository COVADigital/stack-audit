"""Next.js App Router helpers: route inventory and special-file lookup."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

PAGE_RE = re.compile(r"(^|/)(page|route|default)\.(tsx|ts|jsx|js|mdx)$")
SPECIAL = ("layout", "loading", "error", "not-found", "template", "global-error")
PRIVATE_SEGMENTS = re.compile(r"(^|/)(\(auth\)|\(admin\)|\(dashboard\)|\(app\)|dashboard|admin|account|settings|editor|login|signup|register|"
                              r"forgot-password|reset-password|verify-email|onboarding|api)(/|$)", re.I)


@dataclass
class Route:
    file: str          # repo-relative path of page.tsx / route.ts
    kind: str          # page | route | default
    url: str           # /blog/[slug]
    segment_dir: str   # repo-relative dir of the file
    chain: list[str] = field(default_factory=list)  # dirs from app root to segment (inclusive)

    @property
    def private(self) -> bool:
        return bool(PRIVATE_SEGMENTS.search(self.url) or PRIVATE_SEGMENTS.search(self.segment_dir))


def url_for(app_dir: str, segment_dir: str) -> str:
    rel = PurePosixPath(segment_dir).relative_to(app_dir).as_posix() if segment_dir != app_dir else ""
    parts = [p for p in rel.split("/") if p and not (p.startswith("(") and p.endswith(")")) and not p.startswith("@")]
    return "/" + "/".join(parts)


def routes(files: list[str], app_dir: str | None) -> list[Route]:
    if not app_dir:
        return []
    out = []
    prefix = app_dir.rstrip("/") + "/"
    for rel in files:
        if not rel.startswith(prefix) or not PAGE_RE.search(rel):
            continue
        seg = rel.rsplit("/", 1)[0]
        if any(part.startswith("_") for part in seg[len(app_dir):].split("/") if part):
            continue  # private folders
        chain, cur = [], seg
        while True:
            chain.append(cur)
            if cur == app_dir or "/" not in cur:
                break
            cur = cur.rsplit("/", 1)[0]
        kind = re.search(PAGE_RE, rel).group(2)
        out.append(Route(rel, kind, url_for(app_dir, seg), seg, list(reversed(chain))))
    return sorted(out, key=lambda r: (r.url, r.kind))


def special_files(files: list[str]) -> dict[str, dict[str, str]]:
    """dir -> {special_name: file} for layout/loading/error/... files."""
    index: dict[str, dict[str, str]] = {}
    for rel in files:
        m = re.search(r"(^|/)(" + "|".join(SPECIAL) + r")\.(tsx|ts|jsx|js)$", rel)
        if m:
            d = rel.rsplit("/", 1)[0] if "/" in rel else ""
            index.setdefault(d, {})[m.group(2)] = rel
    return index


def nearest(route: Route, specials: dict[str, dict[str, str]], name: str) -> str | None:
    for d in reversed(route.chain):
        f = specials.get(d, {}).get(name)
        if f:
            return f
    return None


def chain_files(route: Route, specials: dict[str, dict[str, str]], name: str) -> list[str]:
    return [specials[d][name] for d in route.chain if name in specials.get(d, {})]
