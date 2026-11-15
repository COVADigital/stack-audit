"""OWASP Cheat Sheet Series: clone discovery, catalog build/load, section access.

The catalog is derived data (headings, anchors, mappings, technology tags; no
prose) generated from a local clone of github.com/OWASP/CheatSheetSeries
(CC BY-SA 4.0). It lives in the plugin data dir, never inside the plugin.
"""

from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from .walker import run_git

CATALOG_SCHEMA = 2
SITE = "https://cheatsheetseries.owasp.org/cheatsheets/"
DEFAULT_CLONE = Path.home() / ".claude" / "data" / "owasp-cheatsheets"
DEFAULT_DATA = Path.home() / ".claude" / "plugins" / "data" / "stack-audit"
SHEET_SUFFIX = "_Cheat_Sheet"

_FENCE = re.compile(r"^\s{0,3}(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_SHEET_LINK = re.compile(r"\]\((?:\.\./)?cheatsheets(?:_draft)?/([\w.-]+?)\.md(?:#[\w-]+)?\)")


class OwaspError(RuntimeError):
    pass


# ----------------------------------------------------------------- locations

def resolve_clone(explicit: str | Path | None = None, config: dict | None = None) -> Path:
    """Find the CheatSheetSeries clone: explicit > $STACK_AUDIT_OWASP_CHEATSHEETS > config > default."""
    candidates = [
        explicit,
        os.environ.get("STACK_AUDIT_OWASP_CHEATSHEETS"),
        ((config or {}).get("owasp") or {}).get("cheatsheetsPath"),
        DEFAULT_CLONE,
    ]
    tried = []
    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser().resolve()
        tried.append(str(p))
        if (p / "cheatsheets").is_dir() and (p / "Index.md").exists():
            return p
    raise OwaspError(
        "OWASP CheatSheetSeries clone not found. Tried: " + ", ".join(tried) + ". "
        f"Clone it yourself with: git clone https://github.com/OWASP/CheatSheetSeries.git \"{DEFAULT_CLONE}\" "
        "(or pass --clone PATH)."
    )


def clone_age_days(clone: Path) -> int | None:
    """Days since the clone was last cloned or fetched (local file times only; no network)."""
    git_dir = Path(clone) / ".git"
    times = [f.stat().st_mtime for f in (git_dir / "FETCH_HEAD", git_dir / "HEAD") if f.exists()]
    return int((time.time() - max(times)) // 86400) if times else None


def update_clone(clone: Path, timeout: int = 20) -> bool:
    """Fast-forward the clone from its remote (network). True on success."""
    return run_git(Path(clone), "pull", "--ff-only", "--quiet", timeout=timeout) is not None


def resolve_data_dir(explicit: str | Path | None = None) -> Path:
    d = Path(explicit or os.environ.get("CLAUDE_PLUGIN_DATA") or DEFAULT_DATA).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


# ----------------------------------------------------------------- slugs

def slugify(text: str) -> str:
    """Python-Markdown toc default slugify (what the published site uses)."""
    value = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def heading_text(raw: str) -> str:
    """Rendered text of a markdown heading: links -> label, strip code/emphasis markers."""
    text = _LINK.sub(r"\1", raw)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("`", "")
    text = re.sub(r"(\*\*|__)(.+?)\1", r"\2", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"\1", text)
    return text.strip()


def sheet_id_from_name(name: str) -> str:
    """'Nextjs_Security' or 'Nextjs_Security_Cheat_Sheet' -> 'Nextjs_Security'."""
    name = name.strip().removesuffix(".md").removesuffix(".html")
    return name[: -len(SHEET_SUFFIX)] if name.lower().endswith(SHEET_SUFFIX.lower()) else name


# ----------------------------------------------------------------- parsing

def parse_sections(text: str) -> tuple[str, list[dict]]:
    """Return (title, sections). Skips fenced code. Anchors deduplicated like toc (_1, _2)."""
    lines = text.split("\n")
    in_fence = False
    fence_marker = ""
    raw: list[dict] = []
    title = ""
    seen: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        m = _FENCE.match(line)
        if m:
            if not in_fence:
                in_fence, fence_marker = True, m.group(1)
            elif m.group(1) == fence_marker:
                in_fence = False
            continue
        if in_fence:
            continue
        h = _HEADING.match(line)
        if not h:
            continue
        level = len(h.group(1))
        text_h = heading_text(h.group(2))
        if level == 1 and not title:
            title = text_h
        slug = slugify(text_h)
        if slug in seen:
            seen[slug] += 1
            anchor = f"{slug}_{seen[slug]}"
        else:
            seen[slug] = 0
            anchor = slug
        raw.append({"level": level, "heading": text_h, "anchor": anchor, "line_start": i})
    # compute section ends (next heading of same or higher level)
    for idx, sec in enumerate(raw):
        end = len(lines)
        for nxt in raw[idx + 1 :]:
            if nxt["level"] <= sec["level"]:
                end = nxt["line_start"] - 1
                break
        sec["line_end"] = end
        body = "\n".join(lines[sec["line_start"] : end])
        sec["words"] = len(re.findall(r"\w+", body))
    return title, raw


def _sheet_links(block: str) -> list[str]:
    out = []
    for name in _SHEET_LINK.findall(block):
        sid = sheet_id_from_name(name)
        if sid not in out:
            out.append(sid)
    return out


def parse_asvs_index(text: str) -> dict:
    """IndexASVS.md (ASVS 5.0.x): '### V1.1 Title' blocks followed by sheet links."""
    result: dict = {}
    parts = re.split(r"^(#{2,3}) +(.+)$", text, flags=re.M)
    # parts: [pre, hashes, title, body, hashes, title, body, ...]
    for k in range(1, len(parts) - 2, 3):
        title, body = parts[k + 1].strip(), parts[k + 2]
        m = re.match(r"(V\d+(?:\.\d+)?)[:.]?\s*:?\s*(.*)", title)
        if not m:
            continue
        code, name = m.group(1), m.group(2).strip(" :")
        if "." not in code:  # upstream sometimes uses ## for sections (V17.2), so decide by the code
            result.setdefault(code, {"title": name, "sections": {}})
        elif code.split(".")[0] in result:
            result[code.split(".")[0]]["sections"][code] = {"title": name, "sheets": _sheet_links(body)}
    return result


def parse_top10_index(text: str) -> dict:
    """IndexTopTen.md: '## [A01:2021 – Name](url)' blocks (title may wrap lines)."""
    result: dict = {}
    blocks = re.split(r"^## ", text, flags=re.M)[1:]
    for block in blocks:
        m = re.match(r"\[(A\d{2}):(\d{4})\s*[–-]\s*(.+?)\]\(", block, re.S)
        if not m:
            continue
        code, year, name = m.group(1), m.group(2), " ".join(m.group(3).split())
        if int(code[1:]) > 10:  # "A11 Next Steps" is commentary, not a category
            continue
        result[code] = {"year": year, "title": name, "sheets": _sheet_links(block.split("\n", 1)[-1] if "\n" in block else "")}
    return result


def parse_proactive_index(text: str) -> dict:
    result: dict = {}
    for block in re.split(r"^## ", text, flags=re.M)[1:]:
        m = re.match(r"\[(C\d+)\.\s*(.+?)\]\(", block, re.S)
        if m:
            result[m.group(1)] = {"title": " ".join(m.group(2).split()), "sheets": _sheet_links(block)}
    return result


def parse_technologies(index_text: str) -> dict[str, list[str]]:
    techs: dict[str, list[str]] = {}
    for line in index_text.splitlines():
        if "(assets/Index_" not in line:
            continue
        m = re.search(r"cheatsheets/([\w.-]+?)\.md", line)
        if not m:
            continue
        sid = sheet_id_from_name(m.group(1))
        techs[sid] = re.findall(r"!\[([^\]]+)\]\(assets/Index_", line)
    return techs


# ----------------------------------------------------------------- catalog

def build_catalog(clone: Path) -> dict:
    clone = Path(clone)
    sheets: dict[str, dict] = {}
    for folder, status in (("cheatsheets", "published"), ("cheatsheets_draft", "draft")):
        d = clone / folder
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.md")):
            sid = sheet_id_from_name(path.name)
            text = path.read_text(encoding="utf-8", errors="replace")
            title, sections = parse_sections(text)
            sheets[sid] = {
                "title": title or sid.replace("_", " "),
                "path": f"{folder}/{path.name}",
                "status": status,
                "bytes": path.stat().st_size,
                "url": f"{SITE}{path.stem}.html" if status == "published" else None,
                "technologies": [],
                "sections": sections,
            }
    techs = parse_technologies((clone / "Index.md").read_text(encoding="utf-8", errors="replace"))
    for sid, t in techs.items():
        if sid in sheets:
            sheets[sid]["technologies"] = t

    def read_index(name: str) -> str:
        p = clone / name
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""

    commit = (run_git(clone, "rev-parse", "HEAD") or "").strip() or None
    commit_date = (run_git(clone, "log", "-1", "--format=%cI") or "").strip() or None
    return {
        "schema": CATALOG_SCHEMA,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "attribution": "Derived from the OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org), CC BY-SA 4.0. Headings and anchors only.",
        "source": {"clone": str(clone), "commit": commit, "commit_date": commit_date},
        "sheets": sheets,
        "mappings": {
            "asvs5": parse_asvs_index(read_index("IndexASVS.md")),
            "top10_2021": parse_top10_index(read_index("IndexTopTen.md")),
            "proactive_2018": parse_proactive_index(read_index("IndexProactiveControls.md")),
        },
    }


def catalog_path(data_dir: Path) -> Path:
    return Path(data_dir) / "owasp-catalog.json"


def save_catalog(catalog: dict, data_dir: Path) -> Path:
    p = catalog_path(data_dir)
    p.write_text(json.dumps(catalog, indent=1, ensure_ascii=False), encoding="utf-8")
    return p


def load_catalog(data_dir: Path, clone: Path | None = None, *, rebuild_if_stale: bool = True) -> dict:
    """Load the catalog; (re)build it from `clone` if missing, old-schema, or behind clone HEAD."""
    p = catalog_path(data_dir)
    catalog = None
    if p.exists():
        try:
            catalog = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            catalog = None
    if clone is not None and rebuild_if_stale:
        head = (run_git(clone, "rev-parse", "HEAD") or "").strip() or None
        stale = (
            catalog is None
            or catalog.get("schema") != CATALOG_SCHEMA
            or catalog.get("source", {}).get("clone") != str(Path(clone))
            or (head and catalog.get("source", {}).get("commit") != head)
        )
        if stale:
            catalog = build_catalog(clone)
            save_catalog(catalog, data_dir)
    if catalog is None:
        raise OwaspError(f"No catalog at {p} and no clone to build it from.")
    return catalog


def find_sheet(catalog: dict, name: str) -> str | None:
    """Resolve a user-supplied sheet name (any case, spaces, suffix) to a catalog id."""
    sid = sheet_id_from_name(name.replace(" ", "_"))
    if sid in catalog["sheets"]:
        return sid
    low = {k.lower(): k for k in catalog["sheets"]}
    return low.get(sid.lower()) or low.get(sid.lower().replace("-", "_"))


def section_text(clone: Path, sheet: dict, section: dict) -> str:
    lines = (Path(clone) / sheet["path"]).read_text(encoding="utf-8", errors="replace").split("\n")
    return "\n".join(lines[section["line_start"] - 1 : section["line_end"]]).rstrip()


def section_url(sheet: dict, section: dict | None = None) -> str | None:
    if not sheet.get("url"):
        return None
    return sheet["url"] + (f"#{section['anchor']}" if section and section["level"] > 1 else "")
