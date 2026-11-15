#!/usr/bin/env python3
"""Find the OWASP cheat sheet sections most relevant to a query (read-only).

    python find_sheets.py "csrf server actions"            [--top 8] [--stack-root REPO]
    python find_sheets.py --asvs V3.3                       # sheets mapped to an ASVS 5.0 section/chapter
    python find_sheets.py --top10 A01                       # sheets mapped to a Top 10 2021 category
    common: [--clone PATH] [--data-dir DIR] [--format md|json]

Results cite sheet + section + anchor + published URL. Read a hit with read_section.py.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.owasp import OwaspError, load_catalog, resolve_clone, resolve_data_dir, section_url

STOPWORDS = {
    "a", "an", "and", "the", "to", "of", "in", "for", "on", "with", "how", "do", "i", "is", "are", "what",
    "should", "my", "we", "our", "best", "practice", "practices", "security", "secure", "app", "apps",
    "using", "use", "about", "owasp", "cheat", "sheet", "vs", "or", "it", "be", "can",
}
SYNONYMS = {
    "csrf": ["cross-site request forgery", "csrf"],
    "xss": ["cross site scripting", "cross-site scripting", "xss"],
    "sqli": ["sql injection"],
    "ssrf": ["server side request forgery", "server-side request forgery", "ssrf"],
    "idor": ["insecure direct object reference", "idor"],
    "jwt": ["json web token", "jwt"],
    "csp": ["content security policy", "csp"],
    "mfa": ["multifactor", "multi-factor", "mfa", "2fa"],
    "2fa": ["multifactor", "multi-factor", "mfa", "2fa"],
    "cors": ["cors", "cross-origin resource sharing"],
    "sbom": ["sbom", "software bill of materials"],
    "rce": ["command injection", "remote code execution"],
    "dos": ["denial of service"],
    "ddos": ["denial of service"],
    "mcp": ["mcp", "model context protocol"],
    "llm": ["llm", "prompt injection", "large language model"],
    "nextjs": ["next.js", "nextjs"],
    "next.js": ["next.js", "nextjs"],
    "node": ["node.js", "nodejs"],
    "k8s": ["kubernetes"],
    "pkce": ["pkce", "proof key"],
    "hsts": ["strict transport security", "hsts"],
}
STACK_BOOST = {
    "next": ["Nextjs_Security", "Nodejs_Security", "NPM_Security", "JavaScript_and_TypeScript_Security", "React_Security"],
    "docker": ["Docker_Security", "NodeJS_Docker"],
    "ci": ["GitHub_Actions_Security", "CI_CD_Security"],
}


def query_terms(query: str) -> list[list[str]]:
    """Each element is a group of alternatives; a group matches if any alternative matches."""
    groups = []
    words = re.findall(r"[\w.+-]+", query.lower())
    for w in words:
        w = w.strip(".")
        if not w or w in STOPWORDS or len(w) < 2:
            continue
        alts = SYNONYMS.get(w, [w])
        if w not in alts:
            alts = [w] + alts
        groups.append(alts)
    return groups


def stack_boosts(root: str | None) -> set[str]:
    if not root:
        return set()
    from wclib.stack import detect_stack

    p = detect_stack(root)
    boosted: set[str] = set()
    if p.has("next") or p.has("react"):
        boosted |= set(STACK_BOOST["next"])
    if p.docker["dockerfiles"] or p.docker["compose"]:
        boosted |= set(STACK_BOOST["docker"])
    if p.ci["github_actions"]:
        boosted |= set(STACK_BOOST["ci"])
    return boosted


def search(catalog: dict, clone: Path, query: str, top: int, boosted: set[str]) -> list[dict]:
    groups = query_terms(query)
    if not groups:
        return []
    hits = []
    for sid, sheet in catalog["sheets"].items():
        title_l = sheet["title"].lower() + " " + sid.lower().replace("_", " ")
        title_groups = sum(1 for g in groups if any(a in title_l for a in g))
        try:
            lines = (clone / sheet["path"]).read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            continue
        secs = sheet["sections"]
        for idx, sec in enumerate(secs):
            if sec["level"] < 2:
                continue
            # own text: until the next heading of any level
            own_end = secs[idx + 1]["line_start"] - 1 if idx + 1 < len(secs) else len(lines)
            body = "\n".join(lines[sec["line_start"] : own_end]).lower()
            heading_l = sec["heading"].lower()
            parents = " ".join(s["heading"].lower() for s in secs[:idx] if s["level"] < sec["level"])
            score, matched = 0.0, 0
            for g in groups:
                g_score = 0.0
                if any(a in heading_l for a in g):
                    g_score += 4
                elif any(a in parents for a in g):
                    g_score += 1.5
                count = sum(body.count(a) for a in g)
                g_score += min(math.log1p(count), 3.0)
                if g_score > 0:
                    matched += 1
                score += g_score
            if matched == 0:
                continue
            score += 3 * title_groups
            score *= (matched / len(groups)) ** 1.5      # reward covering all terms
            if sid in boosted:
                score *= 1.3
            if sheet["status"] == "draft":
                score *= 0.85
            snippet = ""
            for raw in lines[sec["line_start"] : own_end]:
                low = raw.lower()
                if raw.strip() and not raw.startswith("#") and any(a in low for g in groups for a in g):
                    snippet = re.sub(r"\s+", " ", raw.strip())[:180]
                    break
            hits.append({
                "sheet": sid, "title": sheet["title"], "status": sheet["status"],
                "section": sec["heading"], "anchor": sec["anchor"], "level": sec["level"],
                "url": section_url(sheet, sec), "score": round(score, 2), "snippet": snippet,
                "words": sec["words"],
            })
    hits.sort(key=lambda h: -h["score"])
    out, per_sheet = [], {}
    for h in hits:
        if per_sheet.get(h["sheet"], 0) >= 3:
            continue
        per_sheet[h["sheet"]] = per_sheet.get(h["sheet"], 0) + 1
        out.append(h)
        if len(out) >= top:
            break
    return out


def mapping_lookup(catalog: dict, asvs: str | None, top10: str | None) -> dict:
    m = catalog["mappings"]
    if asvs:
        code = asvs.upper()
        chapter = code.split(".")[0]
        ch = m["asvs5"].get(chapter)
        if not ch:
            raise OwaspError(f"ASVS chapter {chapter} not in IndexASVS.md")
        if "." in code:
            sec = ch["sections"].get(code)
            if not sec:
                raise OwaspError(f"ASVS section {code} not in IndexASVS.md")
            return {"kind": "ASVS 5.0", "code": code, "title": sec["title"], "sections": {code: sec}}
        return {"kind": "ASVS 5.0", "code": chapter, "title": ch["title"], "sections": ch["sections"]}
    code = top10.upper()
    cat = m["top10_2021"].get(code)
    if not cat:
        raise OwaspError(f"Top 10 category {code} not in IndexTopTen.md (2021 edition)")
    return {"kind": f"OWASP Top 10 {cat['year']}", "code": code, "title": cat["title"], "sections": {code: cat}}


def render_mapping_md(res: dict, catalog: dict) -> str:
    out = [f"# {res['kind']} {res['code']}: {res['title']}", ""]
    for code, sec in res["sections"].items():
        out.append(f"## {code} {sec['title']}")
        for sid in sec["sheets"]:
            sheet = catalog["sheets"].get(sid)
            label = f"{sheet['title']} ({sheet['status']})" if sheet else f"{sid} (NOT IN CLONE)"
            out.append(f"- `{sid}`: {label}" + (f" <{sheet['url']}>" if sheet and sheet.get("url") else ""))
        out.append("")
    src = catalog["source"]
    out.append(f"_Source: OWASP Cheat Sheet Series index files @ {(src.get('commit') or '?')[:7]}_")
    return "\n".join(out)


def render_hits_md(query: str, hits: list[dict], catalog: dict) -> str:
    src = catalog["source"]
    out = [f"# OWASP sections for: {query}", ""]
    if not hits:
        out.append("No matching sections. Try different terms or a sheet name, e.g. `read_section.py --list --sheet Session_Management`.")
    for i, h in enumerate(hits, 1):
        draft = " **(draft, not yet reviewed by OWASP)**" if h["status"] == "draft" else ""
        out.append(f"{i}. **{h['title']}** › {h['section']}{draft}")
        out.append(f"   - read: `read_section.py --sheet {h['sheet']} --anchor {h['anchor']}` ({h['words']} words)")
        if h["url"]:
            out.append(f"   - cite: <{h['url']}>")
        if h["snippet"]:
            out.append(f"   - “{h['snippet']}”")
    out += ["", f"_OWASP Cheat Sheet Series @ {(src.get('commit') or '?')[:7]} ({(src.get('commit_date') or '')[:10]}), CC BY-SA 4.0_"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("query", nargs="?", help="Free-text query")
    ap.add_argument("--asvs", help="ASVS 5.0 chapter or section, e.g. V3 or V3.3")
    ap.add_argument("--top10", help="Top 10 2021 category, e.g. A01")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--stack-root", help="Boost sheets matching this project's stack")
    ap.add_argument("--clone")
    ap.add_argument("--data-dir")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args()
    if not (args.query or args.asvs or args.top10):
        ap.error("give a query, --asvs, or --top10")
    try:
        clone = resolve_clone(args.clone)
        catalog = load_catalog(resolve_data_dir(args.data_dir), clone)
        if args.asvs or args.top10:
            res = mapping_lookup(catalog, args.asvs, args.top10)
            print(json.dumps(res, indent=2) if args.format == "json" else render_mapping_md(res, catalog))
            return 0
        hits = search(catalog, clone, args.query, args.top, stack_boosts(args.stack_root))
    except OwaspError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"query": args.query, "source": catalog["source"], "hits": hits}, indent=2)
          if args.format == "json" else render_hits_md(args.query, hits, catalog))
    return 0


if __name__ == "__main__":
    sys.exit(main())
