"""SQL migration discovery and parsing for PostgreSQL. Static and read-only: nothing connects to a database.

Finds migrations from Drizzle Kit (both layouts: `<out>/<timestamp>_<name>/migration.sql` and
`<out>/NNNN_<name>.sql` + `<out>/meta/_journal.json`), Prisma (`prisma/migrations/*/migration.sql`), Supabase
and generic `migrations/` folders, then splits them into statements with comments and quoted text masked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DRIZZLE_CONFIG = re.compile(r"(^|/)drizzle\.config\.(ts|js|mjs|cjs|mts)$")
GENERIC = re.compile(r"(^|/)(prisma/migrations/[^/]+/migration\.sql|supabase/migrations/[^/]+\.sql|"
                     r"(db/)?migrations/(.+/)?[^/]+\.sql)$")


@dataclass
class Migration:
    rel: str
    tool: str        # drizzle | drizzle-legacy | prisma | sql
    out_dir: str     # folder the tool owns ("" for generic)


@dataclass
class Statement:
    offset: int      # into the original text
    sql: str         # comment- and string-masked, original length
    raw: str


def drizzle_out_dirs(root: Path, files: list[str]) -> list[str]:
    """`out` folders from drizzle.config.* files (default `drizzle`), relative to root."""
    outs = []
    for rel in files:
        if not DRIZZLE_CONFIG.search(rel):
            continue
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        m = re.search(r"""\bout\s*:\s*['"`]([^'"`]+)['"`]""", text)
        base = PurePosixPath(rel).parent
        out = str(PurePosixPath(base, (m.group(1) if m else "drizzle")))
        outs.append(re.sub(r"^\./|/$", "", out.replace("/./", "/")).lstrip("./") or "drizzle")
    return sorted(set(outs))


def find_migrations(root: Path, files: list[str]) -> list[Migration]:
    out_dirs = drizzle_out_dirs(root, files)
    found: dict[str, Migration] = {}
    for rel in files:
        if not rel.endswith(".sql"):
            continue
        owner = next((d for d in out_dirs if rel.startswith(d + "/")), None)
        if owner:
            inner = rel[len(owner) + 1:]
            if re.fullmatch(r"[^/]+/migration\.sql", inner):
                found[rel] = Migration(rel, "drizzle", owner)
            elif "/" not in inner:
                found[rel] = Migration(rel, "drizzle-legacy", owner)
        elif GENERIC.search(rel):
            found[rel] = Migration(rel, "prisma" if "prisma/migrations/" in rel else "sql", "")
    return sorted(found.values(), key=lambda m: m.rel)


def mask_sql(text: str) -> str:
    """Blank comments, string literals and dollar-quoted bodies, keeping length and newlines (for line numbers)."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "--":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text[i] == "'":
            j = i + 1
            while j < n and not (text[j] == "'" and text[j + 1: j + 2] != "'"):
                j += 2 if text[j:j + 2] == "''" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif text[i] == "$":  # dollar-quoted bodies ($$ ... $$, $tag$ ... $tag$)
            m = re.match(r"\$([A-Za-z_]\w*)?\$", text[i:])
            if m:
                tag = m.group(0)
                j = text.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                for k in range(i + len(tag), max(i + len(tag), j - len(tag))):
                    if out[k] != "\n":
                        out[k] = " "
                i = j
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def statements(text: str) -> list[Statement]:
    masked = mask_sql(text)
    out, start = [], 0
    for m in re.finditer(";", masked):
        if masked[start:m.start()].strip():
            lead = len(masked[start:m.start()]) - len(masked[start:m.start()].lstrip())
            out.append(Statement(start + lead, masked[start + lead:m.start()], text[start + lead:m.start()]))
        start = m.end()
    if masked[start:].strip():
        lead = len(masked[start:]) - len(masked[start:].lstrip())
        out.append(Statement(start + lead, masked[start + lead:], text[start + lead:]))
    return out


def table_name(ident: str) -> str:
    """'"public"."Users"' -> 'users'; unquoted names fold to lower case like Postgres does."""
    parts = re.findall(r'"((?:[^"]|"")+)"|([\w$]+)', ident)
    last = parts[-1] if parts else ("", ident)
    return (last[0].replace('""', '"') if last[0] else last[1].lower())


IDENT = r'(?:"(?:[^"]|"")+"|[\w$]+)(?:\s*\.\s*(?:"(?:[^"]|"")+"|[\w$]+))?'


def journal_problems(root: Path, out_dir: str) -> list[str]:
    """Older Drizzle layout: SQL files vs meta/_journal.json entries."""
    journal = root / out_dir / "meta" / "_journal.json"
    if not journal.is_file():
        return []
    try:
        tags = [e["tag"] for e in json.loads(journal.read_text(encoding="utf-8")).get("entries", [])]
    except (ValueError, KeyError, TypeError):
        return [f"{out_dir}/meta/_journal.json is not valid JSON"]
    files = {p.stem for p in (root / out_dir).glob("*.sql")}
    problems = [f"{out_dir}/{t}.sql is listed in meta/_journal.json but missing" for t in tags if t not in files]
    problems += [f"{out_dir}/{s}.sql is not listed in meta/_journal.json (it will never run)" for s in sorted(files - set(tags))]
    return problems
