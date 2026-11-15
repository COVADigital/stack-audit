"""Drizzle ORM (drizzle-orm/pg-core) schema parsing: tables, columns, keys and indexes. Static and read-only.

Reads TypeScript source with the comment/string masking from jsscan; it does not execute or type-check anything.
Handles `pgTable`, aliases (`pgTable as table`), namespaces (`p.pgTable`), column chains such as
`integer('author_id').notNull().references(() => users.id, { onDelete: 'cascade' })` and the extra-config
callback `(t) => [index('x').on(t.col), primaryKey({ columns: [...] }), foreignKey({...})]` (array or object form).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .jsscan import JsFile, match_close

PG_CORE = re.compile(r"""from\s*['"]drizzle-orm/pg-core['"]""")


@dataclass
class Column:
    key: str
    sql_name: str
    builder: str       # integer, text, timestamp, ...
    builder_args: str  # raw text inside the builder's parentheses
    chain: str         # the whole column expression
    offset: int


@dataclass
class Table:
    name: str
    offset: int
    columns: list[Column] = field(default_factory=list)
    extra: str = ""

    def column(self, key: str) -> Column | None:
        return next((c for c in self.columns if c.key == key), None)

    @property
    def has_primary_key(self) -> bool:
        return any(".primaryKey(" in c.chain for c in self.columns) or bool(re.search(r"\bprimaryKey\s*\(", self.extra))

    def foreign_keys(self) -> list[tuple[str, bool]]:
        """(first column key, onDelete stated) for each column reference and table-level foreignKey()."""
        out = [(c.key, bool(re.search(r"onDelete", _call_args(c.chain, ".references(")))) for c in self.columns
               if ".references(" in c.chain]
        for m in re.finditer(r"\bforeignKey\s*\(", self.extra):
            close = match_close(self.extra, m.end() - 1)
            args = self.extra[m.end(): close if close != -1 else len(self.extra)]
            first = re.search(r"columns\s*:\s*\[\s*[\w$]+\.([\w$]+)", args)
            # Only the calls chained directly onto this foreignKey(...): .onDelete('cascade').onUpdate(...)
            chained = re.match(r"(?:\s*\.\s*[\w$]+\s*\([^()]*\))*", self.extra[close + 1:] if close != -1 else "")
            if first:
                out.append((first.group(1), ".onDelete" in re.sub(r"\s", "", chained.group(0))))
        return out

    def leading_index_columns(self) -> set[str]:
        """Column keys that are the first column of an index, unique constraint or primary key."""
        keys = {c.key for c in self.columns if re.search(r"\.(primaryKey|unique)\s*\(", c.chain)}
        keys |= set(re.findall(r"\.on\s*\(\s*[\w$]+\.([\w$]+)", self.extra))
        keys |= set(re.findall(r"\bprimaryKey\s*\(\s*\{\s*columns\s*:\s*\[\s*[\w$]+\.([\w$]+)", self.extra))
        return keys


def _call_args(text: str, marker: str) -> str:
    i = text.find(marker)
    if i == -1:
        return ""
    open_paren = i + len(marker) - 1
    close = match_close(text, open_paren)
    return text[open_paren + 1: close if close != -1 else len(text)]


def split_top_level(text: str) -> list[tuple[int, str]]:
    """Split on commas at nesting depth 0. Returns (offset, part) with offsets into `text`."""
    parts, depth, start, quote = [], 0, 0, None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((start, text[start:i]))
            start = i + 1
        i += 1
    if text[start:].strip():
        parts.append((start, text[start:]))
    return parts


def _table_call_pattern(code: str) -> re.Pattern:
    names = ["pgTable"] + re.findall(r"\bpgTable\s+as\s+([\w$]+)", code)
    alt = "|".join(re.escape(n) for n in names)
    return re.compile(rf"(?<![\w$])(?:[\w$]+\.)?(?:{alt})\s*\(")


def parse_tables(f: JsFile) -> list[Table]:
    """Tables declared in a file that imports drizzle-orm/pg-core."""
    if not PG_CORE.search(f.code):
        return []
    tables = []
    for m in _table_call_pattern(f.code_nostr).finditer(f.code_nostr):
        paren = m.end() - 1
        close = match_close(f.code_nostr, paren)
        if close == -1:
            continue
        args = f.code[paren + 1: close]
        parts = split_top_level(args)
        if len(parts) < 2:
            continue
        name_m = re.match(r"\s*(['\"`])([^'\"`]+)\1", parts[0][1])
        cols_text = parts[1][1]
        cols_text_stripped = cols_text.strip()
        if not name_m or not cols_text_stripped.startswith("{"):
            continue
        body = cols_text_stripped[1:-1] if cols_text_stripped.endswith("}") else cols_text_stripped[1:]
        table = Table(name=name_m.group(2), offset=m.start(),
                      extra=",".join(p for _, p in parts[2:]))
        for _, entry in split_top_level(body):
            km = re.match(r"\s*(?:(['\"])([^'\"]+)\1|([\w$]+))\s*:\s*([\s\S]+)$", entry)
            if not km:
                continue
            key = km.group(2) or km.group(3)
            chain = km.group(4).strip()
            bm = re.match(r"(?:[\w$]+\.)?([\w$]+)\s*\(", chain)
            if not bm:
                continue
            bargs = _call_args(chain, chain[bm.start(1): bm.end()])
            sql = re.match(r"\s*(['\"`])([^'\"`]+)\1", bargs)
            found = f.code.find(entry.strip(), paren)
            table.columns.append(Column(key=key, sql_name=sql.group(2) if sql else key, builder=bm.group(1),
                                        builder_args=bargs, chain=chain, offset=found if found != -1 else m.start()))
        tables.append(table)
    return tables
