#!/usr/bin/env python3
"""Audit Drizzle ORM (pg-core) schema files: keys, foreign key indexes, timestamps, types. Read-only.

    python audit_schema.py --root REPO [--files PATH ...] [--format md|json|sarif] [--strict]

Covers dbs.01–07. Reads TypeScript source statically; nothing is executed or connected.
"""

from __future__ import annotations

import re

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.drizzle import parse_tables

MONEY = re.compile(r"(?i)(price|amount|total|cost|balance|fee|subtotal|tax|salary|revenue|payout|refund|credit)")
PLAIN_PASSWORD = re.compile(r"(?i)^(password|passwd|pwd|pass|plain_?password|password_?plain(text)?)$")


class SchemaAudit(Audit):
    tool = "data-standards schema"
    prefix = "dbs"
    include_tests = False

    def run(self) -> None:
        tables_seen = 0
        for f in self.files:
            for t in parse_tables(f):
                tables_seen += 1
                self.check_table(f, t)
        if not tables_seen:
            self.report.skipped.append("No Drizzle pg-core tables found (pgTable in files importing drizzle-orm/pg-core)")
        self.report.meta["tables"] = tables_seen
        self.finish_not_checked()

    def check_table(self, f, t) -> None:
        if not t.has_primary_key:
            self.add("dbs.01", f"Table `{t.name}` has no primary key", f, t.offset,
                     fix_hint="integer().primaryKey().generatedAlwaysAsIdentity(), or primaryKey({ columns: [...] })")
        indexed = t.leading_index_columns()
        for key, on_delete in t.foreign_keys():
            col = t.column(key)
            where = col.offset if col else t.offset
            if key not in indexed:
                self.add("dbs.02", f"Foreign key `{t.name}.{col.sql_name if col else key}` has no index (Postgres doesn't create one)",
                         f, where, fix_hint=f"(t) => [index('{t.name}_{col.sql_name if col else key}_idx').on(t.{key})]")
            if not on_delete:
                self.add("dbs.03", f"Reference `{t.name}.{col.sql_name if col else key}` has no explicit onDelete", f, where,
                         fix_hint="Choose 'cascade', 'set null' or 'restrict' for this relationship")
        for c in t.columns:
            if c.builder == "timestamp" and not re.search(r"withTimezone\s*:\s*true", c.builder_args):
                self.add("dbs.04", f"`{t.name}.{c.sql_name}` is timestamp without time zone", f, c.offset,
                         fix_hint="timestamp('…', { withTimezone: true })")
            if c.builder in ("real", "doublePrecision") and MONEY.search(c.key + " " + c.sql_name):
                self.add("dbs.05", f"`{t.name}.{c.sql_name}` looks like money but uses floating point ({c.builder})", f, c.offset,
                         fix_hint="numeric({ precision: 12, scale: 2 }) or an integer number of cents")
            if PLAIN_PASSWORD.match(c.key) or PLAIN_PASSWORD.match(c.sql_name):
                self.add("dbs.06", f"`{t.name}.{c.sql_name}` looks like a plain-text password column", f, c.offset,
                         fix_hint="Store only a hash written by the auth library, in a column named *_hash")
            if c.builder in ("serial", "bigserial", "smallserial"):
                self.add("dbs.07", f"`{t.name}.{c.sql_name}` uses {c.builder}", f, c.offset,
                         fix_hint="integer().generatedAlwaysAsIdentity() (or a UUID)")


if __name__ == "__main__":
    run_main(SchemaAudit, __file__, __doc__)
