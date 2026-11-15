#!/usr/bin/env python3
"""Audit SQL migrations (Drizzle Kit, Prisma, Supabase, plain .sql) for data loss, locks and history drift. Read-only.

    python audit_migrations.py --root REPO [--files PATH ...] [--format md|json|sarif] [--strict]

Covers dbm.01–09. Statements on a table created earlier in the same migration are not flagged.
Never connects to a database; git is only read (dbm.08).
"""

from __future__ import annotations

import re
from collections import Counter

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.sqlmig import IDENT, find_migrations, journal_problems, statements, table_name
from wclib.walker import Walker, run_git

ALTER = re.compile(rf"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({IDENT})\s+([\s\S]*)$", re.I)
CREATE_TABLE = re.compile(rf"^\s*CREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})", re.I)
CREATE_INDEX = re.compile(rf"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?:{IDENT}\s+)?ON\s+(?:ONLY\s+)?({IDENT})", re.I)
DROP_TABLE = re.compile(rf"^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?({IDENT}(?:\s*,\s*{IDENT})*)", re.I)
TRUNCATE = re.compile(rf"^\s*TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?({IDENT})", re.I)


class MigrationAudit(Audit):
    tool = "data-standards migrations"
    prefix = "dbm"
    exts = {".sql"}

    def line(self, text: str, off: int) -> int:
        return text.count("\n", 0, off) + 1

    def flag(self, rule, msg, rel, text, off, **kw):
        self.add(rule, msg, file=rel, line=self.line(text, off), **kw)

    def run(self) -> None:
        # Discovery needs the whole tree (drizzle.config.* names the out folder), even when --files narrows the audit.
        files = Walker(self.root, ignore_paths=self.ctx.config.get("ignorePaths", [])).all_files()
        migrations = find_migrations(self.root, files)
        if self.ctx.walker.only is not None:
            migrations = [m for m in migrations if m.rel in self.ctx.walker.only]
        self.report.meta["migrations"] = len(migrations)
        if not migrations:
            self.report.skipped.append("No SQL migrations found (Drizzle out folder, prisma/migrations, supabase/migrations, migrations/)")
        # Tables created by earlier migrations count as existing; in --files mode, every table not created in the file does.
        for m in migrations:
            text = (self.root / m.rel).read_text(encoding="utf-8", errors="replace")
            self.check_file(m.rel, text)
        for out_dir in sorted({m.out_dir for m in find_migrations(self.root, files) if m.tool == "drizzle-legacy"}):
            for problem in journal_problems(self.root, out_dir):
                self.add("dbm.09", problem, file=f"{out_dir}/meta/_journal.json",
                         fix_hint="Don't add, delete or rename migration files by hand; regenerate and run drizzle-kit check")
        self.edited_after_commit([m.rel for m in migrations])
        self.finish_not_checked()

    def check_file(self, rel: str, text: str) -> None:
        created: set[str] = set()
        for st in statements(text):
            sql, off = st.sql, st.offset
            if m := CREATE_TABLE.match(sql):
                created.add(table_name(m.group(1)))
                continue
            if m := CREATE_INDEX.match(sql):
                if not m.group(1) and table_name(m.group(2)) not in created:
                    self.flag("dbm.05", f"CREATE INDEX on existing table `{table_name(m.group(2))}` without CONCURRENTLY (blocks writes while it builds)",
                              rel, text, off, fix_hint="Fine on small tables; on large ones use CREATE INDEX CONCURRENTLY outside a transaction")
                continue
            if m := DROP_TABLE.match(sql):
                names = [table_name(n) for n in re.findall(IDENT, m.group(1))]
                for name in [n for n in names if n not in created]:
                    self.flag("dbm.01", f"DROP TABLE `{name}` deletes its data", rel, text, off,
                              fix_hint="Back up first, stop using it in an earlier release, then drop")
                continue
            if m := TRUNCATE.match(sql):
                self.flag("dbm.01", f"TRUNCATE `{table_name(m.group(1))}` deletes all rows", rel, text, off)
                continue
            if m := ALTER.match(sql):
                table = table_name(m.group(1))
                if table in created:
                    continue
                self.check_alter(rel, text, off, table, m.group(2))

    def check_alter(self, rel, text, off, table, actions: str) -> None:
        for a in re.finditer(r"\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(" + IDENT + ")", actions, re.I):
            self.flag("dbm.01", f"DROP COLUMN `{table}.{table_name(a.group(1))}` deletes its data", rel, text, off,
                      fix_hint="Stop reading/writing it in an earlier release and back up before dropping")
        for a in re.finditer(r"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(" + IDENT + r")\s+([^,]*)", actions, re.I):
            if a.group(1).upper() in ("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK"):
                continue
            spec = a.group(2)
            if re.search(r"\bNOT\s+NULL\b", spec, re.I) and not re.search(r"\b(DEFAULT|GENERATED)\b|\bserial\b|\bbigserial\b", spec, re.I):
                self.flag("dbm.02", f"ADD COLUMN `{table}.{table_name(a.group(1))}` is NOT NULL without a DEFAULT (fails if the table has rows)",
                          rel, text, off, fix_hint="Add a DEFAULT, or add it nullable, backfill, then SET NOT NULL")
        for a in re.finditer(r"\bALTER\s+(?:COLUMN\s+)?(" + IDENT + r")\s+(?:SET\s+DATA\s+)?TYPE\b", actions, re.I):
            self.flag("dbm.03", f"Changing the type of `{table}.{table_name(a.group(1))}` usually rewrites the table under an exclusive lock",
                      rel, text, off, fix_hint="On large tables: new column, backfill in batches, switch code, drop the old one")
        for a in re.finditer(r"\bALTER\s+(?:COLUMN\s+)?(" + IDENT + r")\s+SET\s+NOT\s+NULL\b", actions, re.I):
            self.flag("dbm.04", f"SET NOT NULL on `{table}.{table_name(a.group(1))}` scans the table under an exclusive lock",
                      rel, text, off, fix_hint="Add CHECK (col IS NOT NULL) NOT VALID, VALIDATE it, then SET NOT NULL")
        if a := re.search(r"\bRENAME\s+(?:COLUMN\s+)?(" + IDENT + r")\s+TO\s+(" + IDENT + ")", actions, re.I):
            self.flag("dbm.06", f"Renaming `{table}.{table_name(a.group(1))}` breaks the app version still running during the deploy",
                      rel, text, off, fix_hint="Expand and contract: add the new name, dual-write, switch reads, drop later")
        elif re.match(r"\s*RENAME\s+TO\b", actions, re.I):
            self.flag("dbm.06", f"Renaming table `{table}` breaks the app version still running during the deploy", rel, text, off)
        if re.search(r"\bFOREIGN\s+KEY\b", actions, re.I) and not re.search(r"\bNOT\s+VALID\b", actions, re.I):
            self.flag("dbm.07", f"Adding a foreign key on existing table `{table}` checks every row under lock", rel, text, off,
                      fix_hint="ADD CONSTRAINT … NOT VALID, then VALIDATE CONSTRAINT in a separate step")

    def edited_after_commit(self, rels: list[str]) -> None:
        if not rels or not self.ctx.walker.git:
            return
        log = run_git(self.root, "log", "--format=", "--name-only", "--relative", "--no-renames", "--", *rels)
        counts = Counter(line.strip() for line in (log or "").splitlines() if line.strip())
        for rel in rels:
            if counts.get(rel, 0) > 1:
                self.add("dbm.08", f"Migration was changed in {counts[rel] - 1} commit(s) after it was added", file=rel,
                         fix_hint="Revert the edit and put the change in a new migration")


if __name__ == "__main__":
    run_main(MigrationAudit, __file__, __doc__)
