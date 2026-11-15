---
name: data-standards
description: Standards plus read-only audits for the database layer of apps on PostgreSQL, focused on Drizzle ORM (schemas, drizzle-kit migrations) and also covering Prisma and hand-written SQL migrations. Use when writing or reviewing a Drizzle schema (pgTable, indexes, foreign keys, column types), generating, reviewing or deploying a migration ("is this migration safe?", "will this lock the table?", "can I drop this column?"), choosing drizzle-kit push vs migrate, setting up database connections (pools, SSL, roles) or seed scripts, or auditing a repo's database setup before a release. Not for SQL injection in app code or Server Actions (web-standards), database containers, volumes and backups in Docker/Compose (container-standards), or OWASP questions in general (owasp-security).
allowed-tools: Bash(python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/*)
---

# Data Standards

Every **Rule** in `references/` is a requirement. Findings cite rule IDs such as `dbm.02` (section 02 of `21-migration-safety.md`). `references/rule-index.md` lists all 25 rules and how each one is checked.

| Prefix | Reference | Covers |
|---|---|---|
| `dbs` | 20-schema-design.md | primary keys, foreign key indexes, onDelete, timestamptz, money types, password columns, identity vs serial, constraints in the database |
| `dbm` | 21-migration-safety.md | drops, NOT NULL without default, type changes, SET NOT NULL, indexes without CONCURRENTLY, renames, foreign keys without NOT VALID, edited migrations, journal consistency, reviewing generated SQL |
| `dbo` | 22-database-operations.md | push vs migrate, drizzle-kit check in CI, SSL to remote databases, least-privilege roles, one pool per process, seed guards, backups before risky migrations |

## 1. Audits (all read-only)

Run each script as **one command with this full path** (no `S=` variable, `cd`, `&&` or pipes), so it matches the skill's pre-approved commands and runs without a permission prompt.

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/run_audit.py --root <repo> --format json        # all three, merged
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_schema.py --root <repo>                    # dbs.* (Drizzle pg-core schema files)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_migrations.py --root <repo>                # dbm.* (Drizzle Kit both layouts, Prisma, Supabase, migrations/)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_db_ops.py --root <repo>                    # dbo.* (package.json, CI, Dockerfiles, compose, .env.example, code)
```

- **Static only.** The scripts never connect to a database, never run migrations or `drizzle-kit`, and never read `.env` files (only `.env.example`-style templates). Connection strings are never printed: only hosts, roles and settings.
- **Migration findings are about tables that already have data.** Statements on a table created earlier in the same migration are skipped. Whether a lock matters depends on table size and traffic: ask the user, or check row counts yourself only if they ask you to query the database.
- **Triage heuristic findings** (`dbo.03–06`, `dbs.05–06`) by opening the file. A single-label host such as `db` is treated as a private Docker network.
- Report findings grouped by severity: severity · `rule-id` · `file:line` · problem · fix. End with the report's "Not checked" list, which includes `dbm.10`: read every generated migration's SQL yourself.

## 2. Writing or changing the database layer

- **Schema changes:** follow `20-schema-design.md`, then generate the migration (`drizzle-kit generate`) and **read the SQL** before committing (`dbm.10`). If the generator turned a rename into drop-and-add, fix the intent before anything runs.
- **Risky migrations:** propose the safe sequence from `21-migration-safety.md` (expand and contract, `NOT VALID` then `VALIDATE`, `CONCURRENTLY` outside a transaction) and say which steps need a separate deploy.
- **Never** run `drizzle-kit push`, `drizzle-kit migrate`, `prisma migrate deploy`, or SQL against any database unless the user explicitly asks for that exact action, and name the database it will touch first. Before anything destructive, ask whether a fresh backup exists (`dbo.07`, container-standards `ops.02`).
- For OWASP depth, use **owasp-security** (`Database_Security`, `SQL_Injection_Prevention`, `Password_Storage`, `Transport_Layer_Security`). For SQL built from user input in app code, **web-standards** `sec.10`.

## 3. Checks worth keeping

When you run a check of your own that isn't one of this plugin's rules and is likely to be needed again (a project-specific migration pattern, a regression you just fixed), ask the user what to do with it before you finish:

1. **Keep it one-off.** Nothing is saved.
2. **Save it as a test in the project's existing test suite.** Suggest this first: it runs on every change and in CI.
3. **Save it as a standalone script** in a folder they choose, for checks that don't fit a test.

Never save anything without asking, never add a test framework the project doesn't have, and show the file before writing it.
