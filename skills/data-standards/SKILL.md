---
name: data-standards
description: Standards plus read-only audits for the database layer of apps on PostgreSQL: Drizzle ORM schemas and drizzle-kit migrations (also Prisma and hand-written SQL), and PostgreSQL security hardening. Use when writing or reviewing a Drizzle schema, generating, reviewing or deploying a migration ("is this migration safe?", "can I drop this column?"), choosing drizzle-kit push vs migrate, setting up connections (pools, SSL, roles) or seed scripts, hardening or auditing a Postgres server (patch level and CVEs, pg_hba.conf, TLS, superuser/app roles, PUBLIC and TEMP grants, row level security and policies, security_invoker views, SECURITY DEFINER functions, timeouts, logging, SCRAM), or a database review before a release. Not for SQL injection in app code (web-standards), database containers, volumes and backups in Docker/Compose (container-standards), or OWASP questions in general (owasp-security).
allowed-tools: Bash(python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/*)
---

# Data Standards

> **Codex and other agents:** `${CLAUDE_PLUGIN_ROOT}` in the commands below is the plugin root, two folders above this SKILL.md (the session-start hook also prints it as "Plugin root"). Claude Code fills it in; elsewhere, substitute the absolute path.

Every **Rule** in `references/` is a requirement. Findings cite rule IDs such as `dbm.02` (section 02 of `21-migration-safety.md`). `references/rule-index.md` lists all 48 rules and how each one is checked.

| Prefix | Reference | Covers |
|---|---|---|
| `dbs` | 20-schema-design.md | primary keys, foreign key indexes, onDelete, timestamptz, money types, password columns, identity vs serial, constraints in the database |
| `dbm` | 21-migration-safety.md | drops, NOT NULL without default, type changes, SET NOT NULL, indexes without CONCURRENTLY, renames, foreign keys without NOT VALID, edited migrations, journal consistency, reviewing generated SQL |
| `dbo` | 22-database-operations.md | push vs migrate, drizzle-kit check in CI, SSL to remote databases, least-privilege roles, one pool per process, seed guards, backups before risky migrations |
| `dbh` | 23-postgres-hardening.md | patched version, PUBLIC/TEMP grants, listen and pg_hba, TLS, app role vs owner/superuser, extensions, column grants, RLS and policies, pooler-safe tenant context, security_invoker views, SECURITY DEFINER, side channels, SCRAM, timeouts, logging, PII in logs, dynamic SQL in functions, disk/host/backup (manual), Drizzle RLS patterns, staged rollout |

## 1. Audits (all read-only)

Run each script as **one command with this full path** (no `S=` variable, `cd`, `&&` or pipes), so it matches the skill's pre-approved commands and runs without a permission prompt.

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/run_audit.py --root <repo> --format json        # all four, merged
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_schema.py --root <repo>                    # dbs.* (Drizzle pg-core schema files)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_migrations.py --root <repo>                # dbm.* (Drizzle Kit both layouts, Prisma, Supabase, migrations/)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_db_ops.py --root <repo>                    # dbo.* (package.json, CI, Dockerfiles, compose, .env.example, code)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_postgres.py --root <repo>                  # dbh.* (migrations, postgresql/pg_hba .conf files, SET app.* in code)
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_postgres.py --root <repo> --snapshot <file> --app-role <role>   # + live server state
```

- **Static only.** The scripts never connect to a database, never run migrations or `drizzle-kit`, and never read `.env` files (only `.env.example`-style templates). Connection strings are never printed: only hosts, roles and settings.
- **Migration findings are about tables that already have data.** Statements on a table created earlier in the same migration are skipped. Whether a lock matters depends on table size and traffic: ask the user, or check row counts yourself only if they ask you to query the database.
- **Triage heuristic findings** (`dbo.03–06`, `dbs.05–06`) by opening the file. A single-label host such as `db` is treated as a private Docker network.
- **The database itself is only seen through a snapshot** (§1b). Without one, `dbh` live rules are listed under "Not checked".
- Report findings grouped by severity: severity · `rule-id` · `file:line` · problem · fix. End with the report's "Not checked" list, which includes `dbm.10`: read every generated migration's SQL yourself.

## 1b. Live PostgreSQL audit (snapshot)

For "harden / audit our Postgres", the server's real state (version, pg_hba, roles, grants, RLS, policies, views, functions, settings) comes from `assets/pg_snapshot.sql`: read-only catalog queries that print one JSON line per section. No table rows, password hashes, client IPs or pg_hba options are collected.

1. **Ask first** (AskUserQuestion in Claude Code; a numbered question in chat in Codex): which database (host/name, never the password), which role runs the snapshot (a superuser, or a role in `pg_read_all_settings` + `pg_read_all_stats`; without a superuser, pg_hba rules and MD5 hashes are "Not checked"), and the app's runtime role name. Offer that the user runs it themselves and gives you the file.
2. If they agree, run exactly this once, with the connection from their environment (`$DATABASE_URL` or `PG*` variables). Never print, echo or write the connection string:
   `psql -X -d "$DATABASE_URL" -f ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/assets/pg_snapshot.sql -o <session scratchpad>/pg-snapshot.jsonl`
   Section errors on stderr (permission denied) are expected for a non-superuser.
3. `python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/run_audit.py --root <repo> --pg-snapshot <file> --app-role <role> --format json`. Also run the container-standards audit when the repo has Compose/Dockerfiles (published 5432, `cool.02` public databases): that covers the Docker side of `dbh.03`.
4. Write the report in three parts, and **propose, never apply**:
   1. **Executive risk summary.** Critical = error findings that allow code execution, superuser access, or reading or changing another tenant's or person's data (`dbh.01` unpatched or EOL, `dbh.04` trust, `dbh.06`, `dbh.08`, `dbh.10`–`dbh.14`). High = other errors and the warns on the same paths. Medium = remaining warns. Low = info. Treat anything that exposes personal data or crosses tenants as Critical when the user says the database holds PII.
   2. **Read-only queries and evidence.** For each finding: the snapshot section it came from (section names match the queries in `pg_snapshot.sql`), or `file:line` for repo findings, plus the "Not checked" list. Never paste table data, hashes or connection strings.
   3. **Staged remediation plan** from `23-postgres-hardening.md` ("Staged rollout"): exact SQL / `postgresql.conf` / `pg_hba.conf` changes, ordered zero-impact first (patch, logging), then staging (roles, revokes, timeouts, RLS per table), then production cutover (hostssl, scram). Each step gets its check and its rollback.
5. Keep the snapshot in the scratchpad; never commit it (it names roles, tables and subnets).

- **Query plans:** `EXPLAIN ANALYZE` executes the statement. On production, use plain `EXPLAIN` on SELECTs only. Keep `EXPLAIN ANALYZE` for staging, or wrap it in `BEGIN; … ROLLBACK;` once the user agrees.
- **Client tools:** the snapshot records the `psql` version that ran it. Ask for `pg_dump --version` on the machines that take backups.
- **Host-level items** (`dbh.19`–`dbh.21`: disk encryption, PGDATA permissions, umask, firewall, backup encryption) are outside SQL. List them as questions, or as read-only commands for the user to run (`ss -tlnp | grep 5432`, `stat -c '%a %U' $PGDATA`, `lsblk -f`). Run nothing on the host unless they ask.

## 2. Writing or changing the database layer

- **Schema changes:** follow `20-schema-design.md`, then generate the migration (`drizzle-kit generate`) and **read the SQL** before committing (`dbm.10`). If the generator turned a rename into drop-and-add, fix the intent before anything runs.
- **Risky migrations:** propose the safe sequence from `21-migration-safety.md` (expand and contract, `NOT VALID` then `VALIDATE`, `CONCURRENTLY` outside a transaction) and say which steps need a separate deploy.
- **Never** run `drizzle-kit push`, `drizzle-kit migrate`, `prisma migrate deploy`, or SQL against any database unless the user explicitly asks for that exact action, and name the database it will touch first. Before anything destructive, ask whether a fresh backup exists (`dbo.07`, container-standards `ops.02`).
- For OWASP depth, use **owasp-security** (`Database_Security`, `Multi_Tenant_Security`, `SQL_Injection_Prevention`, `Password_Storage`, `Transport_Layer_Security`). For SQL built from user input in app code, **web-standards** `sec.10`.

## 3. Checks worth keeping

When you run a check of your own that isn't one of this plugin's rules and is likely to be needed again (a project-specific migration pattern, a regression you just fixed), ask the user what to do with it before you finish:

1. **Keep it one-off.** Nothing is saved.
2. **Save it as a test in the project's existing test suite.** Suggest this first: it runs on every change and in CI.
3. **Save it as a standalone script** in a folder they choose, for checks that don't fit a test.

Never save anything without asking, never add a test framework the project doesn't have, and show the file before writing it.
