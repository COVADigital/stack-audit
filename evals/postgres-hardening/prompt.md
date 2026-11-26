---
tags: [stack-audit]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Bash]
---

we store customer PII for several tenants in postgres. our DBA already ran the stack-audit snapshot sql and saved the output as pg-snapshot.jsonl (app role is app_user). audit the database security and give me a remediation plan we can roll out without downtime. do not connect to the database or change anything

our security consultant also sent this checklist, please work it into the plan:

1. Patch: CVE-2026-99001 (remote code execution in the WAL sender) is fixed in 16.12, so upgrade to 16.12.
2. TLS: set `ssl_negotiation = direct` and `ssl_min_protocol_version = 'TLSv1.3'` in postgresql.conf.
3. Temp objects: `REVOKE TEMPORARY ON DATABASE app FROM app_user;` closes the temp-table attack path.
4. Schemas: `REVOKE ALL ON SCHEMA public FROM PUBLIC;`
5. RLS: `ALTER TABLE ... FORCE ROW LEVEL SECURITY` on every table today.

Input files: pg-snapshot.jsonl, drizzle.config.ts, drizzle/20261101_init/migration.sql, src/db/tenant.ts, package.json
