---
tags: [stack-audit]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Bash]
---

we store customer PII for several tenants in postgres. our DBA already ran the stack-audit snapshot sql and saved the output as pg-snapshot.jsonl (app role is app_user). audit the database security and give me a remediation plan we can roll out without downtime. do not connect to the database or change anything

Input files: pg-snapshot.jsonl, drizzle.config.ts, drizzle/20261101_init/migration.sql, src/db/tenant.ts, package.json
