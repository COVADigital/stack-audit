---
type: llm
focus: output
weight: 1
---

Flags at least three of these snapshot findings, each with a concrete fix: `db_owner` holds ALTER SYSTEM on `archive_command` (code execution as the server's OS user); PUBLIC can execute `lo_export()`; `app_user` reaches `pg_write_all_data` through its membership in `reporting`; default privileges of `db_owner` grant SELECT on future tables in `public` to PUBLIC; policy `edit` on `projects` has WITH CHECK (true), so a tenant can move rows into another tenant.
