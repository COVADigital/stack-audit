# PostgreSQL Security Hardening — 23 Practices

> **Applies to:** a PostgreSQL server (self-hosted, Docker, Coolify or managed) and the SQL that shapes its permissions: grants, row level security (RLS), views, functions, `postgresql.conf`, `pg_hba.conf`. Most useful for apps that hold personal data or serve several tenants from one database.  
> **Rule IDs:** section `NN` in this file is rule `dbh.NN` in audit findings.  
> **Sources:** PostgreSQL documentation (client authentication, roles and privileges, row security policies, CREATE VIEW, CREATE FUNCTION, SSL, runtime config), PostgreSQL security announcements (support/security, support/versioning), CIS PostgreSQL Benchmark topics, OWASP Database Security and Multi-Tenant Security cheat sheets. Written in our own words.

> **Agent directive:** Discover first, change later. Read the live state with `assets/pg_snapshot.sql` (read-only, and only after the user agrees and you have named the database and role). Never run `REVOKE`, `ALTER`, `FORCE ROW LEVEL SECURITY`, timeouts or `pg_hba.conf` changes yourself: propose them in the order of the staged rollout at the end, with a rollback for each step.

**How it is checked.** `audit_postgres.py --root REPO` reads migrations, `postgresql*.conf` / `pg_hba*.conf` files and app code. Add `--snapshot FILE` for the server's real state:

```bash
psql -X -d "$DATABASE_URL" -f ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/assets/pg_snapshot.sql -o <scratchpad>/pg-snapshot.jsonl
python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/audit_postgres.py --root . --snapshot <scratchpad>/pg-snapshot.jsonl --app-role app_user
```

Run the snapshot as a superuser (or a role in `pg_read_all_settings` and `pg_read_all_stats`; `pg_hba_file_rules` and password hash types still need a superuser). It collects catalog metadata only: no rows, no password hashes, no client IPs. Tables, RLS, views and functions are per database, so run it once in **each** application database. Server-wide parts (roles, pg_hba, settings, database grants) are the same in every run. The audit lists the databases a snapshot didn't cover.

---

## 01. Run a Supported, Patched Minor Release
**What:** The server's minor version (`SELECT version()`) against the latest security release for its major version. Client tools (`psql`, `pg_dump`) should be updated too.
**Why:** The 2026-11-12 release (18.7, 17.12, 16.16, 15.20, 14.25) fixed 52 CVEs. They include CVE-2026-6460 (CVSS 8.8), in which a type confusion after `ALTER … SET DATA TYPE` executes arbitrary code in the server process, and CVE-2026-116311, in which `DROP OWNED` removes restrictive RLS policies on tables the role doesn't own. A leaked app password or one SQL injection is enough to reach these bugs. PostgreSQL 14 reached end-of-life with 14.25 and gets no more fixes. Minor upgrades are binary-compatible: new binaries (or image tag) and a restart, no `pg_upgrade`.

The official list (postgresql.org/support/security) shows three patterns worth acting on, beyond "patch the server":
- **Client tools have their own CVEs.** `pg_dump`, `pg_restore`, `psql`, `pg_basebackup`, `reindexdb` and `vacuumdb` have had code-execution and SQL-injection bugs, several triggered by restoring a dump or archive from an untrusted server (CVE-2026-116314, CVE-2026-116330, CVE-2026-18408, CVE-2025-8714). Patch the machines that run backups and restores, not only the server.
- **Some bugs need no login.** Pre-authentication flaws, such as CVE-2026-6479 (denial of service during SSL/GSS negotiation, CVSS 7.5) and CVE-2026-116322 (a cancel request leaking a spinlock), can be reached by anyone who can open a TCP connection. Strong passwords don't help against these. Only network isolation (`dbh.03`) does.
- **Subscribe to the security announcements:** the pgsql-announce list, filtered to the Security tag.

**Rule:** Production runs a supported major version at or above the minimum in `assets/pg-versions.json`, updated within days of a security release. End-of-life majors are upgraded. `psql` and `pg_dump` on admin and backup machines are updated too. The snapshot records the `psql` version that ran it.

---

## 02. No Temporary Objects or CREATE for PUBLIC on Databases
**What:** By default every role gets `CONNECT` and `TEMPORARY` on every database (`PUBLIC` grants).
**Why:** Temporary tables and functions give any authenticated role objects of its own to create, which is the starting point for several of the 2026 code-execution bugs. Revoking this narrows the attack surface, but it doesn't replace patching. `REVOKE … FROM app_user` does nothing if the privilege came from `PUBLIC`.

```sql
REVOKE TEMPORARY, CREATE ON DATABASE app_db FROM PUBLIC;
GRANT CONNECT ON DATABASE app_db TO app_user;   -- then REVOKE CONNECT … FROM PUBLIC if other roles shouldn't connect
```
Privileges also arrive through role membership. If the app role is a member of a group that holds `TEMPORARY` or `CREATE`, it has them too, and the audit follows memberships to find this. `CREATE` on a database also lets a non-superuser install *trusted* extensions (PostgreSQL 13+), so "only superusers create extensions" holds only while nobody else has `CREATE`. `CONNECT` for `PUBLIC` is reported as info. Before you revoke it, grant `CONNECT` by name to the app, owner, backup and monitoring roles, or they lose access.

**Rule:** `PUBLIC` and the app role (directly or through a group) hold no `TEMPORARY` or `CREATE` on application databases. Grant `TEMPORARY` back only to a role that really uses temp tables, after testing it in staging.

---

## 03. Don't Listen on Public Interfaces
**What:** `listen_addresses`, the published port (Docker `ports:`) and the host or cloud firewall.
**Why:** A database reachable from the internet is scanned within minutes, and every auth or protocol bug becomes remotely exploitable. `listen_addresses = '*'` is normal inside a container, as long as the port isn't published past the Docker network (container-standards `cnet.*`, Coolify `cool.02`).

Because some PostgreSQL CVEs are reachable before authentication (see `dbh.01`), an exposed port is a risk even when every password is strong and pg_hba is strict.

**Rule:** Port 5432 is reachable only from the app's host, network or VPN. Admin tools (Drizzle Studio, pgAdmin, DBeaver) connect over an SSH tunnel or a private mesh VPN (WireGuard/Tailscale), never over a public port.

---

## 04. Lock Down `pg_hba.conf`
**What:** The client authentication rules, checked top to bottom (`SELECT * FROM pg_hba_file_rules`).
**Why:** `trust` lets anyone who reaches the port connect as any role, including the superuser, with no password. `password` sends the password in clear text. `md5` hashes are weak and replayable. A `0.0.0.0/0` line undoes the network isolation.

```text
# TYPE  DATABASE  USER       ADDRESS       METHOD
local   all       postgres                 peer
hostssl app_db    app_user   10.0.1.0/24   scram-sha-256
host    all       all        0.0.0.0/0     reject
host    all       all        ::/0          reject
```
PostgreSQL has no account lockout. Brute force is slowed only by keeping the port private, using long random passwords, loading the `auth_delay` module (`shared_preload_libraries = 'auth_delay'`, `auth_delay.milliseconds = 500`), and alerting on repeated `password authentication failed` lines in the log (fail2ban or log alerts).

**Rule:** The superuser can't log in over the network (`host all postgres 0.0.0.0/0 reject` before the other host lines; administer over SSH or a VPN). Network lines use `scram-sha-256` (or certificates) for named databases, users and subnets, and the file ends with a `reject` line. There is no `trust` on `host` lines and no `md5` or `password` anywhere.

---

## 05. Encrypt Connections
**What:** `ssl = on` with a certificate, `ssl_min_protocol_version`, `hostssl` lines, and clients using `sslmode=verify-full` (or `require` on a private network).
**Why:** Without TLS, credentials and personal data cross the network in clear text. Switching `host` to `hostssl` rejects plaintext clients at once, so check `pg_stat_ssl` first.

```sql
SELECT a.usename, s.ssl, s.version, count(*)
FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid)
WHERE a.backend_type = 'client backend' GROUP BY 1, 2, 3;
```
**Rule:** TLS is on, the minimum protocol is TLSv1.2 (the default, and TLSv1.3 only once every client supports it), and `hostssl` is enforced once no session shows `ssl = false`. Direct TLS (`sslnegotiation=direct`, PostgreSQL 17+) is a client connection option, not a server setting: the server accepts it without configuration. Turn it on per client only once its driver supports it.

---

## 06. Separate the App Role from Owners and Superusers
**What:** Three roles: `postgres` (superuser, for setup and emergencies only), a migration role that owns the schema and tables, and an app role with `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` and DML grants only.
**Why:** If the app's role is a superuser, an injection can read every database, change roles and run OS commands. If it owns the tables, it can `ALTER` or `DROP` them and it bypasses RLS. See also `dbo.04`.

```sql
CREATE ROLE app_user LOGIN PASSWORD '…' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE db_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
```
Two shortcuts quietly undo the model:
- **Membership.** `GRANT db_owner TO app_user` makes the app a member of the owner role. Even with `NOINHERIT`, it can `SET ROLE db_owner` (unless, on PostgreSQL 16+, the grant says `SET FALSE`; a grant with only `ADMIN OPTION` still lets the member grant itself `SET`) and then `ALTER`, `DROP` or read past RLS. The audit follows memberships transitively and reports app roles that reach an owner, superuser, `BYPASSRLS` or `CREATEROLE` role.
- **Superuser-owned tables.** Tables owned by `postgres` mean migrations run as the superuser, so CI holds the superuser password. The three tiers collapse to two.

**Rule:** The live app connects as a non-superuser that owns no tables, is not a member (directly or indirectly) of an owner or superuser role, and holds no privilege `WITH GRANT OPTION`. Tables are owned by a dedicated migration role, not a superuser. Migrations (Drizzle Kit, Prisma Migrate) run as that role. `CREATEROLE` and `CREATEDB` belong to administrators only, and role attributes are reviewed periodically. When the app connects as the bootstrap superuser (`postgres`), pass `--app-role postgres`, so the audit reports it as the app role instead of skipping it.

---

## 07. No PUBLIC Privileges Beyond the Defaults You Need
**What:** Grants to `PUBLIC` on schemas, tables and functions. Since PostgreSQL 15, `PUBLIC` no longer has `CREATE` on the `public` schema, but clusters upgraded from 14 or older keep the old grant.
**Why:** `PUBLIC` includes every current and future role. `CREATE` on a schema lets any role plant functions or operators that shadow trusted ones. `EXECUTE` on a `SECURITY DEFINER` function lets any role run it with the owner's rights.

Every new function gets `EXECUTE` for `PUBLIC` when it is created. A `SECURITY DEFINER` function owned by a superuser or `BYPASSRLS` role is therefore callable by everyone, with RLS off. Several public Supabase incidents had this root cause. `REVOKE` needs the exact argument types, because an overloaded name revokes nothing without them.

```sql
REVOKE EXECUTE ON FUNCTION app.lookup_user(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.lookup_user(uuid) TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE db_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
```
CVE-2018-1058 showed the search-path risk. A role that can create objects in a schema on someone else's `search_path` can define a function or operator with a familiar name, such as `lower()` for `text`, which then runs with the privileges of whoever calls it. That includes migrations and superusers. The fix from the PostgreSQL community guide is to let nobody but the owner create objects in `public`, set `search_path` explicitly for roles (and in `postgresql.conf`), and schema-qualify names in functions and migrations.

**Default privileges grant to future objects.** `ALTER DEFAULT PRIVILEGES … GRANT SELECT ON TABLES TO PUBLIC` exposes every table the owner creates later, including tables that hold personal data. The snapshot reads `pg_default_acl` and reports grants to `PUBLIC` on future tables, sequences, schemas and large objects. `PUBLIC EXECUTE` on future functions is the built-in default; revoke it with `ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`.

**Rule:** No `CREATE` on schemas, no table privileges and no default privileges for `PUBLIC`, and the app role can't create objects in any schema. `SECURITY DEFINER` functions have `EXECUTE` revoked from `PUBLIC` in the same migration that creates them, are granted by name, and are not owned by a superuser. Migrations grant to roles, never `TO PUBLIC`.

---

## 08. No Untrusted Languages or File/Network Extensions
**What:** `plpython3u`, `plperlu`, `pltclu` (untrusted languages), `adminpack`, `file_fdw`, `dblink`, `lo`, and features like `COPY … FROM PROGRAM` and `pg_read_file()`.
**Why:** Code in untrusted languages runs as the database's OS user. File and network extensions turn SQL access into file reads or outbound connections. Only superusers (or members of `pg_execute_server_program` / `pg_read_server_files`) should ever reach these.

**A real attack chain.** Imperva's honeypot (2018) watched attackers exploit this. They reached a public Postgres port and logged in as the superuser with a weak password. They wrote a binary to disk with `lo_export`, registered it as a C-language function (a sqlmap `sys_eval` wrapper) and used it to run shell commands. Finally they downloaded a cryptominer hidden inside an image file. Each step is a check here: the exposed port (`dbh.03`), superuser login over the network (`dbh.04`), C or untrusted-language functions that no extension owns, and large objects (both reported by the snapshot as possible signs of compromise). The snapshot also lists event triggers that no extension owns: their function runs on every matching DDL command, or on every login from PostgreSQL 17, including a superuser's, so attackers use them to keep access. Blocking the database host's outbound internet access (egress firewall) breaks the last step.

**Every extension and language is attack surface.** The 2026 releases fixed code-execution bugs in contrib modules (`dblink`, `pgcrypto`, `intarray`, `fuzzystrmatch`, `refint`, `pg_stat_statements`, `pg_trgm`) and many in the *trusted* languages `plperl` and `pltcl`. The snapshot lists the installed ones that had fixes (the list is in `assets/pg-versions.json`, kept with the version data). Logical replication is surface too: CVE-2026-120145 let replication write to a subscriber's system catalogs and execute code there.

**The file functions themselves.** `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`, server-side `lo_import`/`lo_export`, `pg_promote`, `pg_reload_conf` and `pg_rotate_logfile` are superuser-only by default. An explicit `GRANT EXECUTE` hands that power to another role, and the snapshot reports any grantee besides the owner and predefined roles. `lo_compat_privileges = on` turns off the large-object privilege checks added in PostgreSQL 9.0, so every role can read and write every large object again.

**Parameter grants.** Since PostgreSQL 15, `GRANT SET` or `GRANT ALTER SYSTEM ON PARAMETER` hands superuser-only settings to other roles. On `archive_command`, `restore_command`, `*_preload_libraries` or `dynamic_library_path` that is code execution as the server's OS user. The snapshot reports every such grant (`dbh.06`).

**Rule:** Install only the extensions the app needs, and drop the rest. Untrusted languages are absent, or usable by superusers only. Prefer no procedural language beyond PL/pgSQL. Subscriptions point only at publishers you control. Never grant `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files`, `pg_read_all_data` or `pg_write_all_data` to app roles. The snapshot checks these memberships.

---

## 09. Grant Sensitive Columns Individually
**What:** Tables holding password hashes, API keys, TOTP secrets, tokens or personal identifiers (SSN, birth date, card data).
**Why:** A table-wide `SELECT` lets any injected query read every secret column, even when the app only ever needs the name and email. Column grants limit what an injection can read.

```sql
REVOKE SELECT ON users FROM app_user;
GRANT SELECT (id, email, display_name, created_at) ON users TO app_user;
```
**Rule:** The app role can't `SELECT` secret columns it doesn't need. Secrets it does need are encrypted before they are stored (`dbh.19`). Verify with the app's test suite, because column grants break `SELECT *`.

---

## 10. Enable (and Where Needed Force) Row Level Security on Tenant Tables
**What:** `ALTER TABLE … ENABLE ROW LEVEL SECURITY` plus policies on tables keyed by tenant, organization or owner. Add `FORCE ROW LEVEL SECURITY` when the querying role owns the table.
**Why:** RLS is the database's backstop when app code forgets a `WHERE tenant_id = …`. Table owners and `BYPASSRLS` roles skip policies unless RLS is forced. A policy on a table without RLS enabled does nothing.

RLS itself has had bugs fixed in minor releases: `INSERT … ON CONFLICT` reading hidden rows (CVE-2026-120154), `DROP OWNED` removing restrictive policies (CVE-2026-116311), cached policies ignoring role changes (CVE-2026-14666), `security_barrier` leaks (CVE-2026-116327) and `MERGE` skipping policies (CVE-2023-39418). Treat RLS as the second line of defense: patch promptly, and keep explicit tenant filters in app queries too.

RLS has gaps around it that it doesn't cover:
- **Partitions:** RLS on a partitioned (or inheritance) parent applies only to queries through the parent. Querying a partition directly uses the partition's own RLS setting.
- **TRUNCATE and REFERENCES:** neither is subject to RLS.
- **Referential integrity:** unique and foreign key checks always bypass it (`dbh.15`).
- **Testing:** testing as a superuser, `BYPASSRLS` role or table owner proves nothing, because those roles skip the policies.

**Rule:** Tenant-scoped tables have RLS enabled and at least one policy, and are owned by a role other than the app (or forced). Partitions and children of RLS tables have RLS too. The app role has no `TRUNCATE` on them. Test policies by connecting as the real app role: one tenant must see zero rows of another. Roll it out one table at a time in staging (see the staged rollout).

---

## 11. Write Policies That Hold
**What:** The `USING` and `WITH CHECK` expressions of each policy.
**Why:** A `FOR INSERT` policy without `WITH CHECK` accepts any row. A permissive `true` policy opens the table to its roles. `FOR ALL` and `FOR UPDATE` without `WITH CHECK` reuse `USING`, which is safe. `current_setting()` evaluated per row slows scans. Wrapping it in `(select …)` makes the planner evaluate it once per query.

```sql
CREATE POLICY tenant_isolation ON projects
  USING (tenant_id = (select current_setting('app.tenant_id', true))::uuid)
  WITH CHECK (tenant_id = (select current_setting('app.tenant_id', true))::uuid);
CREATE INDEX CONCURRENTLY projects_tenant_idx ON projects (tenant_id);
```
**`WITH CHECK (true)` on UPDATE moves rows between tenants.** The `USING` clause limits which rows a tenant can touch. `WITH CHECK` limits what those rows may become. With `true`, a tenant can `UPDATE projects SET tenant_id = '<other tenant>'` on its own rows and plant them in another tenant. Leave `WITH CHECK` out (it then reuses `USING`) or repeat the condition.

**Fail closed.** A policy like `tenant_id = current_setting(…)::uuid OR current_setting(…) IS NULL`, or one that uses `coalesce(current_setting(…), …)`, returns every tenant's rows to any code path that forgot to set the context: a background job, a script, a new route. Permissive policies are combined with OR, so adding a second permissive policy widens access. A subquery inside a policy runs for every row.

**Rule:** Every `INSERT`/`ALL` policy constrains new rows, no permissive policy is `true` for the app role, no policy falls back to all rows when the context is unset, each command has one permissive policy (extra conditions go in `AS RESTRICTIVE` policies), and policy settings are wrapped in `(select …)` with the tenant column indexed. Check critical queries with `EXPLAIN ANALYZE`. User filters that call non-`LEAKPROOF` functions (such as `ILIKE`) are applied after the security filter, so their indexes may go unused. Keep `LIKE`/`ILIKE` out of policies themselves: compare the tenant or owner column with `=` or `IN`.

---

## 12. Set Tenant Context per Transaction
**What:** How the app tells policies who the user is: `SET LOCAL app.tenant_id = …` or `set_config('app.tenant_id', …, true)` inside a transaction.
**Why:** A session-level `SET app.tenant_id` stays on the connection. Pools (`pg`, `postgres.js`, PgBouncer, Supavisor) hand that connection to the next request, which then runs as the previous user's tenant.

```ts
await db.transaction(async (tx) => {
  await tx.execute(sql`select set_config('app.tenant_id', ${tenantId}, true)`);
  return tx.select().from(projects);
});
```
**The setting is only as trustworthy as the SQL that sets it.** Any SQL injection can run `SELECT set_config('app.tenant_id', '<other tenant>', true)` and read that tenant's rows, so GUC-based RLS relies on every query being parameterized (web-standards `sec.10`). Never build the value or a role name with `sql.raw()`, even though some RLS examples online do it with token claims.

**Rule:** Custom settings used by policies are set with `SET LOCAL` / `set_config(…, true)` inside the same transaction as the queries, with the value passed as a parameter. Policies read them with `current_setting(name, true)`, so a missing value matches nothing instead of raising an error. With PgBouncer in transaction mode, every query that relies on the setting runs inside that transaction.

---

## 13. Views Run as the Caller; Materialized Views Stay Private
**What:** `CREATE VIEW … WITH (security_invoker = true)` (PostgreSQL 15+). Materialized views store a copy of the data.
**Why:** A normal view reads its tables with the view owner's rights, so the caller's RLS policies don't apply. Materialized views have no RLS at all: anyone who can read one sees every tenant's rows.

Logical replication publications are another copy: a `FOR ALL TABLES` publication streams every table, including future ones, to the subscriber with no RLS.

**Rule:** Views over RLS tables are `security_invoker`. Publications list their tables explicitly, using column lists and row filters (PostgreSQL 15+) to keep personal data out. Materialized views built from tenant data aren't readable by the app role, or are exposed only through a filtered `security_invoker` view.

---

## 14. Pin `search_path` in `SECURITY DEFINER` Functions
**What:** Functions that run with their owner's rights.
**Why:** Without a fixed `search_path`, a caller who can create objects in a schema on the path (or in `pg_temp`) can make the function call their code with the owner's privileges.

```sql
CREATE FUNCTION app.current_tenant_projects() RETURNS SETOF app.projects
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT * FROM app.projects WHERE tenant_id = (select current_setting('app.tenant_id', true))::uuid
$$;
REVOKE EXECUTE ON FUNCTION app.current_tenant_projects() FROM PUBLIC;
```
Pinning isn't enough by itself. When `pg_temp` isn't listed, PostgreSQL searches it **first** for tables and types, so `SET search_path = public` lets a caller's temporary table shadow `public.users`. A pinned path that names a schema where `PUBLIC` or the app role can `CREATE` is also hijackable. The widely copied `SET search_path = public, pg_temp` is safe only while nobody else can create objects in `public`. The audit checks both cases.

**Rule:** Avoid `SECURITY DEFINER` where you can. When a function needs it, it sets `search_path` with `pg_temp` listed last and only schemas nobody else can write to (`pg_catalog, pg_temp` is safest), schema-qualifies every name, and is granted by name.

---

## 15. Close Constraint and Cascade Side Channels
**What:** Unique indexes and cascading foreign keys on RLS tables.
**Why:** If `UNIQUE (email)` is global, tenant A inserting an email that tenant B already has gets a duplicate-key error, which reveals the hidden row. `ON DELETE/UPDATE CASCADE` runs without RLS and changes rows the caller can't see.

**Rule:** Per-tenant values are unique per tenant (`UNIQUE (tenant_id, email)`). Cascades between RLS tables are used only when parent and child always share a tenant. Otherwise use `RESTRICT` and delete children explicitly.

---

## 16. SCRAM-SHA-256 Only
**What:** `password_encryption = scram-sha-256` and the stored hash type of each login role.
**Why:** MD5 password hashes can be replayed and cracked offline, and MD5 support is deprecated. Changing the setting affects only passwords set afterwards.

**Rule:** `password_encryption` is `scram-sha-256` and no login role has an MD5 hash. Reset each password after changing the setting, then switch `pg_hba` methods to `scram-sha-256`.

---

## 17. Timeouts and Connection Limits on the App Role
**What:** `statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout` and `CONNECTION LIMIT` set on the app role. Leave the migration role without them, so long index builds and `pg_dump` aren't cut off.
**Why:** A runaway or deliberately slow query, or a transaction left open by a crashed request, holds locks and connections until the database stops serving.

```sql
ALTER ROLE app_user SET statement_timeout = '30s';
ALTER ROLE app_user SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE app_user SET lock_timeout = '5s';
ALTER ROLE app_user CONNECTION LIMIT 50;
```
**Rule:** The app role has all four, sized from real query times (`pg_stat_statements`), and a pooler sits in front when many app instances connect. Role settings apply only to new sessions, so restart the app or recycle its pool after changing them.

---

## 18. Log for Forensics
**What:** `log_connections`, `log_disconnections`, `log_statement = 'ddl'`, `log_min_duration_statement` (for example `1000` ms), and a `log_line_prefix` such as `'%m [%p] user=%u,db=%d,app=%a,client=%h '`. Add `pgaudit` (in `shared_preload_libraries`) when you need DML audit trails.
**Why:** After an incident, you need to know who connected from where, which schema changes ran, and which queries scraped data. Without these settings that record doesn't exist. Watch `pg_stat_user_tables.seq_scan` spikes and repeated authentication failures, too.

**Rule:** Connection, disconnection and DDL logging are on, slow queries are logged (with bind parameters kept out, see `dbh.22`), and each log line names the user, database and client. Logs are shipped off the database host. For personal data, load `pgaudit` (`pgaudit.log = 'ddl, role, write'`, plus `read` on the tables that need it). Loading it without setting `pgaudit.log` audits nothing; the snapshot reports that.

---

## 19. Encrypt at Rest and Encrypt High-Value Secrets in the App
**What:** Volume or disk encryption (LUKS, cloud volume encryption) for the data directory and WAL. Application-layer AES-256-GCM (or `pgcrypto` with keys kept outside the database) for TOTP secrets, API tokens, and identifiers such as SSNs.
**Why:** Open-source PostgreSQL has no transparent data encryption. Disk encryption protects against stolen disks and snapshots. App-layer encryption protects secrets from anyone who can query the table (see `dbs.06` for passwords, which are hashed, not encrypted).

Prefer encrypting in the app over `pgcrypto`. CVE-2026-14663 showed `pgcrypto` silently "encrypting" to cleartext when the requested cipher was disabled in OpenSSL, so test that ciphertext really differs from the input. With `pgp_sym_encrypt(data, key)` the key travels inside the SQL statement, so it can end up in the server log, in `pg_stat_activity`, and in `pg_stat_statements` for non-parameterized queries.

**Rule:** Database volumes are encrypted. High-value secrets are encrypted before insert, with keys in a secret manager or environment vault, never in the database or in SQL text.

---

## 20. Protect the Data Directory on the Host
**What:** `PGDATA` permissions `0700` (the server reports them as `data_directory_mode`), `umask 0077` for the `postgres` OS user, and a host firewall that admits 5432 only from the app.
**Why:** Anyone who can read the data directory can read every table and WAL segment directly, with no database permissions involved.

**Rule:** `PGDATA` is `0700` (`0750` only for a deliberate backup group), owned by the database user, and only the app's hosts can reach the port (container-standards `host.*` and `cnet.*`). The database host can't open connections to the internet (egress firewall: allow only backups, updates and monitoring). The OS and its packages are patched too: several PostgreSQL CVEs were in init scripts and `pg_upgrade` temp files rather than the server.

---

## 21. Encrypted, Off-Site, Immutable Backups
**What:** `pg_dump` and WAL archives encrypted (`age`, `gpg`, or pgBackRest repository encryption) before upload, stored in object storage with object lock or write-only credentials.
**Why:** Backups hold all the personal data with none of the access controls. An attacker who controls the server will delete reachable backups before encrypting or wiping the database.

A dump holds every tenant's data, and the role that takes it needs `BYPASSRLS` or table ownership. Otherwise `pg_dump` stops with an error rather than producing a partial dump. Copies made with `COPY`, materialized views, exports and background jobs leave RLS behind in the same way.

Restoring is also an attack path: `pg_restore` and `psql` have executed code from crafted archives and dumps (`dbh.01`). Restore only dumps you produced, with patched client tools, in an isolated environment.

**Rule:** Backups are encrypted with keys kept off the database host, uploaded with credentials that can't delete or overwrite, and restored on a schedule (container-standards `ops.02`). Restores run in an isolated environment, and test or staging databases never get a copy of production personal data without masking it first.

---

## 22. Keep Personal Data Out of Logs
**What:** Server settings and app logging that write query text with its values.
**Why:** With `log_min_duration_statement` or `log_statement = 'mod'/'all'` set, PostgreSQL logs bind parameter values in full by default (`log_parameter_max_length = -1`). Those values include email addresses, names and `ALTER ROLE … PASSWORD` strings. Logs are copied to more places, kept longer and guarded less than the database. Drizzle's `logger: true` prints every query with its parameters to stdout.

```ini
log_statement = 'ddl'
log_min_duration_statement = 1000
log_parameter_max_length = 0            # no bind values in statement logs
log_parameter_max_length_on_error = 0   # the default: none in error logs
```
```ts
const db = drizzle(client, { logger: process.env.NODE_ENV !== 'production' });
```
**Rule:** Production logs never contain bind parameter values or full result data: `log_parameter_max_length = 0` whenever statements are logged, `log_statement` no broader than `ddl`, and ORM query logging off (or without params) in production. Audit trails of who read what come from `pgaudit` with per-table settings, not from logging every statement.

---

## 23. Dynamic SQL Inside the Database Is Parameterized Too
**What:** `EXECUTE` in PL/pgSQL functions, procedures and `DO` blocks.
**Why:** A function that builds SQL as `'… WHERE ' || col || ' = ' || v` is injectable however carefully the app parameterizes its call: the value arrives safely as a parameter, then the function pastes it into new SQL. In a `SECURITY DEFINER` function, the injected SQL runs with the owner's rights. `format('%s', v)` pastes the value just as unsafely.

```sql
-- ❌ EXECUTE 'SELECT * FROM projects WHERE ' || col || ' = ' || quote_literal(v)   -- col is still raw
-- ✅
RETURN QUERY EXECUTE format('SELECT * FROM projects WHERE %I = $1', col) USING v;
```
Two server settings decide whether escaped strings stay escaped: `standard_conforming_strings` must be `on` and `backslash_quote` must stay at `safe_encoding`. Both are the defaults. Turning them back to the legacy values makes `\'` close a string, which revives old escaping-bypass injections. The snapshot checks both.

Object names are input too. PostgreSQL's own tools (`pg_dump`, `reindexdb`, extension scripts, `REFRESH PUBLICATION`) have had SQL-injection and code-execution CVEs triggered by crafted table, constraint, index or object names (CVE-2026-116318, CVE-2026-116325, CVE-2026-6638, CVE-2025-8715). If the app creates schemas or tables per tenant, build the names from an allow-listed slug (`^[a-z][a-z0-9_]{0,62}$`), never from raw user input.

**Rule:** Dynamic SQL uses `format()` with `%I` for identifiers and `%L` for literals, or passes values with `EXECUTE … USING`. Identifiers that come from callers are also checked against an allow-list. `quote_ident()` / `quote_literal()` are acceptable for single values. The check skips lines that use them, so confirm the other pieces of the string by eye.

---

## Drizzle ORM specifics

- **RLS in the schema:** `pgTable.withRLS(...)` (or `.enableRLS()` on older versions) and `pgPolicy(name, { as, for, to, using, withCheck })` make drizzle-kit emit `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY`. drizzle-kit disables RLS when the last policy on a plain `pgTable` is removed, so use `withRLS` for tables that must stay locked. `FORCE ROW LEVEL SECURITY` isn't generated: add it in a custom migration (`drizzle-kit generate --custom`). The audit reads the generated SQL, so read it before applying (`dbm.10`).
- **Roles:** drizzle-kit leaves roles alone unless `entities: { roles: true }` is set in `drizzle.config.ts`. Create the app and migration roles in a migration or by an admin, never at app start-up.
- **Views:** `pgView(...).with({ securityInvoker: true })` emits `security_invoker = true`.
- **Tenant context:** ``await db.transaction(async (tx) => { await tx.execute(sql`select set_config('app.tenant_id', ${tenantId}, true)`); … })``. Run every tenant query on `tx`, never on `db`, inside that callback.
- **Two clients:** the app uses a `DATABASE_URL` for the runtime role. Migrations (`drizzle.config.ts`, `drizzle-kit migrate`) use a separate URL for the owner role, available only to CI or the release step.
- **Raw SQL:** ``sql`…${value}` `` is parameterized and `sql.raw()` is not. Never pass user input, tokens or role names to `sql.raw()` (web-standards `sec.10`, `dbh.12`).
- **Drizzle Studio and `drizzle-kit push`:** local development only. Never point them at production (`dbo.01`).

---

## Attack coverage map

Where each common attack on a Postgres-backed app is covered. **Static** means a repo audit; **live** means the snapshot; **manual** means a reviewer question.

| Attack | Covered by |
|---|---|
| SQL injection: string concatenation, template strings, `sql.raw`, `$queryRawUnsafe`, `unsafe()` | web-standards `sec.10` (static) |
| Blind, time-based (`pg_sleep`) and stacked-query injection | Same root cause as above (`sec.10`); `dbh.17` statement timeout limits the damage |
| Injection through identifiers (`ORDER BY`, column or table names) | `sec.10` (`sql.identifier`/`sql.raw` with variables) |
| Second-order injection / dynamic SQL in functions | `dbh.23` (static + live) |
| Tenant context forged by injection (`set_config`) | `dbh.12` (`sql.raw` in context, static); depends on `sec.10` |
| LIKE wildcard / regex abuse (`%`, `_`, user-supplied regex) | `sec.10` (LIKE, info); `dbh.17` timeout for regex |
| Mass assignment (client sets `tenant_id`, `role`, `isAdmin`) | `sec.10` (static), `net.19` schema validation |
| Missing input validation in route handlers and Server Actions | web-standards `net.19` (static) |
| IDOR / cross-tenant reads and writes | `dbh.10`–`dbh.13` (live + static), web-standards `sec.17` |
| RLS bypass: owner, `BYPASSRLS`, partitions, views, materialized views, `TRUNCATE` | `dbh.06`, `dbh.10`, `dbh.13` |
| Side channels (unique errors, cascades) | `dbh.15` |
| Privilege escalation: `SECURITY DEFINER`, `search_path`, `PUBLIC CREATE` | `dbh.07`, `dbh.14` |
| Remote code execution / file read: CVEs, `COPY … PROGRAM`, `pg_read_file`, untrusted languages, `lo_import` | `dbh.01`, `dbh.08` (incl. predefined-role memberships) |
| Data exfiltration over the network (`dblink`, `postgres_fdw`) | `dbh.08` |
| Exposed port, `trust`, MD5, brute force, superuser login over the network | `dbh.03`, `dbh.04`, `dbh.16`, container-standards `cnet.*`, Coolify `cool.02` |
| Pre-authentication server bugs (no login needed) | `dbh.03` network isolation, `dbh.01` patching |
| Malicious dumps, archives and object names attacking client tools | `dbh.01` (client versions), `dbh.21` (restore only trusted dumps), `dbh.23` (object names) |
| Bugs in contrib modules and procedural languages | `dbh.08` (live inventory from `pg-versions.json`) |
| Logical replication (publisher → subscriber code execution, all-table publications) | `dbh.08`, `dbh.13` |
| Post-compromise backdoors: C functions (`sys_eval`), large-object staging (`lo_export`), cryptominers | `dbh.08` (live, signs of compromise); egress firewall (`dbh.20`) |
| Search-path hijacking (CVE-2018-1058) | `dbh.07` (`PUBLIC` or app role `CREATE` on schemas), `dbh.14` |
| Over-broad role attributes and re-grantable privileges | `dbh.06` (`SUPERUSER`/`CREATEROLE`/`CREATEDB`, `WITH GRANT OPTION`) |
| Escalation through role membership (`SET ROLE` to the owner or a superuser, inherited `TEMP`/`CREATE`/predefined roles) | `dbh.06`, `dbh.02`, `dbh.08` (live, transitive memberships) |
| Future objects exposed by default privileges | `dbh.07` (live, `pg_default_acl`) |
| Server file functions granted to non-superusers (`pg_read_file`, `lo_export`) | `dbh.08` (live, function ACLs, `lo_compat_privileges`) |
| Superuser-only settings granted to other roles (`ALTER SYSTEM` on `archive_command`) | `dbh.06` (live, `pg_parameter_acl`, PostgreSQL 15+) |
| Sniffing / man-in-the-middle | `dbh.05`, `dbo.03` (`sslmode`, `rejectUnauthorized`) |
| Leaked credentials (code, images, env, client bundle) | `sec.16`, `dbo.04`, container-standards `csec.*` |
| Denial of service (runaway queries, connection floods, idle transactions) | `dbh.17`, `dbo.05`, web `net.15` rate limits |
| Personal data in logs, errors or backups | `dbh.22`, web `net.17` (raw DB errors), `dbh.21` (manual) |
| Stored XSS (poisoned data rendered later) | web-standards `sec.01` (output encoding) |
| Data integrity / poisoning (bad rows) | `dbs.08` constraints, `net.19` validation, `dbo.06` seed guards |
| Destructive or unreviewed schema changes | `dbm.*`, `dbo.01`, `dbo.07` |
| Supply chain (npm packages, images) | `sec.11`, container-standards `sup.*`, `img.01` |
| Disk, snapshot or backup theft | `dbh.19`–`dbh.21` (manual) |

### SQL injection techniques (Invicti cheat sheet) on PostgreSQL

Every technique below needs one thing: user input pasted into SQL text. Parameterized queries (`sec.10`) stop all of them. The other controls limit what an attacker gets if one query slips through.

| Technique | PostgreSQL form | What stops it here |
|---|---|---|
| Comments (`--`, `/* */`), `' OR 1=1`, login bypass | Same syntax | Parameters (`sec.10`); never hand-roll quote escaping (`sec.10` flags `replace(/'/g, "''")`) |
| Quote-free strings and filter bypass | `CHR(75)\|\|…`, dollar quoting `$$text$$`, `E'\x41'` | Parameters. Blocklists and WAF rules don't stop these, so don't rely on them |
| Stacked queries (`; DROP …`) | Allowed by the simple query protocol: `pg.query(text)` and postgres.js `sql.unsafe(text)` with no parameters | Pass parameters, which switches the driver to the extended protocol (one statement per call); the app role can't DROP tables it doesn't own (`dbh.06`) |
| UNION-based extraction | `UNION SELECT NULL, version(), …` | Parameters; column grants (`dbh.09`) and RLS (`dbh.10`) limit what a UNION can reach |
| Error-based extraction (`CAST(… AS int)` errors, column discovery) | Error text names tables, columns and values | No raw errors to the client (web-standards `net.17`) |
| Boolean / time-based blind (`CASE WHEN … pg_sleep(10)`) | `pg_sleep`, heavy `generate_series` | Parameters; `statement_timeout` on the app role (`dbh.17`); alert on bursts of slow or failing queries (`dbh.18`) |
| `ORDER BY` / `LIMIT` injection, column counting | `ORDER BY 5--` | Allow-listed identifiers (`sec.10` flags `sql.identifier`/`sql.raw`); LIMIT validated and capped (`sec.10`) |
| INSERT payloads that add admin users | `'); INSERT INTO users …` | Parameters; mass-assignment check (`sec.10`); RLS `WITH CHECK` (`dbh.11`) |
| Reading files (`LOAD_FILE`, `BULK INSERT` equivalents) | `COPY … FROM '/etc/passwd'`, `pg_read_file()`, `lo_import()` | Superuser or `pg_read_server_files` only, and the app role has neither (`dbh.06`, `dbh.08`) |
| OS commands (`xp_cmdshell` equivalent) | `COPY … FROM PROGRAM`, untrusted languages, C functions | Superuser or `pg_execute_server_program` only (`dbh.06`, `dbh.08`); patch level (`dbh.01`) |
| Out-of-band exfiltration (DNS, HTTP, UNC) | `dblink`, `postgres_fdw`, `http`/`pg_net` extensions, `COPY TO PROGRAM` | No such extensions or memberships for the app role (`dbh.08`); egress firewall on the database host |
| Shutting the server down or killing sessions | `pg_terminate_backend()`, `pg_cancel_backend()` | Superuser or `pg_signal_backend` only (`dbh.08`) |
| Schema discovery (`information_schema`, `sysobjects`) | `pg_catalog`, `information_schema` are readable by every role | Can't be fully revoked: keep secrets out of names and comments, and rely on RLS and grants for the data |
| Version discovery | `version()`, `server_version` | Stay patched (`dbh.01`); don't show error pages that print it (`net.17`) |
| Hiding from logs (`sp_password` trick) | No equivalent; only superusers can change `log_*` settings | Keep the app role non-superuser (`dbh.06`); ship logs off the host (`dbh.18`) |
| Second-order injection | Stored value later pasted into `EXECUTE` | `dbh.23` (functions), `sec.10` (app code) |
| Injection through JSON bodies, GraphQL variables and headers | Same root cause: the value reaches SQL text | `sec.10` checks the SQL sink, whatever the source; tenant taken from a header or query string is `dbh.12` |

Not detectable by any static or catalog check: logic flaws in authorization (who may see what), timing side channels, and attacks through app features that are working as designed. Cover these with tests that connect as the real app role and try to read and write another tenant's data, plus code review.

---

## Corrections to common hardening checklists

Checklists pasted into a request (blog posts, generated blueprints) often contain advice that is wrong or breaks production. When a request includes one of these, follow this file and say what you changed and why:

| Checklist says | What to do instead |
|---|---|
| Set `ssl_negotiation = direct` in `postgresql.conf` | There is no such server setting. `sslnegotiation=direct` is a client connection option (libpq 17+, needs `sslmode=require` or stricter and ALPN), and only PostgreSQL 17+ servers with `ssl = on` accept it (`dbh.05`). |
| `ssl_min_protocol_version = 'TLSv1.3'` | `TLSv1.2` (the default) until every client, driver and pooler is confirmed to support 1.3 (`dbh.05`). |
| `REVOKE TEMPORARY ON DATABASE … FROM app_user` | A no-op when the privilege comes from `PUBLIC` (the default). Revoke from `PUBLIC`, and check group memberships (`dbh.02`). |
| `REVOKE ALL ON SCHEMA public FROM PUBLIC` | This also removes `USAGE`, which breaks every role that calls extension functions in `public`. Revoke `CREATE` only, then grant `USAGE` by name (`dbh.07`). |
| `REVOKE ALL ON DATABASE … FROM PUBLIC` | Grant `CONNECT` to the app, owner, backup and monitoring roles **first**, or they lose access at once (`dbh.02`). |
| `REVOKE SELECT ON users …; GRANT SELECT (id, email, …)` | Correct, but Drizzle's `db.select().from(users)` and `SELECT *` name every column and fail with `permission denied`. Change the queries to list columns in the same release (`dbh.09`). |
| `SET search_path = public, pg_temp` in definer functions | Safe only while nobody else can `CREATE` in `public`. Prefer `pg_catalog, pg_temp` with schema-qualified names (`dbh.14`). |
| `FORCE ROW LEVEL SECURITY` on every table | Forcing also applies the policies to the owner, so data migrations and backfills run as the owner see only the rows the current setting allows. Force only where the app connects as the owner, after testing migrations (`dbh.10`). |
| `EXPLAIN ANALYZE` the critical queries in production | `EXPLAIN ANALYZE` executes the statement. Use plain `EXPLAIN` in production, and `EXPLAIN ANALYZE` in staging or inside `BEGIN … ROLLBACK`. |
| Revoking `TEMPORARY` protects against a code-execution CVE | It narrows the surface, but only the patched minor release fixes the bug (`dbh.01`). Check each CVE's description on postgresql.org/support/security rather than the checklist's summary. |
| `ALTER ROLE app_user SET statement_timeout …` takes effect | Only for new sessions. Recycle the app's pool or restart it (`dbh.17`). |

## Staged rollout (zero outages)

Each step is safe to stop after. Take a backup before each step (`dbo.07`), and keep the rollback ready.

| Step | Change | Check before moving on | Rollback |
|---|---|---|---|
| 0. Contain (only if exposed) | `trust` from a non-local address in `pg_hba.conf`, or 5432 reachable from the internet: replace the line with `scram-sha-256` or `reject`, close the port at the firewall, `SELECT pg_reload_conf()`, then rotate passwords. Do this now, before patching | Logs show which clients used that line; `pg_hba_file_rules` has no errors; a connection from outside is refused | Restore the previous `pg_hba.conf` and reload |
| 1. Patch | New minor version (image tag or packages) for the server and client tools, then restart | `SELECT version()`; app health checks | Previous image tag (minor releases are binary-compatible) |
| 2. Observe | `log_connections`, `log_disconnections`, `log_statement = 'ddl'`, `log_line_prefix`, `log_min_duration_statement`, `ssl = on` (`pg_reload_conf()`; `ssl` needs only a reload) | Snapshot again: which roles, from where, with or without TLS | Reset the settings and reload |
| 3. Roles (staging first) | Create the migration and app roles, move ownership, revoke `PUBLIC`/`TEMPORARY`, column grants, app-role timeouts and connection limit; run the full test suite | No permission errors in tests or logs; migrations still run as the owner | `GRANT` back the revoked privileges; `ALTER ROLE … RESET statement_timeout` |
| 4. TLS and SCRAM | Clients switch to `sslmode=require`/`verify-full`; set `password_encryption`, reset passwords; then `hostssl` + `scram-sha-256` in `pg_hba.conf` and `SELECT pg_reload_conf()` | Zero rows with `ssl = false` in `pg_stat_ssl`; no MD5 hashes left | Restore the previous `pg_hba.conf` and reload |
| 5. RLS, one table at a time | `ENABLE` (then `FORCE`) RLS with policies on one tenant table in staging; `SET LOCAL` tenant context in the app | `EXPLAIN ANALYZE` on critical queries uses the tenant index; INSERT/UPDATE/DELETE paths pass tests | `ALTER TABLE … DISABLE ROW LEVEL SECURITY` (or `NO FORCE`) |

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01 | Vulnerable_Dependency_Management, Database_Security |
| 02–04, 06–08, 14, 17, 20, 21 | Database_Security |
| 05 | Database_Security, Transport_Layer_Security |
| 09, 19 | Cryptographic_Storage, Secrets_Management |
| 10–13, 15 | Multi_Tenant_Security, Authorization |
| 16 | Password_Storage |
| 18, 22 | Logging |
| 23 | SQL_Injection_Prevention, Database_Security |
