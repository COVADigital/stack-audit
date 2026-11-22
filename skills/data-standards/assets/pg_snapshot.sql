-- stack-audit PostgreSQL security snapshot (dbh.*). Read-only catalog queries, no row data.
--
--   psql -X -d <database> -f pg_snapshot.sql -o <scratchpad>/pg-snapshot.jsonl
--   python audit_postgres.py --root <repo> --snapshot <scratchpad>/pg-snapshot.jsonl [--app-role NAME]
--
-- Each query prints one JSON line (jsonb output is single-line; json_agg is not): {"section": ..., "rows": [...]}. A section the role can't read fails on its own
-- (errors go to stderr) and is reported as "not checked"; the others still run. Run it as a superuser, or as a role in
-- pg_read_all_settings + pg_read_all_stats for everything except pg_hba_file_rules and password hash types.
--
-- Never selected: table rows, rolpassword (only its hash type label), pg_hba options (can hold LDAP bind passwords),
-- client IP addresses (only local/private/public), application_name, query text.
-- Catalog reads take only ACCESS SHARE locks on catalog tables; the statement timeout bounds every query.

\set QUIET 1
\set ON_ERROR_STOP 0
\pset pager off
\pset format unaligned
\pset tuples_only on
SET default_transaction_read_only = on;
SET statement_timeout = '5s';
SET lock_timeout = '1s';
SET standard_conforming_strings = on;  -- the regexes below need it; the server's own value is read via reset_val

SELECT jsonb_build_object('section', 'meta', 'rows', jsonb_build_array(jsonb_build_object(
  'snapshot_version', 1,
  'collected_at', now(),
  'server_version_num', current_setting('server_version_num')::int,
  'server_version', current_setting('server_version'),
  'database', current_database(),
  'current_user', current_user,
  'is_superuser', current_setting('is_superuser') = 'on',
  'can_read_stats', pg_has_role('pg_read_all_stats', 'member'),
  'bootstrap_superuser', (SELECT rolname FROM pg_roles WHERE oid = 10))));

-- psql's own version (client tools): dbh.01. Missing when psql is older than 11.
SELECT jsonb_build_object('section', 'client', 'rows', jsonb_build_array(jsonb_build_object('psql_version_num', :VERSION_NUM)));

SELECT jsonb_build_object('section', 'settings', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  -- reset_val for timeouts: this script's own SETs would otherwise show; setting for the rest (reset_val is decimal for octal modes)
  SELECT name, CASE WHEN name LIKE '%timeout' OR name = 'standard_conforming_strings' THEN reset_val ELSE setting END AS setting, source FROM pg_settings
  WHERE name IN ('listen_addresses', 'port', 'ssl', 'ssl_min_protocol_version', 'password_encryption',
                 'log_connections', 'log_disconnections', 'log_statement', 'log_min_duration_statement',
                 'log_line_prefix', 'shared_preload_libraries', 'statement_timeout', 'lock_timeout',
                 'idle_in_transaction_session_timeout', 'row_security', 'data_directory_mode',
                 'log_parameter_max_length', 'log_parameter_max_length_on_error',
                 'standard_conforming_strings', 'backslash_quote')
) t;

SELECT jsonb_build_object('section', 'databases', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT d.datname AS database,
         CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
         a.privilege_type AS privilege
  FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
  WHERE NOT d.datistemplate
) t;

SELECT jsonb_build_object('section', 'hba', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT line_number, type, database, user_name, address, netmask, auth_method, error
  FROM pg_hba_file_rules ORDER BY line_number
) t;

SELECT jsonb_build_object('section', 'sessions', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT a.usename AS role, coalesce(s.ssl, false) AS ssl, s.version AS tls_version,
         CASE WHEN a.client_addr IS NULL OR host(a.client_addr) IN ('127.0.0.1', '::1') THEN 'local'
              WHEN a.client_addr << '10.0.0.0/8' OR a.client_addr << '172.16.0.0/12' OR a.client_addr << '192.168.0.0/16'
                OR a.client_addr << '100.64.0.0/10' OR a.client_addr << 'fc00::/7' THEN 'private'
              ELSE 'public' END AS client,
         count(*) AS sessions
  FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s USING (pid)
  WHERE a.backend_type = 'client backend' AND a.pid <> pg_backend_pid()
  GROUP BY 1, 2, 3, 4
) t;

SELECT jsonb_build_object('section', 'roles', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT r.rolname AS role, r.rolsuper AS superuser, r.rolcreaterole AS createrole, r.rolcreatedb AS createdb,
         r.rolreplication AS replication, r.rolbypassrls AS bypassrls, r.rolcanlogin AS login,
         r.rolconnlimit AS connlimit,
         (SELECT jsonb_agg(c) FROM unnest(r.rolconfig) c
           WHERE c ~ '^(statement_timeout|lock_timeout|idle_in_transaction_session_timeout|idle_session_timeout|search_path)=') AS config,
         (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relowner = r.oid AND c.relkind IN ('r', 'p') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') AS owned_tables
  FROM pg_roles r WHERE r.rolname !~ '^pg_'
) t;

-- Members of predefined roles that read/write server files or run programs (pg_read_file, COPY ... PROGRAM): dbh.08.
SELECT jsonb_build_object('section', 'memberships', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT r.rolname AS role, g.rolname AS granted
  FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member JOIN pg_roles g ON g.oid = am.roleid
  WHERE g.rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files',
                      'pg_read_all_data', 'pg_write_all_data', 'pg_signal_backend', 'pg_read_all_stats', 'pg_monitor')
) t;

SELECT jsonb_build_object('section', 'db_role_settings', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT coalesce(pg_get_userbyid(nullif(s.setrole, 0)), '*') AS role,
         coalesce((SELECT datname FROM pg_database WHERE oid = nullif(s.setdatabase, 0)), '*') AS database,
         (SELECT jsonb_agg(c) FROM unnest(s.setconfig) c
           WHERE c ~ '^(statement_timeout|lock_timeout|idle_in_transaction_session_timeout|idle_session_timeout)=') AS config
  FROM pg_db_role_setting s
) t;

SELECT jsonb_build_object('section', 'password_types', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT rolname AS role,
         CASE WHEN rolpassword IS NULL THEN 'none'
              WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256'
              WHEN rolpassword LIKE 'md5%' THEN 'md5'
              ELSE 'other' END AS hash_type
  FROM pg_authid WHERE rolcanlogin AND rolname !~ '^pg_'
) t;

SELECT jsonb_build_object('section', 'schemas', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, pg_get_userbyid(n.nspowner) AS owner,
         CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
         a.privilege_type AS privilege
  FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
  WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
) t;

SELECT jsonb_build_object('section', 'extensions', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT extname AS name, extversion AS version FROM pg_extension
) t;

SELECT jsonb_build_object('section', 'languages', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT lanname AS name, lanpltrusted AS trusted FROM pg_language WHERE lanispl
) t;

-- Tables, views and materialized views: RLS flags, column names (no data), table-level grants, and for views the
-- tables they read.
SELECT jsonb_build_object('section', 'relations', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, c.relname AS name, c.relkind::text AS kind, pg_get_userbyid(c.relowner) AS owner,
         c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls, c.reloptions,
         (SELECT pn.nspname || '.' || p.relname FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent
           JOIN pg_namespace pn ON pn.oid = p.relnamespace WHERE i.inhrelid = c.oid LIMIT 1) AS parent,
         (SELECT jsonb_agg(a.attname ORDER BY a.attnum) FROM pg_attribute a
           WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS columns,
         (SELECT jsonb_agg(jsonb_build_object('grantee', CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                                            'privilege', g.privilege_type, 'grantable', g.is_grantable))
           FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) g) AS grants,
         CASE WHEN c.relkind IN ('v', 'm') THEN
           (SELECT jsonb_agg(DISTINCT rn.nspname || '.' || rc.relname)
             FROM pg_rewrite rw
             JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid
             JOIN pg_class rc ON rc.oid = d.refobjid AND rc.oid <> c.oid AND rc.relkind IN ('r', 'p')
             JOIN pg_namespace rn ON rn.oid = rc.relnamespace
             WHERE rw.ev_class = c.oid) END AS reads
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
) t;

SELECT jsonb_build_object('section', 'policies', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT schemaname AS schema, tablename AS name, policyname AS policy, permissive, roles, cmd, qual, with_check
  FROM pg_policies
) t;

SELECT jsonb_build_object('section', 'definer_functions', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, p.proname AS name, pg_get_userbyid(p.proowner) AS owner, p.proconfig AS config,
         EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) g
                 WHERE g.grantee = 0 AND g.privilege_type = 'EXECUTE') AS public_execute
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE p.prosecdef AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
) t;

-- PL/pgSQL functions whose EXECUTE is built by concatenation or format('%s'): dbh.23. Only a flag, never the source.
SELECT jsonb_build_object('section', 'dynamic_sql', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, p.proname AS name, p.prosecdef AS definer
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  WHERE l.lanname = 'plpgsql' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
    AND p.prosrc ~* '\mEXECUTE\M'
    AND (p.prosrc ~* 'EXECUTE\s+[^;]*\|\|' OR p.prosrc ~* ':=\s*''[^;]*\m(select|insert|update|delete)\M[^;]*\|\|'
         OR p.prosrc ~* 'format\s*\(\s*''[^'']*%s')
    AND p.prosrc !~* 'quote_(ident|literal|nullable)\s*\('
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
) t;

-- Indicators of compromise (dbh.08): C or untrusted-language functions outside extensions, and large objects
-- (lo_export/lo_import staged the 2018 cryptominer payloads). Names and counts only.
SELECT jsonb_build_object('section', 'native_functions', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, p.proname AS name, l.lanname AS language
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  WHERE (l.lanname = 'c' OR (l.lanispl AND NOT l.lanpltrusted))
    AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
) t;

SELECT jsonb_build_object('section', 'large_objects', 'rows', jsonb_build_array(jsonb_build_object(
  'count', (SELECT count(*) FROM pg_largeobject_metadata),
  'superuser_owned', (SELECT count(*) FROM pg_largeobject_metadata m JOIN pg_roles r ON r.oid = m.lomowner WHERE r.rolsuper))));

-- Logical replication: publications (data streamed out, no RLS) and subscriptions (trust the publisher): dbh.08/dbh.13.
SELECT jsonb_build_object('section', 'publications', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT pubname AS name, puballtables AS all_tables FROM pg_publication
) t;

SELECT jsonb_build_object('section', 'subscriptions', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT subname AS name FROM pg_subscription
) t;

SELECT jsonb_build_object('section', 'unique_indexes', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, t.relname AS name, i.relname AS index,
         (SELECT jsonb_agg(a.attname) FROM unnest(x.indkey::int2[]) k JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k) AS columns
  FROM pg_index x
  JOIN pg_class t ON t.oid = x.indrelid
  JOIN pg_class i ON i.oid = x.indexrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
  WHERE x.indisunique AND NOT x.indisprimary AND t.relrowsecurity
) t;

SELECT jsonb_build_object('section', 'cascades', 'rows', coalesce(jsonb_agg(t), '[]'::jsonb)) FROM (
  SELECT n.nspname AS schema, t.relname AS name, c.conname AS constraint_name,
         rn.nspname || '.' || r.relname AS ref_table, c.confdeltype::text AS on_delete, c.confupdtype::text AS on_update
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
  JOIN pg_class r ON r.oid = c.confrelid JOIN pg_namespace rn ON rn.oid = r.relnamespace
  WHERE c.contype = 'f' AND (c.confdeltype = 'c' OR c.confupdtype = 'c') AND (t.relrowsecurity OR r.relrowsecurity)
) t;
