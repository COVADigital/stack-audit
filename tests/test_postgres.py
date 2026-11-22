"""Tests for data-standards audit_postgres.py: static dbh.* checks and the live snapshot (pg_snapshot.sql output)."""

import copy
import json
import re
import subprocess
import sys
import unittest

from helpers import PLUGIN_ROOT, TempRepo

SKILL = PLUGIN_ROOT / "skills" / "data-standards"
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))
import audit_postgres  # noqa: E402

META = {"snapshot_version": 1, "collected_at": "2026-11-21T10:00:00Z", "server_version_num": 180007, "server_version": "18.7",
        "database": "app", "current_user": "postgres", "is_superuser": True, "can_read_stats": True, "bootstrap_superuser": "postgres"}


def rel(name, cols, kind="r", owner="db_owner", rls=False, force=False, grants=None, reads=None, options=None, parent=None):
    return {"schema": "public", "name": name, "kind": kind, "owner": owner, "rls": rls, "force_rls": force, "reloptions": options,
            "parent": parent,
            "columns": cols, "grants": grants or [{"grantee": "app_user", "privilege": "SELECT"}], "reads": reads}


def clean() -> dict:
    return {
        "meta": [META],
        "client": [{"psql_version_num": 180007}],
        "memberships": [],
        "settings": [{"name": n, "setting": v, "source": "configuration file"} for n, v in {
            "listen_addresses": "*", "ssl": "on", "ssl_min_protocol_version": "TLSv1.2", "password_encryption": "scram-sha-256",
            "log_connections": "on", "log_disconnections": "on", "log_statement": "ddl", "log_min_duration_statement": "1000",
            "log_line_prefix": "%m [%p] user=%u,db=%d,app=%a,client=%h ", "statement_timeout": "0", "lock_timeout": "0",
            "idle_in_transaction_session_timeout": "0", "data_directory_mode": "0700",
            "shared_preload_libraries": "pg_stat_statements,pgaudit", "log_parameter_max_length": "0"}.items()],
        "databases": [{"database": "app", "grantee": "app_user", "privilege": "CONNECT"}],
        "hba": [{"line_number": 1, "type": "local", "database": ["all"], "user_name": ["postgres"], "address": None, "netmask": None,
                 "auth_method": "peer", "error": None},
                {"line_number": 2, "type": "hostssl", "database": ["app"], "user_name": ["app_user"], "address": "10.0.1.0",
                 "netmask": "255.255.255.0", "auth_method": "scram-sha-256", "error": None},
                {"line_number": 3, "type": "host", "database": ["all"], "user_name": ["all"], "address": "0.0.0.0",
                 "netmask": "0.0.0.0", "auth_method": "reject", "error": None}],
        "sessions": [{"role": "app_user", "ssl": True, "tls_version": "TLSv1.3", "client": "private", "sessions": 8}],
        "roles": [{"role": "postgres", "superuser": True, "createrole": True, "createdb": True, "replication": True, "bypassrls": True,
                   "login": True, "connlimit": -1, "config": None, "owned_tables": 0},
                  {"role": "db_owner", "superuser": False, "createrole": False, "createdb": False, "replication": False, "bypassrls": False,
                   "login": False, "connlimit": -1, "config": None, "owned_tables": 3},
                  {"role": "app_user", "superuser": False, "createrole": False, "createdb": False, "replication": False, "bypassrls": False,
                   "login": True, "connlimit": 50, "owned_tables": 0,
                   "config": ["statement_timeout=30s", "lock_timeout=5s", "idle_in_transaction_session_timeout=30s"]}],
        "db_role_settings": [],
        "password_types": [{"role": "app_user", "hash_type": "scram-sha-256"}],
        "schemas": [{"schema": "public", "owner": "pg_database_owner", "grantee": "PUBLIC", "privilege": "USAGE"}],
        "extensions": [{"name": "plpgsql", "version": "1.0"}, {"name": "citext", "version": "1.6"}],
        "languages": [{"name": "plpgsql", "trusted": True}],
        "relations": [rel("projects", ["id", "tenant_id", "name"], rls=True),
                      rel("users", ["id", "tenant_id", "email"], rls=True),
                      rel("project_list", ["id", "name"], kind="v", reads=["public.projects"], options=["security_invoker=true"])],
        "policies": [{"schema": "public", "name": t, "policy": "tenant_isolation", "permissive": "PERMISSIVE", "roles": ["app_user"],
                      "cmd": "ALL", "qual": "(tenant_id = (SELECT (current_setting('app.tenant_id'::text, true))::uuid AS current_setting))",
                      "with_check": None} for t in ("projects", "users")],
        "definer_functions": [{"schema": "public", "name": "lookup", "owner": "db_owner", "config": ["search_path=pg_catalog, pg_temp"],
                               "public_execute": False}],
        "unique_indexes": [{"schema": "public", "name": "users", "index": "users_tenant_email", "columns": ["tenant_id", "email"]}],
        "dynamic_sql": [],
        "native_functions": [],
        "publications": [{"name": "analytics", "all_tables": False}],
        "subscriptions": [],
        "large_objects": [{"count": 0, "superuser_owned": 0}],
        "cascades": [],
    }


def bad() -> dict:
    s = clean()
    s["meta"] = [{**META, "server_version_num": 170005}]
    settings = {r["name"]: r for r in s["settings"]}
    settings["ssl"]["setting"] = "off"
    settings["password_encryption"]["setting"] = "md5"
    settings["log_statement"]["setting"] = "none"
    settings["data_directory_mode"]["setting"] = "0750"
    settings["shared_preload_libraries"]["setting"] = "pg_stat_statements"
    settings["log_parameter_max_length"]["setting"] = "-1"
    s["client"] = [{"psql_version_num": 160002}]
    s["memberships"] = [{"role": "app_user", "granted": "pg_read_server_files"}, {"role": "app_user", "granted": "pg_signal_backend"}]
    s["settings"] += [{"name": "standard_conforming_strings", "setting": "off", "source": "configuration file"},
                      {"name": "backslash_quote", "setting": "on", "source": "configuration file"}]
    s["databases"].append({"database": "app", "grantee": "app_user", "privilege": "TEMPORARY"})
    s["databases"].append({"database": "app", "grantee": "PUBLIC", "privilege": "TEMPORARY"})
    s["hba"][1]["auth_method"] = "md5"
    s["hba"].insert(2, {"line_number": 3, "type": "host", "database": ["all"], "user_name": ["all"], "address": "0.0.0.0",
                        "netmask": "0.0.0.0", "auth_method": "trust", "error": None})
    s["sessions"] = [{"role": "postgres", "ssl": False, "tls_version": None, "client": "public", "sessions": 2}]
    app = s["roles"][2]
    app.update(createdb=True, owned_tables=2, config=None, connlimit=-1)
    s["password_types"].append({"role": "legacy", "hash_type": "md5"})
    s["schemas"].append({"schema": "public", "owner": "postgres", "grantee": "PUBLIC", "privilege": "CREATE"})
    s["extensions"] += [{"name": "dblink", "version": "1.2"}, {"name": "pg_net", "version": "0.14"}]
    s["languages"].append({"name": "plpython3u", "trusted": False})
    s["relations"] = [
        rel("projects", ["id", "tenant_id", "name"], rls=True, owner="app_user"),
        rel("users", ["id", "tenant_id", "email", "password_hash", "totp_secret"], rls=True,
            grants=[{"grantee": "app_user", "privilege": "SELECT"}, {"grantee": "app_user", "privilege": "TRUNCATE"}]),
        rel("invoices", ["id", "org_id", "total"], grants=[{"grantee": "PUBLIC", "privilege": "SELECT"}]),
        rel("audit", ["id", "tenant_id"], rls=True),
        rel("events", ["id", "tenant_id"], kind="p", rls=True),
        rel("events_2026", ["id", "tenant_id"], parent="public.events"),
        rel("project_list", ["id"], kind="v", reads=["public.projects"]),
        rel("tenant_stats", ["tenant_id", "n"], kind="m", reads=["public.users"], grants=[{"grantee": "PUBLIC", "privilege": "SELECT"}]),
    ]
    s["policies"] = [
        {"schema": "public", "name": "projects", "policy": "ins", "permissive": "PERMISSIVE", "roles": ["app_user"], "cmd": "INSERT",
         "qual": None, "with_check": None},
        {"schema": "public", "name": "users", "policy": "all_rows", "permissive": "PERMISSIVE", "roles": ["public"], "cmd": "SELECT",
         "qual": "true", "with_check": None},
        {"schema": "public", "name": "users", "policy": "slow", "permissive": "PERMISSIVE", "roles": ["app_user"], "cmd": "UPDATE",
         "qual": "(tenant_id = (current_setting('app.tenant_id'::text, true))::uuid)", "with_check": None},
        {"schema": "public", "name": "users", "policy": "fallback", "permissive": "PERMISSIVE", "roles": ["app_user"], "cmd": "SELECT",
         "qual": "((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid) OR (current_setting('app.tenant_id'::text, true) IS NULL))",
         "with_check": None},
        {"schema": "public", "name": "events", "policy": "members", "permissive": "PERMISSIVE", "roles": ["app_user"], "cmd": "ALL",
         "qual": "(tenant_id IN ( SELECT m.tenant_id FROM memberships m WHERE (m.user_id = (SELECT current_setting('app.uid'::text, true) AS current_setting))::uuid))",
         "with_check": None},
        {"schema": "public", "name": "users", "policy": "by_name", "permissive": "RESTRICTIVE", "roles": ["app_user"], "cmd": "SELECT",
         "qual": "(email ~~* (SELECT current_setting('app.domain'::text, true) AS current_setting))", "with_check": None},
    ]
    s["definer_functions"] = [{"schema": "public", "name": "grant_admin", "owner": "postgres", "config": None, "public_execute": True}]
    s["unique_indexes"] = [{"schema": "public", "name": "users", "index": "users_email_key", "columns": ["email"]}]
    s["dynamic_sql"] = [{"schema": "public", "name": "search", "definer": True}]
    s["native_functions"] = [{"schema": "public", "name": "fun6440002537", "language": "c"}]
    s["publications"] = [{"name": "everything", "all_tables": True}]
    s["subscriptions"] = [{"name": "from_legacy"}]
    s["languages"].append({"name": "plperl", "trusted": True})
    s["extensions"].append({"name": "pg_trgm", "version": "1.6"})
    s["large_objects"] = [{"count": 2, "superuser_owned": 2}]
    s["schemas"].append({"schema": "public", "owner": "postgres", "grantee": "app_user", "privilege": "CREATE"})
    s["roles"].append({"role": "dev_alice", "superuser": False, "createrole": True, "createdb": True, "replication": False,
                       "bypassrls": False, "login": True, "connlimit": -1, "config": None, "owned_tables": 0})
    s["relations"][2]["grants"].append({"grantee": "app_user", "privilege": "UPDATE", "grantable": True})
    s["cascades"] = [{"schema": "public", "name": "audit", "constraint_name": "audit_user_fk", "ref_table": "public.users",
                      "on_delete": "c", "on_update": "a"}]
    return s


def to_jsonl(snap: dict) -> str:
    return "SET\n" + "\n".join(json.dumps({"section": k, "rows": v}) for k, v in snap.items()) + "\n"


class PostgresLiveTests(TempRepo):
    def run_audit(self, snap: dict | None, *extra):
        args = ["--snapshot", str(self.write("snap.jsonl", to_jsonl(snap)))] if snap is not None else []
        res = subprocess.run([sys.executable, str(SCRIPTS / "audit_postgres.py"), "--root", str(self.dir), "--format", "json",
                              *args, *extra], capture_output=True, text=True, encoding="utf-8")
        return res

    def report(self, snap, *extra):
        res = self.run_audit(snap, *extra)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def test_clean_snapshot_has_no_findings(self):
        data = self.report(clean(), "--app-role", "app_user")
        self.assertEqual([(f["rule"], f["message"]) for f in data["findings"]], [])
        self.assertFalse(any("needs a live target" in n for n in data["not_checked"]))
        self.assertTrue(any("dbh.19" in n for n in data["not_checked"]))

    def test_bad_snapshot_fires_every_live_rule(self):
        data = self.report(bad(), "--app-role", "app_user")
        rules = {f["rule"] for f in data["findings"]}
        want = {"dbh.01", "dbh.02", "dbh.03", "dbh.04", "dbh.05", "dbh.06", "dbh.07", "dbh.08", "dbh.09", "dbh.10", "dbh.11",
                "dbh.13", "dbh.14", "dbh.15", "dbh.16", "dbh.17", "dbh.18", "dbh.20", "dbh.22", "dbh.23"}   # dbh.12 is static only
        self.assertEqual(sorted(want - rules), [])
        msgs = " | ".join(f["message"] for f in data["findings"])
        for part in ("17.5 is missing security fixes", "PUBLIC has TEMPORARY", "`trust`", "accepts connections from any address",
                     "ssl is off", "session(s) from public addresses", "Superuser `postgres` has 2", "App role `app_user` has CREATEDB",
                     "owns 2 table(s)", "PUBLIC can create objects", "SECURITY DEFINER function `public.grant_admin`", "plpython3u", "dblink",
                     "password_hash, totp_secret", "`public.invoices` has `org_id`", "`public.audit` has RLS on but no policy",
                     "RLS isn't forced", "(INSERT) has no WITH CHECK", "allows every row", "current_setting() per row",
                     "View `public.project_list`", "Materialized view `public.tenant_stats`", "doesn't pin search_path",
                     "users_email_key", "audit_user_fk", "MD5 password hashes: legacy", "password_encryption is `md5`",
                     "statement_timeout, idle_in_transaction_session_timeout, lock_timeout, connection limit",
                     "log_statement = none", "Data directory mode is 0750", "pgaudit isn't loaded",
                     "Client tools: psql 16.2 is missing security fixes", "member of `pg_read_server_files`",
                     "App role `app_user` has TEMPORARY on database `app`", "PUBLIC has SELECT on `public.invoices`",
                     "LIKE/ILIKE", "`public.events_2026` is a partition/child of RLS table `public.events`",
                     "app_user can TRUNCATE RLS table `public.users`", "IS NULL / coalesce fallback", "runs a subquery per row",
                     "permissive SELECT policies on `public.users`", "owned by superuser `postgres`: any role runs it with RLS bypassed",
                     "full bind parameter values", "`public.search` builds dynamic SQL by concatenation or format('%s') and is SECURITY DEFINER",
                     "standard_conforming_strings is off", "backslash_quote is on", "Extension `pg_net`",
                     "member of `pg_signal_backend` (can cancel or terminate other sessions: denial of service)",
                     "`public.fun6440002537` is written in `c`", "2 large object(s) exist (2 owned by a superuser)",
                     "superuser `postgres` can log in over the network", "App role `app_user` can create objects in schema `public`",
                     "Login role `dev_alice` has CREATEROLE, CREATEDB", "App role can re-grant UPDATE on `public.invoices`",
                     "Publication `everything` is FOR ALL TABLES", "subscription `from_legacy`", "Procedural language `plperl` is installed",
                     "Extension `pg_trgm` is attack surface", "Extension `dblink` is attack surface"):
            self.assertIn(part, msgs)

    def test_eol_and_inferred_app_role(self):
        s = clean()
        s["meta"] = [{**META, "server_version_num": 140025}]
        s["roles"][2]["config"] = None
        data = self.report(s)
        by = {f["rule"]: f for f in data["findings"]}
        self.assertEqual(by["dbh.01"]["severity"], "error")
        self.assertIn("end-of-life", by["dbh.01"]["message"])
        self.assertEqual(by["dbh.17"]["confidence"], "medium")
        self.assertTrue(any("inferred as app_user" in s for s in data["skipped"]))

    def test_no_rls_anywhere_is_one_info(self):
        s = clean()
        for r in s["relations"]:
            r["rls"] = False
        s["policies"] = []
        found = [f for f in self.report(s, "--app-role", "app_user")["findings"] if f["rule"] == "dbh.10"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "info")

    def test_docker_default_hba(self):
        s = clean()
        s["roles"][0]["login"] = True
        s["hba"] = [{"line_number": n, "type": ty, "database": ["all"], "user_name": ["all"], "address": a, "netmask": m,
                     "auth_method": au, "error": None} for n, ty, a, m, au in (
            (117, "local", None, None, "trust"), (119, "host", "127.0.0.1", "255.255.255.255", "trust"),
            (121, "host", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "trust"), (128, "host", "all", None, "scram-sha-256"))]
        found = [(f["rule"], f["severity"], f["message"]) for f in self.report(s, "--app-role", "app_user")["findings"]]
        self.assertEqual(sorted((r, sev) for r, sev, _ in found if r == "dbh.04"),
                         [("dbh.04", "info"), ("dbh.04", "info"), ("dbh.04", "info"), ("dbh.04", "warn"), ("dbh.04", "warn")])
        self.assertTrue(any("superuser `postgres` can log in over the network (all)" in m for _, _, m in found))
        self.assertFalse(any("::1/ffff" in m or "127.0.0.1" in m for _, _, m in found if "unencrypted" in m))
        self.assertIn(("dbh.03", "warn"), {(r, sev) for r, sev, _ in found})   # listen '*' + host all all all

    def test_missing_sections_are_not_checked(self):
        s = clean()
        del s["hba"], s["password_types"], s["client"]
        s["meta"] = [{**META, "is_superuser": False, "can_read_stats": False}]
        data = self.report(s, "--app-role", "app_user")
        nc = " ".join(data["not_checked"])
        self.assertIn("no `hba` section", nc)
        self.assertIn("no `password_types` section", nc)
        self.assertIn("pg_read_all_stats", nc)
        self.assertIn("pg_dump --version", nc)

    def test_unsafe_snapshots_rejected(self):
        for mutate in (lambda s: s["roles"][2].update(rolpassword="SCRAM-SHA-256$4096:abc"),
                       lambda s: s["hba"][1].update(options=["ldapbindpasswd=x"]),
                       lambda s: s["settings"].append({"name": "x", "setting": "md5" + "a" * 32}),
                       lambda s: s["meta"][0].update(snapshot_version=0)):
            s = copy.deepcopy(clean())
            mutate(s)
            res = self.run_audit(s)
            self.assertEqual(res.returncode, 2, res.stdout)
            self.assertNotIn("abc", res.stderr)
        res = self.run_audit({"settings": []})
        self.assertEqual(res.returncode, 2)

    def test_without_snapshot_live_rules_not_checked(self):
        data = self.report(None)
        nc = " ".join(data["not_checked"])
        for rule in ("`dbh.01`", "`dbh.04`", "`dbh.05`", "`dbh.16`", "`dbh.18`"):
            self.assertIn(rule, nc)
        self.assertIn("needs a live target", nc)

    def test_run_audit_passes_snapshot(self):
        snap = self.write("snap.jsonl", to_jsonl(bad()))
        res = subprocess.run([sys.executable, str(SCRIPTS / "run_audit.py"), "--root", str(self.dir), "--format", "json",
                              "--pg-snapshot", str(snap), "--app-role", "app_user"], capture_output=True, text=True, encoding="utf-8")
        rules = {f["rule"] for f in json.loads(res.stdout)["findings"]}
        self.assertIn("dbh.06", rules)


class PostgresStaticTests(TempRepo):
    def report(self):
        res = subprocess.run([sys.executable, str(SCRIPTS / "audit_postgres.py"), "--root", str(self.dir), "--format", "json"],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)["findings"]

    def test_migrations(self):
        self.write("migrations/0001_init.sql", """
CREATE TABLE projects (id uuid primary key, tenant_id uuid not null);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY "ins" ON projects FOR INSERT TO app_user USING (true);
CREATE POLICY open_read ON projects FOR SELECT USING (true);
CREATE POLICY ok ON projects USING (tenant_id = (select current_setting('app.tenant_id', true))::uuid);
CREATE POLICY slow ON projects AS RESTRICTIVE USING (tenant_id = current_setting('app.tenant_id')::uuid);
CREATE POLICY orphan ON invoices USING (org_id = (select current_setting('app.org', true))::uuid);
CREATE VIEW project_names AS SELECT id FROM projects;
CREATE VIEW safe_names WITH (security_invoker = true) AS SELECT id FROM projects;
CREATE VIEW later_names AS SELECT id FROM projects;
ALTER VIEW later_names SET (security_invoker = true);
CREATE MATERIALIZED VIEW stats AS SELECT tenant_id, count(*) FROM projects GROUP BY 1;
CREATE FUNCTION is_admin() RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true; $$;
CREATE FUNCTION pinned() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT true $$;
REVOKE EXECUTE ON FUNCTION pinned() FROM PUBLIC;
CREATE POLICY open_if_unset ON projects AS RESTRICTIVE USING (tenant_id = (select current_setting('app.tenant_id', true))::uuid OR current_setting('app.tenant_id', true) IS NULL);
CREATE POLICY distinct_ok ON projects AS RESTRICTIVE USING (tenant_id IS NOT DISTINCT FROM (select current_setting('app.tenant_id', true))::uuid);
CREATE OR REPLACE FUNCTION fixed_later() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
ALTER FUNCTION fixed_later() SET search_path = pg_catalog;
GRANT SELECT, INSERT ON projects TO PUBLIC;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT EXECUTE ON FUNCTION pinned() TO public;
CREATE EXTENSION IF NOT EXISTS dblink;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE LANGUAGE plperlu;
CREATE FUNCTION find(col text, v text) RETURNS SETOF projects LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT * FROM projects WHERE ' || col || ' = ' || v;
END $$;
CREATE FUNCTION find_ok(col text, v text) RETURNS SETOF projects LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY EXECUTE format('SELECT * FROM projects WHERE %I = $1', col) USING v;
END $$;
CREATE FUNCTION fmt_s(t text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('DROP TABLE %s', t); END $$;
DO $$ BEGIN EXECUTE 'ALTER TABLE ' || quote_ident('projects') || ' OWNER TO db_owner'; END $$;
""")
        found = self.report()
        msgs = [(f["rule"], f["severity"], f["message"]) for f in found]
        text = " | ".join(m for _, _, m in msgs)
        self.assertIn(("dbh.11", "error", "INSERT policy on `projects` has no WITH CHECK: any row can be inserted"), msgs)
        self.assertEqual(sum("allows every row" in m for _, _, m in msgs), 2)          # ins USING (true) + open_read
        self.assertEqual(sum("per row" in m for _, _, m in msgs), 2)                    # `slow` + the IS NULL branch of open_if_unset
        self.assertIn(("dbh.10", "error"), {(r, s) for r, s, m in msgs if "invoices" in m})
        self.assertIn("View `project_names`", text)
        self.assertNotIn("safe_names", text)
        self.assertNotIn("later_names", text)
        self.assertIn("Materialized view `stats`", text)
        self.assertIn("`is_admin` doesn't pin", text)
        self.assertNotIn("`pinned`", text)
        self.assertNotIn("`fixed_later` doesn't pin", text)
        grants = sorted((s, m.split(" ")[0] + " " + m.split(" ")[1]) for r, s, m in msgs if r == "dbh.07")
        self.assertEqual([s for s, _ in grants], ["info", "warn", "warn", "warn"])        # GRANT EXECUTE; GRANT SELECT; is_admin; fixed_later
        self.assertIn("SECURITY DEFINER function `is_admin` keeps the default EXECUTE for PUBLIC", text)
        self.assertNotIn("function `pinned` keeps", text)
        self.assertEqual(sum("IS NULL / coalesce" in m for _, _, m in msgs), 1)
        self.assertEqual(sum("subquery" in m for _, _, m in msgs), 0)                     # IS NOT DISTINCT FROM isn't one
        self.assertEqual(sorted(m.split("`")[1] for r, _, m in msgs if r == "dbh.08"), ["dblink", "plperlu"])
        dyn = sorted((s, m.split("`")[1]) for r, s, m in msgs if r == "dbh.23")
        self.assertEqual(dyn, [("error", "find"), ("error", "fmt_s")])   # find_ok uses %I + USING; the DO block quotes

    def test_files_mode_reads_rls_state_from_all_migrations(self):
        self.write("migrations/0001.sql", "CREATE TABLE t (id int primary key);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
                                          "CREATE VIEW old_v AS SELECT id FROM t;\n")
        self.write("migrations/0002.sql", "CREATE POLICY p ON t USING (name ILIKE 'a%');\nCREATE VIEW v AS SELECT id FROM t;\n")
        res = subprocess.run([sys.executable, str(SCRIPTS / "audit_postgres.py"), "--root", str(self.dir), "--files",
                              "migrations/0002.sql", "--format", "json"], capture_output=True, text=True, encoding="utf-8")
        found = json.loads(res.stdout)["findings"]
        self.assertEqual({f["file"] for f in found}, {"migrations/0002.sql"})
        rules = sorted(f["rule"] for f in found)
        self.assertEqual(rules, ["dbh.11", "dbh.13"])   # ILIKE in the policy; view v. No dbh.10: RLS was enabled in 0001

    def test_no_rls_means_no_view_findings(self):
        self.write("migrations/0001.sql", "CREATE TABLE t (id int primary key);\nCREATE VIEW v AS SELECT id FROM t;\n")
        self.assertEqual(self.report(), [])

    def test_config_files(self):
        self.write("docker/postgres/postgresql.conf", "listen_addresses = '*'\nssl = off   # TODO\npassword_encryption = md5\nlog_statement = all\n"
                                                      "ssl_min_protocol_version = 'TLSv1.1'\nlog_line_prefix = '%m [%p] '\n")
        self.write("docker/postgres/pg_hba_safe.conf", "host all postgres 0.0.0.0/0 reject\nhost app app 10.0.0.0/8 scram-sha-256\n")
        self.write("docker/postgres/pg_hba.conf", "local all all trust\nhost all all 0.0.0.0/0 md5\nhost all all 0.0.0.0 0.0.0.0 password\n"
                                                  "hostssl app app 10.0.0.0/8 scram-sha-256\nhost all all 127.0.0.1/32 scram-sha-256\n"
                                                  "host all all ::/0 reject\n")
        found = self.report()
        by_rule = {}
        for f in found:
            by_rule.setdefault(f["rule"], []).append(f)
        self.assertEqual({f["line"] for f in by_rule["dbh.05"] if f["file"].endswith("postgresql.conf")}, {2, 5})
        self.assertEqual(by_rule["dbh.16"][0]["line"], 3)
        self.assertEqual(sorted(f["line"] for f in by_rule["dbh.22"]), [4, 4])   # bind values logged + log_statement = all
        self.assertIn("log_line_prefix lacks", by_rule["dbh.18"][0]["message"])
        self.assertIn("log_connections off", by_rule["dbh.18"][0]["message"])   # defaults apply to the main postgresql.conf
        self.assertEqual(by_rule["dbh.03"][0]["severity"], "warn")   # pg_hba in the repo admits 0.0.0.0/0
        hba = sorted((f["line"], f["severity"]) for f in by_rule["dbh.04"] if f["file"].endswith("pg_hba.conf") and "superuser" not in f["message"])
        self.assertEqual(hba, [(1, "info"), (2, "warn"), (2, "warn"), (3, "error"), (3, "warn")])
        su = [(f["file"].rsplit("/", 1)[-1], f["line"]) for f in by_rule["dbh.04"] if "superuser" in f["message"]]
        self.assertEqual(su, [("pg_hba.conf", 2)])   # first matching line only; the safe file rejects postgres first
        self.assertEqual(sorted(f["line"] for f in by_rule["dbh.05"] if f["file"].endswith("pg_hba.conf")), [2, 3])

    def test_session_level_tenant_settings_in_code(self):
        self.write("src/db/tenant.ts", """
import { sql } from 'drizzle-orm';
export async function bad(db, id) {
  await db.execute(sql`SET app.tenant_id = ${id}`);
  await db.execute(sql`select set_config('app.user_id', ${id}, false)`);
}
export async function good(tx, id) {
  await tx.execute(sql`SET LOCAL app.tenant_id = ${id}`);
  await tx.execute(sql`select set_config('app.user_id', ${id}, true)`);
  await tx.execute(sql`SET search_path TO app`);
}
// SET app.tenant_id = 1 in a comment
export async function raw(tx, token) {
  await tx.execute(sql`select set_config('request.jwt.claim.sub', '${sql.raw(token.sub)}', TRUE)`);
  await tx.execute(sql`set local role ${sql.raw(token.role)}`);
}
""")
        self.write("src/db/ctx.ts", "export const f = (tx, req) => tx.execute(sql`select set_config('app.tenant_id', ${req.headers.get('x-tenant')}, true)`);\n"
                                    "export const g = (tx, session) => tx.execute(sql`select set_config('app.tenant_id', ${session.tenantId}, true)`);\n")
        self.write("src/db/client.ts", "import { drizzle } from 'drizzle-orm/postgres-js';\n"
                                       "export const db = drizzle(client, { logger: true });\n"
                                       "export const dev = drizzle(client, { logger: process.env.NODE_ENV !== 'production' });\n")
        found = self.report()
        self.assertEqual(sorted(f["line"] for f in found if f["rule"] == "dbh.12" and "Session-level" in f["message"]), [4, 5])
        self.assertEqual(sorted(f["line"] for f in found if f["rule"] == "dbh.12" and "sql.raw" in f["message"]), [14, 15])
        self.assertEqual([(f["file"], f["line"]) for f in found if f["rule"] == "dbh.22"], [("src/db/client.ts", 2)])
        self.assertEqual([(f["file"], f["line"]) for f in found if "taken from request input" in f["message"]], [("src/db/ctx.ts", 1)])


class PostgresUnitTests(unittest.TestCase):
    def test_version_finding(self):
        v = {"checked": "2026-11-21", "min_patched": {"18": "18.7", "17": "17.12"}, "eol_through": 14}
        self.assertIsNone(audit_postgres.version_finding(180007, v))
        self.assertIsNone(audit_postgres.version_finding(170013, v))
        self.assertEqual(audit_postgres.version_finding(170011, v)[0], "error")
        self.assertEqual(audit_postgres.version_finding(130020, v)[0], "error")
        self.assertEqual(audit_postgres.version_finding(200001, v)[0], "info")

    def test_cidr_and_loopback(self):
        self.assertEqual(audit_postgres.cidr("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "::1/128")
        self.assertEqual(audit_postgres.cidr("0.0.0.0", "0.0.0.0"), "0.0.0.0/0")
        self.assertEqual(audit_postgres.cidr("10.1.2.0", "255.255.255.0"), "10.1.2.0/24")
        self.assertTrue(audit_postgres.is_loopback("127.0.0.1/32"))
        self.assertTrue(audit_postgres.is_loopback("::1/128"))
        self.assertFalse(audit_postgres.is_loopback("all"))
        self.assertFalse(audit_postgres.is_loopback("10.0.0.0/8"))

    def test_versions_file_matches_shape(self):
        v = json.loads((SKILL / "assets" / "pg-versions.json").read_text(encoding="utf-8"))
        self.assertTrue(all("CVE-" in s for s in {**v["cve_extensions"], **v["cve_languages"]}.values()))
        for major, minimum in v["min_patched"].items():
            self.assertTrue(re.fullmatch(rf"{major}\.\d+", minimum), minimum)
            self.assertGreater(int(major), v["eol_through"])

    def test_snapshot_sql_is_read_only_and_covers_sections(self):
        sql = (SKILL / "assets" / "pg_snapshot.sql").read_text(encoding="utf-8")
        code = re.sub(r"--[^\n]*", "", sql)
        self.assertIn("default_transaction_read_only = on", code)
        self.assertNotRegex(code, r"json_(agg|build_object|build_array)\(")   # json_agg output spans lines; jsonb is one line
        self.assertIn("WHEN name LIKE '%timeout' OR name = 'standard_conforming_strings' THEN reset_val", code)
        self.assertIn("SET standard_conforming_strings = on", code)   # its regex literals break on servers with it off        # the script's own SETs must not show
        self.assertNotRegex(code, r"(?i)\b(INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|GRANT|REVOKE|TRUNCATE|COPY)\s")
        self.assertNotRegex(code, r"(?i)SELECT[^;]*\brolpassword\s*(,|AS|FROM)")   # only inside CASE, never selected raw
        self.assertNotRegex(code, r"(?i)\boptions\b[^;]*FROM\s+pg_hba_file_rules")
        sections = set(re.findall(r"'section', '(\w+)'", code))
        used = set(re.findall(r"snap(?:\.get)?\(?\[?[\"'](\w+)[\"']", (SCRIPTS / "audit_postgres.py").read_text(encoding="utf-8")))
        self.assertLessEqual(used - {"meta"}, sections)


if __name__ == "__main__":
    unittest.main()
