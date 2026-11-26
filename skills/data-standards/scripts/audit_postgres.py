#!/usr/bin/env python3
"""Audit PostgreSQL security hardening: grants, RLS, views, functions, pg_hba, TLS, logging, versions. Read-only.

    python audit_postgres.py --root REPO [--snapshot FILE] [--app-role NAME ...] [--format md|json|sarif] [--strict]

Covers dbh.01-18, dbh.20 (data directory mode), dbh.22 and dbh.23. Static checks read SQL migrations, postgresql*.conf / pg_hba*.conf files in the repo and TS/JS code.
Live checks read a snapshot written by assets/pg_snapshot.sql (psql output, one JSON line per section); this script
never connects to a database. Snapshots holding password hashes are refused. --app-role names the app's runtime role;
without it, non-superuser login roles are treated as app roles (medium confidence).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import sys
from pathlib import Path, PurePosixPath

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.sqlmig import IDENT, find_migrations, statements, table_name
from wclib.walker import Walker

SKILL = Path(__file__).resolve().parents[1]
SNAPSHOT_VERSION = 1

TENANT_COL = re.compile(r"^(tenant|org|organization|organisation|workspace|account|team|company|owner|user)_?id$", re.I)
SENSITIVE_COL = re.compile(r"passw|secret|token|api_?key|private_?key|totp|mfa|otp|(^|_)ssn($|_)|social_security|tax_?id|"
                           r"birth|(^|_)dob($|_)|iban|card_?num|cvv|recovery|passport|national_?id|drivers?_?licen[cs]e", re.I)
NOT_SENSITIVE_COL = re.compile(r"(_at|At|_expires?|Expires?|_type|Type|_count|Count|_length|_hint)$")
RISKY_EXTENSIONS = {"adminpack", "file_fdw", "dblink", "postgres_fdw", "http", "pg_net", "plpython3u", "plpythonu", "plpython2u", "plperlu", "pltclu", "lo"}
UNTRUSTED_LANG = re.compile(r"^pl\w*u$", re.I)
LOCAL_ADDR = {"127.0.0.1/32", "::1/128", "samehost", "localhost", "127.0.0.1", "::1"}
BROAD_ADDR = {"all", "0.0.0.0/0", "::/0"}
TIMEOUTS = ("statement_timeout", "idle_in_transaction_session_timeout", "lock_timeout")
CONF_DEFAULTS = {"ssl": "off", "password_encryption": "scram-sha-256", "listen_addresses": "localhost",
                 "log_connections": "off", "log_disconnections": "off", "log_statement": "none",
                 "log_min_duration_statement": "-1", "log_line_prefix": "%m [%p] "}
# Snapshot keys/values that would mean secrets leaked into it. The shipped SQL never selects them.
FORBIDDEN_KEY = re.compile(r"^(rolpassword|password|passwd|secret|token|options|query|client_addr|application_name)$", re.I)
HASH_VALUE = re.compile(r"^(SCRAM-SHA-256\$|md5[0-9a-f]{32}$)")
URL_CREDENTIALS = re.compile(r"://[^/\s:@]+:[^@\s/]+@")

POLICY = re.compile(rf"^\s*CREATE\s+POLICY\s+{IDENT}\s+ON\s+({IDENT})([\s\S]*)$", re.I)
ALTER_TABLE = re.compile(rf"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({IDENT})([\s\S]*)$", re.I)
VIEW = re.compile(rf"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?(?:RECURSIVE\s+)?(MATERIALIZED\s+)?VIEW\s+"
                  rf"(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})([\s\S]*)$", re.I)
ALTER_VIEW_INVOKER = re.compile(rf"^\s*ALTER\s+VIEW\s+(?:IF\s+EXISTS\s+)?({IDENT})\s+SET\s*\([^)]*security_invoker\s*(=\s*(true|on|1))?\s*[,)]", re.I)
FUNCTION = re.compile(rf"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+({IDENT})", re.I)
ALTER_FUNCTION_PATH = re.compile(rf"^\s*ALTER\s+(?:FUNCTION|PROCEDURE)\s+({IDENT})[\s\S]*\bSET\s+search_path\b", re.I)
GRANT = re.compile(r"^\s*GRANT\s+([\s\S]+?)\s+ON\s+[\s\S]+?\bTO\s+([\s\S]+?)(?:\s+WITH\s+GRANT\s+OPTION|\s+GRANTED\s+BY\b[\s\S]*)?\s*$", re.I)
LANGUAGE = re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TRUSTED\s+)?(?:PROCEDURAL\s+)?LANGUAGE\s+\"?(\w+)", re.I)
EXTENSION = re.compile(r"^\s*CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)", re.I)
SESSION_SET = re.compile(r"\bSET\s+(?!LOCAL\b)(?:SESSION\s+)?\"?([a-z_]\w*\.[a-z_]\w*)\"?\s*(?:=|\bTO\b)", re.I)
SET_CONFIG_SESSION = re.compile(r"set_config\s*\(\s*['\"]([a-z_]\w*\.[\w.]+)['\"]\s*,[^)]*?,\s*false\s*\)", re.I)
RAW_IN_CONTEXT = re.compile(r"(set_config\s*\([^)]*|SET\s+LOCAL\s+(ROLE\s+)?[\w.]*\s*(=|TO)?\s*)\$\{\s*sql\.raw\(", re.I)
CLIENT_INPUT = re.compile(r"headers\(\)|\.headers\.get\(|searchParams|cookies\(\)|req\.query|request\.query|params\.", re.I)
DRIZZLE_LOGGER = re.compile(r"\blogger\s*:\s*true\b")
FAIL_OPEN = re.compile(r"current_setting\s*\([^)]*\)\)?\s*(::\s*\w+\s*)?\)?\s*IS\s+NULL|coalesce\s*\(\s*\(?\s*(SELECT\s+)?\(?\s*current_setting", re.I)
DYNAMIC_SQL = re.compile(  # EXECUTE built by concatenation (unless quoted with quote_*) or format() with %s
    r"\bEXECUTE\s+(?!format\b)[^;]*\|\||:=\s*'[^';]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\|\||\bformat\s*\(\s*'[^']*%s", re.I)
DO_BLOCK = re.compile(r"^\s*DO\b", re.I)
CONF_FILE = re.compile(r"(^|/)postgresql[\w.-]*\.conf$")
HBA_FILE = re.compile(r"(^|/)pg_hba[\w.-]*\.conf$")

ROLLOUT = "see the staged rollout in references/23-postgres-hardening.md"
# Predefined roles an app role must not reach (directly or through a group): why, severity.
PREDEFINED = {"pg_signal_backend": ("can cancel or terminate other sessions: denial of service", "warn"),
              "pg_read_all_stats": ("can read every session's query text and statistics", "info"),
              "pg_monitor": ("can read every session's query text and statistics", "info"),
              "pg_read_all_data": ("can read every table and sequence, in every schema", "error"),
              "pg_write_all_data": ("can write every table and sequence, in every schema", "error"),
              **{r: ("server file or program access from SQL", "error") for r in (
                  "pg_execute_server_program", "pg_read_server_files", "pg_write_server_files")}}
SEARCH_PATH = re.compile(r"\bSET\s+search_path\s*(?:=|\bTO\b)\s*((?:\"?[\w$]+\"?\s*,\s*)*\"?[\w$]+\"?)", re.I)


def closure(edges: dict[str, set[str]], start: str) -> set[str]:
    """Every role `start` is a member of, directly or through other roles."""
    seen, todo = set(), [start]
    while todo:
        for g in edges.get(todo.pop(), ()):
            if g not in seen:
                seen.add(g)
                todo.append(g)
    return seen


def path_problem(value: str, unsafe: set[str] = frozenset()) -> str | None:
    """A pinned SECURITY DEFINER search_path ('pg_catalog, pg_temp') -> what is wrong with it, or None."""
    parts = [p.strip().strip('"').lower() for p in value.split(",") if p.strip().strip('"\'')]
    if not parts:   # search_path = '': every name must be schema-qualified, so pg_temp shadows nothing in practice
        return None
    if "pg_temp" not in parts:
        return "doesn't list pg_temp, and an unlisted pg_temp is searched first: a caller's temporary table can shadow the tables it reads"
    if parts[-1] != "pg_temp":
        return "puts pg_temp before other schemas: a caller's temporary objects are found first"
    if hit := sorted(set(parts) & unsafe):
        return f"includes schema {', '.join(hit)}, where PUBLIC or the app role can create objects"
    return None


class SnapshotError(ValueError):
    pass


def check_safe(node, path: str = "$") -> None:
    """Raise if the snapshot holds a secret-shaped key or value. Names the path, never the value."""
    if isinstance(node, dict):
        for k, v in node.items():
            if FORBIDDEN_KEY.search(str(k)) and v not in (None, "", [], {}):
                raise SnapshotError(f"snapshot field {path}.{k} is not collected by pg_snapshot.sql: remove it")
            check_safe(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            check_safe(v, f"{path}[{i}]")
    elif isinstance(node, str) and (HASH_VALUE.search(node) or URL_CREDENTIALS.search(node)):
        raise SnapshotError(f"snapshot field {path} holds a password hash or credentials: remove it")


def load_snapshot(path: str | Path) -> dict[str, list]:
    """psql output (one JSON line per section; other lines ignored) -> {section: rows}."""
    sections: dict[str, list] = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("section"), str):
            sections[obj["section"]] = obj.get("rows") or []
    if not sections.get("meta"):
        raise SnapshotError(f"{path} has no 'meta' section: write it with assets/pg_snapshot.sql")
    if sections["meta"][0].get("snapshot_version") != SNAPSHOT_VERSION:
        raise SnapshotError(f"snapshot_version must be {SNAPSHOT_VERSION}: regenerate it with this plugin's pg_snapshot.sql")
    check_safe(sections)
    return sections


def version_finding(num: int, versions: dict) -> tuple[str, str] | None:
    """server_version_num -> (severity, message) for dbh.01, or None when patched."""
    major, minor = num // 10000, num % 10000
    if major <= versions["eol_through"]:
        return "error", f"PostgreSQL {major}.{minor} is end-of-life and gets no security fixes"
    want = versions["min_patched"].get(str(major))
    if want is None:
        return "info", f"PostgreSQL {major}.{minor} is newer than the version table (checked {versions['checked']}); confirm it is current"
    if minor < int(want.split(".")[1]):
        return "error", f"PostgreSQL {major}.{minor} is missing security fixes: upgrade to {want} or later"
    return None


def parse_conf(text: str) -> dict[str, tuple[str, int]]:
    out = {}
    for no, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*([a-z_][\w.]*)\s*=?\s*('(?:[^']|'')*'|[^#\s]+)", raw, re.I)
        if m and not raw.lstrip().startswith("#"):
            out[m.group(1).lower()] = (m.group(2).strip("'").replace("''", "'"), no)
    return out


def cidr(addr: str, mask: str) -> str:
    """'::1' + 'ffff:…:ffff' -> '::1/128'; ipaddress accepts dotted IPv4 masks but not IPv6 ones."""
    try:
        bits = bin(int(ipaddress.ip_address(mask))).count("1")
        return ipaddress.ip_network(f"{addr}/{bits}", strict=False).with_prefixlen
    except ValueError:
        return f"{addr}/{mask}"


def is_loopback(addr: str | None) -> bool:
    try:
        return addr is not None and (addr.lower() in LOCAL_ADDR or ipaddress.ip_network(addr, strict=False).is_loopback)
    except ValueError:
        return False


def parse_hba(text: str) -> list[dict]:
    rows = []
    for no, raw in enumerate(text.splitlines(), 1):
        f = raw.split("#", 1)[0].split()
        if not f or f[0].startswith(("@", "include")):
            continue
        if f[0] == "local" and len(f) >= 4:
            rows.append({"line": no, "type": "local", "address": None, "auth": f[3], "users": f[2].split(",")})
        elif f[0].startswith("host") and len(f) >= 5:
            addr, rest = f[3], f[4:]
            if "/" not in addr and re.fullmatch(r"[\d.:a-fA-F]+", addr) and rest and re.fullmatch(r"[\d.:a-fA-F]+", rest[0]):
                addr, rest = cidr(addr, rest[0]), rest[1:]
            rows.append({"line": no, "type": f[0], "address": addr, "auth": rest[0] if rest else "", "users": f[2].split(",")})
    return rows


def hba_live_rows(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        addr = r.get("address")
        if addr and r.get("netmask"):
            addr = cidr(addr, r["netmask"])
        out.append({"line": r.get("line_number"), "type": r.get("type"), "address": addr, "auth": r.get("auth_method") or "",
                    "error": r.get("error"), "users": r.get("user_name") or []})
    return out


def is_broad(addr: str | None) -> bool:
    return (addr or "").lower() in BROAD_ADDR


def non_zero(value: str | None) -> bool:
    return value is not None and value.strip().strip("'") not in ("0", "", "-1")


class PostgresAudit(Audit):
    tool = "data-standards postgres"
    prefix = "dbh"

    @classmethod
    def add_arguments(cls, parser) -> None:
        parser.add_argument("--snapshot", help="JSON-lines file written by assets/pg_snapshot.sql")
        parser.add_argument("--app-role", action="append", default=[], help="The app's runtime role (repeatable)")

    def run(self) -> None:
        self.static_migrations()
        self.static_code()
        self.static_conf()
        snapshot = getattr(self.args, "snapshot", None)
        if snapshot:
            try:
                snap = load_snapshot(snapshot)
            except (SnapshotError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                sys.exit(2)
            self.live(snap)
        # Server-setting rules (dbh.03-05, 16, 18) are labelled live: repo config files may not be what is deployed.
        self.finish_not_checked({"live"} if snapshot else set())

    # ================================================================ static: migrations
    def static_migrations(self) -> None:
        files = Walker(self.root, ignore_paths=self.ctx.config.get("ignorePaths", [])).all_files()
        migrations = find_migrations(self.root, files)
        only = self.ctx.walker.only
        enabled, invoker, pinned, revoked = set(), set(), set(), set()  # read from every migration, even in --files mode
        policies, views, definers = [], [], []
        for m in migrations:
            text = (self.root / m.rel).read_text(encoding="utf-8", errors="replace")
            report = only is None or m.rel in only
            for st in statements(text):
                sql, line = st.sql, text.count("\n", 0, st.offset) + 1
                loc = {"file": m.rel, "line": line}
                if mt := ALTER_TABLE.match(sql):
                    if re.search(r"\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b", mt.group(2), re.I):
                        enabled.add(table_name(mt.group(1)))
                elif mt := POLICY.match(sql):
                    if report:
                        policies.append((table_name(mt.group(1)), mt.group(2), loc))
                elif mt := VIEW.match(sql):
                    head = re.split(r"\bAS\b", mt.group(3), maxsplit=1, flags=re.I)[0]
                    on = re.search(r"security_invoker\s*(=\s*(true|on|1))?\s*[,)]", head, re.I)
                    if report:
                        views.append((table_name(mt.group(2)), bool(mt.group(1)), bool(on), loc))
                elif mt := ALTER_VIEW_INVOKER.match(sql):
                    invoker.add(table_name(mt.group(1)))
                elif mt := FUNCTION.match(sql) or DO_BLOCK.match(sql):
                    if report:
                        self.dynamic_sql(st.raw, mt.group(1) if mt.re is FUNCTION else None, loc)
                    if report and mt.re is FUNCTION and re.search(r"\bSECURITY\s+DEFINER\b", sql, re.I):
                        path = SEARCH_PATH.search(sql)
                        definers.append((table_name(mt.group(1)), bool(re.search(r"\bSET\s+search_path\b", sql, re.I)),
                                         path.group(1) if path else None, loc))
                elif mt := ALTER_FUNCTION_PATH.match(sql):
                    pinned.add(table_name(mt.group(1)))
                elif mt := re.match(rf"^\s*REVOKE\s+(?:EXECUTE|ALL)[\s\S]*?\bON\s+(?:FUNCTION|PROCEDURE|ROUTINE)\s+({IDENT})[\s\S]*\bFROM\s+[\s\S]*\bPUBLIC\b", sql, re.I):
                    revoked.add(table_name(mt.group(1)))
                elif not report:
                    continue
                elif mt := GRANT.match(sql):
                    self.public_grant(mt.group(1), mt.group(2), loc)
                elif mt := LANGUAGE.match(sql) or EXTENSION.match(sql):
                    name = mt.group(1).lower()
                    if name in RISKY_EXTENSIONS or UNTRUSTED_LANG.match(name):
                        self.add("dbh.08", f"Migration installs `{name}`, which can read files or run code on the server", **loc,
                                 fix_hint="Remove it unless it is required; never grant its use to the app role")
        for table, rest, loc in policies:
            self.policy_static(table, rest, loc, enabled)
        for name, mat, ok, loc in views:
            if enabled and mat:
                self.add("dbh.13", f"Materialized view `{name}` in a database that uses RLS: materialized views ignore RLS",
                         severity="info", **loc, fix_hint="Don't grant it to the app role, or filter by tenant in a security_invoker view over it")
            elif enabled and not ok and name not in invoker:
                self.add("dbh.13", f"View `{name}` runs with its owner's rights, so RLS on the tables it reads doesn't apply to callers",
                         **loc, fix_hint="CREATE VIEW … WITH (security_invoker = true) AS … (PostgreSQL 15+)")
        for name, has_path, path, loc in definers:
            if not has_path and name not in pinned:
                self.add("dbh.14", f"SECURITY DEFINER function `{name}` doesn't pin search_path (search-path hijacking)", **loc,
                         fix_hint="Add SET search_path = pg_catalog, pg_temp (and schema-qualify names), or ALTER FUNCTION … SET search_path")
            elif path and (why := path_problem(path)):
                self.add("dbh.14", f"SECURITY DEFINER function `{name}` pins search_path `{path}` but {why}", severity="warn", **loc,
                         fix_hint="SET search_path = pg_catalog, pg_temp (pg_temp last) and schema-qualify names")
            if name not in revoked:  # functions get EXECUTE for PUBLIC at creation
                self.add("dbh.07", f"SECURITY DEFINER function `{name}` keeps the default EXECUTE for PUBLIC: every role runs it with its owner's rights",
                         **loc, fix_hint=f"REVOKE EXECUTE ON FUNCTION {name}(<exact argument types>) FROM PUBLIC; GRANT EXECUTE … TO the roles that need it")

    def dynamic_sql(self, raw: str, name: str | None, loc: dict) -> None:
        if not re.search(r"\bEXECUTE\b", raw, re.I):
            return
        for m in DYNAMIC_SQL.finditer(raw):
            line = raw[raw.rfind("\n", 0, m.start()) + 1: raw.find("\n", m.end()) if raw.find("\n", m.end()) > 0 else len(raw)]
            if re.search(r"quote_(ident|literal|nullable)\s*\(", line, re.I):
                continue
            where = f"function `{table_name(name)}`" if name else "DO block"
            self.add("dbh.23", f"Dynamic SQL in {where} is built by concatenation or format('%s') (SQL injection inside the database)",
                     severity="error" if name else "warn", **{**loc, "line": loc["line"] + raw.count("\n", 0, m.start())},
                     fix_hint="EXECUTE format('… %I … %L', ident, value), or EXECUTE '… $1' USING value")
            return

    def public_grant(self, privileges: str, grantees: str, loc: dict) -> None:
        names = [g.strip().lower() for g in re.split(r"\s*,\s*", grantees)]
        if "public" not in names:
            return
        strong = re.search(r"\b(ALL|CREATE|TEMP(ORARY)?|INSERT|UPDATE|DELETE|TRUNCATE|SELECT)\b", privileges, re.I)
        self.add("dbh.07", f"Migration grants {privileges.strip().upper()} to PUBLIC (every role, including future ones)",
                 severity="warn" if strong else "info", **loc, fix_hint="Grant to the app role by name instead")

    def policy_static(self, table: str, rest: str, loc: dict, enabled: set[str]) -> None:
        if table not in enabled:
            self.add("dbh.10", f"Policy on `{table}`, but no migration enables row level security on it: the policy does nothing",
                     severity="error", **loc, fix_hint=f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY (and FORCE if the owner queries it)")
        cmd = (re.search(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", rest, re.I) or [None, "ALL"])[1].upper()
        restrictive = re.search(r"\bAS\s+RESTRICTIVE\b", rest, re.I)
        if cmd == "INSERT" and not re.search(r"\bWITH\s+CHECK\b", rest, re.I):
            self.add("dbh.11", f"INSERT policy on `{table}` has no WITH CHECK: any row can be inserted", severity="error", **loc,
                     fix_hint="Add WITH CHECK (tenant_id = (select current_setting('app.tenant_id', true))::uuid)")
        if not restrictive and re.search(r"\b(USING|WITH\s+CHECK)\s*\(\s*true\s*\)", rest, re.I):
            self.add("dbh.11", f"Permissive policy on `{table}` allows every row (`true`)", **loc,
                     fix_hint="Limit it to a role with TO, or compare the tenant column")
        self.policy_perf(rest, table, loc)

    def policy_perf(self, expr: str, table: str, loc: dict) -> None:
        if FAIL_OPEN.search(expr):
            self.add("dbh.11", f"Policy on `{table}` has an IS NULL / coalesce fallback on current_setting(): it may allow rows when the tenant context isn't set",
                     severity="warn", **loc, fix_hint="Fail closed: compare only (tenant_id = (select current_setting('app.tenant_id', true))::uuid), with no NULL branch")
        if re.search(r"(?<!DISTINCT )\bFROM\s+[\w\"]", expr, re.I):  # a subquery, not IS DISTINCT FROM
            self.add("dbh.11", f"Policy on `{table}` runs a subquery per row", severity="info", **loc,
                     fix_hint="Index the joined columns, or move the lookup into a STABLE function / a (select …) evaluated once")
        if re.search(r"~~\*?|\bI?LIKE\b", expr, re.I):
            self.add("dbh.11", f"Policy on `{table}` uses LIKE/ILIKE pattern matching, which can't use a plain index and runs per row",
                     severity="info", **loc, fix_hint="Compare the tenant/owner column with = or IN; keep pattern matching in the query")
        total = len(re.findall(r"\bcurrent_setting\s*\(", expr, re.I))
        wrapped = len(re.findall(r"\bSELECT\s+[(\s]*current_setting\s*\(", expr, re.I))  # pg_policies deparses as SELECT (current_setting(
        if total > wrapped:
            self.add("dbh.11", f"Policy on `{table}` calls current_setting() per row", severity="info", **loc,
                     fix_hint="Wrap it as (select current_setting(...)) so it is evaluated once per query, and index the tenant column")

    # ================================================================ static: app code
    def static_code(self) -> None:
        for f in self.files:
            for rx in (SESSION_SET, SET_CONFIG_SESSION):
                for m in rx.finditer(f.code):
                    if f.code_nostr[m.start()] == f.code[m.start()]:
                        continue  # not inside a string literal: not SQL
                    self.add("dbh.12", f"Session-level `{m.group(1)}` setting leaks to the next request that reuses this pooled connection",
                             f, m.start(), fix_hint="Inside a transaction: SET LOCAL … or set_config(name, value, true)")
            for m in re.finditer(r"set_config\s*\(\s*['\"]app\.[\w.]+['\"]\s*,\s*\$\{([^}]*)\}|SET\s+LOCAL\s+app\.[\w.]+\s*(?:=|TO)\s*\$\{([^}]*)\}", f.code, re.I):
                value = m.group(1) or m.group(2) or ""
                if CLIENT_INPUT.search(value):
                    self.add("dbh.12", "Tenant context is taken from request input (header, query string, cookie or route param): a client can pick another tenant",
                             f, m.start(), fix_hint="Derive the tenant from the verified session (server-side), and check membership before setting it")
            for m in RAW_IN_CONTEXT.finditer(f.code):
                self.add("dbh.12", "Tenant/role context is built with sql.raw(): a crafted value can set another tenant or role (SQL injection)",
                         f, m.start(), fix_hint="Pass the value as a parameter: set_config('app.tenant_id', ${tenantId}, true); validate role names against an allow-list")
            if "drizzle" in f.code:
                for m in DRIZZLE_LOGGER.finditer(f.code):
                    line = f.code[f.code.rfind("\n", 0, m.start()) + 1: f.code.find("\n", m.start())]
                    if not re.search(r"NODE_ENV|process\.env|isDev|development", line):
                        self.add("dbh.22", "Drizzle `logger: true` prints every query with its parameters (personal data, tokens) to the logs",
                                 f, m.start(), fix_hint="logger: process.env.NODE_ENV !== 'production', or a custom Logger that drops params")

    # ================================================================ static: config files
    def static_conf(self) -> int:
        files = self.ctx.walker.all_files()
        hba = [rel for rel in files if HBA_FILE.search(rel)]
        broad = any([self.check_hba(parse_hba(self.read(rel)), rel) for rel in hba])  # list: check every file
        count = len(hba)
        for rel in files:
            if CONF_FILE.search(rel):
                count += 1
                parsed = parse_conf(self.read(rel))
                main = PurePosixPath(rel).name == "postgresql.conf"
                settings = {k: v for k, (v, _) in parsed.items()}
                if main:
                    settings = {**CONF_DEFAULTS, **settings}
                self.check_settings(settings, rel, {k: n for k, (_, n) in parsed.items()}, broad_hba=broad)
        return count

    # ================================================================ shared: settings + hba
    def check_settings(self, s: dict[str, str], where: str, lines: dict[str, int] | None, broad_hba: bool) -> None:
        def at(name):
            return {"file": where, "line": (lines or {}).get(name)}

        listen = s.get("listen_addresses")
        # '*' alone is normal in containers; it matters when pg_hba also admits any address.
        if broad_hba and listen is not None and re.search(r"(^|[\s,])(\*|0\.0\.0\.0|::)($|[\s,])", listen):
            self.add("dbh.03", "PostgreSQL listens on all interfaces and pg_hba accepts any address", severity="warn", **at("listen_addresses"),
                     fix_hint="Fine inside a Docker network if the port isn't published; otherwise bind to localhost or a private IP and firewall 5432")
        if s.get("ssl", "").lower() in ("off", "false", "0"):
            self.add("dbh.05", "ssl is off: passwords and data cross the network in clear text", **at("ssl"),
                     fix_hint="ssl = on with a certificate; clients use sslmode=verify-full (or require on a private network)")
        if s.get("ssl_min_protocol_version", "").lower() in ("tlsv1", "tlsv1.1"):
            self.add("dbh.05", f"ssl_min_protocol_version allows {s['ssl_min_protocol_version']}", **at("ssl_min_protocol_version"),
                     fix_hint="TLSv1.2 (the default); TLSv1.3 once every client supports it")
        if s.get("lo_compat_privileges", "").lower() in ("on", "true", "1"):
            self.add("dbh.08", "lo_compat_privileges is on: large-object permission checks are off, so any role can read, overwrite "
                               "or delete every large object", severity="warn", **at("lo_compat_privileges"),
                     fix_hint="lo_compat_privileges = off (the default)")
        pe = s.get("password_encryption")
        if pe is not None and pe.lower() not in ("scram-sha-256",):
            self.add("dbh.16", f"password_encryption is `{pe}`: new passwords are stored as MD5 hashes", **at("password_encryption"),
                     fix_hint="password_encryption = scram-sha-256, then reset each role's password")
        gaps = []
        for name in ("log_connections", "log_disconnections"):
            if name in s and s[name].lower() in ("off", "false", "0", ""):
                gaps.append(f"{name} off")
        if s.get("log_statement", "").lower() == "none":
            gaps.append("log_statement = none (use ddl)")
        prefix = s.get("log_line_prefix")
        if prefix is not None and not all(x in prefix for x in ("%u", "%d", "%h")):
            gaps.append("log_line_prefix lacks user/database/client (%u %d %h)")
        if s.get("log_min_duration_statement") == "-1":
            gaps.append("slow queries not logged (log_min_duration_statement = -1)")
        stmt = s.get("log_statement", "").lower()
        logs_queries = stmt in ("mod", "all") or (s.get("log_min_duration_statement") not in (None, "-1"))
        if logs_queries and s.get("log_parameter_max_length", "-1") == "-1":
            self.add("dbh.22", "Logged statements include full bind parameter values (personal data, password changes) "
                     f"({'log_statement = ' + stmt if stmt in ('mod', 'all') else 'slow-query logging'} with log_parameter_max_length = -1)",
                     severity="warn", **at("log_parameter_max_length" if "log_parameter_max_length" in (lines or {}) else "log_statement"),
                     fix_hint="log_parameter_max_length = 0 (or a small number), keep log_parameter_max_length_on_error = 0, "
                              "and log_statement = ddl rather than mod/all")
        if stmt == "all":
            self.add("dbh.22", "log_statement = all writes every query, including reads of personal data, to the server log",
                     severity="warn", **at("log_statement"), fix_hint="log_statement = ddl; use pgaudit with per-table read logging if you need it")
        if gaps:
            self.add("dbh.18", "Forensic logging gaps: " + "; ".join(gaps), **at("log_connections"),
                     fix_hint="log_connections/log_disconnections on, log_statement = ddl, log_line_prefix with %m %p %u %d %a %h; "
                              "add pgaudit if you need DML audit trails")

    def check_hba(self, rows: list[dict], where: str, superusers: set[str] = frozenset({"postgres"})) -> bool:
        broad_any, su_decided = False, False
        for r in rows:
            loc = {"file": where, "line": r["line"]} if not where.startswith("postgres:") else {"file": where}
            line = f"pg_hba line {r['line']}"
            auth, typ, addr = (r.get("auth") or "").lower(), r.get("type") or "", r.get("address")
            if r.get("error"):
                self.add("dbh.04", f"{line} has an error and is ignored: {r['error']}", severity="info", **loc)
                continue
            remote = typ.startswith("host") and not is_loopback(addr)  # 127.0.0.1/::1 lines are local access
            users = {u.lower() for u in r.get("users") or []}
            if remote and not su_decided and ("all" in users or users & {s.lower() for s in superusers}):
                su_decided = is_broad(addr) or bool(users & {s.lower() for s in superusers})
                if auth != "reject":
                    who = ", ".join(sorted(superusers)) if "all" in users else ", ".join(sorted(users & {s.lower() for s in superusers}))
                    self.add("dbh.04", f"{line}: superuser `{who}` can log in over the network ({addr}): a guessed or default password "
                             "gives full control (the cryptominer attacks on exposed Postgres started this way)", severity="warn", **loc,
                             fix_hint="Add `host all postgres 0.0.0.0/0 reject` (and ::/0) above the other host lines; administer over SSH or a VPN")
                    su_decided = True
            if auth == "reject":
                continue
            if auth == "trust":
                self.add("dbh.04", f"{line}: `trust` lets anyone {'on the network ' if remote else 'on the machine '}connect as any role "
                         "without a password", severity="error" if remote else "info", **loc,
                         fix_hint="scram-sha-256 for host lines, peer for local admin access")
            elif remote and auth in ("md5", "password"):
                self.add("dbh.04", f"{line}: `{auth}` authentication" + (" sends the password in clear text" if auth == "password" else ""),
                         severity="error" if auth == "password" else "warn", **loc,
                         fix_hint="scram-sha-256 (after every role's password is stored as SCRAM)")
            if remote and is_broad(addr):
                broad_any = True
                self.add("dbh.04", f"{line} accepts connections from any address ({addr})", severity="warn", **loc,
                         fix_hint="List the app's subnet or host, and end with `host all all 0.0.0.0/0 reject`")
            if typ in ("host", "hostnossl") and remote:
                self.add("dbh.05", f"{line} (`{typ}`) accepts unencrypted connections from {addr}", severity="info", **loc,
                         fix_hint=f"hostssl once no session shows ssl = false ({ROLLOUT})")
        return broad_any

    # ================================================================ live snapshot
    def live(self, snap: dict[str, list]) -> None:
        meta = snap["meta"][0]
        self.snap = snap
        self.where = f"postgres:{meta.get('database', '?')}"
        self.report.meta["snapshot"] = {k: meta.get(k) for k in ("collected_at", "server_version", "database", "current_user")}
        for section, rules in (("hba", "dbh.04/dbh.05 pg_hba rules"), ("password_types", "dbh.16 MD5 password hashes"),
                               ("sessions", "dbh.05 unencrypted sessions"), ("relations", "dbh.09/10/13 tables and views"),
                               ("policies", "dbh.11 policies"), ("roles", "dbh.06/dbh.17 roles"), ("settings", "settings")):
            if section not in snap:
                self.report.not_checked.append(f"Snapshot has no `{section}` section (the role can't read it?): {rules} not checked")
        if "event_triggers" not in snap:   # every role can read pg_event_trigger, so a missing section means an older pg_snapshot.sql
            self.report.not_checked.append("dbh.08 event triggers: the snapshot was taken with a pg_snapshot.sql older than 0.7.2; "
                                           "run the current one to check them")
        roles = {r["role"]: r for r in snap.get("roles", [])}
        bootstrap = meta.get("bootstrap_superuser")
        self.app_roles = set(self.args.app_role)
        self.inferred = not self.app_roles
        if self.inferred:
            self.app_roles = {n for n, r in roles.items() if r.get("login") and not r.get("superuser") and not r.get("replication")
                              and n != bootstrap}
            if self.app_roles:
                self.report.skipped.append(f"App role inferred as {', '.join(sorted(self.app_roles))}: pass --app-role to pin it")
        edges: dict[str, set[str]] = {}
        self.admin_only: set[tuple[str, str]] = set()   # ADMIN-only grants still escalate: the member can grant itself SET
        for m in snap.get("memberships", []):
            edges.setdefault(m.get("role"), set()).add(m.get("granted"))
            if m.get("admin_only"):
                self.admin_only.add((m.get("role"), m.get("granted")))
        self.via: dict[str, str] = {}   # role an app role is a member of (transitively) -> that app role
        for a in sorted(self.app_roles):
            for g in closure(edges, a) - self.app_roles:
                self.via.setdefault(g, a)
        others = sorted({r.get("database") for r in snap.get("databases", [])} - {meta.get("database"), "postgres", None})
        if others:
            self.report.not_checked.append(f"Snapshot covers database `{meta.get('database')}` only: tables, RLS, views and functions in "
                                           f"{', '.join(others[:8])} not checked (run pg_snapshot.sql in each app database)")
        self.relations = {f"{r['schema']}.{r['name']}": r for r in snap.get("relations", [])}
        self.rls = {k for k, r in self.relations.items() if r.get("rls")}
        self.major = (meta.get("server_version_num") or 0) // 10000

        self.live_version(meta)
        self.live_database_grants(snap.get("databases", []), meta.get("database"))
        settings = {r["name"]: r.get("setting") or "" for r in snap.get("settings", [])}
        superusers = {r["role"] for r in snap.get("roles", []) if r.get("superuser") and r.get("login")} or {"postgres"}
        broad = self.check_hba(hba_live_rows(snap.get("hba", [])), self.where, superusers) if "hba" in snap else False
        if settings:
            self.check_settings(settings, self.where, None, broad_hba=broad)
            if "shared_preload_libraries" in settings and "pgaudit" not in settings["shared_preload_libraries"]:
                self.add("dbh.18", "pgaudit isn't loaded: no audit trail of who read or changed personal data", file=self.where,
                         severity="info", fix_hint="shared_preload_libraries = 'pgaudit' and pgaudit.log = 'ddl, role, write' "
                                                   "(add 'read' only for tables that need it)")
            elif settings.get("pgaudit.log", "x").strip().lower() in ("none", ""):
                self.add("dbh.18", "pgaudit is loaded but pgaudit.log is `none`: nothing is audited", file=self.where, severity="info",
                         fix_hint="ALTER SYSTEM SET pgaudit.log = 'ddl, role, write'; SELECT pg_reload_conf();")
            mode = settings.get("data_directory_mode")
            if mode and mode not in ("0700", "700"):
                self.add("dbh.20", f"Data directory mode is {mode}: other local users can read table and WAL files", file=self.where,
                         severity="info", fix_hint="chmod 0700 on PGDATA")
        self.live_sessions(meta, snap.get("sessions", []), roles)
        self.live_roles(roles, bootstrap)
        self.live_privileges(snap)
        self.live_rls(snap.get("policies", []))
        self.live_views()
        self.live_functions(snap.get("definer_functions", []))
        if settings.get("standard_conforming_strings", "on").lower() in ("off", "false", "0"):
            self.add("dbh.23", "standard_conforming_strings is off: backslashes escape quotes in string literals, which reopens "
                               "escaping-bypass injection", file=self.where, severity="error", fix_hint="standard_conforming_strings = on (the default)")
        if settings.get("backslash_quote", "safe_encoding").lower() in ("on", "true", "1"):
            self.add("dbh.23", "backslash_quote is on: \\' is accepted as a quote, which helps injection through escaped strings",
                     file=self.where, severity="warn", fix_hint="backslash_quote = safe_encoding (the default)")
        for f in snap.get("dynamic_sql", []):
            self.flag("dbh.23", f"Function `{f['schema']}.{f['name']}` builds dynamic SQL by concatenation or format('%s')"
                      + (" and is SECURITY DEFINER" if f.get("definer") else ""),
                      fix_hint="EXECUTE format('… %I … %L', ident, value), or EXECUTE '… $1' USING value")
        self.live_side_channels(snap.get("unique_indexes", []), snap.get("cascades", []))
        md5 = sorted(r["role"] for r in snap.get("password_types", []) if r.get("hash_type") == "md5")
        if md5:
            self.add("dbh.16", f"{len(md5)} role(s) still have MD5 password hashes: {', '.join(md5[:8])}", file=self.where,
                     fix_hint="With password_encryption = scram-sha-256, reset each password (ALTER ROLE … PASSWORD …)")
        self.live_guardrails(roles, settings, snap.get("db_role_settings", []), meta.get("database"))

    def flag(self, rule: str, msg: str, **kw) -> None:
        if self.inferred and rule in ("dbh.06", "dbh.09", "dbh.17") and "confidence" not in kw:
            kw["confidence"] = "medium"
        self.add(rule, msg, file=self.where, **kw)

    def live_version(self, meta: dict) -> None:
        versions = json.loads((SKILL / "assets" / "pg-versions.json").read_text(encoding="utf-8"))
        age = (dt.date.today() - dt.date.fromisoformat(versions["checked"])).days
        if age > 120:
            self.report.skipped.append(f"assets/pg-versions.json was checked {age} days ago: newer PostgreSQL security releases "
                                       "may exist (postgresql.org/support/security)")
        if hit := version_finding(int(meta.get("server_version_num") or 0), versions):
            sev, msg = hit
            self.flag("dbh.01", msg, severity=sev, fix_hint=f"Minor upgrades only need new binaries and a restart; latest: {versions['release']}")
        client = (self.snap.get("client") or [{}])[0].get("psql_version_num")
        if client and (hit := version_finding(int(client), versions)):
            self.flag("dbh.01", "Client tools: psql " + hit[1].replace("PostgreSQL ", "", 1), severity="info" if hit[0] == "info" else "warn",
                      fix_hint="Update psql and pg_dump (the postgresql-client package or image) on every machine that runs them")
        elif "client" not in self.snap:
            self.report.not_checked.append("dbh.01 client tools: snapshot has no `client` section (psql older than 11?); "
                                           "check `psql --version` and `pg_dump --version`")

    def live_database_grants(self, rows: list[dict], current: str | None) -> None:
        by_db: dict[tuple[str, str], set[str]] = {}
        connect = set()
        for r in rows:
            who = r.get("grantee")
            if r.get("database") == "postgres" and current != "postgres":  # maintenance database, not an app database
                continue
            if who == "PUBLIC" and r.get("privilege") == "CONNECT":
                connect.add(r["database"])
            if (who == "PUBLIC" or who in self.app_roles or who in self.via) and r.get("privilege") in ("TEMPORARY", "CREATE"):
                by_db.setdefault((r["database"], who), set()).add(r["privilege"])
        for (db, who), privs in sorted(by_db.items()):
            subject = ("PUBLIC" if who == "PUBLIC" else f"App role `{who}`" if who in self.app_roles
                       else f"Role `{who}` (app role `{self.via[who]}` is a member)")
            extra = ", or install trusted extensions" if "CREATE" in privs else ""
            self.flag("dbh.02", f"{subject} has {' and '.join(sorted(privs))} on database `{db}` (it can create temporary objects or schemas{extra})",
                      fix_hint=f"REVOKE TEMPORARY, CREATE ON DATABASE {db} FROM {who}; grant TEMPORARY back only to roles that need it")
        if connect:
            self.flag("dbh.02", f"PUBLIC can connect to database(s) {', '.join(sorted(connect)[:8])}: any role pg_hba admits can log in to them",
                      severity="info", fix_hint="GRANT CONNECT ON DATABASE … TO the app, owner, backup and monitoring roles first, "
                                                "then REVOKE CONNECT ON DATABASE … FROM PUBLIC")

    def live_sessions(self, meta: dict, rows: list[dict], roles: dict) -> None:
        if not (meta.get("is_superuser") or meta.get("can_read_stats")):
            self.report.not_checked.append("dbh.05 other roles' sessions: the snapshot role isn't in pg_read_all_stats")
            return
        plain: dict[str, int] = {}
        for r in rows:
            if not r.get("ssl") and r.get("client") in ("private", "public"):
                plain[r["client"]] = plain.get(r["client"], 0) + int(r.get("sessions") or 0)
            if r.get("client") != "local" and roles.get(r.get("role"), {}).get("superuser"):
                self.flag("dbh.06", f"Superuser `{r['role']}` has {r.get('sessions')} session(s) from a {r['client']} address: "
                                    "is the app connecting as a superuser?", severity="warn",
                          fix_hint="Connect the app as a NOSUPERUSER runtime role; keep the superuser for administration")
        for client, n in sorted(plain.items()):
            self.flag("dbh.05", f"{n} session(s) from {client} addresses are not encrypted", severity="warn" if client == "public" else "info",
                      fix_hint=f"Set sslmode=require/verify-full in the clients first, then switch pg_hba to hostssl ({ROLLOUT})")

    def live_roles(self, roles: dict, bootstrap: str | None) -> None:
        for name, r in sorted(roles.items()):
            if not r.get("login") or (name == bootstrap and name not in self.app_roles):
                continue
            attrs = [a.upper() for a in ("superuser", "createrole", "createdb", "replication", "bypassrls") if r.get(a)]
            if name in self.app_roles and attrs:
                self.flag("dbh.06", f"App role `{name}` has {', '.join(attrs)}"
                          + (": the app connects as the bootstrap superuser" if name == bootstrap else ""), severity="error",
                          fix_hint="Create a separate NOSUPERUSER app role and point the app's connection string at it (the bootstrap "
                                   "superuser can't drop SUPERUSER)" if name == bootstrap else
                                   f"ALTER ROLE {name} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
            elif r.get("superuser"):
                self.flag("dbh.06", f"Login role `{name}` is a second superuser", severity="info",
                          fix_hint="Keep one superuser for emergencies; use NOSUPERUSER roles for migrations and the app")
            elif {"CREATEROLE", "CREATEDB"} & set(attrs):
                self.flag("dbh.06", f"Login role `{name}` has {', '.join(a for a in attrs if a in ('CREATEROLE', 'CREATEDB'))}: "
                                    "keep these for administrators", severity="info",
                          fix_hint=f"ALTER ROLE {name} NOCREATEROLE NOCREATEDB unless it administers roles or databases")
            if name in self.app_roles and int(r.get("owned_tables") or 0):
                self.flag("dbh.06", f"App role `{name}` owns {r['owned_tables']} table(s): owners bypass RLS and can ALTER or DROP them",
                          severity="warn", fix_hint="Let a migration role own the tables (ALTER TABLE … OWNER TO db_owner); grant the app DML only")
        for g, a in sorted(self.via.items()):
            gr = roles.get(g, {})
            why = [w for w, hit in (("SUPERUSER", gr.get("superuser")), ("BYPASSRLS", gr.get("bypassrls")),
                                    ("CREATEROLE", gr.get("createrole")),
                                    (f"owns {gr.get('owned_tables')} table(s)", int(gr.get("owned_tables") or 0))) if hit]
            if why:
                how = (f"it holds only ADMIN OPTION, but it can grant itself SET and then SET ROLE {g}" if (a, g) in self.admin_only
                       else f"it can SET ROLE {g}")
                self.flag("dbh.06", f"App role `{a}` is a member of `{g}` ({', '.join(why)}): {how} and act with those "
                                    "rights (bypass RLS, ALTER or DROP tables)", severity="error", fix_hint=f"REVOKE {g} FROM {a}")
        su = {n for n, r in roles.items() if r.get("superuser")}
        by_su: dict[str, int] = {}
        for rel in self.relations.values():
            if rel.get("kind") in ("r", "p") and rel.get("owner") in su:
                by_su[rel["owner"]] = by_su.get(rel["owner"], 0) + 1
        for owner, n in sorted(by_su.items()):
            self.flag("dbh.06", f"{n} table(s) are owned by superuser `{owner}`: migrations run as a superuser instead of a separate "
                                "owner role", severity="warn",
                      fix_hint="CREATE ROLE db_owner NOLOGIN (or LOGIN for CI only); ALTER TABLE … OWNER TO db_owner; run migrations as db_owner")

    def live_privileges(self, snap: dict) -> None:
        for r in snap.get("schemas", []):
            if r.get("grantee") == "PUBLIC" and r.get("privilege") == "CREATE":
                self.flag("dbh.07", f"PUBLIC can create objects in schema `{r['schema']}`",
                          fix_hint=f"REVOKE CREATE ON SCHEMA {r['schema']} FROM PUBLIC (the default since PostgreSQL 15)")
            elif (r.get("grantee") in self.app_roles or r.get("grantee") in self.via) and r.get("privilege") == "CREATE" \
                    and r.get("grantee") != r.get("owner"):
                who = f"`{r['grantee']}`" if r["grantee"] in self.app_roles else f"`{self.via[r['grantee']]}` (through `{r['grantee']}`)"
                self.flag("dbh.07", f"App role {who} can create objects in schema `{r['schema']}`: injected SQL can plant "
                                    "functions or operators that other roles pick up through search_path (CVE-2018-1058 pattern)",
                          fix_hint=f"REVOKE CREATE ON SCHEMA {r['schema']} FROM {r['grantee']}")
        for key, rel in sorted(self.relations.items()):
            regrant = sorted({g["privilege"] for g in rel.get("grants") or [] if g.get("grantable") and g.get("grantee") in self.app_roles
                              and g["grantee"] != rel.get("owner")})
            if regrant:
                self.flag("dbh.06", f"App role can re-grant {', '.join(regrant)} on `{key}` (WITH GRANT OPTION)", severity="warn",
                          fix_hint=f"REVOKE GRANT OPTION FOR {', '.join(regrant)} ON {key} FROM <app role>")
        for f in snap.get("native_functions", []):
            self.flag("dbh.08", f"Function `{f['schema']}.{f['name']}` is written in `{f['language']}` and isn't part of an extension: "
                                "check who created it (sqlmap-style `sys_eval` backdoors look like this)", severity="error",
                      fix_hint="If nobody can account for it, treat the server as compromised: isolate it, rotate credentials, restore from a clean backup")
        for e in snap.get("event_triggers", []):
            self.flag("dbh.08", f"Event trigger `{e['name']}` (owner `{e.get('owner')}`) runs `{e.get('function')}` on every `{e.get('event')}`"
                                f"{'' if e.get('enabled', True) else ' (disabled)'}, including a superuser's, and isn't part of an extension: "
                                "check who created it", severity="warn" if e.get("enabled", True) else "info",
                      fix_hint=f"If nobody can account for it: DROP EVENT TRIGGER {e['name']}, review the function, and treat the server as possibly compromised")
        lo = (snap.get("large_objects") or [{}])[0]
        if int(lo.get("count") or 0):
            self.flag("dbh.08", f"{lo['count']} large object(s) exist ({lo.get('superuser_owned', 0)} owned by a superuser): attackers stage binaries "
                                "with lo_import/lo_export, so confirm the app uses them", severity="warn" if lo.get("superuser_owned") else "info",
                      fix_hint="If the app doesn't use large objects, inspect them (SELECT oid, lomowner FROM pg_largeobject_metadata) and remove unexpected ones")
        owners = {r["role"]: r for r in snap.get("roles", [])}
        for f in snap.get("definer_functions", []):
            if f.get("public_execute"):
                o = owners.get(f.get("owner"), {})
                strong = o.get("superuser") or o.get("bypassrls")
                self.flag("dbh.07", f"PUBLIC can execute SECURITY DEFINER function `{f['schema']}.{f['name']}`"
                          + (f" owned by {'superuser' if o.get('superuser') else 'BYPASSRLS role'} `{f['owner']}`: any role runs it with RLS bypassed" if strong else ""),
                          severity="error" if strong else "warn",
                          fix_hint="REVOKE EXECUTE ON FUNCTION … (exact argument types) FROM PUBLIC; own it with a NOSUPERUSER NOBYPASSRLS role")
        for key, r in sorted(self.relations.items()):
            privs = sorted({g["privilege"] for g in r.get("grants") or [] if g.get("grantee") == "PUBLIC"})
            if privs:
                self.flag("dbh.07", f"PUBLIC has {', '.join(privs)} on `{key}`", fix_hint=f"REVOKE ALL ON {key} FROM PUBLIC; grant the app role by name")
        for m in snap.get("memberships", []):
            role, granted = m.get("role"), m.get("granted")
            if granted not in PREDEFINED or not (role in self.app_roles or role in self.via):
                continue
            why, sev = PREDEFINED[granted]
            subject = f"App role `{role}`" if role in self.app_roles else f"Role `{role}` (app role `{self.via[role]}` is a member)"
            self.flag("dbh.08", f"{subject} is a member of `{granted}` ({why})", severity=sev, fix_hint=f"REVOKE {granted} FROM {role}")
        for f in snap.get("function_grants", []):
            who = f.get("grantee")
            hit = who == "PUBLIC" or who in self.app_roles or who in self.via
            sig = f.get("signature")   # snapshots before 0.7.2 have only the name
            self.flag("dbh.08", f"{'PUBLIC' if who == 'PUBLIC' else f'Role `{who}`'} can execute `{sig or f['name'] + '()'}` (server file, large-object "
                                "or admin function; superuser only by default)", severity="error" if hit else "warn",
                      fix_hint=f"REVOKE EXECUTE ON FUNCTION pg_catalog.{sig or f['name'] + '(<each overload argument types>)'} FROM {who}")
        for g in snap.get("parameter_grants", []):
            who, param = g.get("grantee"), g.get("parameter") or ""
            runs_code = bool(re.search(r"_command$|librar", param))   # archive/restore_command, *_preload_libraries, dynamic_library_path
            self.flag("dbh.06", f"{'PUBLIC' if who == 'PUBLIC' else f'Role `{who}`'} has {g.get('privilege')} on parameter `{param}`"
                      + (": it runs programs or loads libraries as the server's OS user" if runs_code else
                         " (superuser-only by default)"),
                      severity="error" if runs_code or who == "PUBLIC" or who in self.app_roles or who in self.via else "warn",
                      fix_hint=f"REVOKE {g.get('privilege')} ON PARAMETER {g.get('parameter')} FROM {who}")
        kinds = {"r": "tables", "S": "sequences", "n": "schemas", "L": "large objects"}
        future: dict[tuple[str, str, str], set[str]] = {}
        for d in snap.get("default_acls", []):
            if d.get("grantee") == "PUBLIC" and d.get("objtype") in kinds:   # functions and types grant PUBLIC by default anyway
                future.setdefault((d.get("role"), d.get("schema"), d["objtype"]), set()).add(d.get("privilege"))
        for (role, schema, kind), privs in sorted(future.items()):
            where = "every schema" if schema == "*" else f"schema `{schema}`"
            self.flag("dbh.07", f"Default privileges of `{role}` grant {', '.join(sorted(privs))} on future {kinds[kind]} in {where} to PUBLIC",
                      severity="warn", fix_hint=f"ALTER DEFAULT PRIVILEGES FOR ROLE {role}"
                                                f"{'' if schema == '*' else ' IN SCHEMA ' + schema} REVOKE ALL ON {kinds[kind].upper()} FROM PUBLIC")
        versions = json.loads((SKILL / "assets" / "pg-versions.json").read_text(encoding="utf-8"))
        for lang in snap.get("languages", []):
            base = lang["name"].rstrip("u") if lang["name"].endswith("u") else lang["name"]
            if not lang.get("trusted"):
                self.flag("dbh.08", f"Untrusted language `{lang['name']}` is installed: functions in it run as the OS user",
                          fix_hint=f"DROP EXTENSION {lang['name']} unless required")
            elif base in versions.get("cve_languages", {}):
                self.flag("dbh.08", f"Procedural language `{lang['name']}` is installed: a frequent source of code-execution CVEs "
                                    f"({versions['cve_languages'][base]})", severity="warn",
                          fix_hint=f"DROP EXTENSION {lang['name']} if no function uses it; otherwise patch every minor release")
        for ext in snap.get("extensions", []):
            if ext.get("name") in RISKY_EXTENSIONS - {"plpython3u", "plpythonu", "plpython2u", "plperlu", "pltclu"}:
                self.flag("dbh.08", f"Extension `{ext['name']}` gives file or network access from SQL",
                          fix_hint="Drop it unless required, and keep its functions away from the app role")
            if ext.get("name") in versions.get("cve_extensions", {}):
                self.flag("dbh.08", f"Extension `{ext['name']}` is attack surface with recent security fixes "
                                    f"({versions['cve_extensions'][ext['name']]})", severity="info",
                          fix_hint=f"DROP EXTENSION {ext['name']} if unused; if used, apply every minor release and REVOKE its functions from PUBLIC where possible")
        for sub in snap.get("subscriptions", []):
            self.flag("dbh.08", f"Logical replication subscription `{sub['name']}`: the subscriber trusts its publisher completely "
                                "(CVE-2026-120145: replication could write to the subscriber's system catalogs and execute code)", severity="info",
                      fix_hint="Subscribe only to publishers you control, over TLS, and keep both sides patched")
        for pub in snap.get("publications", []):
            if pub.get("all_tables"):
                self.flag("dbh.13", f"Publication `{pub['name']}` is FOR ALL TABLES: every table, including personal data and future tables, "
                                    "is streamed to subscribers without RLS", severity="warn",
                          fix_hint="Publish an explicit table list (and column lists / row filters, PostgreSQL 15+)")
        readers = self.app_roles | {"PUBLIC"}
        for key, rel in sorted(self.relations.items()):
            if rel.get("kind") not in ("r", "p"):
                continue
            cols = [c for c in rel.get("columns") or [] if SENSITIVE_COL.search(c) and not NOT_SENSITIVE_COL.search(c)]
            who = sorted({g["grantee"] for g in rel.get("grants") or [] if g.get("privilege") == "SELECT" and g.get("grantee") in readers
                          and g["grantee"] != rel.get("owner")})
            if cols and who:
                self.flag("dbh.09", f"`{key}` has sensitive column(s) {', '.join(cols[:5])} and {', '.join(who)} can SELECT the whole table",
                          fix_hint="Grant SELECT on the needed columns only, and encrypt secrets (TOTP keys, API tokens) before storing them")

    def tenant_col(self, key: str) -> str | None:
        return next((c for c in self.relations.get(key, {}).get("columns") or [] if TENANT_COL.match(c)), None)

    def live_rls(self, policies: list[dict]) -> None:
        tables = {k: r for k, r in self.relations.items() if r.get("kind") in ("r", "p")}
        tenant = sorted(k for k in tables if self.tenant_col(k))
        with_policy = {f"{p['schema']}.{p['name']}" for p in policies}
        if not self.rls:
            if tenant:
                self.flag("dbh.10", f"No table uses row level security; {len(tenant)} have tenant/owner columns ({', '.join(tenant[:5])})",
                          severity="info", confidence="medium",
                          fix_hint="If authorization lives only in app code, one missing WHERE leaks data: consider RLS on these tables")
        else:
            for k in tenant:
                if k not in self.rls and tables[k].get("parent") not in self.rls:  # partitions of RLS tables get their own error
                    self.flag("dbh.10", f"`{k}` has `{self.tenant_col(k)}` but row level security is off (other tables use it)",
                              confidence="medium", fix_hint=f"ALTER TABLE {k} ENABLE ROW LEVEL SECURITY plus a policy ({ROLLOUT})")
            for k, r in sorted(tables.items()):
                if r.get("parent") in self.rls and k not in self.rls:
                    self.flag("dbh.10", f"`{k}` is a partition/child of RLS table `{r['parent']}` but has no RLS itself: querying it directly skips the policies",
                              severity="error", fix_hint=f"ALTER TABLE {k} ENABLE ROW LEVEL SECURITY with the same policies, and revoke direct access to partitions")
                truncaters = sorted({g["grantee"] for g in r.get("grants") or [] if g.get("privilege") == "TRUNCATE"
                                     and g.get("grantee") in self.app_roles | {"PUBLIC"} and g["grantee"] != r.get("owner")})
                if k in self.rls and truncaters:
                    self.flag("dbh.10", f"{', '.join(truncaters)} can TRUNCATE RLS table `{k}`: TRUNCATE ignores RLS and empties every tenant",
                              fix_hint=f"REVOKE TRUNCATE ON {k} FROM {', '.join(truncaters)}")
            for k in sorted(self.rls):
                r = tables.get(k, {})
                if k not in with_policy:
                    self.flag("dbh.10", f"`{k}` has RLS on but no policy: every non-owner query sees no rows", severity="info")
                if not r.get("force_rls") and r.get("owner") in self.app_roles:
                    self.flag("dbh.10", f"`{k}` is owned by app role `{r['owner']}` and RLS isn't forced, so the app bypasses it",
                              fix_hint=f"ALTER TABLE {k} FORCE ROW LEVEL SECURITY, or move ownership to a migration role")
        permissive: dict[tuple[str, str], list[str]] = {}
        for p in policies:
            if p.get("permissive") == "PERMISSIVE":
                for cmd in (["SELECT", "INSERT", "UPDATE", "DELETE"] if p.get("cmd") == "ALL" else [p.get("cmd")]):
                    permissive.setdefault((f"{p['schema']}.{p['name']}", cmd), []).append(p["policy"])
        for (key, cmd), names in sorted(permissive.items()):
            if len(names) > 1:
                self.flag("dbh.11", f"{len(names)} permissive {cmd} policies on `{key}` ({', '.join(names)}) are OR-ed: each one widens access",
                          severity="info", fix_hint="Keep one permissive policy per command and add extra conditions AS RESTRICTIVE")
        def hits_app(p: dict) -> bool:
            roles = {x.lower() for x in p.get("roles") or []}
            return bool("public" in roles or self.app_roles & roles)

        # Restrictive policies are AND-ed onto the permissive ones: `USING (true)` plus a restrictive tenant policy is the
        # recommended split, not an open table.
        narrowed = {(f"{p['schema']}.{p['name']}", p.get("cmd")) for p in policies if p.get("permissive") == "RESTRICTIVE"
                    and hits_app(p) and (p.get("qual") or p.get("with_check") or "true").strip() != "true"}
        for p in policies:
            key, roles = f"{p['schema']}.{p['name']}", [x.lower() for x in p.get("roles") or []]
            where = f"Policy `{p['policy']}` on `{key}`"
            if p.get("cmd") == "INSERT" and not p.get("with_check"):
                self.flag("dbh.11", f"{where} (INSERT) has no WITH CHECK: any row can be inserted", severity="error")
            reaches = (p.get("permissive") == "PERMISSIVE" and hits_app(p)
                       and not ({(key, "ALL"), (key, p.get("cmd"))} & narrowed))
            if reaches and (p.get("qual") or p.get("with_check") or "").strip() == "true":
                self.flag("dbh.11", f"{where} allows every row (`true`) for {', '.join(roles)}")
            elif reaches and p.get("qual") and (p.get("with_check") or "").strip() == "true":
                self.flag("dbh.11", f"{where} has WITH CHECK (true): {', '.join(roles)} can write rows with any tenant value, "
                                    "moving them into another tenant", fix_hint="Repeat the USING condition in WITH CHECK, or drop WITH CHECK so USING applies")
            text = f"{p.get('qual') or ''} {p.get('with_check') or ''}"
            self.policy_perf(text, key, {"file": self.where})

    def live_views(self) -> None:
        readers = self.app_roles | {"PUBLIC"}
        for key, r in sorted(self.relations.items()):
            reads_rls = sorted(set(r.get("reads") or []) & self.rls)
            if not reads_rls:
                continue
            if r.get("kind") == "v" and not any(re.fullmatch(r"security_invoker=(true|on|1)", o or "", re.I) for o in r.get("reloptions") or []):
                self.flag("dbh.13", f"View `{key}` reads RLS table(s) {', '.join(reads_rls[:3])} with its owner's rights, bypassing RLS"
                          + ("" if self.major >= 15 else " (security_invoker needs PostgreSQL 15+)"),
                          fix_hint=f"ALTER VIEW {key} SET (security_invoker = true)")
            elif r.get("kind") == "m":
                who = sorted({g["grantee"] for g in r.get("grants") or [] if g.get("privilege") == "SELECT" and g.get("grantee") in readers
                              and g["grantee"] != r.get("owner")})
                if who:
                    self.flag("dbh.13", f"Materialized view `{key}` copies RLS table(s) {', '.join(reads_rls[:3])} and {', '.join(who)} can read it "
                              "(materialized views ignore RLS)", fix_hint=f"REVOKE SELECT ON {key} FROM {', '.join(who)}")

    def live_functions(self, rows: list[dict]) -> None:
        writers = self.app_roles | set(self.via)
        unsafe = {r["schema"].lower() for r in self.snap.get("schemas", []) if r.get("privilege") == "CREATE"
                  and (r.get("grantee") == "PUBLIC" or (r.get("grantee") in writers and r.get("grantee") != r.get("owner")))}
        for f in rows:
            path = next((str(c).split("=", 1)[1] for c in f.get("config") or [] if str(c).startswith("search_path=")), None)
            name = f"{f['schema']}.{f['name']}"
            if path is None:
                self.flag("dbh.14", f"SECURITY DEFINER function `{name}` (owner `{f.get('owner')}`) doesn't pin search_path",
                          fix_hint=f"ALTER FUNCTION {name} SET search_path = pg_catalog, pg_temp")
            elif why := path_problem(path, unsafe):
                self.flag("dbh.14", f"SECURITY DEFINER function `{name}` pins search_path `{path}` but {why}", severity="warn",
                          fix_hint=f"ALTER FUNCTION {name} SET search_path = pg_catalog, pg_temp (and schema-qualify names)")

    def live_side_channels(self, uniques: list[dict], cascades: list[dict]) -> None:
        for u in uniques:
            key = f"{u['schema']}.{u['name']}"
            col, cols = self.tenant_col(key), u.get("columns") or []
            if col and cols and col not in cols:
                self.flag("dbh.15", f"Unique index `{u['index']}` on RLS table `{key}` ({', '.join(cols)}) is global: a duplicate-key error "
                                    "reveals another tenant's value", fix_hint=f"Make it UNIQUE ({col}, {', '.join(cols)}) if values are per tenant")
        for c in cascades:
            if f"{c['schema']}.{c['name']}" in self.rls and c.get("ref_table") in self.rls:
                self.flag("dbh.15", f"Foreign key `{c['constraint_name']}` on `{c['schema']}.{c['name']}` cascades from `{c['ref_table']}`: "
                                    "cascades ignore RLS and change rows the caller can't see",
                          fix_hint="Use RESTRICT and delete children explicitly, unless parent and child always share a tenant")

    def live_guardrails(self, roles: dict, settings: dict, db_settings: list[dict], database: str | None) -> None:
        def values(config) -> dict[str, str]:
            return dict(str(c).split("=", 1) for c in config or [] if "=" in str(c))

        for name in sorted(self.app_roles):
            r = roles.get(name)
            if not r:
                continue
            eff = {k: settings.get(k) for k in TIMEOUTS}
            for row in db_settings:
                if row.get("role") in ("*", name) and row.get("database") in ("*", database):
                    eff.update({k: v for k, v in values(row.get("config")).items() if k in TIMEOUTS})
            eff.update({k: v for k, v in values(r.get("config")).items() if k in TIMEOUTS})
            missing = [k for k in TIMEOUTS if not non_zero(eff.get(k))]
            if int(r.get("connlimit", -1)) == -1:
                missing.append("connection limit")
            if missing:
                serious = {"statement_timeout", "idle_in_transaction_session_timeout"} & set(missing)
                self.flag("dbh.17", f"App role `{name}` has no {', '.join(missing)}", severity="warn" if serious else "info",
                          fix_hint=f"ALTER ROLE {name} SET statement_timeout = '30s'; … SET idle_in_transaction_session_timeout = '30s'; "
                                   f"… SET lock_timeout = '5s'; ALTER ROLE {name} CONNECTION LIMIT 50 (not on the migration role)")


if __name__ == "__main__":
    run_main(PostgresAudit, __file__, __doc__)
