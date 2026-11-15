"""Tests for the data-standards skill: Drizzle schema parser, SQL migration parser, the three audits, content."""

import json
import re
import subprocess
import sys
import unittest

from helpers import PLUGIN_ROOT, TempRepo
from wclib.drizzle import parse_tables
from wclib.jsscan import JsFile
from wclib.sqlmig import find_migrations, journal_problems, statements, table_name

SKILL = PLUGIN_ROOT / "skills" / "data-standards"
SCRIPTS = SKILL / "scripts"

SCHEMA = """import { pgTable, integer, text, timestamp, index, foreignKey, real, numeric, serial } from 'drizzle-orm/pg-core';
import * as p from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow(),
});

export const posts = p.pgTable('posts', {
  id: serial('id').primaryKey(),
  authorId: integer('author_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  editorId: integer('editor_id').references(() => users.id),
  price: real('price'),
  total: numeric('total', { precision: 12, scale: 2 }),
  publishedAt: timestamp('published_at'),
}, (t) => [
  index('posts_author_idx').on(t.authorId),
]);

export const tags = pgTable('tags', {
  name: text('name'),
  postId: integer('post_id'),
  password: text('password'),
}, (table) => [
  foreignKey({ columns: [table.postId], foreignColumns: [posts.id] }).onDelete('cascade'),
]);
"""


class ParserTests(unittest.TestCase):
    def test_drizzle_tables_columns_keys_indexes(self):
        tables = {t.name: t for t in parse_tables(JsFile("db/schema.ts", SCHEMA))}
        self.assertEqual(set(tables), {"users", "posts", "tags"})
        self.assertTrue(tables["users"].has_primary_key)
        self.assertFalse(tables["tags"].has_primary_key)
        self.assertEqual(tables["posts"].foreign_keys(), [("authorId", True), ("editorId", False)])
        self.assertEqual(tables["tags"].foreign_keys(), [("postId", True)])
        self.assertEqual(tables["posts"].leading_index_columns(), {"id", "authorId"})
        self.assertEqual(tables["posts"].column("authorId").sql_name, "author_id")
        self.assertEqual(tables["posts"].column("id").builder, "serial")
        self.assertEqual(parse_tables(JsFile("x.ts", "const pgTable = (n, c) => c; pgTable('t', { a: 1 });")), [])

    def test_sql_statements_mask_strings_comments_and_bodies(self):
        sql = ("CREATE TABLE \"t\" (\"note\" text DEFAULT 'a;b -- x');\n--> statement-breakpoint\n"
               "/* DROP TABLE x; */ ALTER TABLE \"t\" ADD COLUMN \"c\" int;\n"
               "CREATE FUNCTION f() RETURNS void AS $$ BEGIN DROP TABLE y; END $$ LANGUAGE plpgsql;\n-- DROP TABLE z;\n")
        got = [" ".join(s.sql.split()) for s in statements(sql)]
        self.assertEqual(len(got), 3)
        self.assertFalse(any("DROP" in g for g in got))
        self.assertEqual([table_name(x) for x in ('"public"."Orders"', "Users", '"Mixed"')], ["Orders", "users", "Mixed"])


class Case(TempRepo):
    def run_audit(self, script, *extra):
        res = subprocess.run([sys.executable, str(SCRIPTS / script), "--root", str(self.dir), "--format", "json", *extra],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertIn(res.returncode, (0, 1), res.stderr)
        return json.loads(res.stdout)

    @staticmethod
    def found(d, rule, part=None):
        return [f for f in d["findings"] if f["rule"] == rule and (part is None or part in (f.get("file") or ""))]


class SchemaAuditTests(Case):
    def test_schema_rules(self):
        self.write("src/db/schema.ts", SCHEMA)
        d = self.run_audit("audit_schema.py")
        msgs = {r: " ".join(f["message"] for f in self.found(d, r)) for r in ("dbs.01", "dbs.02", "dbs.03", "dbs.04",
                                                                               "dbs.05", "dbs.06", "dbs.07")}
        self.assertIn("`tags`", msgs["dbs.01"])
        self.assertNotIn("`users`", msgs["dbs.01"])
        self.assertIn("posts.editor_id", msgs["dbs.02"])       # no index
        self.assertNotIn("posts.author_id", msgs["dbs.02"])    # indexed
        self.assertIn("tags.post_id", msgs["dbs.02"])          # table-level foreignKey without index
        self.assertIn("posts.editor_id", msgs["dbs.03"])       # no onDelete
        self.assertNotIn("posts.author_id", msgs["dbs.03"])
        self.assertNotIn("tags.post_id", msgs["dbs.03"])       # .onDelete() chained on foreignKey()
        self.assertIn("posts.published_at", msgs["dbs.04"])
        self.assertNotIn("users.created_at", msgs["dbs.04"])
        self.assertIn("posts.price", msgs["dbs.05"])
        self.assertNotIn("posts.total", msgs["dbs.05"])        # numeric is fine
        self.assertIn("tags.password", msgs["dbs.06"])
        self.assertNotIn("password_hash", msgs["dbs.06"])
        self.assertIn("posts.id", msgs["dbs.07"])
        line = self.found(d, "dbs.04")[0]["line"]
        self.assertEqual(SCHEMA.splitlines()[line - 1].strip()[:12], "publishedAt:")

    def test_no_schema_is_skipped(self):
        self.write("src/app.ts", "export const x = 1;\n")
        d = self.run_audit("audit_schema.py")
        self.assertEqual(d["findings"], [])
        self.assertTrue(any("No Drizzle" in s for s in d["skipped"]))


INIT = ('CREATE TABLE "users" ("id" integer PRIMARY KEY);\n--> statement-breakpoint\n'
        'CREATE TABLE "posts" ("id" integer PRIMARY KEY, "author_id" integer NOT NULL);\n--> statement-breakpoint\n'
        'ALTER TABLE "posts" ADD CONSTRAINT "posts_author_fk" FOREIGN KEY ("author_id") REFERENCES "users"("id");\n'
        '--> statement-breakpoint\nCREATE INDEX "posts_author_idx" ON "posts" ("author_id");\n')
CHANGES = ('ALTER TABLE "users" ADD COLUMN "email" text NOT NULL;\n'
           'ALTER TABLE "users" ADD COLUMN "plan" text DEFAULT \'free\' NOT NULL;\n'
           'ALTER TABLE "users" ADD COLUMN "n" integer GENERATED ALWAYS AS IDENTITY NOT NULL;\n'
           'ALTER TABLE "posts" ALTER COLUMN "author_id" SET DATA TYPE bigint;\n'
           'ALTER TABLE "posts" ALTER COLUMN "author_id" SET NOT NULL;\n'
           'CREATE INDEX "users_email_idx" ON "users" ("email");\n'
           'CREATE INDEX CONCURRENTLY "users_plan_idx" ON "users" ("plan");\n'
           'ALTER TABLE "posts" RENAME COLUMN "author_id" TO "owner_id";\n'
           'ALTER TABLE "users" DROP COLUMN "legacy";\n'
           'DROP TABLE "old_stuff";\n'
           'TRUNCATE "audit_log";\n'
           'ALTER TABLE "comments" ADD CONSTRAINT "c_fk" FOREIGN KEY ("post_id") REFERENCES "posts"("id");\n'
           'ALTER TABLE "likes" ADD CONSTRAINT "l_fk" FOREIGN KEY ("post_id") REFERENCES "posts"("id") NOT VALID;\n'
           'ALTER TABLE "users" RENAME TO "accounts";\n')


class MigrationAuditTests(Case):
    def setUp(self):
        super().setUp()
        self.write("drizzle.config.ts", "export default defineConfig({ out: './db/migrations', dialect: 'postgresql' });\n")

    def test_layouts_are_discovered(self):
        self.write("db/migrations/0000_init.sql", INIT)
        self.write("db/migrations/20250101120000_next/migration.sql", "SELECT 1;\n")
        self.write("prisma/migrations/20240101_init/migration.sql", "SELECT 1;\n")
        self.write("supabase/migrations/001.sql", "SELECT 1;\n")
        self.write("docs/example.sql", "DROP TABLE x;\n")  # not a migration
        tools = {m.rel: m.tool for m in find_migrations(self.dir, [p.relative_to(self.dir).as_posix()
                                                                     for p in self.dir.rglob("*") if p.is_file()])}
        self.assertEqual(tools, {"db/migrations/0000_init.sql": "drizzle-legacy",
                                 "db/migrations/20250101120000_next/migration.sql": "drizzle",
                                 "prisma/migrations/20240101_init/migration.sql": "prisma",
                                 "supabase/migrations/001.sql": "sql"})

    def test_risky_statements_only_on_existing_tables(self):
        self.write("db/migrations/0000_init.sql", INIT)
        self.write("db/migrations/0001_changes.sql", CHANGES)
        d = self.run_audit("audit_migrations.py")
        self.assertEqual([f for f in d["findings"] if "0000_init" in (f.get("file") or "")], [])
        by_rule = {}
        for f in d["findings"]:
            by_rule.setdefault(f["rule"], []).append(f)
        self.assertEqual([f["line"] for f in by_rule["dbm.02"]], [1])       # not the DEFAULT or IDENTITY columns
        self.assertEqual([f["line"] for f in by_rule["dbm.03"]], [4])
        self.assertEqual([f["line"] for f in by_rule["dbm.04"]], [5])
        self.assertEqual([f["line"] for f in by_rule["dbm.05"]], [6])       # not the CONCURRENTLY one
        self.assertEqual(sorted(f["line"] for f in by_rule["dbm.06"]), [8, 14])
        self.assertEqual(sorted(f["line"] for f in by_rule["dbm.01"]), [9, 10, 11])
        self.assertEqual([f["line"] for f in by_rule["dbm.07"]], [12])      # not the NOT VALID one
        self.assertEqual(by_rule["dbm.02"][0]["severity"], "error")

    def test_journal_consistency(self):
        self.write("db/migrations/0000_init.sql", INIT)
        self.write("db/migrations/0001_orphan.sql", "SELECT 1;\n")
        self.write("db/migrations/meta/_journal.json", json.dumps({"entries": [{"tag": "0000_init"}, {"tag": "0002_gone"}]}))
        msgs = [f["message"] for f in self.found(self.run_audit("audit_migrations.py"), "dbm.09")]
        self.assertTrue(any("0002_gone.sql is listed" in m for m in msgs), msgs)
        self.assertTrue(any("0001_orphan.sql is not listed" in m for m in msgs), msgs)
        self.assertEqual(journal_problems(self.dir, "nope"), [])

    def test_edited_after_commit(self):
        self.init_git()
        self.write("db/migrations/0000_init.sql", INIT)
        self.write("db/migrations/0001_b.sql", "SELECT 1;\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        self.write("db/migrations/0000_init.sql", INIT + "SELECT 2;\n")
        self.git("commit", "-qam", "edit")
        files = [f["file"] for f in self.found(self.run_audit("audit_migrations.py"), "dbm.08")]
        self.assertEqual(files, ["db/migrations/0000_init.sql"])

    def test_files_mode_still_knows_the_out_folder(self):
        self.write("db/migrations/0001_changes.sql", 'ALTER TABLE "users" ADD COLUMN "email" text NOT NULL;\n')
        d = self.run_audit("audit_migrations.py", "--files", "db/migrations/0001_changes.sql")
        self.assertEqual([f["rule"] for f in d["findings"]], ["dbm.02"])


class DbOpsAuditTests(Case):
    PKG = {"name": "app", "scripts": {"db:push": "drizzle-kit push", "deploy": "drizzle-kit push && next start",
                                      "db:check": "drizzle-kit check"},
           "dependencies": {"drizzle-orm": "0.45.0"}, "devDependencies": {"drizzle-kit": "0.31.0"}}

    def test_ops_rules(self):
        self.write("package.json", json.dumps(self.PKG))
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npm run db:push\n")
        self.write("Dockerfile", "FROM node:22\nCMD npx drizzle-kit push && node server.js\n")
        self.write(".env.example", "DATABASE_URL=postgres://postgres:changeme@db.example.com:5432/app?sslmode=disable\n"
                                   "LOCAL_URL=postgres://postgres:postgres@localhost:5432/app?sslmode=disable\n")
        self.write(".env", "DATABASE_URL=postgres://postgres:REAL@prod.example.com/app?sslmode=disable\n")
        self.write("compose.yaml", "services:\n  app:\n    environment:\n      DATABASE_URL: postgres://postgres:${PW}@db:5432/app\n")
        self.write("compose.dev.yaml", "services:\n  app:\n    environment:\n      DATABASE_URL: postgres://postgres:x@db:5432/app\n")
        self.write("app/api/items/route.ts", "import postgres from 'postgres';\nexport async function GET() {\n"
                                             "  const db = drizzle(postgres(process.env.DATABASE_URL!));\n  return Response.json([]);\n}\n")
        self.write("src/db/index.ts", "export const client = postgres(url, { ssl: { rejectUnauthorized: false } });\n"
                                      "export const db = drizzle(client);\n")
        self.write("src/db/seed.ts", "await db.insert(users).values([{ email: 'a@b.c' }]);\n")
        self.write("scripts/seed-dev.ts", "if (process.env.NODE_ENV === 'production') process.exit(1);\nawait db.insert(users).values([]);\n")
        d = self.run_audit("audit_db_ops.py")
        files = lambda r: sorted({f["file"] for f in self.found(d, r)})  # noqa: E731
        self.assertEqual(files("dbo.01"), [".github/workflows/ci.yml", "Dockerfile", "package.json"])
        self.assertEqual([f["message"] for f in self.found(d, "dbo.01", "package.json")],
                         ["package.json script `deploy` runs drizzle-kit push"])  # not the dev-only db:push
        self.assertEqual(files("dbo.02"), [".github/workflows"])
        self.assertEqual(files("dbo.03"), [".env.example", "src/db/index.ts"])   # never the real .env, not localhost
        self.assertEqual(files("dbo.04"), [".env.example", "compose.yaml"])      # not the local URL or dev compose
        self.assertEqual(len(self.found(d, "dbo.04", ".env.example")), 1)
        self.assertEqual(files("dbo.05"), ["app/api/items/route.ts"])           # not the module-scope client
        self.assertEqual(files("dbo.06"), ["src/db/seed.ts"])                   # not the guarded one
        self.assertTrue(all("REAL" not in f["message"] and "changeme" not in f["message"] for f in d["findings"]))

    def test_ci_with_check_and_migrate_is_clean(self):
        self.write("package.json", json.dumps({"scripts": {"db:check": "drizzle-kit check", "db:migrate": "drizzle-kit migrate"},
                                               "devDependencies": {"drizzle-kit": "0.31.0"}}))
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - run: npm run db:check\n")
        d = self.run_audit("audit_db_ops.py")
        self.assertEqual([f["rule"] for f in d["findings"]], [])


class RunAuditTests(Case):
    def test_merges_all_three(self):
        self.write("drizzle.config.ts", "export default { out: 'drizzle' };\n")
        self.write("drizzle/0000_x.sql", 'ALTER TABLE "users" DROP COLUMN "a";\n')
        self.write("src/db/schema.ts", SCHEMA)
        self.write("package.json", json.dumps(DbOpsAuditTests.PKG))
        res = subprocess.run([sys.executable, str(SCRIPTS / "run_audit.py"), "--root", str(self.dir), "--format", "json"],
                             capture_output=True, text=True, encoding="utf-8")
        prefixes = {f["rule"].split(".")[0] for f in json.loads(res.stdout)["findings"]}
        self.assertEqual(prefixes, {"dbs", "dbm", "dbo"})


class ContentTests(unittest.TestCase):
    def test_rule_index_in_sync(self):
        res = subprocess.run([sys.executable, str(SCRIPTS / "build_rule_index.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_skill_md(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        fm = text.split("---")[1]
        self.assertIn("name: data-standards", fm)
        desc = re.search(r"description: (.+)", fm).group(1)
        self.assertLessEqual(len(desc), 1024)
        self.assertIn("allowed-tools: Bash(python ${CLAUDE_PLUGIN_ROOT}/skills/data-standards/scripts/*)", fm)
        self.assertNotIn("$S/", text)
        rules = json.loads((SKILL / "rules.json").read_text(encoding="utf-8"))["rules"]
        self.assertIn(f"all {sum(len(v) for v in rules.values())} rules", text)
        for script in re.findall(r"scripts/(\w+\.py)", text):
            self.assertTrue((SCRIPTS / script).is_file(), script)

    def test_references_have_banner(self):
        for p in sorted((SKILL / "references").glob("2*.md")):
            head = p.read_text(encoding="utf-8")[:700]
            self.assertIn("**Applies to:**", head, p.name)
            self.assertIn("**Rule IDs:**", head, p.name)


if __name__ == "__main__":
    unittest.main()
