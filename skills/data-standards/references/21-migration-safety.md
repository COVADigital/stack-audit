# Migration Safety — 10 Practices

> **Applies to:** SQL migrations for PostgreSQL: Drizzle Kit (`drizzle-kit generate` output, both the folder-per-migration and the `meta/_journal.json` layouts), Prisma Migrate (`prisma/migrations/*/migration.sql`) and hand-written `.sql` migrations.  
> **Rule IDs:** section `NN` in this file is rule `dbm.NN` in audit findings.  
> **Sources:** PostgreSQL documentation (ALTER TABLE, CREATE INDEX, explicit locking), Drizzle Kit docs (generate, migrate, check). Written in our own words.

> **Agent directive:** Never run migrations, `drizzle-kit push`, or SQL against a database unless the user explicitly asks for that exact action. These audits only read files.

A statement is risky when it touches a table that **already has data**. Statements on a table created earlier in the same migration are not flagged.

---

## 01. Destructive Changes Need a Plan
**What:** `DROP TABLE`, `DROP COLUMN` and `TRUNCATE`.
**Why:** The data is gone the moment the migration runs, and the version of the app that is still serving traffic during the deploy may still read that column.

**Rule:** Before dropping anything with data, take a backup (see `ops.02` in container-standards), stop the code from using it in an earlier release, then drop it in a later one.

---

## 02. New `NOT NULL` Columns Need a Default
**What:** `ALTER TABLE … ADD COLUMN … NOT NULL` without `DEFAULT`.
**Why:** On a table that has rows, the statement fails, so the deploy fails. On Postgres 11+ a constant `DEFAULT` makes the add instant, with no table rewrite.

```sql
ALTER TABLE "orders" ADD COLUMN "currency" text DEFAULT 'EUR' NOT NULL;
```
**Rule:** A `NOT NULL` column added to an existing table has a `DEFAULT`, or is added nullable, backfilled, then made `NOT NULL`.

---

## 03. Column Type Changes Rewrite Tables
**What:** `ALTER COLUMN … TYPE` / `SET DATA TYPE`.
**Why:** Most type changes rewrite the whole table under an `ACCESS EXCLUSIVE` lock: no reads or writes until it finishes. Some changes (such as widening a `varchar`) don't, but a migration should not rely on guessing which.

**Rule:** On large tables, change a type by adding a new column, backfilling in batches, switching the code, then dropping the old column.

---

## 04. Setting `NOT NULL` on Existing Columns
**What:** `ALTER COLUMN … SET NOT NULL`.
**Why:** Postgres scans the whole table under an `ACCESS EXCLUSIVE` lock to prove there are no nulls. On Postgres 12+ it skips the scan if a validated `CHECK (col IS NOT NULL)` constraint already exists.

```sql
ALTER TABLE "users" ADD CONSTRAINT "users_email_nn" CHECK ("email" IS NOT NULL) NOT VALID;
ALTER TABLE "users" VALIDATE CONSTRAINT "users_email_nn";   -- no long write lock
ALTER TABLE "users" ALTER COLUMN "email" SET NOT NULL;      -- uses the check, no scan
```
**Rule:** On large tables, add a `NOT VALID` check constraint, validate it, then set `NOT NULL`.

---

## 05. Build Indexes Concurrently on Large Tables
**What:** `CREATE INDEX` on an existing table without `CONCURRENTLY`.
**Why:** A plain `CREATE INDEX` blocks every write to the table until the index is built. `CREATE INDEX CONCURRENTLY` doesn't, but it cannot run inside a transaction, and migration runners usually wrap each migration in one.

**Rule:** For tables large enough that a write pause matters, build the index concurrently in a migration that runs outside a transaction (or by hand, then record it). Small tables can take the plain form.

---

## 06. Rename with Expand and Contract
**What:** `RENAME COLUMN` and `ALTER TABLE … RENAME TO`.
**Why:** The rename is instant, but the old app version keeps running during a deploy and immediately fails on the old name.

**Rule:** Add the new name, write to both, switch reads, then drop the old name in a later release. Rename in one step only when no running code uses the name.

---

## 07. Add Foreign Keys as `NOT VALID`
**What:** `ADD CONSTRAINT … FOREIGN KEY` on an existing table.
**Why:** Adding the constraint checks every existing row while holding locks on both tables. `NOT VALID` adds it for new rows instantly; `VALIDATE CONSTRAINT` then checks old rows with a lighter lock.

```sql
ALTER TABLE "posts" ADD CONSTRAINT "posts_author_fk" FOREIGN KEY ("author_id") REFERENCES "users"("id") NOT VALID;
ALTER TABLE "posts" VALIDATE CONSTRAINT "posts_author_fk";
```
**Rule:** On large tables, add foreign keys as `NOT VALID` and validate them in a separate step.

---

## 08. Never Edit an Applied Migration
**What:** Changing a migration file after it was committed.
**Why:** Databases that already ran it keep the old version, so environments silently drift apart. Drizzle and Prisma also track applied migrations, so an edit is either ignored or breaks the next deploy.

**Rule:** Once a migration is committed (and certainly once it ran anywhere shared), fix mistakes with a new migration.

---

## 09. Keep Migration History Consistent
**What:** Every SQL file is recorded in the tool's history, and every history entry has its file. In Drizzle's older layout that's `meta/_journal.json`; `drizzle-kit check` verifies the history.
**Why:** A missing or orphaned entry means a migration is silently skipped, or the next `generate` produces the wrong diff.

**Rule:** Never add, delete or rename migration files by hand. Regenerate, and run `drizzle-kit check` in CI.

---

## 10. Review Generated SQL
**What:** Reading the `.sql` that `drizzle-kit generate` or `prisma migrate dev` produced before committing it.
**Why:** Generators turn a renamed field into drop-and-add, or a type change into a rewrite, when they can't infer intent. The schema diff looks harmless; the SQL deletes data.

**Rule:** Every generated migration is read before it's committed, and renames are confirmed as renames.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01 | Database_Security |
