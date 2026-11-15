# Schema Design — 8 Practices

> **Applies to:** PostgreSQL schemas declared with Drizzle ORM (`drizzle-orm/pg-core`). The ideas apply to any Postgres schema.  
> **Rule IDs:** section `NN` in this file is rule `dbs.NN` in audit findings.  
> **Sources:** PostgreSQL documentation (constraints, data types, indexes), Drizzle ORM docs (schema declaration, indexes and constraints), OWASP Password Storage cheat sheet. Written in our own words.

---

## 01. Every Table Has a Primary Key
**What:** A column (or set of columns) that uniquely identifies each row: `.primaryKey()` on a column, or `primaryKey({ columns: [...] })` in the table's extra config.
**Why:** Without one, rows can be duplicated, updates and deletes can hit more rows than intended, and logical replication and many tools refuse the table.

```ts
export const orders = pgTable('orders', {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  // ...
});
```
**Rule:** Every table declares a primary key.

---

## 02. Index Foreign Key Columns
**What:** An index whose first column is the foreign key column.
**Why:** Postgres indexes the referenced primary key, not the referencing column. Without an index, joins and `WHERE user_id = $1` scan the whole table, and every delete on the parent table scans the child table to check the constraint.

```ts
export const posts = pgTable('posts', {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  authorId: integer('author_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
}, (t) => [
  index('posts_author_id_idx').on(t.authorId),
]);
```
**Rule:** Every foreign key column is the first column of an index (or of the primary key or a unique constraint).

---

## 03. Choose `onDelete` Deliberately
**What:** An explicit `onDelete` on each reference: `'cascade'`, `'set null'`, `'restrict'` or `'no action'`.
**Why:** The default (`no action`) blocks deleting a parent that still has children. That is sometimes right, but often nobody decided. Account deletion and GDPR erasure then fail, or someone works around it in code.

**Rule:** Each `.references()` / `foreignKey()` states its `onDelete` behavior, chosen per relationship.

---

## 04. Timestamps with Time Zone
**What:** `timestamp('created_at', { withTimezone: true })`, which is Postgres `timestamptz`.
**Why:** `timestamp` without time zone stores a wall-clock value with no offset. Servers, containers and users in different zones then read different instants, and daylight-saving changes create duplicates and gaps.

```ts
createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
```
**Rule:** Points in time use `timestamptz` (`withTimezone: true`).

---

## 05. Exact Types for Money
**What:** `numeric` (Drizzle `numeric({ precision, scale })`) or an integer count of the smallest unit (cents).
**Why:** `real` and `double precision` are binary floating point: `0.1 + 0.2` is not `0.3`. Totals drift and reconciliation fails.

**Rule:** Money is never stored in `real` or `doublePrecision`.

---

## 06. Never Store Plain-Text Passwords
**What:** Store only a salted, slow hash (Argon2id, scrypt or bcrypt), produced by the auth library.
**Why:** A database leak then exposes hashes that are expensive to crack, not passwords that work on other sites too.

```ts
passwordHash: text('password_hash').notNull(),   // ✅ written by the auth library
// ❌ password: text('password')
```
**Rule:** No column stores a password or secret token in plain text. Name hash columns `*_hash` so reviews can tell.

---

## 07. Identity Columns over `serial`
**What:** `integer().generatedAlwaysAsIdentity()` (or `generatedByDefaultAsIdentity()`) instead of `serial()`.
**Why:** Identity columns are the SQL-standard form. Postgres owns the sequence with the column, permissions are simpler, and `ALWAYS` stops code from writing ids by accident.

**Rule:** New tables use identity columns (or UUIDs) instead of `serial` / `bigserial`.

---

## 08. Constraints Live in the Database
**What:** `notNull()`, `unique()`, `check()` and foreign keys in the schema, not only in Zod or application code.
**Why:** Every writer (scripts, admin tools, a second service, a bug) bypasses application validation. The database is the one place every write passes through.

**Rule:** Invariants that must always hold are database constraints. Application validation is for user-friendly errors, not for integrity.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 06 | Password_Storage |
| 08 | Database_Security |
