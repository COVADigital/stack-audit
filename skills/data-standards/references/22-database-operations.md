# Database Operations — 7 Practices

> **Applies to:** Node.js / Next.js apps using PostgreSQL through Drizzle (`postgres`, `pg`, `@neondatabase/serverless`), deployed with Docker Compose or Coolify.  
> **Rule IDs:** section `NN` in this file is rule `dbo.NN` in audit findings.  
> **Sources:** Drizzle Kit docs (push, migrate, check), PostgreSQL documentation (roles, SSL), OWASP Database Security cheat sheet. Written in our own words.

> **Agent directive:** Never print connection strings or passwords. Report variable names, hosts and settings only.

---

## 01. Migrate, Don't Push, in Production
**What:** `drizzle-kit push` applies the schema straight to a database with no migration files. `drizzle-kit generate` + `drizzle-kit migrate` writes reviewable SQL and records what ran.
**Why:** Drizzle's docs recommend push for rapid local prototyping and `generate` + `migrate` for production, because push leaves no versioned history and no SQL to review. Some teams do push to production; they accept that every deploy is an unreviewed schema change.

**Rule:** Deploy, start, release and CI scripts use `drizzle-kit migrate` (or the migrator), not `drizzle-kit push`. Keep push for local development.

---

## 02. Check Migrations in CI
**What:** A CI step that runs `drizzle-kit check` (history consistency) and, ideally, applies all migrations to a throwaway database.
**Why:** Branches that each add a migration collide, and a broken history is found at deploy time instead of review time.

**Rule:** CI verifies migration history on every pull request that touches the schema or the migrations folder.

---

## 03. Encrypt Connections to Remote Databases
**What:** SSL/TLS on connections that leave the machine or the private Docker network: `sslmode=require` (or `verify-full`) in the URL, or `ssl` in the client options.
**Why:** Without it, credentials and data cross the network in clear text. A connection to `db` on an internal Docker network is different from one to a managed database across the internet.

**Rule:** Connections to a database on another host use SSL, ideally with certificate verification. Never disable SSL for a non-local host.

---

## 04. Least-Privilege Database Roles
**What:** The app connects as its own role that owns or can use only its schema, not as the `postgres` superuser that the official image creates by default.
**Why:** A SQL injection or leaked credential with superuser rights can read every database, change roles, and on some setups run commands on the server.

**Rule:** The app's `DATABASE_URL` uses a dedicated, non-superuser role. Migrations may use a separate, more privileged role.

---

## 05. One Connection Pool per Process
**What:** Create the database client (`postgres()`, `new Pool()`, `drizzle()`) once at module level and reuse it.
**Why:** A client created inside a request handler opens new connections on every request. Postgres runs out of connection slots under modest load, and in development hot reload multiplies clients.

```ts
// lib/db.ts
import 'server-only';
const client = postgres(process.env.DATABASE_URL!, { max: 10 });
export const db = drizzle(client);
```
**Rule:** Database clients are created once per process (module scope, or a cached global in development), never per request.

---

## 06. Guard Seed Scripts
**What:** Seed or fixture scripts refuse to run against production unless explicitly forced.
**Why:** A seed run against the wrong `DATABASE_URL` overwrites or duplicates real data, and may reset passwords to test values.

**Rule:** Seed scripts check `NODE_ENV` (or a dedicated flag) and exit when they would run against production.

---

## 07. Back Up Before Risky Migrations
**What:** A fresh, restorable backup taken right before a migration that drops, rewrites or renames.
**Why:** The scheduled nightly backup may be a day old. Rolling back a destructive migration means restoring.

**Rule:** Destructive or rewriting migrations (`dbm.01`, `dbm.03`) run only after a backup that has been checked, as described in container-standards `ops.02`.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 03 | Database_Security, Transport_Layer_Security |
| 04 | Database_Security |
