# Data and Operations — 7 Practices

> **Applies to:** Docker Compose stacks with databases, volumes and long-running services.  
> **Rule IDs:** section `NN` in this file is rule `ops.NN` in audit findings.  
> **Sources:** Docker Compose specification (volumes, healthcheck, depends_on, logging, deploy), Docker logging driver docs, Coolify backup docs. Not part of the OWASP Docker cheat sheet; these are operational practices. Written in our own words.

> **Agent directive:** Never run `docker compose down -v`, `docker volume rm` or `docker system prune` unless the user explicitly asks. They delete data.

---

## 01. Named Volumes for Databases
**What:** `volumes: [pgdata:/var/lib/postgresql/data]` with a top-level `volumes: { pgdata: }`.
**Why:** Without a volume, data dies with the container. Anonymous volumes are easy to orphan or prune, and bind mounts bring host permission and line-ending problems (especially Windows dev versus Linux prod).

**Rule:** Every database or stateful service stores data in a named volume.

---

## 02. Backups and Tested Restores
**What:** A scheduled `pg_dump` (or Coolify's scheduled database backups with S3 upload) plus a restore that's actually been tried.
**Why:** A backup you've never restored is a hope, not a backup.

**Rule:** Each stateful service has an automated, off-host backup with retention, and a documented restore procedure that's been tested.

---

## 03. Healthchecks and Dependency Conditions
**What:** `healthcheck:` on databases and apps, plus `depends_on: { db: { condition: service_healthy } }`.
**Why:** Without these, the app starts before the database accepts connections and crash-loops. Proxies route to containers that aren't ready.

**Rule:** Long-running services have a healthcheck. Services that need a database wait for `service_healthy`, and one-shot migrations use `service_completed_successfully`.

---

## 04. Restart Policies
**What:** `restart: unless-stopped` for services, and `"no"` for one-shot jobs.
**Why:** It brings services back after host reboots, without endlessly restarting jobs that should run once.

**Rule:** Long-running services set `restart: unless-stopped` (or `always`). One-shot jobs set `restart: "no"`.

---

## 05. Log Rotation per Service
**What:** `logging: { driver: local }` or `options: { max-size: "10m", max-file: "3" }`.
**Why:** The default `json-file` driver grows without limit (see `14-host-daemon.md` §03).

**Rule:** Configure rotation either per service or at the daemon. The audit can't see the daemon from a Compose file, so it reports per-service rotation as missing unless `--daemon-rotation` is passed.

---

## 06. Obsolete `version:` Key
**What:** A top-level `version: "3.8"`.
**Why:** Compose v2/v5 ignores it and prints a warning, and it suggests the outdated v2/v3 file-format split.

**Rule:** Remove the top-level `version:` key.

---

## 07. Graceful Shutdown
**What:** `stop_grace_period`, SIGTERM handling in the app, and `init: true` for signal forwarding.
**Why:** Databases and apps need time to finish requests and flush writes. The default 10 seconds is short for databases.

**Rule:** Give databases a `stop_grace_period` of 30 seconds or more, and make sure app processes receive SIGTERM (exec form, or `init: true`).

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 05 | Logging |
