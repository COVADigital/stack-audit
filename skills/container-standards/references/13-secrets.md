# Container Secrets — 7 Practices

> **Applies to:** Dockerfiles, BuildKit, Docker Compose runtime and build secrets.  
> **Rule IDs:** section `NN` in this file is rule `csec.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rule #12 and build-time secrets), OWASP Secrets Management cheat sheet, Docker Compose secrets docs, NIST SP 800-190 (§3.1.4, §4.1.4). Written in our own words.

> **Agent directive:** Never print secret values. Report variable and file *names* only.

---

## 01. No Literal Secrets in Compose Files or Tracked Env Files
**What:** `environment: { DB_PASSWORD: hunter2 }`, or `env_file: .env` where `.env` is committed.
**Why:** Compose files and git history are widely readable. Anything literal there is leaked.

**Rule:** Secret values come from interpolation (`${VAR:?}`) supplied by an untracked env file or the platform's secret store. `env_file:` never points at a tracked file. Local-only development credentials are acceptable if they're clearly marked and never reused.

---

## 02. Compose Secrets and the `_FILE` Convention
**What:** A top-level `secrets:` entry (file or environment source), mounted at `/run/secrets/<name>`. Official images read `POSTGRES_PASSWORD_FILE` etc.
**Why:** Environment variables are visible to every process, to `docker inspect`, and often to logs. A file mount is scoped to the service. Note that Compose file secrets are bind mounts, not encrypted; protect the source file.

```yaml
services:
  db:
    image: postgres:17
    environment: { POSTGRES_PASSWORD_FILE: /run/secrets/db_password }
    secrets: [db_password]
secrets:
  db_password: { environment: DB_PASSWORD }
```
**Rule:** Prefer secrets plus `*_FILE` for database and service credentials where the image supports it. Plain environment variables are acceptable on platforms whose secret store injects them (record the trade-off).

---

## 03. Build Secrets, Never Build Args
**What:** `build.args: { NPM_TOKEN: … }` / `docker build --build-arg TOKEN=…`.
**Why:** Build arguments are recorded in the image history and metadata.

```yaml
build:
  context: .
  secrets: [npm_token]
secrets:
  npm_token: { environment: NPM_TOKEN }
```
```dockerfile
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci
```
**Rule:** Credentials needed at build time use BuildKit secret mounts (Compose `build.secrets`), never `ARG`, `--build-arg` or `build.args`.

---

## 04. No Secrets in ARG or ENV
**What:** `ARG API_KEY`, `ENV DATABASE_PASSWORD=…` in a Dockerfile.
**Why:** Both persist in the image (`docker history`, `docker inspect`) for anyone who can pull it (DL3064).

**Rule:** No secret-like names in `ARG` or `ENV`. Runtime secrets arrive through the container environment or `/run/secrets` when the container starts.

---

## 05. Never COPY Secret Files (and `COPY` then `rm` Doesn't Help)
**What:** `COPY .env .`, `COPY id_rsa /root/.ssh/`, or copying a file and deleting it in a later `RUN`.
**Why:** Every layer is kept. A file deleted in layer 7 can still be extracted from layer 6. Multi-stage builds don't help either if the secret is in the final stage's history.

**Rule:** Never copy credential files into any stage. Use secret mounts for build-time needs.

---

## 06. .dockerignore
**What:** A `.dockerignore` next to the build context that excludes `.env*`, `.git`, `node_modules`, build output, keys and local data.
**Why:** `COPY . .` copies everything that isn't ignored, including your `.env`.

```gitignore
.env*
!.env.example
.git
node_modules
.next
*.pem
*.key
```
**Rule:** Every build context has a `.dockerignore` that excludes `.env*`, `.git`, `node_modules` and key files.

---

## 07. Never Disable Database Authentication
**What:** Image switches that turn off the password check: `POSTGRES_HOST_AUTH_METHOD: trust`, `MYSQL_ALLOW_EMPTY_PASSWORD`, `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD`, Bitnami's `ALLOW_EMPTY_PASSWORD`.
**Why:** Anything that can reach the port gets in: another container on the network, a port published by mistake, or an SSRF in the app.

```yaml
db:
  image: postgres:17-alpine
  environment:
    POSTGRES_PASSWORD_FILE: /run/secrets/db_password   # ✅ not POSTGRES_HOST_AUTH_METHOD: trust
  secrets: [db_password]
```
**Rule:** Databases always require a password, in every environment that is reachable by more than one person. Use a throwaway password in dev rather than disabling authentication.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02, 03, 04, 05, 06 | Docker_Security, Secrets_Management |
| 07 | Database_Security |
