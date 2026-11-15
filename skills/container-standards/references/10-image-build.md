# Image Build — 11 Practices

> **Applies to:** Dockerfiles built with BuildKit (Docker Engine 23+), Node/Next.js and general services.  
> **Rule IDs:** section `NN` in this file is rule `img.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rules #2, #9, #12, #13), OWASP NodeJS Docker cheat sheet, Docker build docs, hadolint rules (cross-referenced as DLxxxx). Written in our own words.

> **Agent directive:** Every image is built from a pinned base, runs as a non-root user, contains only what the runtime needs, and never contains a secret, not even in an earlier layer.

---

## 01. Pin Base Images
**What:** Reference base images by an explicit version tag, and in production also by digest (`node:24.11-alpine3.22@sha256:…`).
**Why:** `latest` (or no tag) changes underneath you. Builds stop being reproducible and a compromised tag reaches you silently. A digest is immutable.

```dockerfile
ARG NODE_IMAGE=node:24.11.1-alpine3.22@sha256:<digest>
FROM ${NODE_IMAGE} AS deps
```
**Rule:** Never use `latest` or an untagged base (DL3006/DL3007). Pin production bases by digest, and let Dependabot's `docker` ecosystem propose updates.

---

## 02. Run as a Non-Root User
**What:** The final stage switches to an unprivileged user with `USER`.
**Why:** A process running as root inside a container is one kernel or runtime bug away from root on the host (OWASP Docker #2).

```dockerfile
# official node images ship a "node" user (uid 1000)
USER 1000:1000
```
**Rule:** The final stage must set `USER` to a non-root user, preferably as a numeric uid:gid (DL3002). Do the root-only steps (package installs, `chown`) before switching.

---

## 03. COPY, Not ADD
**What:** `ADD` auto-extracts archives and can fetch URLs. `COPY` only copies.
**Why:** Implicit downloads and extraction hide what lands in the image.

**Rule:** Use `COPY` for local files (DL3020). If you must fetch a remote file, use `ADD --checksum=sha256:…` or `curl` with checksum verification.

---

## 04. No Piped Install Scripts
**What:** `curl … | sh` and `wget -O- … | bash` in `RUN`.
**Why:** You execute whatever the server returns at build time, with no pinning or verification (OWASP Docker #9).

**Rule:** Download to a file, verify a checksum or signature, then run it. Better still, use a package or a pinned image.

---

## 05. Minimal Packages, Caches Cleaned in the Same Layer
**What:** `apt-get install --no-install-recommends … && rm -rf /var/lib/apt/lists/*`, `apk add --no-cache`.
**Why:** Every extra package is attack surface and size. Cleaning up in a later layer doesn't shrink the earlier one.

**Rule:** Install only what the runtime needs, with package-manager caches disabled or removed in the same `RUN` (DL3009/DL3015/DL3019). Prefer slim, Alpine or distroless runtime stages.

---

## 06. Exec-Form CMD/ENTRYPOINT and an Init Process
**What:** `CMD ["node", "server.js"]` rather than `CMD node server.js`.
**Why:** Shell form wraps the process in `/bin/sh -c`, which doesn't forward SIGTERM. Containers then get killed after the grace period instead of shutting down cleanly, and zombie processes aren't reaped.

**Rule:** Use JSON exec form (DL3025). Add `init: true` in Compose (or `tini`) for processes that spawn children.

---

## 07. HEALTHCHECK
**What:** A cheap liveness command in the image, or in Compose.
**Why:** Orchestrators, Compose `depends_on: condition: service_healthy` and reverse proxies rely on health to route traffic and order startup.

**Rule:** Define a healthcheck in the image or in every long-running Compose service. Keep image healthchecks free of external dependencies; put readiness, such as a database check, in Compose.

---

## 08. Multi-Stage Builds
**What:** Separate `deps`/`build` stages from a minimal `runtime` stage that copies only the artifacts.
**Why:** Compilers, dev dependencies and source code don't belong in what you ship.

**Rule:** Node/Next.js images use at least a build stage and a runtime stage. The runtime stage copies only the build output, and never `COPY . .` from the context.

---

## 09. Layer Order and Reproducible Installs
**What:** Copy the lockfile, install, then copy the source. Use `npm ci` (or `pnpm install --frozen-lockfile`).
**Why:** Better cache reuse, and installs that match the lockfile exactly.

**Rule:** `COPY package.json package-lock.json ./` then `RUN npm ci` before `COPY . .`. Never `npm install` in an image.

---

## 10. Line Endings and Platforms
**What:** Shell scripts copied from Windows with CRLF endings, and images built for the wrong CPU architecture.
**Why:** CRLF causes `/bin/sh^M: not found` / `exec format error` at runtime, and a wrong architecture fails or runs emulated.

**Rule:** Enforce LF for `*.sh`, Dockerfiles and entrypoints (`.gitattributes`: `*.sh text eol=lf`). Build for the server's platform (`--platform linux/amd64` / buildx multi-arch).

---

## 11. Next.js Standalone Images
**What:** `output: 'standalone'` produces `server.js` plus traced dependencies. The runtime image copies `.next/standalone`, `.next/static` and `public`.
**Why:** The image is much smaller than shipping `node_modules`. Without the static copies, CSS and JS 404.

```dockerfile
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER 1000:1000
CMD ["node", "server.js"]
```
**Rule:** Use standalone output, and set `HOSTNAME=0.0.0.0`. `NEXT_PUBLIC_*` values are baked in at build time, so pass them as build args deliberately, never secrets. With a read-only root filesystem, give `.next/cache` a tmpfs or a volume.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02, 03, 04, 05, 06, 08, 09 | Docker_Security, NodeJS_Docker |
| 07 | Docker_Security |
| 11 | NodeJS_Docker, Nextjs_Security |
