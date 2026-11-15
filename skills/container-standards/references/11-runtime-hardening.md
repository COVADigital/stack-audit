# Runtime Hardening — 9 Practices

> **Applies to:** Docker Compose (v2/v5) services and `docker run` flags.  
> **Rule IDs:** section `NN` in this file is rule `run.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rules #1, #3, #4, #6, #7, #8), Docker Compose specification and trust-model docs. Written in our own words.

> **Agent directive:** Hardening flags can break images. Propose them per service, explain what each one might break, and suggest testing in a non-production stack first.

---

## 01. Never Mount the Docker Socket
**What:** `/var/run/docker.sock:/var/run/docker.sock` in a service's volumes.
**Why:** Whoever can talk to the socket controls the host as root. Mounting it read-only doesn't make the API read-only (OWASP Docker #1).

**Rule:** No application service mounts the Docker socket. Platform containers that need it by design (Coolify, its Traefik proxy) are the only exceptions, and are allow-listed explicitly.

---

## 02. Drop All Capabilities
**What:** `cap_drop: [ALL]`, then `cap_add` only what the process proves it needs.
**Why:** Docker's default capability set is broader than most web processes need (OWASP Docker #3).

```yaml
cap_drop: [ALL]
# cap_add: [NET_BIND_SERVICE]   # only if binding <1024 as non-root
```
**Rule:** Stateless app services drop all capabilities. Databases and images that switch users in their entrypoint may need `CHOWN`/`SETUID`/`SETGID`, so add those back explicitly and test.

---

## 03. Never Privileged; No Dangerous Capabilities
**What:** `privileged: true`, `cap_add: [SYS_ADMIN | NET_ADMIN | SYS_PTRACE | ALL]`, `devices:`.
**Why:** Privileged mode removes almost every isolation boundary.

**Rule:** Never use `privileged: true` for application services. Each dangerous capability needs a documented reason.

---

## 04. no-new-privileges
**What:** `security_opt: ["no-new-privileges:true"]`.
**Why:** It stops setuid/setgid binaries from raising privileges inside the container (OWASP Docker #4).

**Rule:** Set it on every service, or as a daemon default (`"no-new-privileges": true` in `daemon.json`).

---

## 05. Keep Default Security Profiles; No Host Namespaces
**What:** `seccomp:unconfined`, `apparmor:unconfined`, `label:disable`, `network_mode: host`, `pid: host`, `ipc: host`.
**Why:** These turn off the kernel-level guards and share host namespaces (OWASP Docker #6).

**Rule:** Never disable seccomp, AppArmor or SELinux, and never share host namespaces for application services.

---

## 06. Resource Limits
**What:** Memory, CPU and process-count limits: `mem_limit` / `deploy.resources.limits.memory`, `cpus`, `pids_limit`.
**Why:** One leaking or attacked container shouldn't take down the host (OWASP Docker #7).

**Rule:** Every long-running service has a memory limit and a PID limit. Size them from measurements, and set `memswap_limit` equal to `mem_limit` to make OOMs visible.

---

## 07. Read-Only Root Filesystem
**What:** `read_only: true`, plus `tmpfs:` for the paths the process legitimately writes.
**Why:** An attacker who gets code execution can't drop tools or persist changes in the image filesystem (OWASP Docker #8).

```yaml
read_only: true
tmpfs:
  - /tmp:size=64m,mode=0700
  - /app/.next/cache:size=64m,uid=1000,gid=1000   # Next.js standalone writes here
```
**Rule:** Stateless services run read-only, with tmpfs for scratch paths. Next.js needs `.next/cache` writable.

---

## 08. Safe Mounts
**What:** Bind mounts of host system paths (`/`, `/etc`, `/root`, `/home`, `/var/run`, `/proc`, `/sys`), and writable mounts that only need reads.
**Why:** A container that can write host paths can take over the host.

**Rule:** Never bind-mount host system paths into application services. Mount config files `:ro`, and prefer named volumes over bind mounts for data.

---

## 09. Don't Override the Image User to Root
**What:** `user: root` / `user: "0"` in Compose for an image that already runs non-root.
**Why:** It undoes the image's `USER` (OWASP Docker #2).

**Rule:** Leave the image's non-root user in place. Override `user:` only to another non-root uid.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02, 03, 04, 05, 06, 07, 08, 09 | Docker_Security |
