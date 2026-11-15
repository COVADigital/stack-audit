# Docker Host and Daemon — 6 Practices

> **Applies to:** Linux servers running Docker Engine (including Coolify-managed servers).  
> **Rule IDs:** section `NN` in this file is rule `host.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rules #0, #1, #5a, #10, #11), Docker Engine logging and security docs, Coolify installation docs. Written in our own words.

> **Agent directive:** Host checks run **on the server, by the user**, using `audit_host.py`. Never SSH anywhere yourself. Prepare the command for the user to run.

---

## 01. Keep the Engine and Kernel Updated
**What:** Current Docker Engine, containerd/runc, and host kernel security updates.
**Why:** Containers share the host kernel. Container escapes such as CVE-2024-21626 (runc) are fixed by updates, not by configuration (OWASP Docker #0).

**Rule:** Patch the host kernel and Docker Engine regularly (unattended-upgrades or a monthly window), and track the Engine version in the host report.

---

## 02. Never Expose the Daemon Over TCP Without TLS
**What:** `dockerd -H tcp://0.0.0.0:2375`, or `"hosts": ["tcp://…"]` in `daemon.json`.
**Why:** An unauthenticated TCP socket gives anyone who can reach it root on the host (OWASP Docker #1).

**Rule:** The daemon listens on the Unix socket only. Remote management goes over SSH (as Coolify does), or over mutual TLS if TCP is unavoidable.

---

## 03. Log Rotation
**What:** The default `json-file` driver has **no size limit** unless `max-size` is set. The `local` driver rotates by default (20 MB × 5).
**Why:** Unrotated logs fill the disk, and a full disk takes down the database and every other container.

```json
{ "log-driver": "local" }
```
or
```json
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```
**Rule:** Configure rotation in `/etc/docker/daemon.json`. `log-opts` values must be strings, and changes apply only to newly created containers. Coolify's installer configures daemon logging, so read the file before changing it.

---

## 04. Daemon Defaults
**What:** `"no-new-privileges": true`, `"live-restore": true`, `log-level` left at `info` (OWASP Docker #10).
**Why:** Secure defaults apply even to services that forget them. Live-restore keeps containers running across daemon upgrades.

**Rule:** Set `no-new-privileges` and `live-restore` in `daemon.json` where compatible, and don't run the daemon at `debug` log level in production.

---

## 05. Rootless Docker / userns-remap (Where Compatible)
**What:** Rootless mode runs the daemon and containers without host root. `userns-remap` maps container root to an unprivileged host uid, though the daemon itself still runs as root (OWASP Docker #11).
**Why:** It reduces the impact of a daemon or runtime compromise. It doesn't protect against kernel vulnerabilities.

**Rule:** Consider rootless mode for hosts that don't run a platform requiring rootful Docker. Check your platform's requirements before switching (Coolify manages the host over SSH with a rootful daemon).

---

## 06. Firewall vs Published Ports
**What:** Docker inserts iptables rules ahead of UFW.
**Why:** Host firewall rules don't protect published container ports (see `12-network-exposure.md` §02).

**Rule:** Audit published ports on the host (`docker ps --format '{{.Ports}}'`). Anything on `0.0.0.0` must be intended public (80/443 on the proxy). Otherwise bind it to localhost or block it with a Docker-aware firewall or the cloud firewall.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02, 03, 04, 05, 06 | Docker_Security |
