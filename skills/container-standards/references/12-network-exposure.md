# Network Exposure — 3 Practices

> **Applies to:** Docker Compose networks and published ports, single-host servers (including Coolify).  
> **Rule IDs:** section `NN` in this file is rule `cnet.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rules #5 and #5a), Docker networking and packet-filtering docs. Written in our own words.

---

## 01. Per-Stack Networks; Internal Backends
**What:** User-defined networks per stack, with databases and caches on a network marked `internal: true`.
**Why:** The default bridge lets every container talk to every other one. An internal network has no route out, so a compromised database can't phone home (OWASP Docker #5).

```yaml
services:
  db:  { networks: [backend] }
  app: { networks: [backend, edge] }
networks:
  backend: { internal: true }
  edge: {}
```
**Rule:** Databases and caches join only an `internal: true` network. Only the services that must reach the internet or the proxy join a non-internal one.

---

## 02. Bind Published Ports to Localhost
**What:** `ports: ["5432:5432"]` publishes on every interface.
**Why:** Docker writes its own iptables/nftables rules, which are evaluated before UFW. A UFW "deny 5432" doesn't stop the published port: **your database is on the internet** (OWASP Docker #5a).

```yaml
ports:
  - "127.0.0.1:5432:5432"   # reachable from the host only
```
**Rule:** Never publish database, cache or admin ports without a `127.0.0.1:` (or `::1`) host IP. If something must be reachable externally, publish it deliberately and firewall it with a Docker-aware tool (for example ufw-docker), or use the provider's cloud firewall.

---

## 03. Route Apps Through the Reverse Proxy
**What:** On a server with a reverse proxy (Traefik, Caddy, nginx, Coolify), apps are reached over the proxy's Docker network, so `expose:` is enough.
**Why:** Publishing the app port as well bypasses TLS, headers and rate limits, and makes "trust the proxy" settings (`X-Forwarded-For`) spoofable.

**Rule:** App services behind a proxy use `expose:` (or nothing), not `ports:`. If a port must be published for local testing, bind it to `127.0.0.1` in a separate override file.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01 | Docker_Security, Network_Segmentation |
| 02, 03 | Docker_Security |
