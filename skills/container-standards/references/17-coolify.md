# Coolify — 5 Practices

> **Applies to:** Stacks deployed through Coolify (self-hosted or Cloud) with its Traefik proxy.  
> **Rule IDs:** section `NN` in this file is rule `cool.NN` in audit findings.  
> **Sources:** Coolify documentation (Traefik proxy overview, database "Make it publicly available" option, scheduled backups, installation requirements), verified 2026-11-13. Written in our own words.

---

## 01. Expose Apps Through the Proxy
**What:** Coolify runs `coolify-proxy` (Traefik) on ports 80/443 and routes each resource's domain to its container over Docker networks.
**Why:** A published app port bypasses TLS, headers and rate limits, and opens the app to the internet past UFW (see `12-network-exposure.md` §02).

**Rule:** Give apps a domain in Coolify and let Traefik route to the container port (`expose:`). Don't publish app ports with `ports:`.

---

## 02. Keep Databases Private
**What:** Coolify's database setting **"Make it publicly available"** with a public port.
**Why:** Coolify's own docs say to keep databases private by default, and to firewall the public port and use encryption when exposure is truly needed.

**Rule:** Leave databases private. If external access is needed, restrict the port with the server or provider firewall to known IPs, require TLS, and use a dedicated credential. This is a UI setting, so verify it in Coolify; it can't be seen in the repo.

---

## 03. Platform Containers That Hold the Docker Socket
**What:** Coolify's own containers (`coolify`, `coolify-proxy`, and related services) need Docker API access to manage the server.
**Why:** That's expected for the platform, but no *application* container should have the same access (see `11-runtime-hardening.md` §01).

**Rule:** Socket mounts are allow-listed only for Coolify's platform containers (configurable as `containers.platformAllowlist`). Report socket mounts anywhere else.

---

## 04. Secrets in Coolify's Environment Store
**What:** Coolify stores environment variables per resource and can generate `SERVICE_PASSWORD_*` / `SERVICE_BASE64_*` values.
**Why:** It keeps secrets out of the repository.

**Rule:** Reference secrets as `${VAR:?}` in Compose and keep their values in Coolify. Avoid putting messages after `:?`, since Coolify may store that text as the initial value. Never commit `.env` files.

---

## 05. Coolify Networks vs Declared Isolation
**What:** Coolify attaches its own resource network to a stack's services.
**Why:** A database declared on an `internal: true` network can still gain outbound access through the extra network, and environment variables may reach services that don't use them.

**Rule:** Document the deviation in the Compose file or an ADR, and verify actual container networks on the server (`audit_runtime.py` / `docker inspect`) instead of trusting the file.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 03 | Docker_Security |
| 04 | Secrets_Management |
