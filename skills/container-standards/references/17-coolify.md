# Coolify — 11 Practices

> **Applies to:** Stacks deployed through Coolify (self-hosted or Cloud) with its Traefik proxy.  
> **Rule IDs:** section `NN` in this file is rule `cool.NN` in audit findings.  
> **Sources:** Coolify documentation (Traefik proxy overview, database "Make it publicly available" option, scheduled backups, installation requirements), verified 2026-11-13; Coolify MCP connector read tools (Coolify 4.7.5), checked 2026-11-15. Written in our own words.  
> **Live checks:** rules 02 and 06–11 need a snapshot from the optional Coolify add-on (see "Live checks" below).

---

## 01. Expose Apps Through the Proxy
**What:** Coolify runs `coolify-proxy` (Traefik) on ports 80/443 and routes each resource's domain to its container over Docker networks.
**Why:** A published app port bypasses TLS, headers and rate limits, and opens the app to the internet past UFW (see `12-network-exposure.md` §02).

**Rule:** Give apps a domain in Coolify and let Traefik route to the container port (`expose:`). Don't publish app ports with `ports:`.

---

## 02. Keep Databases Private
**What:** Coolify's database setting **"Make it publicly available"** with a public port.
**Why:** Coolify's own docs say to keep databases private by default, and to firewall the public port and use encryption when exposure is truly needed.

**Rule:** Leave databases private. If external access is needed, restrict the port with the server or provider firewall to known IPs, require TLS, and use a dedicated credential. This is a UI setting that can't be seen in the repo. The live check reads `is_public` / `public_port` for standalone databases and for databases inside service stacks.

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

## 06. Secrets Are Runtime-Only
**What:** Each Coolify environment variable has "Available at Buildtime" and "Available at Runtime" switches.
**Why:** Build-time variables are passed to the image build as build arguments, so a secret can end up in the image history or a build layer (see `13-secrets.md` §04).

**Rule:** For apps that Coolify builds (Nixpacks, Dockerfile, Compose with a build, static), keep secret variables runtime-only unless the build really needs them, and then use a build secret instead.

---

## 07. Automatic Security Updates
**What:** Coolify can install OS security updates on a server on a schedule.
**Why:** A server that waits for someone to remember updates stays exposed for days or weeks after a fix ships (see `14-host-daemon.md` §01).

**Rule:** Turn on automatic security updates for each server, or document the patch routine that replaces them. Reboot when the installed kernel is newer than the running one.

---

## 08. Server Access Hardening
**What:** Coolify reaches servers over SSH and offers a web terminal into servers and containers.
**Why:** Without host key checking, a spoofed server can capture the connection. The web terminal turns a Coolify login into a root shell. A root SSH user gives Coolify's key full control of the host.

**Rule:** Keep SSH host key checking on. Turn the web terminal off unless the team uses it. Prefer a non-root user with sudo where Coolify supports it for the server type.

---

## 09. Don't Auto-Delete Volumes
**What:** Coolify's scheduled Docker cleanup can delete unused volumes.
**Why:** A volume counts as "unused" whenever its stack is stopped or being recreated, so a cleanup at the wrong moment deletes database data.

**Rule:** Leave "delete unused volumes" off on servers that hold data. Remove old volumes by hand after a backup.

---

## 10. Redact Env Values in Logs
**What:** Service stacks have a setting that masks environment variable values in Coolify's logs.
**Why:** Deploy and container logs are shown in the UI and sent to log drains, and an unmasked secret in a log is a leaked secret.

**Rule:** Keep "redact all env values in logs" on for every service stack.

---

## 11. One Volume per Mount Path
**What:** A resource where two persistent volumes point at the same path inside one container.
**Why:** Only one of them holds the live data. The other is usually left over from a migration or template change, and it confuses backups and restores.

**Rule:** Confirm which volume holds the data, back it up, and remove the stale volume record. This is a heuristic: check in Coolify before deleting anything.

---

## Live checks (optional Coolify add-on)

Not everyone runs Coolify, so the live checks are an opt-in add-on. The static rules above always run on Compose files.

### Opt in once

1. When Coolify comes up (the user mentions it, a Compose file uses `SERVICE_FQDN_*` / `SERVICE_PASSWORD_*`, or `audit_compose.py` reports `coolify_files`), run `scripts/coolify_addon.py status`. It returns the saved `choice`, whether `COOLIFY_TOKEN` is set, and for `claude` and `codex` whether the CLI exists (`cli`) and already has an MCP server named `coolify` (`server`).
2. If `choice` is `null`, ask the user with AskUserQuestion (Yes / No): *"Add the stack-audit Coolify add-on? It connects your Coolify server's MCP endpoint to Claude Code (and Codex CLI if you use it) with a read-only API token, so audits can check the live server: public databases, backups, pending updates, image scans and app settings."* Save the answer with `coolify_addon.py set yes|no`. After "no", don't ask again. The user can say "turn on the Coolify add-on" later.
3. If `choice` is `yes` and a CLI that exists has `server: false` (and no Coolify MCP tools are loaded in this session), set it up:
   - Ask which clients to configure with AskUserQuestion (multi-select), listing only the CLIs that exist and lack the server: **Claude Code**, **Codex CLI**.
   - Ask for the Coolify URL (the address of the Coolify dashboard).
   - Run `coolify_addon.py install --url <url> --client claude|codex|both`. Claude Code gets a user-scope server whose header is `Bearer ${COOLIFY_TOKEN}`, and Codex gets `--bearer-token-env-var COOLIFY_TOKEN`. Neither config stores the token, and an existing `coolify` server is left unchanged.
4. Token: tell the user to create an API token in Coolify (**Keys & Tokens → API tokens**) with only the **read** permission (add **read:sensitive** only if they want docker run options checked), never write, deploy or root. Then ask with AskUserQuestion how they want to provide it:
   - **Hidden prompt in my terminal (recommended).** They run `python <plugin>/skills/container-standards/scripts/coolify_addon.py set-token` in their own terminal and paste the token at the hidden prompt. It never enters the conversation.
   - **Paste it here.** They paste it into the "Other" field. Say first that the token then becomes part of this conversation's transcript. Pass it on stdin only, never as an argument: `python <plugin>/.../coolify_addon.py set-token` with the token as a heredoc on stdin. Never repeat, log or write the token anywhere else.
   - **I'll set `COOLIFY_TOKEN` myself.**

   `set-token` stores `COOLIFY_TOKEN` as a user environment variable (Windows: user environment in the registry; macOS/Linux: `~/.config/stack-audit/coolify.env`, mode 0600, sourced from `~/.zshrc` or `~/.bashrc`). It then checks that Claude Code connects, without printing the config.
5. Tell them to restart Claude Code and Codex from a new terminal, then check `/mcp`. `coolify_addon.py verify` re-checks the connection. If it fails, check the URL, the token, and that the API is enabled in Coolify's settings.

### Collect a snapshot (read tools only)

Never call `control`, `deploy`, `cancel_deployment`, `rollback_application`, any `create_*` or `manage_*` tool, `docker_cleanup`, `get_env_values` or `get_logs` for an audit.

1. `get_infrastructure_overview`. Ask the user with AskUserQuestion (multi-select) which projects to audit. A question holds 4 options and a prompt holds 4 questions: up to 4 projects fit in one question, and up to 16 are split across questions. Beyond that, offer "All projects" plus the largest projects, with "Other" for typed names. Pre-select nothing, and read only the chosen projects.
2. For each server: `get_server`, keep `data`.
3. For each chosen project, list its resources (`list_applications` / `list_services` / `list_databases` with `project_uuid`), then per resource:
   - application: `get_application`, `list_env_keys`, `list_storages`;
   - service: `get_service`, `list_service_applications` + `get_service_application`, `list_service_databases` + `get_service_database`, `list_env_keys`, `list_storages`;
   - standalone database: `get_database`, `list_env_keys`, `list_storages`, `list_database_backups`, and for each schedule the first page of `list_backup_executions`, newest first.
4. `get_vulnerabilities` with `action: list`, and copy each resource's `security` object onto it.
5. Write the snapshot to the session scratchpad (never into a repository) and run `scripts/audit_coolify.py --snapshot <file>`.

Snapshot shape (`snapshot_version` 1):

```json
{
  "snapshot_version": 1, "collected_at": "2026-11-15T20:00:00Z", "coolify_version": "4.7.5",
  "projects": ["Shop"], "read_sensitive": false,
  "servers": [{"name": "main", "user": "root", "settings": {"is_image_scan_enabled": true}}],
  "applications": [{"name": "web", "project": "Shop", "build_pack": "dockerfile",
                    "env_keys": [{"key": "DATABASE_URL", "is_buildtime": false, "is_preview": false}],
                    "storages": [{"name": "web-data", "mount_path": "/data", "owner": "application:1"}],
                    "security": {"status": "ok"}}],
  "services": [{"name": "n8n", "project": "Shop", "redact_all_env_values_in_logs": true,
                "applications": [{"name": "n8n", "image": "n8nio/n8n:1.80.0", "ports": ""}],
                "databases": [{"name": "postgresql", "image": "postgres:17-alpine", "is_public": false}],
                "env_keys": [], "storages": [], "security": {}}],
  "databases": [{"name": "shop-db", "project": "Shop", "is_public": false, "image": "postgres:17",
                 "backups": [{"enabled": true, "save_s3": true, "executions": [{"status": "success", "created_at": "2026-11-15"}]}],
                 "env_keys": [], "storages": [], "security": {}}]
}
```

Save `get_*` data as returned, with these exceptions. Never save env values, `get_env_values` output, commands (`*_command`, scheduled task commands), raw Compose files, Dockerfiles, custom labels or nginx configuration, or database URLs. The audit refuses a snapshot with secret-shaped fields. With **read:sensitive**, keep `custom_docker_run_options` on the application and set `read_sensitive: true`. The audit only matches flags (`--privileged`, `--cap-add`, Docker socket mounts, host namespaces) and never prints the options.

What the live checks add: `cool.01` (published ports), `cool.02` (public databases), `cool.06`–`cool.11`, `host.01` (pending security updates, reboot needed, Docker packages), `sup.01` (scanning off, vulnerable images), `ops.02` (standalone database backup schedules, failed or missing runs, local-only backups), `ops.03` (healthcheck off), `run.06` (no limits), `img.01` (untagged images), and `run.01`/`run.03`/`run.05` from docker run options. Coolify has no backup API for databases inside service stacks, so those stay manual.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 03 | Docker_Security |
| 04, 06 | Secrets_Management |
| 06, 07, 08 | Docker_Security |
| 10 | Logging |
