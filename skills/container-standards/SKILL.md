---
name: container-standards
description: Security and operations standards plus read-only audits for Dockerfiles, Docker images, Docker Compose stacks, volumes, networks, published ports, container secrets, and Docker hosts (including Coolify-managed servers). Based on the OWASP Docker Security cheat sheet plus build, data and ops practices. Use when writing or reviewing a Dockerfile or compose file, containerizing an app (including Next.js standalone images), adding a database, volume or network, exposing ports, handling container secrets, preparing a deploy, checking running containers, or hardening/auditing a Docker server. Not for Kubernetes clusters, and not for application code (web-standards) or OWASP questions in general (owasp-security).
allowed-tools: Bash(python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/*)
---

# Container Standards

> **Codex and other agents:** `${CLAUDE_PLUGIN_ROOT}` in the commands below is the plugin root, two folders above this SKILL.md (the session-start hook also prints it as "Plugin root"). Claude Code fills it in; elsewhere, substitute the absolute path. `<scratchpad>` is Claude Code's session scratchpad; elsewhere, use a temporary folder outside the repository (for example `$TMPDIR/stack-audit`).

Every **Rule** in `references/` is a requirement. Findings cite rule IDs such as `cnet.02` (section 02 of `12-network-exposure.md`). `references/rule-index.md` lists all 59 rules and how each one is checked.

| Prefix | Reference | Covers |
|---|---|---|
| `img` | 10-image-build.md | base pinning, non-root USER, ADD, curl\|sh, multi-stage, exec form, healthcheck, CRLF, Next.js standalone |
| `run` | 11-runtime-hardening.md | Docker socket, capabilities, privileged, no-new-privileges, host namespaces, limits, read-only, mounts |
| `cnet` | 12-network-exposure.md | internal networks, **ports published past UFW**, proxy routing |
| `csec` | 13-secrets.md | literal secrets, Compose secrets/`_FILE`, build secrets, ARG/ENV, copied key files, .dockerignore, database auth switched off |
| `host` | 14-host-daemon.md | engine/kernel updates, TCP socket, log rotation, daemon defaults, rootless, firewall |
| `sup` | 15-supply-chain.md | scanning, hadolint, SBOM/provenance, signing, base-image updates |
| `ops` | 16-data-ops.md | volumes, backups, healthchecks, restart, log rotation, `version:`, graceful shutdown |
| `cool` | 17-coolify.md | proxy routing, public databases, platform socket allow-list, env store, extra networks, build-time secrets, server updates and access, volume cleanup, log redaction, plus **live checks** (optional add-on) |

## 1. Audits (all read-only)

Run each script as **one command with this full path** (no `S=` variable, `cd`, `&&` or pipes), so it matches the skill's pre-approved commands and runs without a permission prompt.

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/run_audit.py --root <repo> --phase build --format json     # Dockerfiles + compose files (static)
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/run_audit.py --root <repo> --phase deploy                  # + running containers via docker inspect (local daemon)
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/audit_dockerfile.py --root <repo>                          # img.*, csec.03–06, sup.05
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/audit_compose.py    --root <repo> [--daemon-rotation]      # run.*, cnet.*, csec.01–03, csec.07, ops.*, cool.*
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/audit_runtime.py    [--all]                                # the same rules on real containers
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/scan_image.py --dockerfile <path> | --image <name:tag>     # hadolint / trivy / grype if installed
python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/audit_coolify.py --snapshot <file> [--project NAME]       # Coolify live checks from a snapshot (§4)
python3 audit_host.py                                                # ON THE LINUX SERVER, run by the user
```

- **Compose files are parsed directly.** The audit never runs `docker compose config` and never reads env or secret files, so no secret values are loaded. Keep it that way: report variable *names* only.
- **Dev/test Compose files** (`compose.dev.yaml`, `*.local.*`, `*.test.*`, `*.smoke.*`) get only the critical checks: socket, privileged, host paths, exposed ports, literal secrets.
- **Ask first** before `--image` (trivy/grype download a vulnerability database) and before `audit_runtime.py` against a server. For host checks, give the user the command to run on the server. Never SSH yourself.
- **Missing scanner (hadolint, trivy, grype).** The scripts never install anything; they report what is missing. When that happens, ask the user which they want: (1) run it once from the tool's official container image, with nothing installed (needs Docker; pin a version tag; scan a `docker save` tarball, or pass the Dockerfile on stdin, rather than mounting the Docker socket); (2) install it system-wide with their package manager, from the tool's official source; (3) skip it, and list the check under "Not checked". Confirm the exact command against the tool's official documentation, show it, and run it only after they choose.
- **Triage medium/low-confidence findings** by opening the file. Many hardening flags have legitimate exceptions, such as databases needing `CHOWN`/`SETUID` or platform containers holding the socket.
- Report findings grouped by severity: severity · `rule-id` · `file:line` · problem · fix. End with each report's "Not checked" list.

## 2. Writing or changing container files

- Start from `assets/`: `Dockerfile.nextjs-standalone`, `Dockerfile.node-service`, `dockerignore.node`, `compose.hardened.yaml`, `daemon.json`, `ci-container-scan.yml`. Adapt them to the repo, and never overwrite an existing file without showing the diff.
- Propose hardening **one service at a time**, and say what each flag may break. For example, `read_only` needs a tmpfs for `/tmp` and Next.js `.next/cache`, and `cap_drop: [ALL]` can break images that switch users at startup. Suggest testing in a non-production stack.
- Next.js images: `output: 'standalone'`, `HOSTNAME=0.0.0.0`, a non-root `USER`. `NEXT_PUBLIC_*` values are baked in at build time, so one image per environment, and never a secret. For caching across several replicas, see `web-standards/references/next16-cache-model.md` §5.

## 3. Safety

- **Never** run `docker compose down -v`, `docker volume rm`, `docker system prune`, `docker rm`, or anything that stops, recreates or deletes containers, images or volumes, unless the user explicitly asks for that exact action.
- Live scripts use only `docker ps`, `docker inspect`, `docker info` and `docker version`.
- For OWASP depth, use **owasp-security** (`Docker_Security`, `NodeJS_Docker`, `Secrets_Management`). Each reference ends with an OWASP mapping table.

## 4. Coolify add-on (optional)

Not everyone runs Coolify, so live Coolify checks are opt-in. When Coolify comes up, run `python ${CLAUDE_PLUGIN_ROOT}/skills/container-standards/scripts/coolify_addon.py status`. If `choice` is `null`, ask the user Yes/No whether they want the add-on (AskUserQuestion in Claude Code; a numbered question in chat in Codex), and save the answer with `coolify_addon.py set yes|no`. Never ask again after "no". On "yes", follow `17-coolify.md` "Live checks" exactly: check whether Claude Code and Codex CLI already have the `coolify` MCP server, install it where missing (`coolify_addon.py install --url <coolify-url> --client claude|codex|both`), store the token (`coolify_addon.py set-token`), verify, and collect snapshots.

- **Strictly read-only.** Use only the read tools in the recipe. Never call `control`, `deploy`, `rollback_application`, `create_*`, `manage_*`, `docker_cleanup`, `get_env_values` or `get_logs` for an audit.
- **Token handling.** Recommend the hidden `set-token` prompt in the user's own terminal. If they choose to paste the token in the chat, warn that it enters the transcript, pass it to `set-token` on stdin only, and never repeat or store it elsewhere. Client configs hold only the `COOLIFY_TOKEN` variable name.
- **Ask which projects to audit** (multi-select) before reading any resource, and keep the snapshot in `<scratchpad>`, never in a repository.

## 5. Checks worth keeping

When you run a check of your own that isn't one of this plugin's rules and is likely to be needed again (a search for a project-specific mistake, a regression you just fixed), ask the user what to do with it before you finish:

1. **Keep it one-off.** Nothing is saved.
2. **Save it as a test in the project's existing test suite.** Suggest this first: it runs on every change and in CI, so the problem is caught again without anyone remembering it.
3. **Save it as a standalone script** in a folder they choose, for checks that don't fit a test.

Never save anything without asking, never add a test framework the project doesn't have, and show the file before writing it.
