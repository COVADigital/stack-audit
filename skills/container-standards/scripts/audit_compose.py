#!/usr/bin/env python3
"""Docker Compose audit (run.*, cnet.*, csec.01-03, ops.*, cool.*, img.01). Read-only, static.

Parses compose files itself: never runs `docker compose config` and never reads env
or secret files, so no secret values are loaded. Reports variable names only.

    python audit_compose.py --root REPO [--daemon-rotation] [--format md|json|sarif] [--strict]
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.containers import (COMPOSE_RE, COOLIFY_HINT, DEV_FILE, HOST_SYSTEM_PATHS, classify, env_items, is_interpolated,
                              is_secret_name, parse_port)
from wclib.dockerfile import image_parts, parse as parse_dockerfile
from wclib.walker import repo_paths
from wclib.yamlish import YamlError, load

DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "ALL", "BPF", "PERFMON"}
ONE_SHOT = re.compile(r"migrat|seed|setup|init|bootstrap|backup|restore|job|task|cron|once", re.I)


class ComposeAudit(Audit):
    tool = "audit_compose"
    prefix = "run"
    exts: set[str] = set()

    @classmethod
    def add_arguments(cls, parser) -> None:
        parser.add_argument("--daemon-rotation", action="store_true",
                            help="Daemon-level log rotation is configured (suppresses per-service ops.05)")

    def compose_files(self) -> list[tuple[str, str]]:
        seen, out = set(), []
        for base in repo_paths(self.root):
            for p in sorted(base.glob("*.y*ml")) + sorted(base.glob("*/*.y*ml")):
                rel = p.relative_to(self.root).as_posix() if base == self.root else p.relative_to(base).as_posix()
                if COMPOSE_RE.search(p.name) and p.resolve() not in seen and "node_modules" not in p.parts:
                    seen.add(p.resolve())
                    out.append((rel, p.read_text(encoding="utf-8", errors="replace")))
        return out

    def file_add(self, rel, lines, path, rule, msg, **kw):
        line = None
        for k in range(len(path), 0, -1):
            line = lines.get(tuple(path[:k]))
            if line:
                break
        self.add(rule, msg, file=rel, line=line, **kw)

    def check_file(self, rel: str, text: str) -> None:
        try:
            data, lines = load(text)
        except YamlError as exc:
            self.report.skipped.append(f"{rel}: could not parse ({exc})")
            return
        if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
            return
        is_dev = bool(DEV_FILE.search(PurePosixPath(rel).name))
        coolify = bool(COOLIFY_HINT.search(text))
        has_proxy = coolify or "traefik." in text or any(classify(n, (s or {}).get("image")) == "proxy" for n, s in data["services"].items())
        allow = set(self.ctx.config.get("containers", {}).get("platformAllowlist", []))
        networks = data.get("networks") or {}
        add = lambda path, rule, msg, **kw: self.file_add(rel, lines, path, rule, msg, **kw)  # noqa: E731

        if "version" in data:
            add(("version",), "ops.06", "Top-level `version:` is obsolete (Compose v2/v5 ignores it)")
        no_rotation = []
        for name, svc in data["services"].items():
            svc = svc or {}
            sp = ("services", name)
            image = svc.get("image") if isinstance(svc.get("image"), str) else None
            kind = classify(name, image)
            # Partial services in override files, and dev/test stacks, get only the critical checks
            # (socket, privileged, host paths, exposed ports, literal secrets), not production hardening.
            override_only = (not image and "build" not in svc) or is_dev
            one_shot = svc.get("restart") in ("no", False, '"no"') or bool(ONE_SHOT.search(name)) and svc.get("restart") in (None, "no", False)
            platform = name in allow or (svc.get("container_name") in allow)

            # img.01 image pinning
            if image and not is_interpolated(image):
                _, tag, digest = image_parts(image)
                if (not tag and not digest) or tag == "latest":
                    add(sp + ("image",), "img.01", f"`{name}` image `{image}` is unpinned", severity="warn",
                        fix_hint="Pin a version tag (and digest for production)")
                elif kind == "db" and not digest and not is_dev:
                    add(sp + ("image",), "img.01", f"`{name}` database image is tag-pinned but not digest-pinned", severity="info")
            # run.01 socket
            for vi, vol in enumerate(svc.get("volumes") or []):
                src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":")[0]
                if "docker.sock" in str(vol):
                    if platform:
                        add(sp + ("volumes", vi), "cool.03", f"Platform container `{name}` mounts the Docker socket (expected, allow-listed)")
                    else:
                        add(sp + ("volumes", vi), "run.01", f"`{name}` mounts the Docker socket: root-equivalent access to the host",
                            fix_hint="Remove it; only allow-listed platform containers may hold the socket")
                    continue
                # run.08 host system paths / ops.01 db storage
                target = vol.get("target", "") if isinstance(vol, dict) else (str(vol).split(":")[1] if ":" in str(vol) else str(vol))
                if src.startswith(("/", "C:", "c:")) and HOST_SYSTEM_PATHS.match(src.rstrip("/") or "/"):
                    add(sp + ("volumes", vi), "run.08", f"`{name}` bind-mounts host system path `{src}`")
                elif src.startswith((".", "/")) and re.search(r"\.(conf|ya?ml|json|toml|ini|cfg|sh)$", src) and ":ro" not in str(vol) \
                        and not (isinstance(vol, dict) and vol.get("read_only")):
                    add(sp + ("volumes", vi), "run.08", f"`{name}` mounts config file `{src}` writable (add :ro)", severity="info")
            if kind == "db" and not override_only:
                vols = svc.get("volumes") or []
                data_vol = [v for v in vols if not isinstance(v, dict) and ":" in str(v) and re.search(r"/data|/var/lib|/bitnami", str(v).split(":", 1)[1])]
                named = [v for v in data_vol if not str(v).startswith((".", "/", "~", "C:"))]
                if not vols:
                    add(sp, "ops.01", f"Database `{name}` has no volume: data is lost when the container is recreated",
                        fix_hint="volumes: [pgdata:/var/lib/postgresql/data] + top-level volumes: { pgdata: }")
                elif data_vol and not named:
                    add(sp + ("volumes",), "ops.01", f"Database `{name}` stores data on a bind mount (permissions/portability issues)", severity="info")
            # run.02 / run.03 capabilities
            caps_drop = [str(c).upper() for c in (svc.get("cap_drop") or [])]
            caps_add = [str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])]
            if svc.get("privileged") is True:
                add(sp + ("privileged",), "run.03", f"`{name}` runs privileged (almost no isolation)")
            bad = sorted(set(caps_add) & DANGEROUS_CAPS)
            if bad:
                add(sp + ("cap_add",), "run.03", f"`{name}` adds dangerous capabilities: {', '.join(bad)}")
            if svc.get("devices"):
                add(sp + ("devices",), "run.03", f"`{name}` maps host devices", severity="warn")
            if not override_only and kind in ("app", "admin") and "ALL" not in caps_drop and not platform:
                add(sp, "run.02", f"`{name}` keeps Docker's default capabilities (add cap_drop: [ALL])")
            # run.04 / run.05
            sec = [str(s) for s in (svc.get("security_opt") or [])]
            if not override_only and not platform and not any(re.search(r"no-new-privileges(:true|=true)?$", s) for s in sec):
                add(sp, "run.04", f"`{name}` lacks security_opt no-new-privileges:true", confidence="medium",
                    fix_hint='security_opt: ["no-new-privileges:true"] (or set it as a daemon default)')
            for s in sec:
                if re.search(r"(seccomp|apparmor)[:=]unconfined|label[:=]disable", s):
                    add(sp + ("security_opt",), "run.05", f"`{name}` disables a kernel security profile ({s})")
            for key in ("network_mode", "pid", "ipc", "userns_mode", "uts"):
                if str(svc.get(key, "")).lower() == "host":
                    add(sp + (key,), "run.05", f"`{name}` shares the host {key.replace('_mode', '')} namespace")
            # run.06 limits
            limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
            if not override_only and not one_shot and not platform:
                if not (svc.get("mem_limit") or limits.get("memory")):
                    add(sp, "run.06", f"`{name}` has no memory limit", fix_hint="mem_limit (or deploy.resources.limits.memory) sized from measurements")
                if not (svc.get("pids_limit") or limits.get("pids")):
                    add(sp, "run.06", f"`{name}` has no PID limit", severity="info")
            # run.07 read-only
            if not override_only and kind == "app" and not platform:
                if svc.get("read_only") is not True:
                    add(sp, "run.07", f"`{name}` root filesystem is writable (read_only: true + tmpfs for scratch paths)")
                elif self.is_next_service(svc, rel) and ".next/cache" not in str(svc.get("tmpfs", "")) + str(svc.get("volumes", "")):
                    add(sp, "run.07", f"`{name}` is read-only but `.next/cache` has no tmpfs/volume (Next.js writes there)",
                        severity="warn")
            # run.09 user override
            if str(svc.get("user", "")).split(":")[0] in ("root", "0"):
                add(sp + ("user",), "run.09", f"`{name}` overrides the image user to root")
            # cnet.02 / cnet.03 / cool.01 ports
            for pi, entry in enumerate(svc.get("ports") or []):
                pub = parse_port(entry)
                if not pub or not pub.all_interfaces:
                    continue
                pp = sp + ("ports", pi)
                if kind in ("db", "admin"):
                    add(pp, "cnet.02", f"`{name}` publishes {pub.raw} on ALL interfaces: Docker bypasses UFW, so this is internet-reachable",
                        fix_hint=f"\"127.0.0.1:{pub.host_port or pub.container_port}:{pub.container_port}\" or remove the published port")
                elif kind == "app" and has_proxy:
                    rule = "cool.01" if coolify else "cnet.03"
                    add(pp, rule, f"`{name}` publishes {pub.raw} although a reverse proxy routes traffic (bypasses TLS/headers/rate limits)",
                        fix_hint="Use expose: and let the proxy route; publish only on 127.0.0.1 in an override for local testing")
                elif not is_dev and str(pub.host_port) not in ("80", "443"):
                    add(pp, "cnet.02", f"`{name}` publishes {pub.raw} on ALL interfaces: Docker bypasses UFW, so this is internet-reachable",
                        severity="warn", fix_hint=f"Bind \"127.0.0.1:{pub.host_port or pub.container_port}:{pub.container_port}\" "
                                                  "behind a host proxy, or route it through a proxy container")
            # cnet.01 internal networks for data services
            if kind == "db" and not override_only:
                svc_nets = svc.get("networks") or []
                names = list(svc_nets) if isinstance(svc_nets, (list, dict)) else []
                if not names or not any(isinstance(networks.get(n), dict) and networks[n].get("internal") for n in names):
                    add(sp, "cnet.01", f"Database `{name}` is not on an internal-only network", fix_hint="networks: { backend: { internal: true } }")
            # csec.01 / csec.02 environment
            for k, v in env_items(svc.get("environment")):
                if v in (None, "") or is_interpolated(v) or not is_secret_name(k):
                    continue
                if isinstance(v, str) and v.startswith("/run/secrets/"):
                    continue
                if is_dev:
                    add(sp + ("environment", k), "csec.01", f"`{name}` sets literal `{k}` in a dev/test compose file (OK only if local-only)",
                        severity="info")
                else:
                    add(sp + ("environment", k), "csec.01", f"`{name}` has a literal secret value for `{k}` (value not shown)",
                        fix_hint="Use ${VAR:?} from an untracked env file / platform secret store, or Compose secrets")
            env_names = {k for k, _ in env_items(svc.get("environment"))}
            if kind == "db" and not override_only and any(n in env_names for n in ("POSTGRES_PASSWORD", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", "MARIADB_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD")) \
                    and not is_dev:
                add(sp + ("environment",), "csec.02", f"`{name}` takes its password from an env var (consider secrets + *_FILE)")
            for ef in ([svc["env_file"]] if isinstance(svc.get("env_file"), (str, dict)) else svc.get("env_file") or []):
                path = ef.get("path") if isinstance(ef, dict) else str(ef)
                base = PurePosixPath(rel).parent
                cand = str(base / path) if str(base) != "." else path
                if path and self.ctx.walker.git and self.ctx.walker.tracked(cand.lstrip("./")) and not path.endswith((".example", ".sample")):
                    add(sp + ("env_file",), "csec.01", f"`{name}` env_file `{path}` is tracked by git")
            # csec.03 build args
            build = svc.get("build") if isinstance(svc.get("build"), dict) else {}
            for k, _v in env_items(build.get("args")):
                if is_secret_name(k):
                    add(sp + ("build", "args"), "csec.03", f"`{name}` passes `{k}` as a build arg (recorded in image history)",
                        fix_hint="build.secrets + RUN --mount=type=secret")
            # ops.03 healthchecks + depends_on
            if not override_only and not one_shot and not platform:
                hc = svc.get("healthcheck")
                if not hc or (isinstance(hc, dict) and hc.get("disable")):
                    if not self.image_has_healthcheck(svc, rel):
                        add(sp, "ops.03", f"`{name}` has no healthcheck")
            dep = svc.get("depends_on")
            if isinstance(dep, list):
                db_deps = [d for d in dep if classify(d, (data["services"].get(d) or {}).get("image")) == "db"]
                if db_deps:
                    add(sp + ("depends_on",), "ops.03", f"`{name}` depends on {', '.join(db_deps)} without condition: service_healthy",
                        fix_hint="depends_on: { db: { condition: service_healthy } }")
            # ops.04 restart
            if not override_only and not platform:
                if svc.get("restart") is None and not one_shot:
                    add(sp, "ops.04", f"`{name}` has no restart policy (doesn't come back after a reboot)")
                elif one_shot and svc.get("restart") in ("always", "unless-stopped"):
                    add(sp + ("restart",), "ops.04", f"One-shot `{name}` restarts forever")
            # ops.05 logging
            log = svc.get("logging") or {}
            if not override_only and not (log.get("driver") in ("local", "journald", "syslog", "fluentd", "gelf", "awslogs", "loki")
                                          or (log.get("options") or {}).get("max-size")):
                no_rotation.append(name)
            # ops.07 grace period
            if kind == "db" and not override_only:
                g = str(svc.get("stop_grace_period", ""))
                m = re.match(r"(\d+)(s|m)?$", g)
                secs = (int(m.group(1)) * (60 if m.group(2) == "m" else 1)) if m else 0
                if secs < 30:
                    add(sp, "ops.07", f"Database `{name}` stop_grace_period is {g or 'default 10s'} (use ≥30s)")
        if no_rotation and not self.args.daemon_rotation and not is_dev:
            sev = "info" if coolify else "warn"
            add(("services",), "ops.05", f"No per-service log rotation for: {', '.join(no_rotation)} (json-file grows without limit unless the daemon rotates)",
                severity=sev, confidence="medium",
                fix_hint="logging: { driver: local } per service, or log-driver/log-opts in daemon.json (then pass --daemon-rotation)")
        if coolify:
            self.report.meta.setdefault("coolify_files", []).append(rel)

    def is_next_service(self, svc: dict, rel: str) -> bool:
        b = svc.get("build")
        ctx = b if isinstance(b, str) else (b or {}).get("context") if isinstance(b, dict) else None
        if not ctx:
            return "next" in str(svc.get("image", "")).lower()
        base = (self.root / PurePosixPath(rel).parent / ctx)
        pkg = base / "package.json"
        return pkg.exists() and '"next"' in pkg.read_text(encoding="utf-8", errors="replace")

    def image_has_healthcheck(self, svc: dict, rel: str) -> bool:
        b = svc.get("build")
        if not b:
            return False
        ctx = b if isinstance(b, str) else b.get("context", ".")
        dfile = (b.get("dockerfile") if isinstance(b, dict) else None) or "Dockerfile"
        p = self.root / PurePosixPath(rel).parent / ctx / dfile
        if not p.exists():
            return False
        df = parse_dockerfile(p.read_text(encoding="utf-8", errors="replace"))
        return bool(df.stages and df.find("HEALTHCHECK", df.final_stage.index))

    def run(self) -> None:
        files = self.compose_files()
        if not files:
            self.report.skipped.append("No compose files found")
        for rel, text in files:
            self.check_file(rel, text)
        self.report.meta["compose_files"] = [r for r, _ in files]
        for p in ("run", "cnet", "ops", "cool"):
            self.report.not_checked += self.rb.not_checked(p)
        self.report.not_checked.append("Effective config on the server (Coolify UI settings, extra networks): run audit_runtime.py there")


if __name__ == "__main__":
    run_main(ComposeAudit, __file__, __doc__)
