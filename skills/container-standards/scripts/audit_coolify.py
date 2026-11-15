#!/usr/bin/env python3
"""Audit a Coolify snapshot (cool.*, plus live evidence for host.01, sup.01, ops.02/03, run.*, img.01). Read-only.

    python audit_coolify.py --snapshot FILE [--project NAME ...] [--format md|json|sarif] [--strict]

The snapshot is a JSON file Claude writes from the Coolify MCP connector's read tools
(recipe: references/17-coolify.md, "Live checks"). This script never touches the network
or Coolify. It refuses a snapshot that holds secret-shaped fields, and reports never
quote env values, commands or docker run options.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.containers import is_secret_name
from wclib.findings import Report
from wclib.rules import RuleBook

SKILL = Path(__file__).resolve().parents[1]
SNAPSHOT_VERSION = 1

# Keys that hold secrets or free text that can embed them. The recipe never saves these.
FORBIDDEN_KEY = re.compile(
    r"(^|_)(value|password|passwd|secret|private_key|api_key|credentials?)(_|$)|(^|_)token$|_db_url$"
    r"|^command$|_command$|^(docker_compose_raw|docker_compose|dockerfile|custom_labels|custom_nginx_configuration)$",
    re.I)
URL_CREDENTIALS = re.compile(r"://[^/\s:@]+:[^@\s/]+@")
BUILDS = {"nixpacks", "dockerfile", "dockercompose", "static", "railpack"}  # build packs that run a build
DOCKER_FLAGS = (  # (pattern on custom_docker_run_options, rule, message)
    (re.compile(r"(^|\s)--privileged(\s|=true|$)"), "run.03", "runs privileged (custom docker run options)"),
    (re.compile(r"--cap-add[=\s]+(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\b", re.I), "run.03",
     "adds a dangerous capability (custom docker run options)"),
    (re.compile(r"docker\.sock"), "run.01", "mounts the Docker socket (custom docker run options)"),
    (re.compile(r"--(network|net|pid|ipc|uts)[=\s]+host\b"), "run.05", "shares a host namespace (custom docker run options)"),
)


class SnapshotError(ValueError):
    pass


def check_safe(node, path: str = "$") -> None:
    """Raise if the snapshot holds a secret-shaped key or a URL with credentials. Names the path, never the value."""
    if isinstance(node, dict):
        for k, v in node.items():
            if FORBIDDEN_KEY.search(str(k)) and not re.search(r"_(id|uuid)$", str(k)) and v not in (None, "", [], {}):
                raise SnapshotError(f"snapshot field {path}.{k} may hold a secret: remove it (the recipe never saves it)")
            check_safe(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            check_safe(v, f"{path}[{i}]")
    elif isinstance(node, str) and URL_CREDENTIALS.search(node):
        raise SnapshotError(f"snapshot field {path} holds a URL with credentials: remove it")


def unlimited(v) -> bool:
    return str(v or "0").strip() in ("0", "")


def untagged(image: str | None) -> bool:
    if not image or "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


class CoolifyAudit:
    def __init__(self, snap: dict, rb: RuleBook, projects: list[str] | None = None) -> None:
        self.snap, self.rb = snap, rb
        self.only = {p.lower() for p in projects or []}
        self.report = Report(tool="audit_coolify", root=f"coolify snapshot ({snap.get('collected_at', 'undated')})")

    def add(self, rule: str, msg: str, where: str, **kw) -> None:
        self.report.add(self.rb.make(rule, msg, file=f"coolify:{where}", **kw))

    def wanted(self, res: dict) -> bool:
        return not self.only or str(res.get("project", "")).lower() in self.only

    def run(self) -> Report:
        snap = self.snap
        for s in snap.get("servers") or []:
            self.server(s)
        apps = [a for a in snap.get("applications") or [] if self.wanted(a)]
        services = [s for s in snap.get("services") or [] if self.wanted(s)]
        dbs = [d for d in snap.get("databases") or [] if self.wanted(d)]
        for a in apps:
            self.application(a)
        for s in services:
            self.service(s)
        for d in dbs:
            self.database(d)
        r = self.report
        r.meta.update({"coolify_version": snap.get("coolify_version"), "projects": snap.get("projects", []),
                       "resources": {"applications": len(apps), "services": len(services), "databases": len(dbs)}})
        if any(s.get("databases") for s in services):
            r.not_checked.append("Backups of databases inside service stacks (`ops.02`): Coolify has no API for them; check in the UI")
        if not snap.get("read_sensitive"):
            r.not_checked.append("Custom docker run options (`run.01`/`run.03`/`run.05`): token has no read:sensitive")
        r.not_checked += [n for n in self.rb.not_checked("cool", ran={"live"})]
        r.not_checked.append("Restore tests (`ops.02`): a schedule and a successful run don't prove a restore works")
        return r

    # ------------------------------------------------------------------ server

    def server(self, s: dict) -> None:
        name = s.get("name", "?")
        where = f"server/{name}"
        st = s.get("settings") or {}
        if st.get("is_image_scan_enabled") is False:
            self.add("sup.01", f"Image vulnerability scanning is off on server `{name}`", where, severity="warn",
                     fix_hint="Turn on image scanning for the server in Coolify")
        patch = st.get("patch_check_result")
        if isinstance(patch, dict):
            if (patch.get("security_updates") or 0) > 0:
                self.add("host.01", f"`{name}` has {patch['security_updates']} pending security updates", where, severity="warn")
            k = patch.get("kernels") or {}
            if patch.get("reboot_required") or (k.get("running") and k.get("boot") and k["running"] != k["boot"]):
                self.add("host.01", f"`{name}` needs a reboot (running kernel {k.get('running', '?')}, installed {k.get('boot', '?')})",
                         where, severity="warn")
            docker = sorted({u.get("package", "?") for u in patch.get("updates") or [] if u.get("risk") == "docker"})
            if docker:
                self.add("host.01", f"`{name}` has Docker package updates pending: {', '.join(docker)}", where)
        else:
            self.report.not_checked.append(f"Pending OS updates on `{name}` (`host.01`): no patch check result in the snapshot")
        if st.get("is_auto_security_updates_enabled") is False:
            self.add("cool.07", f"Automatic security updates are off on `{name}`", where)
        if st.get("is_ssh_host_key_check_disabled"):
            self.add("cool.08", f"SSH host key checking is disabled for `{name}`", where)
        if st.get("is_terminal_enabled"):
            self.add("cool.08", f"The Coolify web terminal is enabled on `{name}`", where, severity="info")
        if s.get("user") == "root":
            self.add("cool.08", f"Coolify connects to `{name}` as root", where, severity="info")
        if st.get("delete_unused_volumes"):
            self.add("cool.09", f"Docker cleanup on `{name}` deletes unused volumes", where)

    # ------------------------------------------------------------- resources

    def common(self, res: dict, where: str) -> None:
        sec = res.get("security") or {}
        status, label = sec.get("status"), res.get("name", "?")
        if status == "update_now" or sec.get("any_exploited"):
            self.add("sup.01", f"`{label}` has image vulnerabilities to fix now ({sec.get('critical_count', 0)} critical, "
                               f"{sec.get('high_count', 0)} high{', exploited in the wild' if sec.get('any_exploited') else ''})",
                     where, severity="error")
        elif status == "update_available":
            self.add("sup.01", f"`{label}` has image updates that fix known vulnerabilities", where, severity="warn")
        seen: dict[tuple, str] = {}
        for st in res.get("storages") or []:
            key = (st.get("owner"), st.get("mount_path"))
            if key[1] and key in seen:
                self.add("cool.11", f"`{label}` has two volumes on `{key[1]}` (`{seen[key]}`, `{st.get('name')}`)", where,
                         confidence="medium")
            seen.setdefault(key, st.get("name", "?"))

    def application(self, a: dict) -> None:
        name, pack = a.get("name", "?"), a.get("build_pack")
        where = f"app/{name}"
        if a.get("ports_mappings"):
            self.add("cool.01", f"`{name}` publishes host ports {a['ports_mappings']} past the proxy", where)
        if a.get("health_check_enabled") is False and not a.get("custom_healthcheck_found"):
            self.add("ops.03", f"`{name}` has no healthcheck (off in Coolify, none in the image or compose)", where)
        if pack != "dockercompose" and unlimited(a.get("limits_memory")) and unlimited(a.get("limits_cpus")):
            self.add("run.06", f"`{name}` has no memory or CPU limit", where, severity="info")
        if pack == "dockerimage" and untagged(f"{a.get('docker_registry_image_name') or 'image'}:{a.get('docker_registry_image_tag') or 'latest'}"):
            self.add("img.01", f"`{name}` deploys an image with no version tag", where)
        if pack in BUILDS:
            leaked = sorted({k["key"] for k in a.get("env_keys") or [] if k.get("is_buildtime") and not k.get("is_preview")
                             and is_secret_name(k.get("key", ""))})
            if leaked:
                self.add("cool.06", f"`{name}` passes secrets to the build: {', '.join(leaked)}", where,
                         fix_hint="Untick 'Available at Buildtime' for these variables unless the build needs them")
        opts = a.get("custom_docker_run_options") or ""
        for pat, rule, msg in DOCKER_FLAGS:
            if pat.search(opts):
                self.add(rule, f"`{name}` {msg}", where)
        self.common(a, where)

    def service(self, s: dict) -> None:
        name = s.get("name", "?")
        where = f"service/{name}"
        if s.get("redact_all_env_values_in_logs") is False:
            self.add("cool.10", f"`{name}` does not redact env values in logs", where)
        for c in s.get("applications") or []:
            cname = f"{name}/{c.get('name', '?')}"
            if str(c.get("ports") or "").strip():
                self.add("cool.01", f"`{cname}` publishes host ports {c['ports']} past the proxy", where)
            if untagged(c.get("image")):
                self.add("img.01", f"`{cname}` uses image `{c.get('image')}` with no version tag", where)
        for d in s.get("databases") or []:
            self.public_db(d, f"{name}/{d.get('name', '?')}", where)
            if untagged(d.get("image")):
                self.add("img.01", f"`{name}/{d.get('name', '?')}` uses image `{d.get('image')}` with no version tag", where)
        self.common(s, where)

    def public_db(self, d: dict, label: str, where: str) -> None:
        if d.get("is_public"):
            self.add("cool.02", f"Database `{label}` is publicly available on port {d.get('public_port') or '?'}", where)

    def database(self, d: dict) -> None:
        name = d.get("name", "?")
        where = f"database/{name}"
        self.public_db(d, name, where)
        if untagged(d.get("image")):
            self.add("img.01", f"Database `{name}` uses image `{d.get('image')}` with no version tag", where)
        schedules = [b for b in d.get("backups") or [] if b.get("enabled", True)]
        if not schedules:
            self.add("ops.02", f"Database `{name}` has no enabled backup schedule", where)
        for b in schedules:
            runs = b.get("executions") or []
            last = runs[0] if runs else None
            if last is None:
                self.add("ops.02", f"Backup schedule of `{name}` has never run", where)
            elif str(last.get("status", "")).lower() == "failed":
                self.add("ops.02", f"Last backup of `{name}` failed ({last.get('created_at', '?')})", where, severity="error")
            if not b.get("save_s3") and "save_s3" in b:
                self.add("ops.02", f"Backups of `{name}` stay on the same server (no S3 or remote storage)", where, severity="info")
        self.common(d, where)


def load_snapshot(path: str | Path) -> dict:
    try:
        snap = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read snapshot {path}: {exc}") from exc
    if not isinstance(snap, dict) or snap.get("snapshot_version") != SNAPSHOT_VERSION:
        raise SnapshotError(f"{path} is not a version {SNAPSHOT_VERSION} Coolify snapshot (see references/17-coolify.md)")
    check_safe(snap)
    return snap


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--project", action="append", help="Only these Coolify projects (repeatable)")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    try:
        snap = load_snapshot(args.snapshot)
    except SnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = CoolifyAudit(snap, RuleBook(SKILL), args.project).run()
    print(report.render(args.format))
    return 1 if args.strict and report.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
