#!/usr/bin/env python3
"""Audit running containers via `docker inspect` (run.*, cnet.02, ops.03-05, cool.03). Read-only.

    python audit_runtime.py [--all] [--format md|json|sarif] [--strict]

Uses only `docker ps` and `docker inspect` against the local Docker daemon (run it on the
server for production). Never starts, stops, or changes containers. Environment values
are never read into the report.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.config import load_config
from wclib.containers import HOST_SYSTEM_PATHS, classify
from wclib.findings import Report
from wclib.rules import RuleBook

SKILL = Path(__file__).resolve().parents[1]
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "ALL", "BPF"}


def docker(*args: str) -> tuple[int, str]:
    timeout = 15 if args[:1] == ("ps",) else 60  # a stopped Docker Desktop hangs; fail fast
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout if r.returncode == 0 else r.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def audit(containers: list[dict], rb: RuleBook, report: Report, allow: set[str]) -> None:
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        cfg, hc = c.get("Config") or {}, c.get("HostConfig") or {}
        image = cfg.get("Image", "")
        kind = classify(name, image)
        where = f"container:{name}"
        platform = name in allow
        add = lambda rule, msg, **kw: report.add(rb.make(rule, msg, file=where, **kw))  # noqa: E731
        one_shot = (hc.get("RestartPolicy") or {}).get("Name") in ("no", "") and c.get("State", {}).get("Status") == "exited"
        for m in c.get("Mounts") or []:
            src = str(m.get("Source", ""))
            if src.endswith("docker.sock"):
                if platform:
                    add("cool.03", f"Platform container `{name}` mounts the Docker socket (allow-listed)")
                else:
                    add("run.01", f"`{name}` has the Docker socket mounted ({'rw' if m.get('RW') else 'ro: still root-equivalent'})")
            elif m.get("Type") == "bind" and HOST_SYSTEM_PATHS.match(src.rstrip("/") or "/"):
                add("run.08", f"`{name}` bind-mounts host path `{src}` ({'rw' if m.get('RW') else 'ro'})",
                    severity="error" if m.get("RW") else "warn")
        if hc.get("Privileged"):
            add("run.03", f"`{name}` is running privileged")
        bad = sorted({str(x).upper().removeprefix("CAP_") for x in (hc.get("CapAdd") or [])} & DANGEROUS_CAPS)
        if bad:
            add("run.03", f"`{name}` has dangerous capabilities: {', '.join(bad)}")
        if not platform and kind in ("app", "admin") and "ALL" not in [str(x).upper() for x in (hc.get("CapDrop") or [])]:
            add("run.02", f"`{name}` keeps Docker's default capabilities")
        sec = [str(s) for s in (hc.get("SecurityOpt") or [])]
        if not platform and not any("no-new-privileges" in s for s in sec):
            add("run.04", f"`{name}` runs without no-new-privileges (unless set as a daemon default)", confidence="medium")
        for s in sec:
            if "unconfined" in s or "label=disable" in s or "label:disable" in s:
                add("run.05", f"`{name}` has a disabled security profile ({s})")
        for key, label in (("NetworkMode", "network"), ("PidMode", "pid"), ("IpcMode", "ipc"), ("UTSMode", "uts")):
            if hc.get(key) == "host" and not platform:
                add("run.05", f"`{name}` shares the host {label} namespace")
        if not platform and not one_shot:
            if not hc.get("Memory"):
                add("run.06", f"`{name}` has no memory limit")
            if not hc.get("PidsLimit") or hc.get("PidsLimit") in (0, -1):
                add("run.06", f"`{name}` has no PID limit", severity="info")
            if kind == "app" and not hc.get("ReadonlyRootfs"):
                add("run.07", f"`{name}` root filesystem is writable")
        user = str(cfg.get("User", "")).split(":")[0]
        if kind == "app" and not platform and user in ("", "root", "0"):
            add("img.02", f"`{name}` runs as root (image has no USER, or it was overridden)", severity="warn")
        for port, binds in (hc.get("PortBindings") or {}).items():
            for b in binds or []:
                if b.get("HostIp") in ("", "0.0.0.0", "::") and kind in ("db", "admin"):
                    add("cnet.02", f"`{name}` publishes {port} on all interfaces (host port {b.get('HostPort')}): bypasses UFW")
                elif b.get("HostIp") in ("", "0.0.0.0", "::") and kind == "app" and port.split("/")[0] not in ("80", "443") and not platform:
                    add("cnet.03", f"`{name}` publishes {port} on all interfaces (host port {b.get('HostPort')})", severity="info")
        if not one_shot and not platform:
            if not cfg.get("Healthcheck") or cfg["Healthcheck"].get("Test") in (None, ["NONE"]):
                add("ops.03", f"`{name}` has no healthcheck")
            health = (c.get("State") or {}).get("Health") or {}
            if health.get("Status") == "unhealthy":
                add("ops.03", f"`{name}` is currently UNHEALTHY", severity="error")
            if (hc.get("RestartPolicy") or {}).get("Name") in ("", "no"):
                add("ops.04", f"`{name}` has no restart policy")
        logc = hc.get("LogConfig") or {}
        if logc.get("Type") == "json-file" and not (logc.get("Config") or {}).get("max-size"):
            add("ops.05", f"`{name}` logs with json-file and no max-size (unbounded growth)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="Include stopped containers")
    ap.add_argument("--config", help="stack-audit.config.json (for containers.platformAllowlist)")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    rb = RuleBook(SKILL)
    report = Report(tool="audit_runtime", root="docker (local daemon)")
    code, out = docker("ps", "-q", *(["-a"] if args.all else []))
    if code != 0:
        report.skipped.append(f"Docker daemon not reachable: {out.strip()[:200]}")
    else:
        ids = out.split()
        if not ids:
            report.skipped.append("No containers running")
        else:
            code, raw = docker("inspect", *ids)
            if code == 0:
                containers = json.loads(raw)
                cfg = load_config(Path.cwd(), args.config) if args.config else load_config(Path.cwd())
                allow = set(cfg.get("containers", {}).get("platformAllowlist", []))
                for c in containers:  # never carry env values into memory longer than needed
                    (c.get("Config") or {}).pop("Env", None)
                audit(containers, rb, report, allow)
                report.meta["containers"] = [c.get("Name", "").lstrip("/") for c in containers]
            else:
                report.skipped.append(f"docker inspect failed: {raw.strip()[:200]}")
    report.not_checked.append("Daemon-level defaults (no-new-privileges, log rotation): run audit_host.py on the server")
    print(report.render(args.format))
    return 1 if args.strict and report.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
