#!/usr/bin/env python3
"""Docker host audit (host.*). Run ON THE LINUX SERVER by the user. Read-only.

    python3 audit_host.py [--daemon-json /etc/docker/daemon.json] [--format md|json]

Reads daemon.json, `docker info`, `docker version`, the dockerd command line, published
ports, and (if permitted) `ufw status`. Changes nothing.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.findings import Report
from wclib.rules import RuleBook

SKILL = Path(__file__).resolve().parents[1]


def run(*cmd: str) -> tuple[int, str]:
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return r.returncode, r.stdout if r.returncode == 0 else r.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def audit(daemon: dict | None, info: dict | None, dockerd_args: str, ports: list[tuple[str, str]], ufw: str | None,
          rb: RuleBook, report: Report) -> None:
    add = lambda rule, msg, **kw: report.add(rb.make(rule, msg, file=kw.pop("file", "/etc/docker/daemon.json"), **kw))  # noqa: E731
    d = daemon or {}
    if info:
        report.meta["engine"] = info.get("ServerVersion")
        report.meta["kernel"] = info.get("KernelVersion")
        report.meta["os"] = info.get("OperatingSystem")
        add("host.01", f"Docker Engine {info.get('ServerVersion')} on kernel {info.get('KernelVersion')}: confirm both are on current security patches",
            file="docker info")
    hosts = d.get("hosts") or []
    if any(str(h).startswith("tcp://") for h in hosts) or re.search(r"-H\s*=?\s*tcp://|--host\s*=?\s*tcp://", dockerd_args):
        tls = d.get("tlsverify") or "--tlsverify" in dockerd_args
        add("host.02", "Docker daemon listens on TCP" + ("" if tls else " WITHOUT TLS verification: root on the host for anyone who can reach it"),
            severity="error" if not tls else "warn", fix_hint="Remove tcp:// hosts; manage remotely over SSH")
    driver = d.get("log-driver") or (info or {}).get("LoggingDriver") or "json-file"
    opts = d.get("log-opts") or {}
    if driver == "json-file" and not opts.get("max-size"):
        add("host.03", "Default log driver json-file without max-size: container logs grow until the disk is full",
            fix_hint='{"log-driver": "local"} or {"log-opts": {"max-size": "10m", "max-file": "3"}} (values as strings)')
    if opts and any(not isinstance(v, str) for v in opts.values()):
        add("host.03", "daemon.json log-opts values must be strings (e.g. \"3\", not 3)", severity="warn")
    if not d.get("no-new-privileges"):
        add("host.04", "Daemon default no-new-privileges is not set", fix_hint='"no-new-privileges": true (test images that use setuid first)')
    if not d.get("live-restore") and not (info or {}).get("LiveRestoreEnabled"):
        add("host.04", "live-restore is off (daemon upgrades restart every container)")
    level = d.get("log-level") or (re.search(r"--log-level[= ](\w+)", dockerd_args) or [None, None])[1]
    if level == "debug":
        add("host.04", "Daemon log level is debug", severity="warn", fix_hint='"log-level": "info"')
    secopts = " ".join((info or {}).get("SecurityOptions") or [])
    if info is not None:
        if "rootless" not in secopts and "userns" not in secopts:
            add("host.05", "Daemon runs rootful without userns-remap (fine for platforms that require it, e.g. Coolify)", file="docker info")
        if "seccomp" not in secopts:
            add("host.04", "seccomp is not active in the daemon", severity="warn", file="docker info")
    # `docker ps` Ports look like "0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp"
    exposed = [(n, p) for n, p in ports
               if any(m.group(2) not in ("80", "443") for m in re.finditer(r"(0\.0\.0\.0|\[::\]|::):(\d+)->", p))]
    for name, p in exposed:
        add("host.06", f"Container `{name}` publishes on all interfaces: {p} (UFW does not filter Docker-published ports)",
            file="docker ps", fix_hint="Bind to 127.0.0.1, route through the proxy, or block with a Docker-aware/cloud firewall")
    if ufw is not None and "Status: active" in ufw and exposed:
        report.meta["ufw"] = "active (does not cover the ports above)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--daemon-json", default="/etc/docker/daemon.json")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    args = ap.parse_args()
    rb = RuleBook(SKILL)
    report = Report(tool="audit_host", root="this host")
    if not sys.platform.startswith("linux"):
        report.skipped.append(f"Not a Linux host ({sys.platform}). Copy this script to the server and run it there "
                              "with python3 (e.g. via `ssh user@server`), then share the report.")
        print(report.render(args.format))
        return 0
    daemon = None
    p = Path(args.daemon_json)
    if p.exists():
        try:
            daemon = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.skipped.append(f"Could not read {p}: {exc}")
    else:
        report.meta["daemon_json"] = "missing (all defaults)"
    code, out = run("docker", "info", "--format", "{{json .}}")
    info = json.loads(out) if code == 0 and out.strip().startswith("{") else None
    if info is None:
        report.skipped.append(f"docker info failed (permission? try with sudo): {out.strip()[:160]}")
    code, ps = run("ps", "-eo", "args")
    dockerd = next((l for l in ps.splitlines() if "dockerd" in l), "") if code == 0 else ""
    code, dps = run("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
    ports = [tuple(l.split("\t", 1)) for l in dps.splitlines() if "\t" in l] if code == 0 else []
    ufw = None
    if shutil.which("ufw"):
        code, ufw_out = run("ufw", "status")
        ufw = ufw_out if code == 0 else None
    audit(daemon, info, dockerd, ports, ufw, rb, report)
    print(report.render(args.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
