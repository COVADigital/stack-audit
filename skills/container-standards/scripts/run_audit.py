#!/usr/bin/env python3
"""Run container audits by phase and merge them into one report. Read-only.

    python run_audit.py --root REPO --phase build            # Dockerfiles + compose files (static)
    python run_audit.py --root REPO --phase deploy           # build + running containers (local daemon)
    python run_audit.py --root REPO --phase deploy --image app:sha   # + image scan (trivy/grype: network)
    common: [--format md|json|sarif] [--out FILE] [--strict] [--daemon-rotation]

Host checks are separate: run audit_host.py on the server.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.findings import Report

HERE = Path(__file__).resolve().parent


def run_json(cmd: list[str], label: str) -> Report:
    res = subprocess.run([sys.executable, *cmd, "--format", "json"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if not res.stdout.strip().startswith("{"):
        r = Report(tool=label, root="")
        r.skipped.append(f"{label} failed (exit {res.returncode}): {res.stderr.strip()[-300:]}")
        return r
    return Report.from_json(res.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--phase", choices=("build", "deploy"), default="build")
    ap.add_argument("--image")
    ap.add_argument("--daemon-rotation", action="store_true")
    ap.add_argument("--config")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--out")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    extra = (["--config", args.config] if args.config else [])
    merged = Report(tool=f"container-standards {args.phase}", root=str(Path(args.root).resolve()))
    merged.merge(run_json([str(HERE / "audit_dockerfile.py"), "--root", args.root, *extra], "audit_dockerfile"))
    merged.merge(run_json([str(HERE / "audit_compose.py"), "--root", args.root, *extra,
                           *(["--daemon-rotation"] if args.daemon_rotation else [])], "audit_compose"))
    if args.phase == "deploy":
        merged.merge(run_json([str(HERE / "audit_runtime.py"), *extra], "audit_runtime"))
        if args.image:
            merged.merge(run_json([str(HERE / "scan_image.py"), "--image", args.image], "scan_image"))
        else:
            merged.skipped.append("Image vulnerability scan not run (pass --image; trivy/grype download a vulnerability DB)")
    merged.not_checked.append("Host daemon settings: run audit_host.py on the server (Linux)")
    merged.dedupe()
    text = merged.render(args.format)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(merged.findings)} findings)", file=sys.stderr)
    else:
        try:
            print(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")
    return 1 if args.strict and merged.has_errors() else 0


if __name__ == "__main__":
    sys.exit(main())
