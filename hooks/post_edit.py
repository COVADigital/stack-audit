"""PostToolUse hook: checks each file Claude writes or edits for error-level security findings.

Why: review-time audits find problems after the code is written; this tells Claude while the
file is still in front of it. Read-only, offline, and silent when the file is clean.
Off with STACK_AUDIT_ON_EDIT=0 or { "hooks": { "onEdit": false } } in stack-audit.config.json.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parent.parent
WEB = PLUGIN / "skills" / "web-standards" / "scripts"
CONTAINERS = PLUGIN / "skills" / "container-standards" / "scripts"
DATA = PLUGIN / "skills" / "data-standards" / "scripts"
TIMEOUT_S = 20
MAX_FINDINGS = 8


def scripts_for(file: Path) -> list[Path]:
    name = file.name
    if re.search(r"\.(tsx?|jsx?|mjs|cjs)$", name) and not re.search(r"\.d\.ts$", name):
        scripts = [WEB / "audit_security.py"]
        try:  # Drizzle schema files also get the schema audit
            if "drizzle-orm/pg-core" in file.read_text(encoding="utf-8", errors="replace"):
                scripts.append(DATA / "audit_schema.py")
        except OSError:
            pass
        return scripts
    if name.endswith(".sql"):
        return [DATA / "audit_migrations.py"]  # reports nothing unless the file is a migration
    if re.match(r"(Dockerfile|Containerfile)(\..+)?$|.+\.Dockerfile$", name):
        return [CONTAINERS / "audit_dockerfile.py"]
    if re.match(r"(docker-)?compose([.-][\w.-]+)?\.ya?ml$", name):
        return [CONTAINERS / "audit_compose.py"]
    return []


def project_root(file: Path, cwd: Path) -> Path:
    """The session's directory when the file is inside it, else the file's own folder."""
    try:
        file.relative_to(cwd)
        return cwd
    except ValueError:
        return file.parent


def enabled(root: Path) -> bool:
    if os.environ.get("STACK_AUDIT_ON_EDIT", "").strip().lower() in ("0", "false", "no", "off"):
        return False
    sys.path.insert(0, str(PLUGIN / "lib"))
    from wclib.config import load_config
    try:
        return bool((load_config(root).get("hooks") or {}).get("onEdit", True))
    except Exception:
        return True


def findings_for(payload: dict) -> tuple[str, list[dict]]:
    path = (payload.get("tool_input") or {}).get("file_path")
    if not path:
        return "", []
    file = Path(path).resolve()
    if not file.is_file():
        return "", []
    scripts = scripts_for(file)
    if not scripts:
        return "", []
    cwd = Path(payload.get("cwd") or os.getcwd()).resolve()
    root = project_root(file, cwd)
    if not enabled(root):
        return "", []
    rel = file.relative_to(root).as_posix()
    found = []
    for script in scripts:
        res = subprocess.run([sys.executable, str(script), "--root", str(root), "--files", rel, "--format", "json"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_S)
        if res.returncode not in (0, 1):
            continue
        data = json.loads(res.stdout)
        # Only this file's own error-level findings; project-wide ones (headers, lockfile) belong to a full audit.
        found += [f for f in data.get("findings", []) if f.get("file") == rel and f.get("severity") == "error"]
    # Outside the session folder the root is the file's own folder, so rel is a bare name: show the full path.
    return (rel if root == cwd else str(file)), found


def message(rel: str, found: list[dict]) -> str:
    lines = [f"stack-audit found {len(found)} error-level issue(s) in {rel} after this edit:"]
    for f in found[:MAX_FINDINGS]:
        hint = f" Fix: {f['fix_hint']}" if f.get("fix_hint") else ""
        lines.append(f"- {f['rule']} line {f.get('line') or '?'}: {f['message']}.{hint}")
    if len(found) > MAX_FINDINGS:
        lines.append(f"- … and {len(found) - MAX_FINDINGS} more (run the full audit)")
    lines.append("Fix these now unless they are intended. If one is a false positive, tell the user and suppress it with "
                 "`stack-audit-ignore <rule> -- <reason>` on the line above.")
    return "\n".join(lines)


def main() -> None:
    try:  # a broken hook must never block an edit
        rel, found = findings_for(json.load(sys.stdin))
    except Exception:
        return
    if found:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": message(rel, found)}}))


if __name__ == "__main__":
    main()
