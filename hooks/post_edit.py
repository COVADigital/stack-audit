"""PostToolUse hook: checks each file the agent writes or edits for error-level security findings.

Why: review-time audits find problems after the code is written; this tells the agent while the
file is still in front of it. Claude Code sends `tool_input.file_path`; Codex sends an `apply_patch`
patch in `tool_input.command`, so the file names are read from its `*** Add/Update File:` lines. Read-only, offline, and silent when the file is clean.
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
MAX_FILES = 5  # a large Codex patch gets a full audit, not a slow hook
PATCH_FILE = re.compile(r"^\*\*\* (?:Add File|Update File|Move to): (.+?)\s*$", re.M)
SESSION_SETTING = re.compile(r"set_config|\bSET\s+(SESSION\s+)?\"?[a-z_]\w*\.[a-z_]\w*", re.I)  # tenant context in SQL strings


def scripts_for(file: Path) -> list[Path]:
    name = file.name
    if re.search(r"\.(tsx?|jsx?|mjs|cjs)$", name) and not re.search(r"\.d\.ts$", name):
        scripts = [WEB / "audit_security.py"]
        try:  # Drizzle schema files also get the schema audit; session-level tenant settings get dbh.12
            text = file.read_text(encoding="utf-8", errors="replace")
            if "drizzle-orm/pg-core" in text:
                scripts.append(DATA / "audit_schema.py")
            if SESSION_SETTING.search(text):
                scripts.append(DATA / "audit_postgres.py")
        except OSError:
            pass
        return scripts
    if name.endswith(".sql"):  # both report nothing unless the file is a migration
        return [DATA / "audit_migrations.py", DATA / "audit_postgres.py"]
    if re.match(r"(postgresql|pg_hba)[\w.-]*\.conf$", name):
        return [DATA / "audit_postgres.py"]
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


def edited_paths(payload: dict) -> list[str]:
    """Files an edit touched: Claude Code's `file_path`, or the files named in a Codex `apply_patch`."""
    ti = payload.get("tool_input") or {}
    if not isinstance(ti, dict):
        return []
    if ti.get("file_path"):
        return [str(ti["file_path"])]
    cmd = ti.get("command")
    if isinstance(cmd, list):
        cmd = "\n".join(map(str, cmd))
    if not isinstance(cmd, str) or "*** Begin Patch" not in cmd:
        return []
    return list(dict.fromkeys(m.strip() for m in PATCH_FILE.findall(cmd)))[:MAX_FILES]


def findings_for(payload: dict) -> list[tuple[str, list[dict]]]:
    cwd = Path(payload.get("cwd") or os.getcwd()).resolve()
    results = []
    for path in edited_paths(payload):
        rel, found = check_file(cwd / path, cwd)  # an absolute path replaces cwd
        if found:
            results.append((rel, found))
    return results


def check_file(path: Path, cwd: Path) -> tuple[str, list[dict]]:
    file = Path(path).resolve()
    if not file.is_file():
        return "", []
    scripts = scripts_for(file)
    if not scripts:
        return "", []
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
        results = findings_for(json.load(sys.stdin))
    except Exception:
        return
    if results:
        text = "\n\n".join(message(rel, found) for rel, found in results)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}}))


if __name__ == "__main__":
    main()
