#!/usr/bin/env python3
"""The optional Coolify add-on: remember the user's yes/no, connect Coolify's MCP server to
Claude Code and/or Codex CLI, and store the API token.

    python coolify_addon.py status                    # choice, which CLIs exist, which already have the server
    python coolify_addon.py set yes|no                # remember the answer (never ask again after "no")
    python coolify_addon.py install --url https://coolify.example.com [--client claude|codex|both] [--dry-run]
    python coolify_addon.py set-token                 # read the token (hidden prompt, or stdin) and store it
    python coolify_addon.py verify                    # does Claude Code connect? (never prints the config)

Both clients read the token from the COOLIFY_TOKEN environment variable: Claude Code through
the header `Bearer ${COOLIFY_TOKEN}`, Codex through `--bearer-token-env-var`. So the token is
never written into either client's config. `set-token` stores it as a user environment
variable (Windows registry; elsewhere a 0600 file sourced from the shell profile). The token
is read from a hidden prompt or stdin, never from the command line, and never printed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

TOKEN_ENV = "COOLIFY_TOKEN"
NAME = "coolify"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SAFE_URL = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~\-/]*)?$")


def state_file() -> Path:
    return Path.home() / ".claude" / "data" / "stack-audit" / "addons.json"


def read_state() -> dict:
    try:
        data = json.loads(state_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def set_choice(choice: str) -> None:
    data = read_state()
    data["coolify"] = choice
    p = state_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def mcp_url(url: str) -> str:
    """Validate a Coolify base URL and return its MCP endpoint. Raises ValueError."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("give the Coolify URL, e.g. https://coolify.example.com")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("the URL must not contain a user, password, query or fragment")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in LOCAL_HOSTS):
        raise ValueError("use https (plain http would send the token unencrypted; allowed only for localhost)")
    path = parts.path.rstrip("/")
    path = path[: -len("/mcp")] if path.endswith("/mcp") else path
    out = f"{parts.scheme}://{parts.netloc}{path}/mcp"
    if not SAFE_URL.match(out):  # the URL is passed to CLI shims (codex.cmd on Windows): keep it shell-inert
        raise ValueError("the URL contains unexpected characters")
    return out


def install_commands(url: str, client: str) -> dict[str, list[str]]:
    endpoint = mcp_url(url)
    cfg = {"type": "http", "url": endpoint, "headers": {"Authorization": "Bearer ${" + TOKEN_ENV + "}"}}
    cmds = {"claude": ["claude", "mcp", "add-json", NAME, json.dumps(cfg), "--scope", "user"],
            "codex": ["codex", "mcp", "add", NAME, "--url", endpoint, "--bearer-token-env-var", TOKEN_ENV]}
    return {k: v for k, v in cmds.items() if client in (k, "both")}


def cli(name: str, *args: str, env: dict | None = None, timeout: int = 60) -> tuple[int, str]:
    """Run a CLI; output is returned to the caller, which must not print it (`mcp get` shows headers)."""
    exe = shutil.which(name)
    if not exe:
        return 127, f"{name} not found"
    try:
        r = subprocess.run([exe, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def has_server(client: str) -> bool:
    """Is a `coolify` MCP server configured? Reads the client's config file instead of running its CLI,
    which fails inside Codex's sandbox. Only checks the server name; never returns config values."""
    if client == "codex":
        cfg = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "config.toml"
        try:
            text = cfg.read_text(encoding="utf-8")
        except OSError:
            return False
        return re.search(rf'^\[mcp_servers\.(?:{NAME}|"{NAME}")\]', text, re.M) is not None
    base = Path(os.environ["CLAUDE_CONFIG_DIR"]) if os.environ.get("CLAUDE_CONFIG_DIR") else Path.home()
    try:
        data = json.loads((base / ".claude.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    scopes = [data, *((data.get("projects") or {}).values())] if isinstance(data, dict) else []
    return any(isinstance(s, dict) and NAME in (s.get("mcpServers") or {}) for s in scopes)


def client_status() -> dict:
    return {name: {"cli": shutil.which(name) is not None, "server": has_server(name)} for name in ("claude", "codex")}


def token_saved(windows: bool = os.name == "nt") -> bool:
    """Has set-token stored the token for this user? (Presence only.)"""
    if windows:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                return bool(winreg.QueryValueEx(key, TOKEN_ENV)[0])
        except OSError:
            return False
    return (Path.home() / ".config" / "stack-audit" / "coolify.env").exists()


def load_hint(windows: bool = os.name == "nt") -> str:
    """How to load the saved token into a terminal that was already open."""
    if windows:
        return f"$env:{TOKEN_ENV} = [Environment]::GetEnvironmentVariable('{TOKEN_ENV}', 'User')"
    return ". ~/.config/stack-audit/coolify.env"


def read_token() -> str:
    tok = getpass.getpass("Coolify API token (input hidden): ") if sys.stdin.isatty() else sys.stdin.readline()
    tok = tok.strip()
    if not tok or len(tok) > 1024 or any(c.isspace() for c in tok):
        raise ValueError("that doesn't look like a Coolify API token (empty, too long, or contains spaces)")
    return tok


def store_token(token: str, windows: bool = os.name == "nt") -> str:
    """Persist COOLIFY_TOKEN for the user. Returns where it went (never the value)."""
    if windows:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, TOKEN_ENV, 0, winreg.REG_SZ, token)
        try:  # tell Explorer so newly started terminals see it
            import ctypes
            ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 5000, None)
        except Exception:
            pass
        return "your Windows user environment variables"
    env_file = Path.home() / ".config" / "stack-audit" / "coolify.env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"export {TOKEN_ENV}={shlex.quote(token)}\n")
    os.chmod(env_file, 0o600)
    profile = Path.home() / (".zshrc" if "zsh" in os.environ.get("SHELL", "") else ".bashrc")
    text = profile.read_text(encoding="utf-8") if profile.exists() else ""
    if str(env_file) not in text:
        with profile.open("a", encoding="utf-8") as f:
            f.write(f'\n[ -f "{env_file}" ] && . "{env_file}"  # stack-audit: Coolify API token\n')
    return f"{env_file} (loaded by {profile})"


def restart_codex_daemon(token: str) -> str:
    """Stop Codex's app-server and start it again with the token in its environment. Only on the user's say-so."""
    env = dict(os.environ, **{TOKEN_ENV: token})
    cli("codex", "app-server", "daemon", "stop", env=env)
    code, _ = cli("codex", "app-server", "daemon", "start", env=env)
    if code == 0:
        return "Codex: background app-server restarted with the token. Start Codex and check /mcp."
    return ("Codex: the app-server stopped but didn't start again. Run `codex app-server daemon start` from a terminal "
            f"that has {TOKEN_ENV} set.")


def verify(token: str | None = None) -> str:
    """Report the token and each client's server. Prints nothing from a CLI's output."""
    lines = []
    if not (token or os.environ.get(TOKEN_ENV)):
        if token_saved():
            lines.append(f"{TOKEN_ENV} is saved, but this terminal was opened before it was set. "
                         f"Run this in the terminal, then start (or resume) the client: {load_hint()}")
        else:
            lines.append(f"{TOKEN_ENV} is not set: store it with `coolify_addon.py set-token`.")
    if has_server("claude"):
        if not shutil.which("claude"):
            lines.append(f"Claude Code: '{NAME}' server configured; CLI not found, so the connection wasn't checked")
        else:
            env = dict(os.environ, **({TOKEN_ENV: token} if token else {}))
            code, out = cli("claude", "mcp", "get", NAME, env=env, timeout=90)
            if code == 0 and "Connected" in out and "Failed" not in out:
                lines.append("Claude Code: connects to Coolify")
            else:
                lines.append("Claude Code: could not connect (check the token, the URL and that the API is enabled in "
                             "Coolify; inside a sandboxed agent this check may not be able to run)")
    elif shutil.which("claude"):
        lines.append(f"Claude Code: no '{NAME}' MCP server")
    if has_server("codex"):
        lines.append(f"Codex: '{NAME}' server configured; Codex connects at start-up, so check it with /mcp. If /mcp "
                     f"shows 'failed', its background app-server started before {TOKEN_ENV} was set: run "
                     "`codex app-server daemon stop` from a terminal that has it, then start Codex again")
    elif shutil.which("codex"):
        lines.append(f"Codex: no '{NAME}' MCP server")
    return "\n".join(lines) or "Neither Claude Code nor Codex is installed"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p_set = sub.add_parser("set")
    p_set.add_argument("choice", choices=("yes", "no"))
    p_inst = sub.add_parser("install")
    p_inst.add_argument("--url", required=True)
    p_inst.add_argument("--client", choices=("claude", "codex", "both"), default="claude")
    p_inst.add_argument("--dry-run", action="store_true")
    sub.add_parser("set-token")
    sub.add_parser("verify")
    args = ap.parse_args()

    if args.cmd == "status":
        print(json.dumps({"choice": read_state().get("coolify"), "token_env_set": bool(os.environ.get(TOKEN_ENV)),
                          "token_saved": token_saved(), "clients": client_status()}))
        return 0
    if args.cmd == "set":
        set_choice(args.choice)
        print(f"Coolify add-on: {args.choice} (saved to {state_file().as_posix()})")
        return 0
    if args.cmd == "verify":
        print(verify())
        return 0
    if args.cmd == "set-token":
        try:
            token = read_token()
        except (ValueError, EOFError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        where = store_token(token)
        print(f"Saved {TOKEN_ENV} to {where}.")
        print(verify(token))
        print("Start Claude Code / Codex from a new terminal so they pick it up. To use a terminal that is "
              f"already open instead, run this in it first: {load_hint()}")
        if has_server("codex") and shutil.which("codex"):
            if sys.stdin.isatty() and input("Codex starts MCP servers from a background app-server that doesn't have the "
                                            "token yet. Restart it now? This interrupts running Codex sessions. [y/N] "
                                            ).strip().lower() in ("y", "yes"):
                print(restart_codex_daemon(token))
            else:
                print("Codex: restart its background app-server so it picks up the token: run `codex app-server daemon "
                      "stop` and then `codex app-server daemon start` from a terminal that has "
                      f"{TOKEN_ENV} set (see above).")
            print("Also restart VS Code and the Codex desktop app if you use Codex there.")
        return 0

    try:
        cmds = install_commands(args.url, args.client)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    failed = False
    for name, cmd in cmds.items():
        shown = " ".join(shlex.quote(c) for c in cmd)
        if args.dry_run:
            print(shown)
            continue
        if not shutil.which(name):
            print(f"{name}: CLI not found; skipped")
            continue
        if has_server(name):
            print(f"{name}: an MCP server named '{NAME}' already exists; left unchanged")
            continue
        code, out = cli(*cmd)
        if code == 0:
            print(f"{name}: added MCP server '{NAME}' -> {mcp_url(args.url)} (token read from {TOKEN_ENV})")
        else:
            failed = True
            print(f"{name}: install failed: {out.strip()[-300:]}", file=sys.stderr)
    if not args.dry_run and not failed:
        set_choice("yes")
        if not os.environ.get(TOKEN_ENV):
            print(f"Next: create a read-only Coolify API token and store it with `coolify_addon.py set-token`.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
