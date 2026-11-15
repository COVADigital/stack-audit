"""SessionStart hook: tells Claude when to load the stack-audit skills.

Why: descriptions alone don't get these skills loaded when a question points at one file;
the model reads the file and answers from memory. This puts the rule in context up front.
It also keeps the OWASP cheat sheet clone from going missing or stale without anyone noticing.
"""
import json
import os
import sys
from pathlib import Path

MAX_AGE_DAYS = 30

CONTEXT = """The stack-audit plugin is installed. Load the matching skill BEFORE reading files or answering, even for a single-file question you could answer from memory:
- stack-audit:web-standards: reviewing, auditing, debugging or changing React / Next.js code (components, pages, data fetching, caching, Server Actions, auth, sessions, headers, accessibility).
- stack-audit:container-standards: reviewing or changing a Dockerfile, a Compose file, a container image, published ports, container secrets or a Docker host.
- stack-audit:owasp-security: what OWASP, ASVS or the OWASP Top 10 says, or security advice that needs citations.
Do not load them for unrelated work."""

SETUP = """
One-time setup is pending for stack-audit:owasp-security: its local copy of the OWASP Cheat Sheet Series is missing. The first time an OWASP, ASVS or Top 10 question comes up, tell the user and offer to run this for them (a download from GitHub into their home folder), and run it only after they agree:
git clone https://github.com/OWASP/CheatSheetSeries.git "{clone}"
Do not mention this for unrelated work, and do not answer OWASP questions from memory as if they were checked."""

STALE = """
The local OWASP Cheat Sheet Series copy used by stack-audit:owasp-security was last updated {days} days ago. The first time an OWASP, ASVS or Top 10 question comes up, tell the user and offer to update it (a download from GitHub), and run this only after they agree:
git -C "{clone}" pull --ff-only
Then carry on with their question; the copy still works if they decline. Do not mention this for unrelated work."""

UPDATED = """
The local OWASP Cheat Sheet Series copy was {days} days old and was updated automatically at session start (owasp.autoUpdate is on)."""


def auto_update_enabled(config: dict) -> bool:
    env = os.environ.get("STACK_AUDIT_OWASP_AUTO_UPDATE", "").strip().lower()
    return env in ("1", "true", "yes", "on") or bool((config.get("owasp") or {}).get("autoUpdate"))


def owasp_note() -> str:
    """A note about the cheat sheet clone when it is missing or stale, else ''."""
    try:  # a broken hook must never block a session
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
        from wclib.config import load_config
        from wclib.owasp import DEFAULT_CLONE, OwaspError, clone_age_days, resolve_clone, update_clone
        try:
            config = load_config(Path.cwd())
        except Exception:
            config = {}
        try:
            clone = resolve_clone(config=config)
        except OwaspError:
            return SETUP.format(clone=DEFAULT_CLONE.as_posix())
        days = clone_age_days(clone)
        if days is None or days <= MAX_AGE_DAYS:
            return ""
        # Opt-in only: this is the one place the plugin uses the network without asking first.
        if auto_update_enabled(config) and update_clone(clone):
            return UPDATED.format(days=days)
        return STALE.format(days=days, clone=clone.as_posix())
    except Exception:
        return ""


print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": CONTEXT + owasp_note()}}))
