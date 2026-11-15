"""Shared library for the stack-audit plugin skills.

Standard library only. Every audit script in the plugin builds on:

- findings  : Finding / Report model and JSON, Markdown, SARIF writers
- walker    : git-aware file discovery (+ --changed against a base ref)
- textutil  : comment/string masking for JS/TS, glob matching, line helpers
- config    : per-repo `stack-audit.config.json` with defaults
- suppress  : inline `stack-audit-ignore` comments and config-level ignores
- stack     : project stack detection (Next/React/Zod/ORM/auth/i18n/Docker...)
- cli       : shared argparse options and output/exit-code handling

All scripts are read-only: they never modify the audited repository.
"""

import sys

__version__ = "0.2.2"

# Reports are UTF-8 everywhere. Before Python 3.15, Windows writes piped output in the ANSI
# code page (cp1252), which callers reading UTF-8 (run_audit.py, the hooks, CI) can't decode.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure") and (_stream.encoding or "").lower().replace("-", "") != "utf8":
        _stream.reconfigure(encoding="utf-8")
