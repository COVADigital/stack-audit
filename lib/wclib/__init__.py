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

__version__ = "0.1.0"
