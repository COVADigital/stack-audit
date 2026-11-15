"""Per-repo configuration: `stack-audit.config.json` at the audited repo root.

Every key is optional; defaults come from the concept references.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

CONFIG_FILENAME = "stack-audit.config.json"

DEFAULTS: dict = {
    "budgets": {
        "initialJsGzipKb": 170,
        "lcpMs": 2500,
        "maxThirdPartyScripts": 3,
        "dynamicImportKb": 30,
        "virtualizeRows": 200,
        "componentMaxLines": 150,
    },
    "cors": {"allowedOrigins": []},
    "features": {"root": "src/features", "publicApi": "index.ts"},
    "i18n": {"sourceLocale": "en", "messagesDir": "messages"},
    "asvs": {"level": None},  # None = infer (L1 content sites, L2 accounts/payments/admin)
    "containers": {"platformAllowlist": ["coolify", "coolify-proxy", "coolify-realtime", "coolify-db", "coolify-redis"]},
    "owasp": {"cheatsheetsPath": None, "autoUpdate": False},  # path None = ~/.claude/data/owasp-cheatsheets
    "ignorePaths": [],
    "ignore": {},  # { "sec.01": ["src/legacy/**"] }
}


class ConfigError(ValueError):
    pass


def _deep_merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_config(root: str | Path, explicit: str | Path | None = None) -> dict:
    """Load config from `explicit` path, else `<root>/stack-audit.config.json`, else defaults."""
    path = Path(explicit) if explicit else Path(root) / CONFIG_FILENAME
    if not path.exists():
        if explicit:
            raise ConfigError(f"config file not found: {path}")
        cfg = copy.deepcopy(DEFAULTS)
        cfg["_source"] = None
        return cfg
    try:
        user = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(user, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    _validate(user, path)
    cfg = _deep_merge(DEFAULTS, user)
    cfg["_source"] = str(path)
    return cfg


def _validate(user: dict, path: Path) -> None:
    ignore = user.get("ignore", {})
    if not isinstance(ignore, dict) or not all(
        isinstance(v, list) and all(isinstance(g, str) for g in v) for v in ignore.values()
    ):
        raise ConfigError(f"{path}: 'ignore' must map rule IDs to lists of glob strings")
    ip = user.get("ignorePaths", [])
    if not isinstance(ip, list) or not all(isinstance(g, str) for g in ip):
        raise ConfigError(f"{path}: 'ignorePaths' must be a list of glob strings")
    budgets = user.get("budgets", {})
    if not isinstance(budgets, dict) or not all(isinstance(v, (int, float)) for v in budgets.values()):
        raise ConfigError(f"{path}: 'budgets' values must be numbers")
