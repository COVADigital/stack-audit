"""Put the plugin's shared `lib/` on sys.path.

Every script does `import _bootstrap  # noqa: F401` first. Works from any
working directory because it locates the plugin root by its manifest.
"""

import sys
from pathlib import Path


def plugin_root(start: Path) -> Path:
    for parent in [start, *start.parents]:
        if (parent / ".claude-plugin" / "plugin.json").exists():
            return parent
    raise RuntimeError(f"stack-audit plugin root not found above {start}")


ROOT = plugin_root(Path(__file__).resolve().parent)
_lib = str(ROOT / "lib")
if _lib not in sys.path:
    sys.path.insert(0, _lib)
