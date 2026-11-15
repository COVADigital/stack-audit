"""Git-aware, read-only file discovery."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .textutil import any_glob

DEFAULT_SKIP_DIRS = {
    "node_modules", ".next", ".git", "dist", "build", "out", "coverage",
    ".turbo", ".vercel", ".cache", "__pycache__", ".venv", "venv", ".pnpm-store",
}

JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
CSS_EXTS = {".css", ".scss", ".sass", ".less", ".pcss"}

MAX_FILE_BYTES = 1_500_000  # skip generated/minified giants


def run_git(root: Path, *args: str, timeout: int = 30) -> str | None:
    """Run a read-only git command. Returns stdout, or None if git/repo unavailable."""
    try:
        res = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return res.stdout if res.returncode == 0 else None


def is_git_repo(root: Path) -> bool:
    out = run_git(root, "rev-parse", "--is-inside-work-tree")
    return bool(out and out.strip() == "true")


def git_toplevel(root: Path) -> Path | None:
    """The repository root containing `root` (may be a parent, e.g. in monorepos)."""
    out = run_git(Path(root), "rev-parse", "--show-toplevel")
    return Path(out.strip()).resolve() if out and out.strip() else None


def repo_paths(root: Path) -> list[Path]:
    """[root] plus the git toplevel if different: where .github/, hooks and .gitignore may live."""
    root = Path(root).resolve()
    top = git_toplevel(root)
    return [root] + ([top] if top and top != root else [])


def default_base(root: Path) -> str | None:
    """Best guess at the base ref for --changed: origin/HEAD, origin/main, main, master."""
    out = run_git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    if out and out.strip():
        return out.strip()
    for ref in ("origin/main", "origin/master", "main", "master"):
        if run_git(root, "rev-parse", "--verify", "--quiet", ref) is not None:
            return ref
    return None


@dataclass
class SourceFile:
    root: Path
    rel: str  # forward-slash path relative to root

    @property
    def path(self) -> Path:
        return self.root / self.rel

    @property
    def ext(self) -> str:
        return os.path.splitext(self.rel)[1].lower()

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    def read(self) -> str:
        try:
            if self.path.stat().st_size > MAX_FILE_BYTES:
                return ""
            data = self.path.read_bytes()
        except OSError:
            return ""
        return data.decode("utf-8", errors="replace")

    def has_crlf(self) -> bool:
        try:
            return b"\r\n" in self.path.read_bytes()[:200_000]
        except OSError:
            return False


class Walker:
    """Enumerates files under `root`.

    In a git repo, uses `git ls-files` (tracked + untracked-not-ignored), so
    .gitignore is respected. Otherwise walks the tree skipping DEFAULT_SKIP_DIRS.
    `changed_only` restricts to files changed relative to `base` (plus untracked).
    """

    def __init__(
        self,
        root: str | Path,
        *,
        ignore_paths: list[str] | None = None,
        changed_only: bool = False,
        base: str | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.ignore_paths = list(ignore_paths or [])
        self.git = is_git_repo(self.root)
        self.changed_only = changed_only
        self.base = base
        self.notes: list[str] = []
        # A folder ignored by an enclosing repo would list zero files via ls-files: walk it instead.
        if self.git and run_git(self.root, "check-ignore", "-q", ".") is not None:
            self.git = False
            self.notes.append("--root is gitignored by the enclosing repository; scanning the folder directly")
        self._files: list[str] | None = None

    # ----------------------------------------------------------------- listing

    def _git_files(self) -> list[str] | None:
        out = run_git(self.root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        if out is None:
            return None
        return [p for p in out.split("\0") if p]

    def _walk_files(self) -> list[str]:
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
            for fn in filenames:
                full = Path(dirpath) / fn
                found.append(full.relative_to(self.root).as_posix())
        return found

    def _changed_files(self) -> set[str] | None:
        base = self.base or default_base(self.root)
        if not base:
            self.notes.append("--changed: no base ref found; scanning all files")
            return None
        merge_base = run_git(self.root, "merge-base", "HEAD", base)
        ref = merge_base.strip() if merge_base else base
        diff = run_git(self.root, "diff", "--name-only", "-z", "--diff-filter=ACMR", ref)
        untracked = run_git(self.root, "ls-files", "-z", "--others", "--exclude-standard")
        if diff is None:
            self.notes.append(f"--changed: git diff against {base} failed; scanning all files")
            return None
        changed = {p for p in diff.split("\0") if p}
        if untracked:
            changed |= {p for p in untracked.split("\0") if p}
        self.notes.append(f"--changed: {len(changed)} file(s) changed vs {base}")
        return changed

    def all_files(self) -> list[str]:
        if self._files is not None:
            return self._files
        files = self._git_files() if self.git else None
        if files is None:
            files = self._walk_files()
        # Even in git mode, never descend into vendored/build dirs that slipped in.
        files = [
            f for f in files
            if not any(part in DEFAULT_SKIP_DIRS for part in f.split("/")[:-1])
            and not any_glob(f, self.ignore_paths)
            and (self.root / f).is_file()
        ]
        if self.changed_only and self.git:
            changed = self._changed_files()
            if changed is not None:
                files = [f for f in files if f in changed]
        elif self.changed_only:
            self.notes.append("--changed: not a git repo; scanning all files")
        self._files = sorted(files)
        return self._files

    # ----------------------------------------------------------------- queries

    def files(self, *, exts: set[str] | None = None, globs: list[str] | None = None) -> list[SourceFile]:
        result = []
        for rel in self.all_files():
            ext = os.path.splitext(rel)[1].lower()
            if exts is not None and ext not in exts:
                continue
            if globs is not None and not any_glob(rel, globs):
                continue
            result.append(SourceFile(self.root, rel))
        return result

    def js_files(self) -> list[SourceFile]:
        return self.files(exts=JS_EXTS)

    def css_files(self) -> list[SourceFile]:
        return self.files(exts=CSS_EXTS)

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def tracked(self, rel: str) -> bool:
        """True if `rel` is tracked by git (False outside a repo)."""
        if not self.git:
            return False
        out = run_git(self.root, "ls-files", "--error-unmatch", rel)
        return out is not None
