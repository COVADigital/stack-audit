#!/usr/bin/env python3
"""Git & CI security audit (rules git.*, 01-git-security.md). Read-only.

    python audit_git.py --root REPO [--format md|json|sarif] [--strict]
                        [--scan]     run gitleaks over history if installed (local only)
                        [--remote]   read GitHub settings with `gh api` (branch rules, collaborators, keys)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.cli import build_parser, finish, make_context
from wclib.findings import Report
from wclib.rules import RuleBook
from wclib.walker import default_base, repo_paths, run_git

SKILL = Path(__file__).resolve().parents[1]
SECRET_FILE = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|[^/]+\.(pem|key|p12|pfx|keystore|jks)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?)$")
SECRET_FILE_OK = re.compile(r"\.(example|sample|template|dist|defaults)$|\.pub$|(^|/)\.env\.(test|ci)$")
GITIGNORE_NEEDS = {
    ".env": [r"^/?\.env\*?$", r"^/?\.env$", r"^\*\*/\.env"],
    ".env.* (local variants)": [r"^/?\.env\.\*", r"^/?\.env\*", r"^/?\.env\*\.local", r"^\.env\.local"],
    "node_modules": [r"node_modules"],
    ".next": [r"^/?\.next/?"],
    "*.pem": [r"\*\.pem"],
}
SCANNER = re.compile(r"gitleaks|trufflehog|detect-secrets|secretlint|ggshield", re.I)


def gh(*args: str) -> tuple[int, str]:
    if not shutil.which("gh"):
        return 127, "gh not installed"
    try:
        res = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return res.returncode, res.stdout if res.returncode == 0 else (res.stderr or res.stdout)


class GitAudit:
    def __init__(self, ctx, rb: RuleBook, report: Report) -> None:
        self.ctx, self.rb, self.report = ctx, rb, report
        self.root = ctx.root
        self.places = repo_paths(self.root)  # audited dir, then the git toplevel if it's a parent
        if len(self.places) > 1:
            self.report.meta["git_toplevel"] = str(self.places[1])

    def add(self, rule: str, msg: str, **kw) -> None:
        self.report.add(self.rb.make(rule, msg, **kw))

    def read(self, rel: str) -> str:
        """First match of `rel` in the audited dir or the git toplevel."""
        for base in self.places:
            p = base / rel
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")
        return ""

    def exists(self, rel: str) -> bool:
        return any((base / rel).exists() for base in self.places)

    # --------------------------------------------------------------- local repo
    def signing(self) -> None:
        if (run_git(self.root, "config", "--get", "commit.gpgsign") or "").strip().lower() != "true":
            self.add("git.01", "Commit signing is not enabled (commit.gpgsign)",
                     fix_hint="git config --global gpg.format ssh; user.signingkey ~/.ssh/<key>.pub; commit.gpgsign true")
        sigs = (run_git(self.root, "log", "-20", "--format=%G?") or "").split()
        if sigs:
            unsigned = sum(1 for s in sigs if s == "N")
            if unsigned:
                self.add("git.01", f"{unsigned} of the last {len(sigs)} commits are unsigned", severity="info")

    def gitignore(self) -> None:
        text = "\n".join((b / ".gitignore").read_text(encoding="utf-8", errors="replace")
                         for b in self.places if (b / ".gitignore").is_file())
        if not text:
            self.add("git.04", "No .gitignore: secrets and build output can be committed", file=".gitignore", severity="error",
                     fix_hint="Copy assets/gitignore.nextjs before the next `git add`")
        else:
            lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
            pkg = (self.root / "package.json").exists()
            missing = []
            for label, pats in GITIGNORE_NEEDS.items():
                if label in ("node_modules", ".next") and not pkg:
                    continue
                if not any(re.search(p, l) for p in pats for l in lines):
                    missing.append(label)
            if missing:
                self.add("git.04", f".gitignore does not cover: {', '.join(missing)}", file=".gitignore", severity="warn",
                         fix_hint="See assets/gitignore.nextjs")
        tracked = (run_git(self.root, "ls-files", "-z") or "").split("\0")
        for rel in tracked:
            if rel and SECRET_FILE.search(rel) and not SECRET_FILE_OK.search(rel):
                self.add("git.04", f"Secret-like file is tracked by git: {rel}", file=rel,
                         fix_hint="git rm --cached the file, add it to .gitignore, and rotate anything it contained "
                                  "(it stays in history until rewritten)")
        if not any(r.endswith((".env.example", ".env.sample", ".env.template")) for r in tracked) \
                and (self.root / "package.json").exists():
            self.add("git.04", "No committed .env.example documenting required variables", severity="info")

    def hooks(self, scan: bool) -> None:
        sources = {p: self.read(p) for p in (".pre-commit-config.yaml", ".husky/pre-commit", "lefthook.yml", ".lefthook.yml",
                                              "lefthook.yaml", ".lintstagedrc", ".lintstagedrc.json")}
        pkg = self.read("package.json")
        has_hook = any(SCANNER.search(t) for t in sources.values() if t) or bool(re.search(r'"(pre-commit|lint-staged)"[^}]*gitleaks', pkg))
        if not has_hook:
            self.add("git.05", "No pre-commit secret scan configured (gitleaks / trufflehog / detect-secrets)",
                     fix_hint="assets/pre-commit-config.yaml, or a husky hook running `gitleaks git --pre-commit --redact --staged`")
        workflows = self.workflows()
        all_text = "\n".join(list(sources.values()) + [t for _, t in workflows])
        for m in re.finditer(r"gitleaks\s+(protect|detect)\b", all_text):
            self.add("git.05", f"`gitleaks {m.group(1)}` is deprecated since v8.19", severity="info",
                     fix_hint="Use `gitleaks git` (repos) or `gitleaks dir` (folders)")
            break
        if workflows and not any(SCANNER.search(t) for _, t in workflows):
            self.add("git.05", "No secret scanning in CI as a backstop to the local hook", severity="info")
        if scan:
            self.gitleaks_scan()
        else:
            self.report.skipped.append("History secret scan not run (pass --scan; needs gitleaks installed)")

    def gitleaks_scan(self) -> None:
        exe = shutil.which("gitleaks")
        if not exe:
            self.report.skipped.append("gitleaks not found: install from https://github.com/gitleaks/gitleaks/releases")
            return
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "gl.json"
            subprocess.run([exe, "git", "--no-banner", "--redact", "--report-format", "json", "--report-path", str(out), str(self.root)],
                           capture_output=True, text=True, timeout=600)
            try:
                leaks = json.loads(out.read_text(encoding="utf-8")) if out.exists() else []
            except json.JSONDecodeError:
                leaks = []
        for leak in leaks[:200]:
            self.add("git.05", f"gitleaks: {leak.get('RuleID') or leak.get('Description')} in commit {str(leak.get('Commit'))[:7]}",
                     file=leak.get("File"), line=leak.get("StartLine"),
                     fix_hint="Rotate the credential first, then remove it from history if needed")
        if not leaks:
            self.report.meta["gitleaks"] = "no leaks found"

    def workflows(self) -> list[tuple[str, str]]:
        for base in self.places:
            d = base / ".github" / "workflows"
            if d.is_dir():
                return [(f".github/workflows/{p.name}", p.read_text(encoding="utf-8", errors="replace"))
                        for p in sorted(d.glob("*.y*ml"))]
        return []

    def ci(self) -> None:
        workflows = self.workflows()
        for rel, text in workflows:
            lines = text.splitlines()
            top_perm = any(re.match(r"^permissions\s*:", l) for l in lines)
            jobs_without = []
            in_jobs, current = False, None
            job_perm: dict[str, bool] = {}
            for l in lines:
                if re.match(r"^jobs\s*:", l):
                    in_jobs = True
                    continue
                if in_jobs:
                    mj = re.match(r"^  ([\w-]+)\s*:\s*$", l)
                    if mj:
                        current = mj.group(1)
                        job_perm[current] = False
                    elif current and re.match(r"^    permissions\s*:", l):
                        job_perm[current] = True
            jobs_without = [j for j, ok in job_perm.items() if not ok]
            if not top_perm and jobs_without:
                self.add("git.08", f"Workflow has no `permissions:` (GITHUB_TOKEN gets the repo default) for job(s): {', '.join(jobs_without)}",
                         file=rel, fix_hint="Add top-level `permissions: contents: read` and widen per job only as needed")
            for m in re.finditer(r"permissions\s*:\s*write-all", text):
                self.add("git.08", "permissions: write-all grants every scope", file=rel, line=text.count("\n", 0, m.start()) + 1)
            if re.search(r"^on\s*:[\s\S]*?pull_request_target", text, re.M) and \
                    re.search(r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text):
                self.add("git.08", "pull_request_target checks out untrusted PR code with a privileged token", file=rel,
                         severity="error", fix_hint="Use pull_request, or never check out/run PR code in pull_request_target")
            unpinned: dict[str, int] = {}
            for n, l in enumerate(lines, 1):
                m = re.match(r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^\s'\"#]+)", l)
                if not m:
                    continue
                ref = m.group(1)
                if ref.startswith(("./", "docker://")) or "@" not in ref:
                    continue
                name, version = ref.rsplit("@", 1)
                if not re.fullmatch(r"[0-9a-f]{40}", version):
                    unpinned.setdefault(ref, n)
            for ref, n in unpinned.items():
                self.add("git.09", f"Action not pinned to a commit SHA: {ref}", file=rel, line=n,
                         fix_hint="Pin to the full 40-char SHA with a `# vX.Y.Z` comment; let Dependabot update it")
            for n, l in enumerate(lines, 1):
                if re.search(r"\becho\b[^\n]*\$\{\{\s*secrets\.", l) or re.search(r"\becho\b[^\n]*\$\{?[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)", l):
                    self.add("git.11", "Workflow echoes a secret into the log", file=rel, line=n,
                             fix_hint="Never print secrets; mask derived values with ::add-mask::")
                if re.search(r"\bset\s+-[a-z]*x", l) and "secrets." in text:
                    self.add("git.11", "`set -x` in a workflow that uses secrets can print them", file=rel, line=n, severity="warn")
        dep = self.read(".github/dependabot.yml") or self.read(".github/dependabot.yaml")
        renovate = any(self.exists(p) for p in ("renovate.json", ".github/renovate.json", "renovate.json5", ".renovaterc"))
        if not dep and not renovate:
            self.add("git.09", "No Dependabot (or Renovate) config for automated dependency updates",
                     file=".github/dependabot.yml", fix_hint="Copy assets/dependabot.yml")
        elif dep:
            if (self.root / "package.json").exists() and "npm" not in dep:
                self.add("git.09", "dependabot.yml does not cover the npm ecosystem", file=".github/dependabot.yml")
            if workflows and "github-actions" not in dep:
                self.add("git.09", "dependabot.yml does not cover github-actions", file=".github/dependabot.yml")
        owners = next((p for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS") if self.exists(p)), None)
        if not owners:
            self.add("git.03", "No CODEOWNERS file", fix_hint="Add .github/CODEOWNERS; require code-owner review on sensitive paths")

    def branches(self) -> None:
        base = default_base(self.root)
        if not base:
            return
        short = base.split("/")[-1]
        # `git branch` prefixes: "* " current branch, "+ " checked out in another worktree
        merged = [b.strip().lstrip("*+ ") for b in (run_git(self.root, "branch", "--merged", base) or "").splitlines()]
        merged = [b for b in merged if b and b not in (short, "main", "master") and not b.startswith("(")]
        if merged:
            self.add("git.10", f"{len(merged)} local branch(es) already merged into {base}: {', '.join(merged[:8])}",
                     fix_hint="git branch -d <name>; enable 'Automatically delete head branches'")
        out = run_git(self.root, "for-each-ref", "--format=%(refname:short)|%(committerdate:iso-strict)", "refs/heads") or ""
        now = datetime.now(timezone.utc)
        stale = []
        for line in out.splitlines():
            name, _, date = line.partition("|")
            try:
                if (now - datetime.fromisoformat(date)).days > 90 and name not in (short, "main", "master"):
                    stale.append(name)
            except ValueError:
                continue
        if stale:
            self.add("git.10", f"{len(stale)} branch(es) with no commits in 90+ days: {', '.join(stale[:8])}")

    # --------------------------------------------------------------- remote (gh)
    def remote(self) -> None:
        url = (run_git(self.root, "remote", "get-url", "origin") or "").strip()
        m = re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$", url)
        if not m:
            self.report.skipped.append("--remote: origin is not a GitHub repository")
            return
        repo = f"{m.group(1)}/{m.group(2)}"
        code, out = gh("api", f"repos/{repo}")
        if code != 0:
            self.report.skipped.append(f"--remote: gh api repos/{repo} failed ({out.strip()[:120]})")
            return
        info = json.loads(out)
        branch = info.get("default_branch", "main")
        if not info.get("delete_branch_on_merge"):
            self.add("git.10", "'Automatically delete head branches' is off", fix_hint="gh repo edit --delete-branch-on-merge")
        code, rules_out = gh("api", f"repos/{repo}/rules/branches/{branch}")
        rule_types = {r.get("type"): r for r in json.loads(rules_out)} if code == 0 else {}
        code_p, prot_out = gh("api", f"repos/{repo}/branches/{branch}/protection")
        prot = json.loads(prot_out) if code_p == 0 else {}
        if not rule_types and not prot:
            self.add("git.02", f"Default branch `{branch}` has no ruleset or branch protection",
                     fix_hint="Create a ruleset: block deletion and force-push, require PRs (see 01-git-security §02)")
        else:
            force_blocked = "non_fast_forward" in rule_types or (
                bool(prot) and (prot.get("allow_force_pushes") or {}).get("enabled") is False)
            if not force_blocked:
                self.add("git.02", f"Force-pushes to `{branch}` are not blocked", severity="warn")
            pr_rule = rule_types.get("pull_request", {}).get("parameters", {})
            reviews = pr_rule.get("required_approving_review_count",
                                  (prot.get("required_pull_request_reviews") or {}).get("required_approving_review_count", 0))
            if not reviews:
                self.add("git.03", f"No required approving review on `{branch}` (use a required AI/CI check if solo)")
            if "required_signatures" not in rule_types and not (prot.get("required_signatures") or {}).get("enabled"):
                self.add("git.01", f"Signed commits are not required on `{branch}`", severity="info")
        code, collabs = gh("api", f"repos/{repo}/collaborators", "--jq", ".[].login")
        if code == 0:
            self.report.meta["collaborators"] = collabs.split()
        code, keys = gh("api", f"repos/{repo}/keys", "--jq", ".[] | .title + \" (\" + .created_at[:10] + \")\"")
        if code == 0 and keys.strip():
            self.report.meta["deploy_keys"] = keys.splitlines()
        self.report.not_checked.append("`git.12` review the collaborators/deploy keys listed in meta (quarterly)")

    def run(self, args) -> None:
        self.gitignore()
        if not self.ctx.walker.git:
            # Hooks, CODEOWNERS, Dependabot and CI only make sense for a repository.
            self.report.skipped.append("Not a git repository: only the .gitignore check ran (run `git init` first)")
            self.report.not_checked += self.rb.not_checked("git")
            return
        self.signing()
        self.branches()
        self.hooks(args.scan)
        self.ci()
        if args.remote:
            self.remote()
        self.report.not_checked += self.rb.not_checked("git", ran={"live"} if args.remote else set())


def main() -> int:
    ap = build_parser(__doc__.splitlines()[0])
    ap.add_argument("--scan", action="store_true", help="Run gitleaks over git history (local)")
    ap.add_argument("--remote", action="store_true", help="Query GitHub with gh api (read-only)")
    args = ap.parse_args()
    ctx = make_context(args)
    report = Report(tool="audit_git", root=str(ctx.root))
    GitAudit(ctx, RuleBook(SKILL), report).run(args)
    return finish(report, ctx)


if __name__ == "__main__":
    sys.exit(main())
