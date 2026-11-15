import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"


class SessionStartHookTests(unittest.TestCase):
    def test_hooks_json_points_at_existing_script(self):
        cfg = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        cmd = cfg["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/hooks/session_start.py", cmd)
        self.assertTrue(HOOK.is_file())

    def test_script_prints_valid_context_naming_every_skill(self):
        out = subprocess.run([sys.executable, str(HOOK)], capture_output=True, check=True).stdout
        payload = json.loads(out.decode("utf-8"))["hookSpecificOutput"]
        self.assertEqual(payload["hookEventName"], "SessionStart")
        for skill in sorted(p.name for p in (ROOT / "skills").iterdir() if (p / "SKILL.md").is_file()):
            self.assertIn(f"stack-audit:{skill}", payload["additionalContext"])


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


def _age(clone: Path, days: int):
    """Make the clone look like it was last fetched `days` ago."""
    old = time.time() - days * 86400
    for name in ("HEAD", "FETCH_HEAD"):
        f = clone / ".git" / name
        if f.exists():
            os.utime(f, (old, old))


class OwaspCloneNoteTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)  # git leaves read-only files on Windows
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    def _context(self, clone: str = "", auto: str = "") -> str:
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "STACK_AUDIT_OWASP_CHEATSHEETS": clone, "STACK_AUDIT_OWASP_AUTO_UPDATE": auto}
        out = subprocess.run([sys.executable, str(HOOK)], capture_output=True, check=True, env=env, cwd=self.home).stdout
        return json.loads(out.decode("utf-8"))["hookSpecificOutput"]["additionalContext"]

    def _fake_clone(self) -> Path:
        clone = self.home / "sheets"
        (clone / "cheatsheets").mkdir(parents=True)
        (clone / "Index.md").write_text("# Index\n", encoding="utf-8")
        (clone / ".git").mkdir()
        (clone / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        return clone

    def test_missing_clone_offers_setup(self):
        ctx = self._context()
        self.assertIn("git clone https://github.com/OWASP/CheatSheetSeries.git", ctx)
        self.assertIn("only after they agree", ctx)

    def test_fresh_clone_says_nothing(self):
        ctx = self._context(str(self._fake_clone()))
        self.assertNotIn("git clone", ctx)
        self.assertNotIn("pull --ff-only", ctx)

    def test_stale_clone_offers_update(self):
        clone = self._fake_clone()
        _age(clone, 45)
        ctx = self._context(str(clone))
        self.assertIn("last updated 45 days ago", ctx)
        self.assertIn("pull --ff-only", ctx)
        self.assertIn("only after they agree", ctx)

    def test_auto_update_falls_back_to_offer_when_pull_fails(self):
        clone = self._fake_clone()  # not a real repository, so the pull fails
        _age(clone, 45)
        ctx = self._context(str(clone), auto="1")
        self.assertIn("pull --ff-only", ctx)
        self.assertNotIn("updated automatically", ctx)

    def test_auto_update_pulls_only_when_enabled(self):
        origin = self.home / "origin"
        (origin / "cheatsheets").mkdir(parents=True)
        (origin / "Index.md").write_text("# Index\n", encoding="utf-8")
        (origin / "cheatsheets" / "A_Cheat_Sheet.md").write_text("# A\n", encoding="utf-8")
        _git(origin, "init", "-q")
        _git(origin, "add", "-A")
        _git(origin, "commit", "-q", "-m", "one")
        clone = self.home / "clone"
        _git(self.home, "clone", "-q", str(origin), str(clone))
        new_sheet = clone / "cheatsheets" / "B_Cheat_Sheet.md"
        (origin / "cheatsheets" / "B_Cheat_Sheet.md").write_text("# B\n", encoding="utf-8")
        _git(origin, "add", "-A")
        _git(origin, "commit", "-q", "-m", "two")
        _age(clone, 45)

        self.assertIn("pull --ff-only", self._context(str(clone)))  # off by default: offer only
        self.assertFalse(new_sheet.exists())

        self.assertIn("updated automatically", self._context(str(clone), auto="1"))
        self.assertTrue(new_sheet.exists())
        self.assertNotIn("pull --ff-only", self._context(str(clone), auto="1"))  # fresh again: quiet


if __name__ == "__main__":
    unittest.main()


EDIT_HOOK = ROOT / "hooks" / "post_edit.py"


class PostEditHookTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="wc-hook-"))
        (self.dir / "package.json").write_text('{"dependencies": {"next": "16.0.0"}}', encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_hook(self, rel, content, env=None, tool="Write"):
        f = self.dir / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
        payload = {"hook_event_name": "PostToolUse", "tool_name": tool, "cwd": str(self.dir),
                   "tool_input": {"file_path": str(f)}}
        res = subprocess.run([sys.executable, str(EDIT_HOOK)], input=json.dumps(payload), capture_output=True,
                             text=True, encoding="utf-8", env={**os.environ, **(env or {})}, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)["hookSpecificOutput"]["additionalContext"] if res.stdout.strip() else ""

    def test_hooks_json_registers_post_edit(self):
        cfg = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        entry = cfg["hooks"]["PostToolUse"][0]
        self.assertEqual(set(entry["matcher"].split("|")), {"Write", "Edit", "MultiEdit"})
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/hooks/post_edit.py", entry["hooks"][0]["command"])

    def test_flags_errors_in_the_edited_file_only(self):
        (self.dir / "app").mkdir()
        (self.dir / "app" / "other.ts").write_text("const t = 'sk_live_" + "a" * 24 + "';", encoding="utf-8")
        ctx = self.run_hook("app/u/page.tsx", "export default function P({ bio }) {\n"
                                              "  return <div dangerouslySetInnerHTML={{ __html: bio }} />;\n}\n")
        self.assertIn("sec.01 line 2", ctx)
        self.assertIn("app/u/page.tsx", ctx)
        self.assertNotIn("other.ts", ctx)
        self.assertNotIn("sec.03", ctx)  # project-wide header findings stay out

    def test_clean_file_and_other_types_are_silent(self):
        self.assertEqual(self.run_hook("app/ok.tsx", "export const A = () => <p>hi</p>;\n", tool="Edit"), "")
        self.assertEqual(self.run_hook("README.md", "el.innerHTML = x; eval(y)\n"), "")

    def test_compose_secret(self):
        ctx = self.run_hook("compose.yaml", "services:\n  db:\n    image: postgres:17\n"
                                            "    environment: { POSTGRES_PASSWORD: hunter2 }\n")
        self.assertIn("csec.01", ctx)
        self.assertNotIn("hunter2", ctx)

    def test_opt_out(self):
        bad = "export const f = (c) => eval(c);\n"
        self.assertIn("sec.01", self.run_hook("lib/a.ts", bad))
        self.assertEqual(self.run_hook("lib/a.ts", bad, env={"STACK_AUDIT_ON_EDIT": "0"}), "")
        (self.dir / "stack-audit.config.json").write_text('{"hooks": {"onEdit": false}}', encoding="utf-8")
        self.assertEqual(self.run_hook("lib/a.ts", bad), "")

    def test_bad_payload_never_fails(self):
        res = subprocess.run([sys.executable, str(EDIT_HOOK)], input="not json", capture_output=True, text=True)
        self.assertEqual((res.returncode, res.stdout), (0, ""))
