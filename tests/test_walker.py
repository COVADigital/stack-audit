import unittest

from helpers import TempRepo
from wclib.walker import Walker


class WalkerNoGitTests(TempRepo):
    def test_skips_vendor_dirs_and_filters(self):
        self.write("src/a.tsx", "x")
        self.write("src/b.css", "y")
        self.write("node_modules/pkg/index.js", "z")
        self.write(".next/static/chunk.js", "z")
        w = Walker(self.dir)
        self.assertFalse(w.git)
        self.assertEqual(w.all_files(), ["src/a.tsx", "src/b.css"])
        self.assertEqual([f.rel for f in w.js_files()], ["src/a.tsx"])
        self.assertEqual([f.rel for f in w.css_files()], ["src/b.css"])

    def test_ignore_paths(self):
        self.write("src/gen/x.ts", "")
        self.write("src/y.ts", "")
        w = Walker(self.dir, ignore_paths=["src/gen/**"])
        self.assertEqual(w.all_files(), ["src/y.ts"])

    def test_changed_without_git_notes_and_scans_all(self):
        self.write("a.ts", "")
        w = Walker(self.dir, changed_only=True)
        self.assertEqual(w.all_files(), ["a.ts"])
        self.assertTrue(any("not a git repo" in n for n in w.notes))

    def test_sourcefile_read_and_crlf(self):
        self.write("win.sh", "echo hi\r\n")
        f = Walker(self.dir).files(globs=["*.sh"])[0]
        self.assertTrue(f.has_crlf())
        self.assertIn("echo hi", f.read())
        self.assertEqual(f.ext, ".sh")


class WalkerGitTests(TempRepo):
    def setUp(self):
        super().setUp()
        self.init_git()
        self.write(".gitignore", ".env\nbuild-out/\n")
        self.write("src/a.ts", "a")
        self.write(".env", "SECRET=1")
        self.write("build-out/x.js", "")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "init")

    def test_respects_gitignore_and_includes_untracked(self):
        self.write("src/new.ts", "n")  # untracked, not ignored
        w = Walker(self.dir)
        self.assertTrue(w.git)
        self.assertEqual(w.all_files(), [".gitignore", "src/a.ts", "src/new.ts"])
        self.assertTrue(w.tracked("src/a.ts"))
        self.assertFalse(w.tracked("src/new.ts"))

    def test_root_ignored_by_enclosing_repo_is_walked(self):
        # Found by the M7 eval: auditing a gitignored subfolder listed zero files.
        self.write("build-out/app/page.tsx", "x")
        w = Walker(self.dir / "build-out")
        self.assertFalse(w.git)
        self.assertEqual(w.all_files(), ["app/page.tsx", "x.js"])
        self.assertTrue(any("gitignored" in n for n in w.notes))

    def test_changed_only(self):
        self.git("checkout", "-q", "-b", "feature")
        self.write("src/b.ts", "b")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "b")
        self.write("src/c.ts", "c")  # untracked counts as changed
        w = Walker(self.dir, changed_only=True, base="main")
        self.assertEqual(w.all_files(), ["src/b.ts", "src/c.ts"])


if __name__ == "__main__":
    unittest.main()
