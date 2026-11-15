import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "lib"))


class TempRepo(unittest.TestCase):
    """Test case with a throwaway project directory."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="wc-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, rel: str, content: str = "") -> Path:
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="")
        return p

    def git(self, *args: str) -> str:
        res = subprocess.run(
            ["git", "-C", str(self.dir), "-c", "user.email=test@example.com", "-c", "user.name=test",
             "-c", "commit.gpgsign=false", *args],
            capture_output=True, text=True, check=True,
        )
        return res.stdout

    def init_git(self) -> None:
        self.git("init", "-q", "-b", "main")
