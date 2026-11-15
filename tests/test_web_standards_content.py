"""Content integrity tests for skills/web-standards."""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import PLUGIN_ROOT
from wclib.config import load_config

SKILL = PLUGIN_ROOT / "skills" / "web-standards"
REFS = SKILL / "references"
OWASP_CANDIDATES = [
    Path.home() / ".claude" / "data" / "owasp-cheatsheets" / "cheatsheets",
    PLUGIN_ROOT.parent / "CheatSheetSeries" / "cheatsheets",
]

# Patterns that must not appear in references, unless the same line marks them as legacy/deprecated.
STALE_PATTERNS = {
    r"revalidateTag\('[\w-]+'\)": "deprecated|legacy|one-arg",
    r"\bpriority\b(?!\s*=)": "deprecated|fetchpriority",
    r"z\.string\(\)\.(email|url)\(\)": None,
    r"\$queryRaw|findMany|findUnique": None,
    r"interest-cohort=\(\)": None,
    r"gitleaks protect": "deprecated",
    r"(?<!\()cookies\(\)\.set\(": None,
    r"middleware\.ts": r"formerly|before|was middleware",
    r"force-dynamic|unstable_cache|export const revalidate": "legacy",
    r"runtime = 'edge'": "legacy|not supported",
}


def frontmatter(text: str) -> dict:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    fm = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return fm


class RuleIndexTests(unittest.TestCase):
    def test_rule_index_in_sync(self):
        res = subprocess.run(
            [sys.executable, str(SKILL / "scripts" / "build_rule_index.py"), "--check"],
            capture_output=True, text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)


class SkillFileTests(unittest.TestCase):
    def setUp(self):
        self.text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.fm = frontmatter(self.text)

    def test_frontmatter(self):
        self.assertEqual(self.fm["name"], "web-standards")
        self.assertLessEqual(len(self.fm["description"]), 1024)
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/scripts/stack_profile.py", self.fm["allowed-tools"])

    def test_referenced_files_exist(self):
        for ref in set(re.findall(r"`(\d{2}-[\w-]+\.md|next16-cache-model\.md|rule-index\.md)`", self.text)):
            self.assertTrue((REFS / ref).exists(), f"SKILL.md mentions missing reference {ref}")
        assets_line = next(l for l in self.text.splitlines() if "holds starting templates" in l)
        listed = re.findall(r"`([\w.-]+)`", assets_line.split("templates:", 1)[1])
        self.assertGreaterEqual(len(listed), 10)
        for asset in listed:
            self.assertTrue((SKILL / "assets" / asset).exists(), f"SKILL.md lists missing asset {asset}")
        for asset in re.findall(r"assets/([\w.-]+)", self.text):
            self.assertTrue((SKILL / "assets" / asset).exists(), f"SKILL.md mentions missing asset {asset}")
        self.assertTrue((PLUGIN_ROOT / "scripts" / "stack_profile.py").exists())


class FreshnessTests(unittest.TestCase):
    def test_no_stale_patterns(self):
        problems = []
        for path in sorted(REFS.glob("*.md")):
            # The cache-model guide is the legacy↔new comparison: only name checks apply there.
            migration_doc = path.name in {"next16-cache-model.md", "rule-index.md"}
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for pattern, allowed in STALE_PATTERNS.items():
                    if migration_doc and allowed is not None:
                        continue
                    if re.search(pattern, line, re.I if allowed is None else 0):
                        if allowed and re.search(allowed, line, re.I):
                            continue
                        problems.append(f"{path.name}:{n}: /{pattern}/ → {line.strip()[:100]}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_reference_has_banner(self):
        for path in sorted(REFS.glob("0*.md")):
            head = path.read_text(encoding="utf-8")[:600]
            self.assertIn("**Applies to:**", head, path.name)
            self.assertIn("**Rule IDs:**", head, path.name)


class OwaspReferenceTests(unittest.TestCase):
    def _clone(self):
        for c in OWASP_CANDIDATES:
            if c.is_dir():
                return c
        self.skipTest("OWASP CheatSheetSeries clone not found")

    def _named_sheets(self) -> set[str]:
        meta = json.loads((SKILL / "rules.json").read_text(encoding="utf-8"))
        names = {s for dom in meta["rules"].values() for e in dom.values() if len(e) > 2 for s in e[2]}
        for path in REFS.glob("0*.md"):
            text = path.read_text(encoding="utf-8")
            if "## OWASP mapping" in text:
                table = text.split("## OWASP mapping", 1)[1]
                for row in re.findall(r"^\|[^|]+\|\s*([^|]+?)\s*\|$", table, re.M):
                    names |= {s.strip() for s in row.split(",") if s.strip() and not s.strip().startswith("OWASP")}
        names.discard("---")
        return names

    def test_named_sheets_exist(self):
        clone = self._clone()
        missing = sorted(n for n in self._named_sheets() if not (clone / f"{n}_Cheat_Sheet.md").exists())
        self.assertEqual(missing, [], f"OWASP sheets not in clone: {missing}")


class AssetTests(unittest.TestCase):
    def test_config_template_loads(self):
        cfg = load_config(SKILL, SKILL / "assets" / "stack-audit.config.json")
        self.assertEqual(cfg["budgets"]["initialJsGzipKb"], 170)

    def test_json_assets_parse(self):
        for p in (SKILL / "assets").glob("*.json"):
            json.loads(p.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
