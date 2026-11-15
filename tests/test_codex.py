"""Codex CLI support: the overlay manifest, version sync and agent-neutral skills."""

import json
import re
import unittest

from helpers import PLUGIN_ROOT

CODEX = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
CLAUDE = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"


class CodexManifestTests(unittest.TestCase):
    def setUp(self):
        self.codex = json.loads(CODEX.read_text(encoding="utf-8"))
        self.claude = json.loads(CLAUDE.read_text(encoding="utf-8"))

    def test_versions_match_across_manifests(self):
        # Both clients cache installs by version: a manifest left behind never reaches its users.
        import sys
        sys.path.insert(0, str(PLUGIN_ROOT / "lib"))
        import wclib
        self.assertEqual({self.codex["version"], self.claude["version"], wclib.__version__}, {wclib.__version__})

    def test_identity_matches_claude_manifest(self):
        for key in ("name", "description", "license", "homepage", "repository"):
            self.assertEqual(self.codex[key], self.claude[key], key)

    def test_paths_exist_inside_plugin(self):
        ui = self.codex["interface"]
        for rel in (self.codex["skills"], self.codex["hooks"], ui["composerIcon"], ui["logo"]):
            self.assertTrue(rel.startswith("./") and ".." not in rel, rel)
            self.assertTrue((PLUGIN_ROOT / rel).exists(), rel)
        self.assertEqual(sorted(p.parent.name for p in (PLUGIN_ROOT / "skills").glob("*/SKILL.md")),
                         ["container-standards", "data-standards", "owasp-security", "web-standards"])

    def test_interface_listing(self):
        ui = self.codex["interface"]
        for key in ("displayName", "shortDescription", "longDescription", "developerName", "category"):
            self.assertTrue(ui.get(key), key)
        self.assertTrue(1 <= len(ui["defaultPrompt"]) <= 3)


class AgentNeutralSkillTests(unittest.TestCase):
    def test_every_skill_explains_plugin_root_for_codex(self):
        for skill in sorted((PLUGIN_ROOT / "skills").glob("*/SKILL.md")):
            text = skill.read_text(encoding="utf-8")
            if "${CLAUDE_PLUGIN_ROOT}" in text:
                self.assertIn("Codex and other agents", text, skill.parent.name)

    def test_skills_do_not_address_claude_as_the_agent(self):
        word = re.compile(r"\bClaude\b(?! Code)")
        for p in sorted((PLUGIN_ROOT / "skills").glob("*/SKILL.md")) + sorted((PLUGIN_ROOT / "skills").glob("*/references/*.md")):
            hits = [line for line in p.read_text(encoding="utf-8").splitlines() if word.search(line)]
            self.assertEqual(hits, [], p.relative_to(PLUGIN_ROOT).as_posix())

    def test_ask_steps_have_a_codex_fallback(self):
        for p in sorted((PLUGIN_ROOT / "skills").glob("*/SKILL.md")) + sorted((PLUGIN_ROOT / "skills").glob("*/references/*.md")):
            text = p.read_text(encoding="utf-8")
            if "AskUserQuestion" in text:
                self.assertRegex(text, r"numbered (question|list)", p.name)


if __name__ == "__main__":
    unittest.main()
