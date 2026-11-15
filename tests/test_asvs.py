"""Tests for wclib.asvs and the ASVS requirement features of the owasp-security scripts.

The fixture uses made-up requirement text: no CC BY-SA ASVS text is stored in this repo (D7).
Subprocesses get a temporary home folder, so a real ~/.claude/data/owasp-asvs install can't leak in.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from helpers import PLUGIN_ROOT
from test_owasp import MiniClone
from wclib import asvs

SCRIPTS = PLUGIN_ROOT / "skills" / "owasp-security" / "scripts"


def _req(ch, ch_name, sec, sec_name, rid, level):
    return {"chapter_id": ch, "chapter_name": ch_name, "section_id": sec, "section_name": sec_name,
            "req_id": rid, "req_description": f"Synthetic test requirement {rid}.", "L": str(level)}


FIXTURE = {"requirements": [
    _req("V3", "Web Frontend Security", "V3.3", "Cookie Setup", "V3.3.1", 1),
    _req("V3", "Web Frontend Security", "V3.3", "Cookie Setup", "V3.3.2", 2),
    _req("V3", "Web Frontend Security", "V3.4", "Browser Security Mechanism Headers", "V3.4.1", 3),
    _req("V15", "Secure Coding and Architecture", "V15.1", "Secure Coding and Architecture Documentation", "V15.1.1", 1),
]}


class AsvsCase(MiniClone):
    def setUp(self):
        super().setUp()
        self.asvs_file = self.write("asvs/asvs-5.0.0.flat.json", json.dumps(FIXTURE))
        self.sha = hashlib.sha256(self.asvs_file.read_bytes()).hexdigest()
        self.home = self.dir / "home"
        self.home.mkdir()

    def env(self, installed=True):
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home)}
        env.pop("STACK_AUDIT_OWASP_ASVS", None)
        env["STACK_AUDIT_OWASP_ASVS_SHA256"] = self.sha
        if installed:
            env["STACK_AUDIT_OWASP_ASVS"] = str(self.asvs_file)
        return env

    def run_script(self, name, *args, installed=True):
        return subprocess.run([sys.executable, str(SCRIPTS / name), *args, "--clone", str(self.clone),
                               "--data-dir", str(self.data)], capture_output=True, text=True, encoding="utf-8",
                              env=self.env(installed))

    def load(self):
        with mock.patch.dict(os.environ, {"STACK_AUDIT_OWASP_ASVS_SHA256": self.sha}):
            return asvs.load(self.asvs_file)


class LibraryTests(AsvsCase):
    def test_load_index_and_integrity(self):
        d = self.load()
        self.assertEqual(len(d["requirements"]), 4)
        self.assertEqual(d["sections"]["V3.3"]["requirements"], ["V3.3.1", "V3.3.2"])
        self.assertEqual(d["requirements"]["V3.4.1"]["level"], 3)
        self.assertEqual(asvs.in_level(d, ["V3.3.1", "V3.3.2", "V3.4.1"], 2), ["V3.3.1", "V3.3.2"])
        with self.assertRaisesRegex(asvs.AsvsError, "does not match the pinned SHA-256"):
            asvs.load(self.asvs_file)  # the real pinned hash, not the fixture's
        self.asvs_file.write_bytes(self.asvs_file.read_bytes() + b" ")
        with mock.patch.dict(os.environ, {"STACK_AUDIT_OWASP_ASVS_SHA256": self.sha}), \
                self.assertRaisesRegex(asvs.AsvsError, "pinned SHA-256"):
            asvs.load(self.asvs_file)  # one changed byte
        bad = self.write("asvs/bad.json", '{"other": []}')
        with mock.patch.dict(os.environ, {"STACK_AUDIT_OWASP_ASVS_SHA256": hashlib.sha256(bad.read_bytes()).hexdigest()}), \
                self.assertRaisesRegex(asvs.AsvsError, "not the ASVS flat JSON format"):
            asvs.load(bad)

    def test_missing_file_names_the_download(self):
        with mock.patch.object(asvs, "DEFAULT_PATH", self.dir / "nope.json"), mock.patch.dict(os.environ, {"STACK_AUDIT_OWASP_ASVS": ""}):
            data, why = asvs.try_load()
        self.assertIsNone(data)
        self.assertIn(asvs.DOWNLOAD_URL, why)

    def test_citation_links_and_references(self):
        d = self.load()
        self.assertEqual(asvs.cite_url(d, "V3.3.1"), asvs.SOURCE_BASE + "0x12-V3-Web-Frontend-Security.md#v33-cookie-setup")
        self.assertEqual(asvs.cite_url(d, "V15.1"), asvs.SOURCE_BASE + "0x24-V15-Secure-Coding-and-Architecture.md"
                         "#v151-secure-coding-and-architecture-documentation")
        self.assertEqual(asvs.github_anchor("V1.4 Memory, String, and Unmanaged Code"), "v14-memory-string-and-unmanaged-code")
        refs = asvs.refs_in_text("See V3.3.1. Also V3.3, ASVS v4.0.3, V5.0.0 and (V12.1.2).\nNext: V3.3.10")
        self.assertEqual(refs, [(1, "req", "V3.3.1"), (1, "req", "V12.1.2"), (1, "section", "V3.3"), (2, "req", "V3.3.10")])

    def test_pinned_release_constants(self):
        self.assertRegex(asvs.SHA256, r"^[0-9a-f]{64}$")
        self.assertIn(asvs.RELEASE_TAG, asvs.DOWNLOAD_URL)
        self.assertIn(asvs.VERSION, asvs.DOWNLOAD_URL)
        self.assertTrue(asvs.DOWNLOAD_URL.startswith("https://github.com/OWASP/ASVS/releases/download/"))
        self.assertEqual(sorted(asvs.CHAPTER_FILES, key=lambda c: int(c[1:])), [f"V{i}" for i in range(1, 18)])
        for ch, name in asvs.CHAPTER_FILES.items():
            self.assertRegex(name, rf"^0x\d\d-{ch}-[\w-]+\.md$")


class ScriptTests(AsvsCase):
    def test_read_requirement(self):
        res = self.run_script("read_requirement.py", "V3.3.1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("## V3.3.1 (L1) · V3.3 Cookie Setup", res.stdout)
        self.assertIn("Synthetic test requirement V3.3.1.", res.stdout)
        self.assertIn("cite: " + asvs.SOURCE_BASE + "0x12-V3-Web-Frontend-Security.md#v33-cookie-setup", res.stdout)
        self.assertIn("`Session_Management`", res.stdout)  # related sheet from the mini clone's IndexASVS
        self.assertIn("CC BY-SA 4.0", res.stdout)
        res = self.run_script("read_requirement.py", "--chapter", "V3", "--level", "2", "--format", "json")
        self.assertEqual([r["id"] for r in json.loads(res.stdout)["requirements"]], ["V3.3.1", "V3.3.2"])
        res = self.run_script("read_requirement.py", "V3.3.9", "--section", "V9.9")
        self.assertEqual(res.returncode, 2)
        self.assertIn("V3.3.9, V9.9", res.stderr)

    def test_read_requirement_without_data(self):
        res = self.run_script("read_requirement.py", "V3.3.1", installed=False)
        self.assertEqual(res.returncode, 2)
        self.assertIn(asvs.DOWNLOAD_URL, res.stderr)

    def test_find_sheets_lists_requirements_or_falls_back(self):
        res = self.run_script("find_sheets.py", "--asvs", "V3.3")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("- `V3.3.2` (L2) Synthetic test requirement V3.3.2.", res.stdout)
        self.assertIn("read_requirement.py --section V3.3", res.stdout)
        res = self.run_script("find_sheets.py", "--asvs", "V3.3", installed=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("V3.3.1", res.stdout)
        self.assertIn("section level only", res.stdout)

    def test_verify_citations_checks_asvs_ids(self):
        good = self.write("docs/good.md", "Cookies: ASVS 5.0 V3.3.1 and V3.3.2; headers in V3.4.\n")
        res = self.run_script("verify_citations.py", str(good))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("3 ASVS 5.0.0 reference(s) checked", res.stdout)
        bad = self.write("docs/bad.md", "Line one.\nSee V3.3.9 and section V9.9 (ASVS v4.0.3 is ignored).\n")
        res = self.run_script("verify_citations.py", str(bad), "--format", "json")
        self.assertEqual(res.returncode, 1)
        found = sorted((f["rule"], f["line"], f["message"]) for f in json.loads(res.stdout)["findings"])
        self.assertEqual([(r, ln) for r, ln, _ in found], [("owasp.04", 2), ("owasp.04", 2)])
        self.assertTrue(any("V9.9" in m for _, _, m in found))
        res = self.run_script("verify_citations.py", str(bad), "--format", "json", installed=False)
        self.assertEqual(res.returncode, 0)  # can't check without data: info, never a pass claim
        self.assertEqual([f["rule"] for f in json.loads(res.stdout)["findings"]], ["owasp.05"])

    def test_check_freshness_asvs(self):
        res = self.run_script("check_freshness.py", "--asvs")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("4 requirements in 3 sections", res.stdout)
        res = self.run_script("check_freshness.py", "--asvs", installed=False)
        self.assertEqual(res.returncode, 2)
        self.assertIn("section level", res.stdout)


class StartupNoteTests(AsvsCase):
    def note(self, installed):
        out = subprocess.run([sys.executable, str(PLUGIN_ROOT / "hooks" / "session_start.py")], capture_output=True,
                             text=True, encoding="utf-8", env=self.env(installed), cwd=self.dir).stdout
        return json.loads(out)["hookSpecificOutput"]["additionalContext"]

    def test_note_only_when_missing(self):
        ctx = self.note(installed=False)
        self.assertIn("ASVS 5.0.0 requirement text is not installed", ctx)
        self.assertIn(asvs.DOWNLOAD_URL, ctx)
        self.assertIn("only after they agree", ctx)
        self.assertNotIn("ASVS 5.0.0 requirement text", self.note(installed=True))


if __name__ == "__main__":
    unittest.main()
