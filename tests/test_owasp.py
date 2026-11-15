"""Tests for wclib.owasp and the owasp-security scripts."""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import PLUGIN_ROOT, TempRepo
from wclib.owasp import (
    build_catalog, find_sheet, heading_text, load_catalog, parse_asvs_index, parse_sections,
    parse_top10_index, section_text, section_url, slugify,
)

SCRIPTS = PLUGIN_ROOT / "skills" / "owasp-security" / "scripts"
REAL_CLONES = [Path.home() / ".claude" / "data" / "owasp-cheatsheets", PLUGIN_ROOT.parent / "CheatSheetSeries"]

SHEET_A = """# Session Management Cheat Sheet

## Introduction

Sessions identify users. Never store a JWT in localStorage.

## Cookies

### Secure Attribute

Set `Secure` on session cookies.

```bash
# not a heading
```

### Secure Attribute

Duplicate heading text gets a suffixed anchor.

## JavaScript: Tokens & `HttpOnly`

Use HttpOnly cookies for csrf-safe sessions with cross-site request forgery defenses.

## References

- [OWASP](https://owasp.org)
"""

SHEET_B = """# Cross-Site Request Forgery Prevention Cheat Sheet

## Introduction

CSRF tricks a browser into sending requests. Cross-Site Request Forgery defenses include tokens.

## Token Based Mitigation

Use synchronizer tokens for csrf protection.
"""

DRAFT = """# React Security Cheat Sheet

## Avoid dangerouslySetInnerHTML

Sanitize HTML.
"""

INDEX = """# Index
[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md) ![Java](assets/Index_Java.svg) ![Javascript](assets/Index_Javascript.svg)
[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
"""

ASVS = """# ASVS Index

## Table of Contents

- [V3: Web Frontend Security](#v3-web-frontend-security)

## Objective

Based on ASVS 5.0.x.

## V3: Web Frontend Security

### V3.3 Cookie Setup

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

### V3.4 Browser Security Mechanism Headers

[Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

## V15: Secure Coding and Architecture

### V15.1: Secure Coding and Architecture Documentation

[Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)
"""

TOP10 = """# Top Ten

## [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

- [Cross-Site Request Forgery Prevention Cheat Sheet](cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

## [A10:2021 – Server-Side Request Forgery
(SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

- [Session Management Cheat Sheet](cheatsheets/Session_Management_Cheat_Sheet.md)
"""


class SlugTests(unittest.TestCase):
    def test_slugify_matches_published_site(self):
        # Verified against cheatsheetseries.owasp.org permalinks (2026-11-13)
        self.assertEqual(slugify("JavaScript: Automatically Including CSRF Tokens as an AJAX Request Header"),
                         "javascript-automatically-including-csrf-tokens-as-an-ajax-request-header")
        self.assertEqual(slugify("Treat Next.js Configuration as Security Code"), "treat-nextjs-configuration-as-security-code")
        self.assertEqual(slugify("Employing Custom Request Headers for AJAX/API"), "employing-custom-request-headers-for-ajaxapi")
        self.assertEqual(slugify("Dealing with Client-Side CSRF Attacks (IMPORTANT)"), "dealing-with-client-side-csrf-attacks-important")

    def test_heading_text_strips_markdown(self):
        self.assertEqual(heading_text("Use [`HttpOnly`](https://x) **always**"), "Use HttpOnly always")


class ParseTests(unittest.TestCase):
    def test_sections_fences_and_duplicates(self):
        title, secs = parse_sections(SHEET_A)
        self.assertEqual(title, "Session Management Cheat Sheet")
        anchors = [s["anchor"] for s in secs]
        self.assertIn("secure-attribute", anchors)
        self.assertIn("secure-attribute_1", anchors)
        self.assertIn("javascript-tokens-httponly", anchors)
        self.assertNotIn("not-a-heading", anchors)
        cookies = next(s for s in secs if s["anchor"] == "cookies")
        refs = next(s for s in secs if s["anchor"] == "references")
        self.assertLess(cookies["line_end"], next(s for s in secs if s["anchor"].startswith("javascript"))["line_start"])
        self.assertEqual(refs["line_end"], len(SHEET_A.split("\n")))

    def test_asvs_index(self):
        a = parse_asvs_index(ASVS)
        self.assertEqual(list(a), ["V3", "V15"])
        self.assertEqual(a["V3"]["title"], "Web Frontend Security")
        self.assertEqual(a["V3"]["sections"]["V3.3"]["sheets"], ["Session_Management", "Cross-Site_Request_Forgery_Prevention"])
        self.assertEqual(a["V15"]["sections"]["V15.1"]["title"], "Secure Coding and Architecture Documentation")

    def test_top10_index_wrapped_title(self):
        t = parse_top10_index(TOP10)
        self.assertEqual(t["A10"]["title"], "Server-Side Request Forgery (SSRF)")
        self.assertEqual(t["A10"]["sheets"], ["Session_Management"])
        self.assertEqual(t["A01"]["year"], "2021")


class MiniClone(TempRepo):
    def setUp(self):
        super().setUp()
        self.clone = self.dir / "clone"
        self.data = self.dir / "data"
        self.write("clone/cheatsheets/Session_Management_Cheat_Sheet.md", SHEET_A)
        self.write("clone/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md", SHEET_B)
        self.write("clone/cheatsheets_draft/React_Security_Cheat_Sheet.md", DRAFT)
        self.write("clone/Index.md", INDEX)
        self.write("clone/IndexASVS.md", ASVS)
        self.write("clone/IndexTopTen.md", TOP10)
        self.data.mkdir()

    def run_script(self, name, *args):
        # A temporary home keeps a real ~/.claude/data/owasp-asvs install out of these tests.
        home = self.dir / "home"
        home.mkdir(exist_ok=True)
        env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
        env.pop("STACK_AUDIT_OWASP_ASVS", None)
        return subprocess.run(
            [sys.executable, str(SCRIPTS / name), *args, "--clone", str(self.clone), "--data-dir", str(self.data)],
            capture_output=True, text=True, encoding="utf-8", env=env,
        )


class CatalogTests(MiniClone):
    def test_build_and_lookup(self):
        c = build_catalog(self.clone)
        s = c["sheets"]
        self.assertEqual(set(s), {"Session_Management", "Cross-Site_Request_Forgery_Prevention", "React_Security"})
        self.assertEqual(s["React_Security"]["status"], "draft")
        self.assertIsNone(s["React_Security"]["url"])
        self.assertEqual(s["Session_Management"]["technologies"], ["Java", "Javascript"])
        self.assertEqual(find_sheet(c, "session management"), "Session_Management")
        self.assertEqual(find_sheet(c, "cross-site_request_forgery_prevention_cheat_sheet"), "Cross-Site_Request_Forgery_Prevention")
        sec = next(x for x in s["Session_Management"]["sections"] if x["anchor"] == "cookies")
        self.assertTrue(section_text(self.clone, s["Session_Management"], sec).startswith("## Cookies"))
        self.assertTrue(section_url(s["Session_Management"], sec).endswith("Session_Management_Cheat_Sheet.html#cookies"))
        self.assertIn("CC BY-SA", c["attribution"])

    def test_load_catalog_rebuilds_when_clone_changes(self):
        c1 = load_catalog(self.data, self.clone)
        self.assertNotIn("New_Sheet", c1["sheets"])
        (self.clone / "cheatsheets" / "New_Sheet_Cheat_Sheet.md").write_text("# New\n\n## A\n", encoding="utf-8")
        # Not a git repo: commit unknown -> same; force by changing clone path in cached catalog
        cached = json.loads((self.data / "owasp-catalog.json").read_text(encoding="utf-8"))
        cached["source"]["clone"] = "elsewhere"
        (self.data / "owasp-catalog.json").write_text(json.dumps(cached), encoding="utf-8")
        c2 = load_catalog(self.data, self.clone)
        self.assertIn("New_Sheet", c2["sheets"])


class ScriptTests(MiniClone):
    def test_find_ranks_and_expands_acronyms(self):
        res = self.run_script("find_sheets.py", "csrf tokens", "--format", "json")
        self.assertEqual(res.returncode, 0, res.stderr)
        hits = json.loads(res.stdout)["hits"]
        self.assertEqual(hits[0]["sheet"], "Cross-Site_Request_Forgery_Prevention")
        self.assertTrue(all(h["url"] is None or h["url"].startswith("https://cheatsheetseries.owasp.org/") for h in hits))

    def test_find_asvs_and_top10(self):
        res = self.run_script("find_sheets.py", "--asvs", "V3.3")
        self.assertIn("Cookie Setup", res.stdout)
        self.assertIn("`Session_Management`", res.stdout)
        res = self.run_script("find_sheets.py", "--top10", "a10")
        self.assertIn("Server-Side Request Forgery (SSRF)", res.stdout)
        res = self.run_script("find_sheets.py", "--asvs", "V99")
        self.assertEqual(res.returncode, 2)

    def test_read_section_anchor_heading_list(self):
        res = self.run_script("read_section.py", "--sheet", "Session_Management", "--anchor", "secure-attribute_1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Duplicate heading text", res.stdout)
        self.assertIn("cite: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute_1", res.stdout)
        res = self.run_script("read_section.py", "--sheet", "Session_Management", "--heading", "secure attribute")
        self.assertEqual(res.returncode, 2)  # ambiguous (two matches)
        self.assertIn("--anchor secure-attribute_1", res.stderr)
        res = self.run_script("read_section.py", "--sheet", "React_Security", "--list")
        self.assertIn("DRAFT", res.stdout)
        res = self.run_script("read_section.py", "--sheet", "Nope", "--list")
        self.assertEqual(res.returncode, 2)

    def test_verify_citations(self):
        good = self.write("docs/good.md", "## OWASP mapping\n\n| § | OWASP cheat sheet(s) |\n|---|---|\n| 01 | Session_Management, Cross-Site_Request_Forgery_Prevention |\n\nSee OWASP: Session_Management#cookies\n")
        res = self.run_script("verify_citations.py", str(good))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("3 citation(s) checked", res.stdout)
        bad = self.write("docs/bad.md", "Link: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#no-such-anchor\n\n## OWASP mapping\n\n| § | Sheets |\n|---|---|\n| 02 | Made_Up_Sheet |\n")
        res = self.run_script("verify_citations.py", str(bad), "--format", "json")
        self.assertEqual(res.returncode, 1)
        rules = sorted(f["rule"] for f in json.loads(res.stdout)["findings"])
        self.assertEqual(rules, ["owasp.01", "owasp.02"])
        rj = self.write("skill/rules.json", json.dumps({"files": {}, "rules": {"sec": {"01": ["auto", "error", ["React_Security"]]}}}))
        res = self.run_script("verify_citations.py", str(rj), "--format", "json")
        self.assertEqual(res.returncode, 0)
        self.assertEqual([f["rule"] for f in json.loads(res.stdout)["findings"]], ["owasp.03"])  # draft = info


class RealCloneTests(unittest.TestCase):
    def setUp(self):
        self.clone = next((c for c in REAL_CLONES if (c / "cheatsheets").is_dir()), None)
        if not self.clone:
            self.skipTest("real OWASP clone not available")

    def test_skill_references_name_existing_sheets(self):
        names = set()
        for f in (PLUGIN_ROOT / "skills" / "owasp-security").rglob("*.md"):
            names |= set(re.findall(r"`([A-Z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)+)`", f.read_text(encoding="utf-8")))
        names = {n for n in names if not n.startswith(("CLAUDE_", "V", "A0"))}
        self.assertGreater(len(names), 40)
        missing = sorted(
            n for n in names
            if not (self.clone / "cheatsheets" / f"{n}_Cheat_Sheet.md").exists()
            and not (self.clone / "cheatsheets_draft" / f"{n}_Cheat_Sheet.md").exists()
        )
        self.assertEqual(missing, [])

    def test_all_plugin_citations_verify(self):
        data = Path(__import__("tempfile").mkdtemp(prefix="wc-owasp-"))
        res = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_citations.py"), "--clone", str(self.clone), "--data-dir", str(data)],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(res.returncode, 0, res.stdout[-2000:] + res.stderr)


if __name__ == "__main__":
    unittest.main()
