"""Tests for wclib.controls, map_controls.py and compliance_checklist.py (M7)."""

import json
import unittest

from helpers import PLUGIN_ROOT, TempRepo
from test_owasp import REAL_CLONES, MiniClone
from wclib.controls import EVIDENCE, GATED, NOT_APPLICABLE, SIGNALS, map_controls
from wclib.owasp import build_catalog, parse_asvs_index, parse_top10_index
from wclib.rules import RuleBook


def tiny_catalog():
    sheet = lambda t: {"title": t, "status": "published", "url": f"https://x/{t}.html", "sections": []}  # noqa: E731
    return {
        "source": {"commit": "abc1234"},
        "sheets": {s: sheet(s) for s in ("File_Upload", "Webhook_Security", "Authentication", "Nextjs_Security")},
        "mappings": {
            "asvs5": {
                "V1": {"title": "Encoding", "sections": {"V1.2": {"title": "Injection", "sheets": []},
                                                         "V1.4": {"title": "Memory", "sheets": []}}},
                "V5": {"title": "Files", "sections": {"V5.2": {"title": "Upload", "sheets": ["File_Upload"]}}},
                "V6": {"title": "Authentication", "sections": {"V6.2": {"title": "Passwords", "sheets": ["Authentication"]}}},
                "V17": {"title": "WebRTC", "sections": {"V17.1": {"title": "TURN", "sheets": []}}},
            },
            "top10_2021": {"A04": {"title": "Insecure Design", "sheets": ["File_Upload"]},
                           "A07": {"title": "Auth Failures", "sheets": ["Authentication"]}},
        },
    }


class ParserQuirkTests(unittest.TestCase):
    def test_asvs_section_written_as_h2_stays_in_chapter(self):
        a = parse_asvs_index("## V17: WebRTC\n\n### V17.1 TURN Server\n\n## V17.2 Media\n\n## V17.3 Signaling\n")
        self.assertEqual(list(a), ["V17"])
        self.assertEqual(list(a["V17"]["sections"]), ["V17.1", "V17.2", "V17.3"])

    def test_top10_drops_next_steps(self):
        t = parse_top10_index("## [A10:2021 – SSRF](u)\n\n## [A11:2021 – Next Steps](u)\n")
        self.assertEqual(list(t), ["A10"])


class MapControlsTests(TempRepo):
    def test_signals_gate_sections_sheets_and_top10(self):
        self.write("package.json", json.dumps({"dependencies": {"next": "16.0.0", "react": "19.0.0"}}))
        self.write("src/app/upload/page.tsx", 'export default function P(){return <input type="file" name="f"/>}\n')
        self.write("src/app/api/webhooks/sanity/route.ts", "export async function POST(){}\n")
        cm = map_controls(self.dir, tiny_catalog())
        self.assertIn("web", cm.signals)
        self.assertIn("uploads", cm.signals)
        self.assertIn("webhooks", cm.signals)
        self.assertNotIn("auth", cm.signals)
        scope = {a["code"]: a["applies"] for a in cm.asvs}
        self.assertEqual(scope, {"V1.2": True, "V1.4": False, "V5.2": True, "V6.2": False, "V17.1": False})
        ids = [s["id"] for s in cm.sheets]
        self.assertIn("File_Upload", ids)
        self.assertIn("Webhook_Security", ids)
        self.assertEqual([t["code"] for t in cm.top10], ["A04"])
        self.assertIsNone(cm.container_root)

    def test_auth_and_docker(self):
        self.write("package.json", json.dumps({"dependencies": {"next": "16.0.0", "better-auth": "1.0.0"}}))
        self.write("Dockerfile", "FROM node:22-alpine\n")
        cm = map_controls(self.dir, tiny_catalog())
        self.assertIn("auth", cm.signals)
        self.assertIn("docker", cm.signals)
        self.assertTrue(next(a for a in cm.asvs if a["code"] == "V6.2")["applies"])
        self.assertTrue(cm.container_root)


class ChecklistTests(MiniClone):
    def test_status_from_evidence(self):
        self.write("app/package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        report = {"tool": "web-standards review", "root": "app", "meta": {"domains": ["sec"]}, "findings": [
            {"rule": "sec.06", "severity": "error", "confidence": "high", "message": "cookie lacks Secure",
             "file": "src/lib/auth.ts", "line": 4},
            {"rule": "sec.19", "severity": "warn", "confidence": "medium", "message": "No HSTS", "file": "next.config.ts"},
        ]}
        ev = self.write("evidence.json", json.dumps(report))
        res = self.run_script("compliance_checklist.py", "--root", str(self.dir / "app"), "--no-run",
                              "--evidence", str(ev), "--format", "json")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        rows = {r["code"]: r for r in data["sections"]}
        self.assertEqual(rows["V3.3"]["status"], "not met")
        self.assertEqual(rows["V3.4"]["status"], "partial")
        self.assertIn("sec.03", rows["V3.4"]["clean_checks"])  # sec ran, sec.03 maps to V3.4, no finding
        self.assertEqual(rows["V15.1"]["status"], "not assessed")
        self.assertEqual(data["level"], 1)  # no auth signal
        md = self.run_script("compliance_checklist.py", "--root", str(self.dir / "app"), "--no-run", "--evidence", str(ev))
        self.assertIn("not an audit, certification", md.stdout)
        self.assertNotIn("| met |", md.stdout)

    def test_map_controls_script(self):
        self.write("app/package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        res = self.run_script("map_controls.py", "--root", str(self.dir / "app"))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("## ASVS 5.0 sections", res.stdout)
        self.assertIn("V3.3", res.stdout)


class DataIntegrityTests(unittest.TestCase):
    """Every sheet, ASVS section and rule named in controls.py must exist."""

    def test_rules_exist(self):
        books = [RuleBook(PLUGIN_ROOT / "skills" / s) for s in ("web-standards", "container-standards")]
        known = {f"{p}.{nn}" for rb in books for p, rules in rb.rules.items() for nn in rules}
        self.assertEqual(sorted(set(EVIDENCE) - known), [])

    def test_sheets_and_sections_exist_in_real_clone(self):
        clone = next((c for c in REAL_CLONES if (c / "cheatsheets").is_dir()), None)
        if not clone:
            self.skipTest("real OWASP clone not available")
        cat = build_catalog(clone)
        sheets = {s for sig in SIGNALS.values() for s in sig[4]}
        self.assertEqual(sorted(sheets - set(cat["sheets"])), [])
        asvs = cat["mappings"]["asvs5"]
        codes = set(asvs) | {s for ch in asvs.values() for s in ch["sections"]}
        named = set(GATED) | set(NOT_APPLICABLE) | {s for secs in EVIDENCE.values() for s in secs}
        self.assertEqual(sorted(named - codes), [])
        self.assertEqual(list(cat["mappings"]["top10_2021"]), [f"A{n:02d}" for n in range(1, 11)])


if __name__ == "__main__":
    unittest.main()
