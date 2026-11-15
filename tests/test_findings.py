import json
import unittest

from helpers import PLUGIN_ROOT  # noqa: F401
from wclib.findings import Finding, Report


def sample_report() -> Report:
    r = Report(tool="test-audit", root="/repo")
    r.add(Finding("sec.16", "error", "NEXT_PUBLIC_STRIPE_SECRET looks secret", file="src\\env.ts", line=3,
                  fix_hint="Drop the NEXT_PUBLIC_ prefix", owasp=["Secrets_Management#..."]))
    r.add(Finding("a11y.07", "warn", "img without alt", file="app/page.tsx", line=10, confidence="medium"))
    r.add(Finding("perf.20", "info", "No RUM reporting found"))
    return r


class FindingTests(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            Finding("x.01", "critical", "bad")
        with self.assertRaises(ValueError):
            Finding("x.01", "warn", "bad", confidence="sure")

    def test_path_normalised_and_domain(self):
        f = Finding("sec.16", "error", "m", file="a\\b.ts", line=2)
        self.assertEqual(f.file, "a/b.ts")
        self.assertEqual(f.domain, "sec")
        self.assertEqual(f.location, "a/b.ts:2")

    def test_fingerprint_stable(self):
        a = Finding("sec.01", "warn", "m", file="a.ts", line=1)
        b = Finding("sec.01", "warn", "m", file="a.ts", line=1)
        self.assertEqual(a.fingerprint(), b.fingerprint())


class ReportTests(unittest.TestCase):
    def test_counts_and_sorting(self):
        r = sample_report()
        self.assertEqual(r.counts(), {"error": 1, "warn": 1, "info": 1})
        self.assertEqual([f.severity for f in r.sorted_findings()], ["error", "warn", "info"])
        self.assertTrue(r.has_errors())

    def test_dedupe(self):
        r = sample_report()
        r.add(Finding("a11y.07", "warn", "img without alt", file="app/page.tsx", line=10, confidence="medium"))
        r.dedupe()
        self.assertEqual(len(r.findings), 3)

    def test_json(self):
        data = json.loads(sample_report().to_json())
        self.assertEqual(data["counts"]["error"], 1)
        self.assertEqual(data["findings"][0]["rule"], "sec.16")
        self.assertEqual(data["findings"][0]["domain"], "sec")
        self.assertNotIn("snippet", data["findings"][0])  # empty fields dropped

    def test_markdown(self):
        md = sample_report().to_markdown()
        self.assertIn("**1 error**", md)
        self.assertIn("| Security | 1 | 0 | 0 |", md)
        self.assertIn("`src/env.ts:3`", md)
        self.assertIn("confidence: medium", md)
        self.assertIn("OWASP: Secrets_Management", md)

    def test_markdown_lists_skipped_and_not_checked(self):
        r = Report(tool="t", root="/r", skipped=["gitleaks not found"], not_checked=["ren.20 strategy choice"])
        md = r.to_markdown()
        self.assertIn("No findings.", md)
        self.assertIn("gitleaks not found", md)
        self.assertIn("ren.20 strategy choice", md)

    def test_sarif(self):
        data = json.loads(sample_report().to_sarif())
        self.assertEqual(data["version"], "2.1.0")
        results = data["runs"][0]["results"]
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        # Found by running the CI template on GitHub: one result without a location makes code scanning
        # reject the whole upload, so every result needs one.
        self.assertTrue(all(r.get("locations") for r in results))
        self.assertEqual(results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "README.md")
        self.assertTrue(results[2]["message"]["text"].startswith("(project-level) "))
        self.assertEqual(len(data["runs"][0]["tool"]["driver"]["rules"]), 3)

    def test_sarif_uris_and_anchors(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package.json").write_text("{}", encoding="utf-8")
            r = Report(tool="t", root=d)
            r.add(Finding("sec.01", "error", "xss", file="app/u/[name]/page.tsx", line=4))
            r.add(Finding("sec.03", "warn", "No CSP"))
            r.add(Finding("run.03", "error", "privileged", file="container:app"))
            res = json.loads(r.to_sarif())["runs"][0]["results"]
        uris = {x["ruleId"]: x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for x in res}
        self.assertEqual(uris["sec.01"], "app/u/%5Bname%5D/page.tsx")  # brackets are not valid in a URI
        self.assertEqual(uris["sec.03"], "package.json")  # anchored to a file that exists at the root
        self.assertEqual(uris["run.03"], "package.json")
        self.assertIn("container:app", next(x for x in res if x["ruleId"] == "run.03")["message"]["text"])

    def test_merge(self):
        a, b = sample_report(), Report(tool="b", root="/repo", skipped=["x"], suppressed=2)
        b.add(Finding("git.04", "error", "secret tracked", file=".env"))
        a.merge(b)
        self.assertEqual(len(a.findings), 4)
        self.assertEqual(a.suppressed, 2)
        self.assertIn("x", a.skipped)


if __name__ == "__main__":
    unittest.main()
