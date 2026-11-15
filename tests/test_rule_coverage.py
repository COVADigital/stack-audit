"""Keeps rules.json honest and the scripts tested.

- Every rule labelled auto/heuristic must be reported by some script. Reports and the ASVS
  checklist count those rules as checked, so a label with no check behind it is a silent pass.
- Every rule a script reports must appear in some test (UNTESTED is the escape hatch; keep it empty).
"""

import json
import re
import unittest

from helpers import PLUGIN_ROOT

RID = r"(?:git|ren|perf|state|net|cache|arch|sec|a11y|img|run|cnet|csec|host|sup|ops|cool|dbs|dbm|dbo)\.\d{2}"

# Labelled auto because another rule's check covers them; the report says which.
CROSS_REF = {"net.14": "sec.04", "cache.05": "sec.07"}

# Reported by a script but no test yet. Empty since 0.2.4: every new rule ships with a test.
UNTESTED: set[str] = set()


def _read(paths) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in paths)


def reported_rules() -> set[str]:
    """Rule IDs on a line that creates a finding: add(...), make(...), flag(...) or `rule = ...`."""
    code = _read(sorted(PLUGIN_ROOT.glob("skills/*/scripts/*.py")) + sorted((PLUGIN_ROOT / "lib" / "wclib").glob("*.py")))
    out = set()
    for line in code.splitlines():
        if re.search(r"\b(add|make|flag)\(|\brule\s*=", line):
            out.update(re.findall(rf"[\"']({RID})[\"']", line))
    return out


def labelled(*checks: str) -> set[str]:
    out = set()
    for skill in ("web-standards", "container-standards", "data-standards"):
        rules = json.loads((PLUGIN_ROOT / "skills" / skill / "rules.json").read_text(encoding="utf-8"))["rules"]
        out.update(f"{p}.{nn}" for p, rs in rules.items() for nn, e in rs.items() if e[0] in checks)
    return out


class RuleCoverageTests(unittest.TestCase):
    def setUp(self):
        self.reported = reported_rules()
        self.tested = set(re.findall(RID, _read(p for p in sorted(PLUGIN_ROOT.glob("tests/*.py"))
                                              if p.name != "test_rule_coverage.py")))

    def test_scripted_labels_have_a_check(self):
        missing = labelled("auto", "heuristic") - self.reported - set(CROSS_REF)
        self.assertEqual(sorted(missing), [], "labelled auto/heuristic but no script reports them: "
                                             "write the check or label the rule manual")

    def test_cross_refs_point_at_reported_rules(self):
        self.assertLessEqual(set(CROSS_REF.values()), self.reported)

    def test_reported_rules_are_tested(self):
        self.assertEqual(sorted(self.reported - self.tested - UNTESTED), [], "add a test for these rules")

    def test_untested_list_only_shrinks(self):
        self.assertEqual(sorted(UNTESTED & self.tested), [], "now tested: remove from UNTESTED")
        self.assertEqual(sorted(UNTESTED - self.reported), [], "no longer reported: remove from UNTESTED")


if __name__ == "__main__":
    unittest.main()
