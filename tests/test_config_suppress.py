import json
import unittest

from helpers import TempRepo
from wclib.config import ConfigError, DEFAULTS, load_config
from wclib.findings import Finding, Report
from wclib.suppress import Suppressor, parse_inline


class ConfigTests(TempRepo):
    def test_defaults_when_missing(self):
        cfg = load_config(self.dir)
        self.assertEqual(cfg["budgets"]["initialJsGzipKb"], DEFAULTS["budgets"]["initialJsGzipKb"])
        self.assertIsNone(cfg["_source"])

    def test_deep_merge(self):
        self.write("stack-audit.config.json", json.dumps({"budgets": {"lcpMs": 2000}, "ignorePaths": ["gen/**"]}))
        cfg = load_config(self.dir)
        self.assertEqual(cfg["budgets"]["lcpMs"], 2000)
        self.assertEqual(cfg["budgets"]["initialJsGzipKb"], 170)  # default kept
        self.assertEqual(cfg["ignorePaths"], ["gen/**"])

    def test_invalid_json_and_shape(self):
        self.write("stack-audit.config.json", "{not json")
        with self.assertRaises(ConfigError):
            load_config(self.dir)
        self.write("stack-audit.config.json", json.dumps({"ignore": {"sec.01": "src/**"}}))
        with self.assertRaises(ConfigError):
            load_config(self.dir)

    def test_explicit_missing_path_errors(self):
        with self.assertRaises(ConfigError):
            load_config(self.dir, self.dir / "nope.json")


class InlineParseTests(TempRepo):
    def test_parse_variants(self):
        self.assertEqual(parse_inline("// stack-audit-ignore sec.01 -- sanitized"), (["sec.01"], "sanitized"))
        self.assertEqual(parse_inline("# stack-audit-ignore cnet.02,run.03 -- private iface")[0], ["cnet.02", "run.03"])
        self.assertEqual(parse_inline("{/* stack-audit-ignore a11y.07 -- decorative */}"), (["a11y.07"], "decorative"))
        self.assertEqual(parse_inline("// stack-audit-ignore sec.*  --  legacy"), (["sec.*"], "legacy"))
        self.assertEqual(parse_inline("// stack-audit-ignore sec.01"), (["sec.01"], None))
        self.assertIsNone(parse_inline("// nothing here"))


class SuppressorTests(TempRepo):
    def _report(self, *findings):
        r = Report(tool="t", root=str(self.dir))
        r.extend(findings)
        return r

    def test_inline_same_line_and_line_above(self):
        self.write("a.tsx", "x\n// stack-audit-ignore sec.01 -- sanitized upstream\n<div dangerouslySetInnerHTML={h} />\n<p>{y}</p> // stack-audit-ignore a11y.* -- ok\n")
        r = self._report(
            Finding("sec.01", "error", "xss sink", file="a.tsx", line=3),
            Finding("a11y.05", "warn", "name", file="a.tsx", line=4),
            Finding("sec.09", "error", "other", file="a.tsx", line=3),
        )
        Suppressor(self.dir, {"ignore": {}}).apply(r)
        self.assertEqual([f.rule for f in r.findings], ["sec.09"])
        self.assertEqual(r.suppressed, 2)

    def test_reasonless_inline_does_not_suppress(self):
        self.write("a.tsx", "<div dangerouslySetInnerHTML={h} /> // stack-audit-ignore sec.01\n")
        r = self._report(Finding("sec.01", "error", "xss sink", file="a.tsx", line=1))
        Suppressor(self.dir, {"ignore": {}}).apply(r)
        rules = sorted(f.rule for f in r.findings)
        self.assertEqual(rules, ["meta.01", "sec.01"])
        self.assertEqual(r.suppressed, 0)

    def test_config_ignore_globs_and_wildcard(self):
        r = self._report(
            Finding("sec.01", "error", "m", file="src/legacy/old.tsx", line=1),
            Finding("sec.14", "warn", "m", file="src/legacy/x/y.tsx", line=1),
            Finding("sec.01", "error", "m", file="src/new.tsx", line=1),
        )
        Suppressor(self.dir, {"ignore": {"sec.*": ["src/legacy/**"]}}).apply(r)
        self.assertEqual([f.file for f in r.findings], ["src/new.tsx"])
        self.assertEqual(r.suppressed, 2)


if __name__ == "__main__":
    unittest.main()
