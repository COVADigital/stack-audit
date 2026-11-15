import contextlib
import io
import json
import unittest

from helpers import TempRepo
from wclib.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, build_parser, finish, make_context
from wclib.findings import Finding, Report


class CliTests(TempRepo):
    def _run(self, argv, findings):
        args = build_parser("test").parse_args(["--root", str(self.dir), *argv])
        ctx = make_context(args)
        report = Report(tool="t", root=str(ctx.root))
        report.extend(findings)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = finish(report, ctx)
        return code, buf.getvalue()

    def test_default_md_and_exit_ok_even_with_errors(self):
        code, out = self._run([], [Finding("sec.16", "error", "secret", file="a.ts", line=1)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("# t report", out)

    def test_strict_exits_1_on_errors_only(self):
        code, _ = self._run(["--strict"], [Finding("sec.16", "error", "secret")])
        self.assertEqual(code, EXIT_FINDINGS)
        code, _ = self._run(["--strict"], [Finding("perf.20", "info", "no rum")])
        self.assertEqual(code, EXIT_OK)

    def test_json_and_out_file(self):
        out_file = self.dir / "reports" / "r.json"
        code, stdout = self._run(["--format", "json", "--out", str(out_file)], [Finding("a.01", "warn", "m")])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(stdout, "")
        self.assertEqual(json.loads(out_file.read_text(encoding="utf-8"))["counts"]["warn"], 1)

    def test_suppression_applied_via_config(self):
        self.write("stack-audit.config.json", json.dumps({"ignore": {"sec.01": ["legacy/**"]}}))
        code, out = self._run(["--format", "json"], [Finding("sec.01", "error", "m", file="legacy/x.tsx", line=1)])
        data = json.loads(out)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["suppressed"], 1)

    def test_bad_config_exits_2(self):
        self.write("stack-audit.config.json", "{broken")
        args = build_parser("test").parse_args(["--root", str(self.dir)])
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            make_context(args)
        self.assertEqual(cm.exception.code, EXIT_USAGE)

    def test_files_limits_walker_and_rejects_outside_root(self):
        self.write("a.ts", "x")
        self.write("sub/b.ts", "y")
        args = build_parser("test").parse_args(["--root", str(self.dir), "--files", "sub/b.ts", str(self.dir / "a.ts")])
        self.assertEqual(make_context(args).walker.all_files(), ["a.ts", "sub/b.ts"])
        args = build_parser("test").parse_args(["--root", str(self.dir), "--files", "sub/b.ts"])
        self.assertEqual(make_context(args).walker.all_files(), ["sub/b.ts"])
        args = build_parser("test").parse_args(["--root", str(self.dir / "sub"), "--files", str(self.dir / "a.ts")])
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            make_context(args)
        self.assertEqual(cm.exception.code, EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
