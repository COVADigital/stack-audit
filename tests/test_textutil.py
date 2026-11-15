import unittest

from helpers import PLUGIN_ROOT  # noqa: F401  (sets sys.path)
from wclib.textutil import LineIndex, glob_match, mask_css_comments, mask_hash_comments, mask_js


class MaskJsTests(unittest.TestCase):
    def test_line_comment_blanked_and_length_preserved(self):
        src = "const a = 1; // eval(x)\nconst b = 2;"
        out = mask_js(src)
        self.assertEqual(len(out), len(src))
        self.assertNotIn("eval", out)
        self.assertIn("const b = 2;", out)

    def test_block_comment_keeps_newlines(self):
        src = "/* line1\n dangerouslySetInnerHTML \n*/x"
        out = mask_js(src)
        self.assertEqual(out.count("\n"), 2)
        self.assertNotIn("dangerously", out)
        self.assertTrue(out.endswith("x"))

    def test_strings_kept_by_default_masked_on_request(self):
        src = "fetch('https://example.com/eval')"
        self.assertIn("eval", mask_js(src))
        masked = mask_js(src, strings=True)
        self.assertNotIn("eval", masked)
        self.assertIn("fetch('", masked)

    def test_comment_markers_inside_strings_are_not_comments(self):
        src = "const u = 'http://x.y'; eval(u)"
        out = mask_js(src)
        self.assertIn("eval(u)", out)

    def test_template_literal_expression_is_code(self):
        src = "const s = `a ${ eval(x) } b // not comment`; next()"
        out = mask_js(src, strings=True)
        self.assertIn("eval(x)", out)
        self.assertNotIn("not comment", out)
        self.assertIn("next()", out)

    def test_nested_template(self):
        src = "x = `a ${ `b ${c} d` } e`; tail()"
        out = mask_js(src, strings=True)
        self.assertIn("c", out)
        self.assertIn("tail()", out)

    def test_jsx_apostrophe_not_string(self):
        src = "<p>Don't stop</p>\n<div onClick={go} />"
        out = mask_js(src, strings=True)
        self.assertIn("onClick={go}", out)

    def test_regex_literal_with_slashes_and_quotes(self):
        src = "const r = /\\/\\/'[\"]/g; eval(r)"
        out = mask_js(src)
        self.assertIn("eval(r)", out)

    def test_division_not_regex(self):
        src = "const x = a / b; // c\nconst y = 1;"
        out = mask_js(src)
        self.assertIn("a / b;", out)
        self.assertNotIn("// c", out)


class OtherMaskTests(unittest.TestCase):
    def test_hash_comments(self):
        src = "FROM node:22 # base\n# full line\nRUN echo '#notcomment'"
        out = mask_hash_comments(src)
        self.assertNotIn("base", out)
        self.assertNotIn("full line", out)
        self.assertIn("echo '#notcomment'", out)

    def test_css_comments(self):
        out = mask_css_comments("a{ /* outline:none */ color:red }")
        self.assertNotIn("outline", out)
        self.assertIn("color:red", out)


class LineIndexTests(unittest.TestCase):
    def test_line_of(self):
        text = "a\nbb\nccc"
        idx = LineIndex(text)
        self.assertEqual(idx.line_of(0), 1)
        self.assertEqual(idx.line_of(2), 2)
        self.assertEqual(idx.line_of(text.index("ccc")), 3)
        self.assertEqual(idx.line_text(2), "bb")


class GlobTests(unittest.TestCase):
    def test_double_star(self):
        self.assertTrue(glob_match("src/legacy/a/b.tsx", "src/legacy/**"))
        self.assertTrue(glob_match("src/a/b.test.ts", "**/*.test.ts"))
        self.assertTrue(glob_match("x.test.ts", "**/*.test.ts"))
        self.assertFalse(glob_match("src/a/b.ts", "**/*.test.ts"))

    def test_basename_pattern_matches_anywhere(self):
        self.assertTrue(glob_match("a/b/.env", ".env"))
        self.assertTrue(glob_match("deep/x.generated.ts", "*.generated.ts"))

    def test_directory_prefix_and_braces(self):
        self.assertTrue(glob_match("src/generated/x/y.ts", "src/generated"))
        self.assertTrue(glob_match("app/page.tsx", "app/*.{ts,tsx}"))
        self.assertFalse(glob_match("app/page.css", "app/*.{ts,tsx}"))

    def test_dot_slash_prefix(self):
        self.assertTrue(glob_match(".env", "./.env"))


if __name__ == "__main__":
    unittest.main()
