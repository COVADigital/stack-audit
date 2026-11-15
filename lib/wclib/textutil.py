"""Text helpers: JS/TS comment+string masking, glob matching, line lookup.

Masking replaces characters with spaces while preserving newlines, so byte
offsets and line numbers in the masked text match the original file. Rules run
regexes on masked text to avoid matching inside comments or strings.
"""

from __future__ import annotations

import bisect
import re
from functools import lru_cache

# Characters after which a "/" starts a regex literal rather than division.
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = ("return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await")


def mask_js(text: str, *, comments: bool = True, strings: bool = False, jsx: bool = True) -> str:
    """Return `text` with JS/TS comments (and optionally string contents) blanked.

    - Newlines are always preserved.
    - String delimiters are kept; only their contents are blanked when strings=True.
    - Template literal `${...}` expressions are treated as code.
    - With jsx=True, a quote directly preceded by a letter/digit is treated as
      JSX text (e.g. `Don't`), not a string start.
    """
    out = list(text)
    n = len(text)
    i = 0
    tmpl_stack: list[int] = []  # brace depth at which each open template's ${ began
    brace_depth = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    def prev_significant(idx: int) -> str:
        j = idx - 1
        while j >= 0 and text[j] in " \t\r\n":
            j -= 1
        return text[j] if j >= 0 else ""

    def prev_word(idx: int) -> str:
        j = idx - 1
        while j >= 0 and text[j] in " \t\r\n":
            j -= 1
        end = j + 1
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        return text[j + 1 : end]

    def scan_template(start: int) -> int:
        """Scan a template literal body starting after the backtick. Returns index
        of the closing backtick, or of the `${` that suspends it."""
        k = start
        while k < n:
            ch = text[k]
            if ch == "\\":
                k += 2
                continue
            if ch == "`":
                return k
            if ch == "$" and k + 1 < n and text[k + 1] == "{":
                return k
            k += 1
        return n

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # Line comment
        if ch == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            if comments:
                blank(i, end)
            i = end
            continue
        # Block comment
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            if comments:
                blank(i, end)
            i = end
            continue
        # Quotes
        if ch in ("'", '"'):
            if jsx and i > 0 and (text[i - 1].isalnum()):
                i += 1
                continue
            k = i + 1
            while k < n and text[k] != ch and text[k] != "\n":
                if text[k] == "\\":
                    k += 1
                k += 1
            if strings:
                blank(i + 1, k)
            i = k + 1
            continue
        # Template literal start
        if ch == "`":
            k = scan_template(i + 1)
            if strings:
                blank(i + 1, k)
            if k < n and text[k] == "$":
                tmpl_stack.append(brace_depth)
                brace_depth += 1
                i = k + 2
            else:
                i = k + 1
            continue
        # Regex literal
        if ch == "/":
            p = prev_significant(i)
            if p == "" or p in _REGEX_PRECEDERS or prev_word(i) in _REGEX_KEYWORDS:
                k = i + 1
                in_class = False
                while k < n and text[k] != "\n":
                    c = text[k]
                    if c == "\\":
                        k += 2
                        continue
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        break
                    k += 1
                if k < n and text[k] == "/":
                    if strings:
                        blank(i + 1, k)
                    i = k + 1
                    continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
            if tmpl_stack and brace_depth == tmpl_stack[-1]:
                tmpl_stack.pop()
                k = scan_template(i + 1)
                if strings:
                    blank(i + 1, k)
                if k < n and text[k] == "$":
                    tmpl_stack.append(brace_depth)
                    brace_depth += 1
                    i = k + 2
                else:
                    i = k + 1
                continue
        i += 1
    return "".join(out)


def mask_hash_comments(text: str) -> str:
    """Blank `#` comments (YAML, Dockerfile, shell). Naive about quotes containing #,
    but only treats `#` as a comment at line start or after whitespace."""
    out = []
    for line in text.split("\n"):
        m = re.search(r"(^|\s)#", line)
        if m:
            cut = m.start() + len(m.group(1))
            line = line[:cut] + " " * (len(line) - cut)
        out.append(line)
    return "\n".join(out)


def mask_css_comments(text: str) -> str:
    def repl(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    return re.sub(r"/\*.*?\*/", repl, text, flags=re.S)


class LineIndex:
    """Map character offsets to 1-based line numbers."""

    def __init__(self, text: str) -> None:
        self._starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self._lines = text.split("\n")

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self._lines):
            return self._lines[line - 1].rstrip("\r")
        return ""


@lru_cache(maxsize=512)
def _glob_regex(pattern: str) -> re.Pattern:
    p = pattern.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    res = ""
    i = 0
    while i < len(p):
        c = p[i]
        if c == "*":
            if p[i : i + 3] == "**/":
                res += "(?:.*/)?"
                i += 3
                continue
            if p[i : i + 2] == "**":
                res += ".*"
                i += 2
                continue
            res += "[^/]*"
        elif c == "?":
            res += "[^/]"
        elif c == "{":
            j = p.find("}", i)
            if j == -1:
                res += re.escape(c)
            else:
                alts = p[i + 1 : j].split(",")
                res += "(?:" + "|".join(re.escape(a) for a in alts) + ")"
                i = j
        else:
            res += re.escape(c)
        i += 1
    # A pattern without a slash matches the basename anywhere (gitignore-like).
    if "/" not in p:
        res = "(?:.*/)?" + res
    return re.compile("^" + res + "(?:/.*)?$")


def glob_match(path: str, pattern: str) -> bool:
    """Match a forward-slash relative path against a glob supporting **, *, ?, {a,b}.
    A pattern also matches everything under a matching directory."""
    return bool(_glob_regex(pattern).match(path.replace("\\", "/")))


def any_glob(path: str, patterns: list[str]) -> bool:
    return any(glob_match(path, p) for p in patterns)
