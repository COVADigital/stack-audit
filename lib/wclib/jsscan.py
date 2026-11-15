"""Lightweight JS/TS/JSX structure helpers (no AST). Positions always refer to the
original text: callers pass masked text (see textutil.mask_js) which preserves offsets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .textutil import LineIndex, mask_js

TEST_FILE = re.compile(r"(^|/)(__tests__|__mocks__|e2e|tests?|cypress|playwright)(/|$)|\.(test|spec|stories)\.[cm]?[jt]sx?$")
JSX_EXTS = (".tsx", ".jsx", ".js", ".mjs")
_TAG_OPEN = re.compile(r"<([A-Za-z][\w.:-]*)(?=[\s/>])")
_DIRECTIVE = re.compile(r"""^\s*(?:(?://[^\n]*|/\*.*?\*/)\s*)*['"]use (client|server)['"]""", re.S)


def is_test_file(rel: str) -> bool:
    return bool(TEST_FILE.search(rel))


def directive(text: str) -> str | None:
    """'client' / 'server' if the module starts with that directive."""
    m = _DIRECTIVE.match(text)
    return m.group(1) if m else None


class JsFile:
    """A source file with lazily computed masked variants and a line index."""

    def __init__(self, rel: str, text: str) -> None:
        self.rel = rel
        self.text = text
        self._code: str | None = None
        self._code_nostr: str | None = None
        self.lines = LineIndex(text)
        self.jsx = rel.endswith(JSX_EXTS)

    @property
    def code(self) -> str:
        """Comments blanked, strings kept."""
        if self._code is None:
            self._code = mask_js(self.text, comments=True, strings=False, jsx=self.jsx)
        return self._code

    @property
    def code_nostr(self) -> str:
        """Comments and string contents blanked."""
        if self._code_nostr is None:
            self._code_nostr = mask_js(self.text, comments=True, strings=True, jsx=self.jsx)
        return self._code_nostr

    @property
    def directive(self) -> str | None:
        return directive(self.text)

    def line_of(self, offset: int) -> int:
        return self.lines.line_of(offset)

    def snippet(self, offset: int) -> str:
        return self.lines.line_text(self.line_of(offset)).strip()[:160]


# ----------------------------------------------------------------- balanced scanning

def match_close(text: str, open_idx: int) -> int:
    """Index of the bracket closing text[open_idx] ('(', '{', '['), or -1. Use string-masked text."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = text[open_idx]
    closer = pairs[opener]
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
    return -1


def call_args(f: JsFile, open_paren: int) -> str:
    """Raw argument text of a call whose '(' is at open_paren (from the comment-masked code)."""
    end = match_close(f.code_nostr, open_paren)
    return f.code[open_paren + 1 : end] if end != -1 else f.code[open_paren + 1 : open_paren + 400]


def find_calls(f: JsFile, pattern: str, *, nostr: bool = True) -> list[tuple[int, str]]:
    """All calls matching `pattern` (regex ending right before '('). Returns (offset, args)."""
    hay = f.code_nostr if nostr else f.code
    out = []
    for m in re.finditer(pattern + r"\s*\(", hay):
        paren = m.end() - 1
        out.append((m.start(), call_args(f, paren)))
    return out


@dataclass
class Func:
    name: str
    start: int
    body_start: int
    body_end: int
    exported: bool
    has_use_server: bool = False

    def body(self, f: JsFile) -> str:
        return f.code[self.body_start : self.body_end]


_FUNC_DECL = re.compile(
    r"(?P<export>export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(?P<name>[\w$]*)\s*(?:<[^>]*>)?\s*\("
)
_ARROW = re.compile(
    r"(?P<export>export\s+)?(?:const|let|var)\s+(?P<name>[\w$]+)\s*(?::[^=]+)?=\s*(?:async\s*)?"
    r"(?:\([^)]*\)|[\w$]+)\s*(?::[^=]+?)?=>\s*\{"
)


def functions(f: JsFile) -> list[Func]:
    """Function declarations and block-bodied arrow functions (top-level and nested)."""
    hay = f.code_nostr
    out: list[Func] = []
    for m in _FUNC_DECL.finditer(hay):
        paren = m.end() - 1
        close = match_close(hay, paren)
        if close == -1:
            continue
        # skip a return type annotation, then expect '{'
        j = close + 1
        angle = 0
        while j < len(hay):
            c = hay[j]
            if c == "<":
                angle += 1
            elif c == ">" and angle:
                angle -= 1
            elif c == "{" and angle == 0:
                break
            elif c in ";" and angle == 0:
                j = -1
                break
            j += 1
        if j == -1 or j >= len(hay):
            continue
        end = match_close(hay, j)
        if end == -1:
            continue
        out.append(Func(m.group("name") or "default", m.start(), j + 1, end, bool(m.group("export"))))
    for m in _ARROW.finditer(hay):
        brace = m.end() - 1
        end = match_close(hay, brace)
        if end == -1:
            continue
        out.append(Func(m.group("name"), m.start(), brace + 1, end, bool(m.group("export"))))
    for fn in out:
        fn.has_use_server = bool(re.match(r"""\s*['"]use server['"]""", f.code[fn.body_start : fn.body_start + 40]))
    return sorted(out, key=lambda x: x.start)


# ----------------------------------------------------------------- JSX tags

@dataclass
class Tag:
    name: str
    start: int
    end: int  # index of the closing '>' of the opening tag
    attrs: dict[str, str | bool] = field(default_factory=dict)
    self_closing: bool = False
    has_spread: bool = False

    def _key(self, name: str) -> str | None:
        """Exact attribute name, else a case-insensitive match (HTML `onclick` == JSX `onClick`)."""
        if name in self.attrs:
            return name
        low = name.lower()
        return next((k for k in self.attrs if k.lower() == low), None)

    def attr(self, name: str) -> str | bool | None:
        k = self._key(name)
        return self.attrs.get(k) if k else None

    def has(self, *names: str) -> bool:
        return any(self._key(n) for n in names)

    def literal(self, name: str) -> str | None:
        """String value of an attribute given as "x", 'x' or {'x'} / {"x"}; else None."""
        v = self.attr(name)
        if not isinstance(v, str):
            return None
        m = re.fullmatch(r"""\s*(?:\{\s*)?(['"`])(.*?)\1(?:\s*\})?\s*""", v, re.S)
        return m.group(2) if m else None


def _parse_attrs(raw: str) -> tuple[dict[str, str | bool], bool]:
    attrs: dict[str, str | bool] = {}
    spread = False
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c.isspace() or c == "/":
            i += 1
            continue
        if c == "{":
            depth, j = 0, i
            while j < n:
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if raw[i + 1 : i + 4] == "...":
                spread = True
            i = j + 1
            continue
        m = re.match(r"[\w:.@-]+", raw[i:])
        if not m:
            i += 1
            continue
        name = m.group(0)
        i += len(name)
        while i < n and raw[i].isspace():
            i += 1
        if i < n and raw[i] == "=":
            i += 1
            while i < n and raw[i].isspace():
                i += 1
            if i < n and raw[i] in "\"'":
                q = raw[i]
                j = raw.find(q, i + 1)
                j = n - 1 if j == -1 else j
                attrs[name] = raw[i : j + 1]
                i = j + 1
            elif i < n and raw[i] == "{":
                depth, j = 0, i
                while j < n:
                    if raw[j] == "{":
                        depth += 1
                    elif raw[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                attrs[name] = raw[i : j + 1]
                i = j + 1
            else:
                m2 = re.match(r"\S+", raw[i:])
                attrs[name] = m2.group(0) if m2 else ""
                i += len(attrs[name])
        else:
            attrs[name] = True
    return attrs, spread


def tags(f: JsFile, names: set[str] | None = None) -> list[Tag]:
    """Opening JSX/HTML tags (optionally only `names`). Scans comment-masked code."""
    code = f.code
    out = []
    for m in _TAG_OPEN.finditer(code):
        name = m.group(1)
        if names is not None and name not in names:
            continue
        i = m.end()
        depth = 0
        quote = ""
        while i < len(code):
            c = code[i]
            if quote:
                if c == quote:
                    quote = ""
            elif c in "\"'`" and depth == 0:
                quote = c
            elif c in "\"'`" and depth > 0:
                quote = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif c == ">" and depth == 0:
                break
            elif c == "<" and depth == 0 and code[i + 1 : i + 2].isalpha():
                i = -1  # not a real tag (e.g. TS generic followed by JSX)
                break
            i += 1
        if i == -1 or i >= len(code):
            continue
        raw = code[m.end() : i]
        attrs, spread = _parse_attrs(raw)
        out.append(Tag(name, m.start(), i, attrs, raw.rstrip().endswith("/"), spread))
    return out


def children(f: JsFile, tag: Tag) -> str | None:
    """Raw children of a non-self-closing tag (naive matching of same-name nesting)."""
    if tag.self_closing:
        return ""
    code = f.code
    depth = 1
    pos = tag.end + 1
    pat = re.compile(rf"<(/?){re.escape(tag.name)}(?=[\s/>])")
    while True:
        m = pat.search(code, pos)
        if not m:
            return None
        if m.group(1):
            depth -= 1
            if depth == 0:
                return code[tag.end + 1 : m.start()]
        else:
            close = code.find(">", m.end())
            if close != -1 and code[close - 1] != "/":
                depth += 1
        pos = m.end()


def visible_text(children_raw: str) -> tuple[str, bool]:
    """(text with tags and {expressions} removed, whether any {expression} was present)."""
    has_expr = "{" in children_raw
    text = children_raw
    prev = None
    while prev != text:  # strip nested braces
        prev = text
        text = re.sub(r"\{[^{}]*\}", " ", text)
    text = re.sub(r"<[^>]*>", " ", text)
    return " ".join(text.split()), has_expr
