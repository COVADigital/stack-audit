"""Minimal YAML reader for Docker Compose files (stdlib only).

Supports what Compose files use: block mappings and sequences, flow collections
([a, b], {k: v}), single/double-quoted and plain scalars, comments, block scalars
(| and >), anchors (&a), aliases (*a) and merge keys (<<: *a / <<: [*a, *b]),
plus multiple documents (only the first is used).

Not supported: tags, complex keys, multi-line plain scalars. Values are never
interpolated (`${VAR}` stays literal), so no environment data is read.

`load(text)` returns (data, lines) where `lines` maps key paths (tuples) to the
1-based line number where that key was defined.
"""

from __future__ import annotations

import re

_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$")


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out, quote, i = [], "", 0
    while i < len(line):
        c = line[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                if quote == "'" and line[i + 1: i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = ""
        else:
            if c in "\"'" and (not out or out[-1] in " \t[{,:-") :
                quote = c
                out.append(c)
            elif c == "#" and (not out or out[-1] in " \t"):
                break
            else:
                out.append(c)
        i += 1
    return "".join(out).rstrip()


def _scalar(tok: str):
    t = tok.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        body = t[1:-1]
        return re.sub(r'\\(["\\/nrt0]|u[0-9a-fA-F]{4})',
                      lambda m: {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(m.group(1),
                                                                                 chr(int(m.group(1)[1:], 16)) if m.group(1).startswith("u") else m.group(1)),
                      body)
    if t.startswith("'") and t.endswith("'") and len(t) >= 2:
        return t[1:-1].replace("''", "'")
    if _INT.match(t) and not (len(t.lstrip("+-")) > 1 and t.lstrip("+-").startswith("0")):
        return int(t)
    if _FLOAT.match(t):
        return float(t)
    return t


class _Parser:
    def __init__(self, text: str) -> None:
        raw = text.replace("\r\n", "\n").replace("\t", "  ").split("\n")
        self.lines: list[tuple[int, int, str]] = []  # (lineno, indent, content)
        for n, line in enumerate(raw, 1):
            if line.strip() == "---":
                if self.lines:
                    break
                continue
            if line.strip() == "...":
                break
            self.raw_index = None
            content = _strip_comment(line)
            if not content.strip():
                self.lines.append((n, -1, ""))  # blank (kept for block scalars)
                continue
            self.lines.append((n, len(content) - len(content.lstrip(" ")), content.strip()))
        self.raw = raw
        self.anchors: dict[str, object] = {}
        self.line_of: dict[tuple, int] = {}

    # ------------------------------------------------------------ helpers
    def _next(self, i: int) -> int:
        while i < len(self.lines) and self.lines[i][1] == -1:
            i += 1
        return i

    def _resolve_inline(self, text: str, path: tuple):
        """Value written on the same line as its key / dash."""
        text = text.strip()
        anchor = None
        m = re.match(r"&([\w.-]+)\s*(.*)$", text)
        if m:
            anchor, text = m.group(1), m.group(2).strip()
        if text.startswith("*"):
            name = text[1:].strip()
            if name not in self.anchors:
                raise YamlError(f"unknown alias *{name}")
            val = self.anchors[name]
        elif text.startswith(("[", "{")):
            val, rest = self._flow(text, 0)
            if text[rest:].strip():
                raise YamlError(f"trailing text after flow collection: {text[rest:]!r}")
        else:
            val = _scalar(text)
        if anchor:
            self.anchors[anchor] = val
        return val, anchor

    def _flow(self, s: str, i: int):
        while i < len(s) and s[i] == " ":
            i += 1
        c = s[i]
        if c == "[":
            out, i = [], i + 1
            while True:
                while i < len(s) and s[i] in " ,":
                    i += 1
                if i >= len(s):
                    raise YamlError("unterminated flow sequence")
                if s[i] == "]":
                    return out, i + 1
                val, i = self._flow(s, i)
                out.append(val)
        if c == "{":
            out, i = {}, i + 1
            while True:
                while i < len(s) and s[i] in " ,":
                    i += 1
                if i >= len(s):
                    raise YamlError("unterminated flow mapping")
                if s[i] == "}":
                    return out, i + 1
                key, i = self._flow_scalar(s, i, stop=":,}")
                while i < len(s) and s[i] == " ":
                    i += 1
                if i < len(s) and s[i] == ":":
                    val, i = self._flow(s, i + 1)
                else:
                    val = None
                out[str(key)] = val
        if c == "*":
            m = re.match(r"\*([\w.-]+)", s[i:])
            name = m.group(1)
            return self.anchors.get(name), i + m.end()
        return self._flow_scalar(s, i, stop=",]}")

    def _flow_scalar(self, s: str, i: int, stop: str):
        while i < len(s) and s[i] == " ":
            i += 1
        if i < len(s) and s[i] in "\"'":
            q = s[i]
            j = i + 1
            while j < len(s):
                if s[j] == "\\" and q == '"':
                    j += 2
                    continue
                if s[j] == q:
                    if q == "'" and s[j + 1: j + 2] == "'":
                        j += 2
                        continue
                    break
                j += 1
            return _scalar(s[i: j + 1]), j + 1
        j = i
        while j < len(s) and s[j] not in stop:
            if s[j] == ":" and ":" in stop and j + 1 < len(s) and s[j + 1] not in " ,}]":
                j += 1  # "a:b" inside a scalar (e.g. ports)
                continue
            j += 1
        return _scalar(s[i:j]), j

    def _block_scalar(self, i: int, indicator: str, parent_indent: int):
        style = indicator[0]
        chomp = "-" if "-" in indicator else ("+" if "+" in indicator else "")
        lines_out = []
        block_indent = None
        j = i
        while j < len(self.lines):
            n, ind, content = self.lines[j]
            raw = self.raw[n - 1]
            if ind == -1:
                lines_out.append("")
                j += 1
                continue
            cur = len(raw) - len(raw.lstrip(" "))
            if cur <= parent_indent:
                break
            if block_indent is None:
                block_indent = cur
            lines_out.append(raw[block_indent:])
            j += 1
        while lines_out and lines_out[-1] == "" and chomp != "+":
            lines_out.pop()
        text = "\n".join(lines_out) if style == "|" else re.sub(r"(?<!\n)\n(?!\n)", " ", "\n".join(lines_out))
        return text + ("" if chomp == "-" else "\n"), j

    # ------------------------------------------------------------ block parsing
    def parse_node(self, i: int, indent: int, path: tuple):
        i = self._next(i)
        if i >= len(self.lines):
            return None, i
        n, ind, content = self.lines[i]
        if ind < indent:
            return None, i
        if content.startswith("- ") or content == "-":
            return self.parse_seq(i, ind, path)
        if re.match(r"""^(?:"[^"]*"|'[^']*'|[^\s"'#][^:]*?)\s*:(\s|$)""", content):
            return self.parse_map(i, ind, path)
        val, _ = self._resolve_inline(content, path)
        return val, i + 1

    def parse_map(self, i: int, indent: int, path: tuple):
        out: dict = {}
        merges: list = []
        while True:
            i = self._next(i)
            if i >= len(self.lines):
                break
            n, ind, content = self.lines[i]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"line {n}: unexpected indentation")
            if content.startswith("- "):
                break
            m = re.match(r"""^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:]+?)\s*:(?:\s+(.*))?$""", content)
            if not m:
                raise YamlError(f"line {n}: expected 'key: value', got {content!r}")
            key = _scalar(m.group(1))
            key = str(key) if key is not None else ""
            rest = (m.group(2) or "").strip()
            kpath = path + (key,)
            self.line_of[kpath] = n
            i += 1
            if rest and rest[0] in "|>" and re.fullmatch(r"[|>][-+]?\d?", rest):
                val, i = self._block_scalar(i, rest, indent)
            elif rest and not (rest.startswith("&") and re.fullmatch(r"&[\w.-]+", rest)):
                val, _ = self._resolve_inline(rest, kpath)
            else:
                anchor = rest[1:] if rest.startswith("&") else None
                j = self._next(i)
                if j < len(self.lines) and (self.lines[j][1] > indent or
                                            (self.lines[j][1] == indent and self.lines[j][2].startswith("- "))):
                    val, i = self.parse_node(j, self.lines[j][1], kpath)
                else:
                    val = None
                if anchor:
                    self.anchors[anchor] = val
            if key == "<<":
                merges += val if isinstance(val, list) else [val]
            else:
                out[key] = val
        for mp in merges:
            if isinstance(mp, dict):
                for k, v in mp.items():
                    out.setdefault(k, v)
                    if path + (k,) not in self.line_of:
                        self.line_of[path + (k,)] = self.line_of.get(path + ("<<",), 0)
        return out, i

    def parse_seq(self, i: int, indent: int, path: tuple):
        out: list = []
        while True:
            i = self._next(i)
            if i >= len(self.lines):
                break
            n, ind, content = self.lines[i]
            if ind != indent or not (content.startswith("- ") or content == "-"):
                break
            ipath = path + (len(out),)
            self.line_of[ipath] = n
            rest = content[1:].strip()
            if not rest:
                val, i = self.parse_node(i + 1, indent + 1, ipath)
            elif re.match(r"""^(?:"[^"]*"|'[^']*'|[^\s"'\[{*&][^:]*?)\s*:(\s|$)""", rest) and not rest.startswith(("[", "{")):
                # "- key: value" starts an inline mapping; following keys are indented past the dash
                child_indent = indent + (len(content) - len(rest))
                self.lines[i] = (n, child_indent, rest)
                val, i = self.parse_map(i, child_indent, ipath)
            else:
                val, _ = self._resolve_inline(rest, ipath)
                i += 1
            out.append(val)
        return out, i


def load(text: str) -> tuple[object, dict[tuple, int]]:
    p = _Parser(text)
    data, _ = p.parse_node(0, 0, ())
    return data, p.line_of
