"""CSS color parsing, WCAG contrast, and design-token extraction (light/dark scopes).

Supports hex (3/4/6/8), rgb()/rgba(), hsl()/hsla() (comma and space syntax),
bare shadcn-style HSL triplets ("222.2 47.4% 11.2%"), oklch(), oklab(), and a
few named colors. Alpha < 1 is reported so callers can skip unreliable pairs.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .textutil import mask_css_comments

NAMED = {"white": (1.0, 1.0, 1.0), "black": (0.0, 0.0, 0.0), "red": (1.0, 0.0, 0.0), "transparent": None}


@dataclass
class Color:
    r: float  # linear-light sRGB 0..1 (already decoded from gamma)
    g: float
    b: float
    alpha: float = 1.0

    @property
    def luminance(self) -> float:
        return 0.2126 * self.r + 0.7152 * self.g + 0.0722 * self.b


def _srgb_to_linear(c: float) -> float:
    c = min(max(c, 0.0), 1.0)
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _num(tok: str, scale: float = 1.0, pct_scale: float = 1.0) -> float:
    tok = tok.strip()
    if tok.endswith("%"):
        return float(tok[:-1]) / 100.0 * pct_scale
    if tok.endswith("deg"):
        return float(tok[:-3])
    return float(tok) * scale


def _split_args(inner: str) -> tuple[list[str], str | None]:
    alpha = None
    if "/" in inner:
        inner, alpha = inner.split("/", 1)
    parts = [p for p in re.split(r"[\s,]+", inner.strip()) if p]
    if alpha is None and len(parts) == 4:
        alpha = parts.pop()
    return parts, alpha


def _alpha(a: str | None) -> float:
    if a is None:
        return 1.0
    a = a.strip()
    return float(a[:-1]) / 100 if a.endswith("%") else float(a)


def _hsl_to_rgb(h: float, s: float, l: float) -> tuple[float, float, float]:
    h = (h % 360) / 360
    if s == 0:
        return l, l, l
    q = l * (1 + s) if l < 0.5 else l + s - l * s
    p = 2 * l - q

    def hue(t: float) -> float:
        t %= 1
        if t < 1 / 6:
            return p + (q - p) * 6 * t
        if t < 1 / 2:
            return q
        if t < 2 / 3:
            return p + (q - p) * (2 / 3 - t) * 6
        return p

    return hue(h + 1 / 3), hue(h), hue(h - 1 / 3)


def _oklab_to_linear(L: float, a: float, b: float) -> tuple[float, float, float]:
    l_ = L + 0.3963377774 * a + 0.2158037573 * b
    m_ = L - 0.1055613458 * a - 0.0638541728 * b
    s_ = L - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    r = 4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s
    g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s
    bb = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s
    return tuple(min(max(x, 0.0), 1.0) for x in (r, g, bb))  # type: ignore[return-value]


def parse_color(value: str) -> Color | None:
    v = value.strip().lower().rstrip(";").strip()
    v = re.sub(r"\s*!important$", "", v)
    try:
        if v in NAMED:
            rgb = NAMED[v]
            return None if rgb is None else Color(*(_srgb_to_linear(c) for c in rgb))
        if v.startswith("#"):
            h = v[1:]
            if len(h) in (3, 4):
                h = "".join(c * 2 for c in h)
            if len(h) not in (6, 8) or not re.fullmatch(r"[0-9a-f]+", h):
                return None
            r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
            a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
            return Color(_srgb_to_linear(r), _srgb_to_linear(g), _srgb_to_linear(b), a)
        m = re.fullmatch(r"(rgba?|hsla?|oklch|oklab)\((.*)\)", v)
        if m:
            fn, (parts, a) = m.group(1), _split_args(m.group(2))
            if len(parts) != 3:
                return None
            if fn.startswith("rgb"):
                r, g, b = (_num(p, 1 / 255, 1.0) for p in parts)
                return Color(_srgb_to_linear(r), _srgb_to_linear(g), _srgb_to_linear(b), _alpha(a))
            if fn.startswith("hsl"):
                h, s, l = _num(parts[0]), _num(parts[1], 0.01), _num(parts[2], 0.01)
                r, g, b = _hsl_to_rgb(h, s, l)
                return Color(_srgb_to_linear(r), _srgb_to_linear(g), _srgb_to_linear(b), _alpha(a))
            if fn == "oklch":
                L = _num(parts[0], 1.0, 1.0)
                C = _num(parts[1], 1.0, 0.4)
                H = math.radians(_num(parts[2]) if parts[2] != "none" else 0.0)
                r, g, b = _oklab_to_linear(L, C * math.cos(H), C * math.sin(H))
                return Color(r, g, b, _alpha(a))
            if fn == "oklab":
                L = _num(parts[0], 1.0, 1.0)
                r, g, b = _oklab_to_linear(L, _num(parts[1], 1.0, 0.4), _num(parts[2], 1.0, 0.4))
                return Color(r, g, b, _alpha(a))
        # shadcn v3 bare HSL triplet: "222.2 47.4% 11.2%"
        m = re.fullmatch(r"(-?[\d.]+)(?:deg)?\s+([\d.]+)%\s+([\d.]+)%(?:\s*/\s*([\d.]+%?))?", v)
        if m:
            r, g, b = _hsl_to_rgb(float(m.group(1)), float(m.group(2)) / 100, float(m.group(3)) / 100)
            return Color(_srgb_to_linear(r), _srgb_to_linear(g), _srgb_to_linear(b), _alpha(m.group(4)))
    except (ValueError, ZeroDivisionError):
        return None
    return None


def contrast(fg: Color, bg: Color) -> float:
    l1, l2 = sorted((fg.luminance, bg.luminance), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


# ----------------------------------------------------------------- token extraction

DARK_SELECTOR = re.compile(r"\.dark\b|\[data-theme=['\"]?dark|\[data-mode=['\"]?dark|prefers-color-scheme:\s*dark")
LIGHT_SELECTOR = re.compile(r":root|^html\b|@theme|\[data-theme=['\"]?light|:host|^body\b")


@dataclass
class Token:
    name: str
    value: str
    scope: str  # "light" | "dark"
    file: str
    line: int


def extract_tokens(css: str, rel: str) -> list[Token]:
    """Custom properties declared in theme-like blocks, with their scope."""
    text = mask_css_comments(css)
    tokens: list[Token] = []
    stack: list[str] = []
    buf_start = 0
    i = 0
    while i < len(text):
        c = text[i]
        if c == "{":
            selector = text[buf_start:i].strip().split(";")[-1].strip()
            stack.append(selector)
            buf_start = i + 1
        elif c == "}":
            if stack:
                stack.pop()
            buf_start = i + 1
        elif c == ";":
            decl = text[buf_start:i]
            dm = re.match(r"\s*(--[\w-]+)\s*:\s*(.+?)\s*$", decl, re.S)
            if dm and stack:
                chain = " ".join(stack)
                scope = "dark" if DARK_SELECTOR.search(chain) else ("light" if LIGHT_SELECTOR.search(stack[-1]) or "@theme" in chain else None)
                if scope:
                    line = text.count("\n", 0, buf_start + (len(decl) - len(decl.lstrip()))) + 1
                    tokens.append(Token(dm.group(1), " ".join(dm.group(2).split()), scope, rel, line))
            buf_start = i + 1
        i += 1
    return tokens


def _key(name: str) -> str:
    return re.sub(r"^--(color-)?", "", name)


def resolve_scope(tokens: list[Token], scope: str) -> dict[str, Token]:
    """Merged token table for a scope (dark inherits light). Keys normalized (--color-x == --x)."""
    table: dict[str, Token] = {}
    for t in tokens:
        if t.scope == "light":
            table.setdefault(_key(t.name), t) if t.name.startswith("--color-") else table.__setitem__(_key(t.name), t)
    if scope == "dark":
        for t in tokens:
            if t.scope == "dark":
                table[_key(t.name)] = t
    return table


def resolve_value(table: dict[str, Token], key: str, depth: int = 0) -> tuple[str | None, Token | None]:
    tok = table.get(key)
    if not tok or depth > 8:
        return None, tok
    val = tok.value
    m = re.fullmatch(r"var\(\s*(--[\w-]+)\s*(?:,\s*(.+))?\)", val)
    if m:
        inner, inner_tok = resolve_value(table, _key(m.group(1)), depth + 1)
        if inner is None and m.group(2):
            return m.group(2), tok
        return inner, tok
    m = re.fullmatch(r"(hsl|oklch|rgb)\(\s*var\(\s*(--[\w-]+)\s*\)\s*\)", val)  # hsl(var(--x)) shadcn v3 pattern
    if m:
        inner, _ = resolve_value(table, _key(m.group(2)), depth + 1)
        return (f"{m.group(1)}({inner})" if inner else None), tok
    return val, tok


def candidate_pairs(table: dict[str, Token]) -> list[tuple[str, str]]:
    pairs = []
    for k in table:
        if k.endswith("-foreground"):
            base = k[: -len("-foreground")]
            if base in table:
                pairs.append((k, base))
    for fg, bg in (("foreground", "background"), ("fg", "bg"), ("text", "background"), ("text", "bg"),
                   ("muted-foreground", "background"), ("card-foreground", "background")):
        if fg in table and bg in table and (fg, bg) not in pairs:
            pairs.append((fg, bg))
    return pairs
