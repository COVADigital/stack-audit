#!/usr/bin/env python3
"""Accessibility & i18n audit (rules a11y.*, 09-accessibility-i18n.md). Read-only, static.

    python audit_a11y_i18n.py --root REPO [--changed] [--format md|json|sarif] [--strict]

Runtime checks (axe, keyboard, screen reader) are not done here: use playwright-cli
with assets/axe.spec.ts, plus a manual pass.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import _bootstrap  # noqa: F401
from wclib.cli import build_parser, finish, make_context
from wclib.color import candidate_pairs, contrast, extract_tokens, parse_color, resolve_scope, resolve_value
from wclib.findings import Report
from wclib.jsscan import JsFile, children, is_test_file, tags, visible_text
from wclib.rules import RuleBook
from wclib.stack import detect_stack
from wclib.textutil import mask_css_comments

SKILL = Path(__file__).resolve().parents[1]
NONINTERACTIVE = {"div", "span", "li", "p", "td", "tr", "img", "section", "article", "label", "h1", "h2", "h3", "svg"}
INTERACTIVE_ROLES = {"button", "link", "checkbox", "menuitem", "tab", "switch", "option", "radio", "slider", "textbox", "combobox", "treeitem", "gridcell"}
DIALOG_LIBS = re.compile(
    r"@radix-ui/react-(alert-)?dialog|from\s+['\"]radix-ui['\"]|@base-ui|react-aria|@headlessui|vaul|@ark-ui|"
    r"components/ui/(dialog|sheet|drawer|alert-dialog)|(Dialog|Sheet|Drawer)Primitive|<dialog\b|showModal\("
)
FOCUSABLE_TAGS = {"button", "a", "input", "select", "textarea", "summary", "Button", "Link", "Input", "Textarea", "Select", "SelectTrigger"}
TOAST_LIBS = re.compile(r"sonner|react-hot-toast|react-toastify|@radix-ui/react-toast|components/ui/(toast|sonner)|notistack")
RTL_LOCALES = {"ar", "he", "fa", "ur", "yi", "ps", "dv", "ckb"}
PHYSICAL_CSS = re.compile(r"\b(margin|padding|border)-(left|right)\b|\btext-align\s*:\s*(left|right)\b|(?<![\w-])(left|right)\s*:")
PHYSICAL_TW = re.compile(r"(?<![\w:-])(-?m[lr]-|p[lr]-|left-|right-|text-(left|right)\b|rounded-[lr]-|border-[lr](-|\b))")


class A11yAudit:
    def __init__(self, ctx, rb: RuleBook, report: Report) -> None:
        self.ctx, self.rb, self.report = ctx, rb, report
        self.stack = detect_stack(ctx.root)
        self.files: list[JsFile] = []
        for sf in ctx.walker.files(exts={".tsx", ".jsx", ".js", ".mjs", ".html", ".mdx"}):
            if is_test_file(sf.rel):
                continue
            text = sf.read()
            if text and ("<" in text):
                self.files.append(JsFile(sf.rel, text))
        self.css = [(sf.rel, sf.read()) for sf in ctx.walker.css_files()]
        self.all_code = "\n".join(f.code for f in self.files)

    def add(self, rule, msg, f: JsFile | None = None, offset: int | None = None, **kw):
        self.report.add(self.rb.make(
            rule, msg, file=f.rel if f else kw.pop("file", None),
            line=f.line_of(offset) if (f and offset is not None) else kw.pop("line", None),
            snippet=f.snippet(offset) if (f and offset is not None) else None, **kw))

    # ------------------------------------------------------------- per JSX file
    def jsx_checks(self, f: JsFile) -> None:
        all_tags = tags(f)
        ids_with_label = set(re.findall(r"htmlFor\s*=\s*\{?\s*['\"]([^'\"]+)['\"]", f.code)) | \
            set(re.findall(r"\bfor\s*=\s*['\"]([^'\"]+)['\"]", f.code))
        # dynamic ids: <Label htmlFor={id}> … <input id={id}> (compare the expression text)
        label_exprs = {re.sub(r"\s+", "", e) for e in re.findall(r"htmlFor\s*=\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", f.code)}
        h1_count = 0
        for t in all_tags:
            n = t.name
            # a11y.01 semantic interactive elements
            if n in NONINTERACTIVE and t.has("onClick"):
                role = t.literal("role")
                if not role and not t.has("role"):
                    self.add("a11y.01", f"<{n}> with onClick: not focusable or announced as interactive", f, t.start,
                             fix_hint="Use <button type=\"button\"> (actions) or <a href> / <Link> (navigation)")
                elif role in INTERACTIVE_ROLES and (not t.has("tabIndex", "tabindex") or not t.has("onKeyDown", "onKeyUp", "onKeyPress")):
                    self.add("a11y.03", f"<{n} role=\"{role}\"> needs tabIndex={{0}} and Enter/Space key handling", f, t.start,
                             severity="warn", fix_hint="Prefer a real <button>; otherwise add tabIndex and onKeyDown")
            if n == "a" and t.has("onClick") and not t.has("href", "role"):
                self.add("a11y.01", "<a> without href used as a button", f, t.start, fix_hint="Use <button type=\"button\">")
            if n == "h1":
                h1_count += 1
            # a11y.03 positive tabindex
            for key in ("tabIndex", "tabindex"):
                v = t.attr(key)
                if isinstance(v, str) and re.fullmatch(r"\{?\s*['\"]?([1-9]\d*)['\"]?\s*\}?", v.strip()):
                    self.add("a11y.03", f"Positive tabIndex ({v.strip('{}')}) breaks the natural focus order", f, t.start,
                             fix_hint="Use 0 or -1 and fix the DOM order instead")
            # a11y.03 outline-none without replacement, only on keyboard-focusable elements.
            # tabIndex={-1} targets (programmatic focus for screen readers) and Radix *.Content panels are fine.
            cls = t.attr("className") or t.attr("class")
            tab = t.attr("tabIndex")
            prog_focus = isinstance(tab, str) and re.fullmatch(r"\{?\s*-1\s*\}?|['\"]-1['\"]", tab.strip()) is not None
            keyboard_focusable = (n in FOCUSABLE_TAGS or (t.has("tabIndex") and not prog_focus)
                                  or (t.literal("role") or "") in INTERACTIVE_ROLES) and not n.endswith(".Content")
            if keyboard_focusable and isinstance(cls, str) and re.search(r"(?<![\w:-])outline-none\b", cls) \
                    and not re.search(r"focus(-visible|-within)?:(ring|outline|border|shadow|bg|underline)", cls):
                self.add("a11y.03", "outline-none without a focus-visible replacement", f, t.start,
                         fix_hint="Add e.g. focus-visible:ring-2 focus-visible:ring-offset-2")
            # a11y.05 icon-only buttons / links
            if n in ("button", "a", "Link", "Button") and not t.has("aria-label", "aria-labelledby", "title") and not t.has_spread:
                kids = children(f, t)
                if kids is not None:
                    text, has_expr = visible_text(kids)
                    if not text and not has_expr and re.search(r"<\s*(svg|img|Image|[A-Z]\w*Icon|Icon\b|[A-Z]\w*)\b", kids):
                        if not re.search(r"sr-only|visually-hidden|VisuallyHidden|alt=['\"{][^'\"}]", kids):
                            self.add("a11y.05", f"Icon-only <{n}> has no accessible name", f, t.start,
                                     fix_hint="Add aria-label=\"…\" (and aria-hidden on the icon) or sr-only text")
            # a11y.07 images
            if n in ("img", "Image"):
                if not t.has("alt") and not t.has_spread:
                    self.add("a11y.07", f"<{n}> without alt", f, t.start,
                             fix_hint="Describe the purpose; use alt=\"\" for decorative images")
                alt = t.literal("alt")
                if alt and re.match(r"(image|picture|photo|graphic|icon) of\b", alt.strip(), re.I):
                    self.add("a11y.07", f"alt text starts with \"{alt.split()[0]} of…\"", f, t.start, severity="info",
                             fix_hint="Describe what it shows or does; screen readers already announce 'image'")
            # a11y.08 form controls
            if n in ("input", "select", "textarea") and not t.has_spread:
                typ = (t.literal("type") or "text").lower()
                if typ in ("hidden", "submit", "button", "reset", "image"):
                    continue
                if t.has("hidden") or t.literal("aria-hidden") == "true":
                    continue  # not rendered / not exposed (e.g. file input opened by a visible button)
                id_attr = t.attr("id")
                labelled = t.has("aria-label", "aria-labelledby") or (t.literal("id") in ids_with_label) or \
                    (isinstance(id_attr, str) and id_attr.startswith("{") and re.sub(r"\s+", "", id_attr) in label_exprs)
                if not labelled:
                    before = f.code[max(0, t.start - 600): t.start]
                    if before.rfind("<label") > before.rfind("</label>") or before.rfind("<Label") > before.rfind("</Label>"):
                        labelled = True
                if not labelled:
                    extra = " (placeholder is not a label)" if t.has("placeholder") else ""
                    self.add("a11y.08", f"<{n}> has no associated label{extra}", f, t.start,
                             fix_hint="<label htmlFor=\"id\"> + id, a wrapping <label>, or aria-label")
                if typ in ("email", "tel") and not t.has("autoComplete", "autocomplete"):
                    self.add("a11y.08", f"type=\"{typ}\" input without autoComplete", f, t.start, severity="info",
                             fix_hint=f"autoComplete=\"{'email' if typ == 'email' else 'tel'}\"")
            # a11y.15 html lang
            if n == "html" and not t.has("lang") and not t.has_spread:
                self.add("a11y.15", "<html> without lang", f, t.start, severity="error",
                         fix_hint="<html lang={locale}> (and dir for RTL locales)")
        if h1_count > 1 and re.search(r"(^|/)page\.[jt]sx?$", f.rel):
            # Count per `return` branch: alternative returns (empty state vs data) each have their own <h1>.
            segments = re.split(r"\breturn\b", f.code)
            if any(len(re.findall(r"<h1[\s>]", seg)) > 1 for seg in segments):
                self.add("a11y.01", "More than one <h1> rendered in the same view", f, severity="warn", line=None,
                         fix_hint="One <h1> per page; demote the rest to <h2>")
        levels = [int(t.name[1]) for t in all_tags if re.fullmatch(r"h[1-6]", t.name)]
        for prev, cur in zip(levels, levels[1:]):
            if cur > prev + 1:
                self.add("a11y.01", f"Heading level jumps from h{prev} to h{cur}", f, severity="info",
                         fix_hint="Don't skip heading levels; style with CSS instead")
                break

    def i18n_strings(self, f: JsFile) -> None:
        if not re.search(r"(^|/)(app|components|src|features)/", f.rel) or f.rel.endswith((".html", ".mdx")):
            return
        hits = []
        for m in re.finditer(r">([^<>{}]*[A-Za-z][^<>{}]*)<", f.code):
            text = m.group(1).strip()
            if len(re.findall(r"[A-Za-z]{2,}", text)) >= 2 and not re.search(r"[=;()]|=>|&&|\|\|", text):
                hits.append(m.start(1))
        if hits:
            self.add("a11y.15", f"{len(hits)} hard-coded user-facing string(s) not passed through t()", f, hits[0],
                     confidence="medium", fix_hint="Move strings to messages/<locale>.json and render with t('key')")

    def l10n_formats(self, f: JsFile) -> None:
        for m in re.finditer(r"\.(toLocaleDateString|toLocaleTimeString|toLocaleString)\(\s*\)", f.code_nostr):
            self.add("a11y.17", f"{m.group(1)}() without an explicit locale (server and client may differ: hydration mismatch)",
                     f, m.start(), fix_hint="Intl.DateTimeFormat(locale, { …, timeZone }) with an explicit locale")
        for m in re.finditer(r"new\s+Intl\.(DateTimeFormat|NumberFormat)\(\s*\)", f.code_nostr):
            self.add("a11y.17", f"Intl.{m.group(1)}() without a locale", f, m.start())
        for m in re.finditer(r"\$\{[^}]+\}\s*\w+\$\{\s*[\w.]+\s*={2,3}\s*1\s*\?\s*(['\"])\1\s*:\s*(['\"])s\2\s*\}", f.code):
            self.add("a11y.18", "English-only pluralization in a template string", f, m.start(),
                     fix_hint="Use ICU plurals: {count, plural, one {# item} other {# items}}")
        for m in re.finditer(r"\bt\([^)]*\)\s*\+\s*(['\"`]|t\()", f.code):
            self.add("a11y.20", "Concatenating translated fragments (word order differs between languages)", f, m.start(),
                     severity="warn", fix_hint="One message with placeholders: t('key', { name })")

    # ------------------------------------------------------------- project level
    def project(self) -> None:
        code = self.all_code
        is_app = bool(self.stack.router.get("app") or self.stack.router.get("pages"))
        if is_app and re.search(r"<nav\b", code):
            if not re.search(r"href=['\"{]*#(main|content|main-content)\b|skip-?link|SkipLink|skip to", code, re.I):
                self.add("a11y.09", "Navigation present but no skip link to the main content found",
                         fix_hint="First focusable element: <a href=\"#main\" class=\"skip-link\">Skip to main content</a>")
        if is_app and self.files and not re.search(r"<main\b", code):
            self.add("a11y.09", "No <main> landmark found", fix_hint="Wrap page content in <main id=\"main\">")
        motion = self.stack.categories.get("motion")
        css_all = "\n".join(t for _, t in self.css)
        reduced = re.search(r"useReducedMotion|prefers-reduced-motion|reducedMotion|motion-safe:|motion-reduce:", code + css_all)
        if motion and not reduced:
            self.add("a11y.10", f"{motion} is used but nothing honors prefers-reduced-motion",
                     fix_hint="useReducedMotion() / <MotionConfig reducedMotion=\"user\"> or a CSS media query")
        if re.search(r"@keyframes|animation\s*:", css_all) and not reduced:
            self.add("a11y.10", "CSS animations without a prefers-reduced-motion rule",
                     fix_hint="Add the reduced-motion block from 09-accessibility-i18n §10")
        for f in self.files:
            name = f.rel.rsplit("/", 1)[-1].lower()
            if re.search(r"toast|snackbar|notification|flash", name) and not TOAST_LIBS.search(f.code) \
                    and not re.search(r"aria-live|role=['\"{]*(status|alert)", f.code):
                self.add("a11y.11", "Notification component without a live region", f, severity="warn", confidence="low",
                         fix_hint="aria-live=\"polite\" (role=\"status\"), present in the DOM before messages appear")
            if re.search(r"fixed\s+inset-0|position:\s*['\"]?fixed", f.code) and re.search(r"\bz-\[?\d|zIndex", f.code) \
                    and re.search(r"modal|dialog|overlay|lightbox|drawer", f.code, re.I) and not DIALOG_LIBS.search(f.code):
                self.add("a11y.12", "Custom modal/overlay without <dialog> or an accessible dialog primitive", f,
                         confidence="low", fix_hint="Use <dialog>.showModal() or Radix/React Aria Dialog (focus trap, Esc, inert)")
        i18n = self.stack.categories.get("i18n")
        if i18n:
            for f in self.files:
                self.i18n_strings(f)
            if re.search(r"\[locale\]", " ".join(self.ctx.walker.all_files())) and not re.search(r"hreflang|hrefLang|alternates\s*:\s*\{[^}]*languages", code + self.next_config_text()):
                self.add("a11y.19", "Locale-prefixed routes but no hreflang / alternates.languages metadata found",
                         fix_hint="generateMetadata → alternates: { languages: { en: '/en/…', es: '/es/…' } }")
        self.messages(rtl_check=True)

    def next_config_text(self) -> str:
        nc = self.stack.next_config.get("file")
        return (self.ctx.root / nc).read_text(encoding="utf-8", errors="replace") if nc else ""

    def messages(self, rtl_check: bool) -> None:
        cfg = self.ctx.config.get("i18n", {})
        source = cfg.get("sourceLocale", "en")
        candidates = [cfg.get("messagesDir", "messages"), "messages", "src/messages", "locales", "src/locales", "public/locales", "src/i18n/messages"]
        mdir = next((self.ctx.root / d for d in candidates if (self.ctx.root / d).is_dir()), None)
        locales: dict[str, dict] = {}
        if mdir:
            for p in sorted(mdir.glob("*.json")):
                locales[p.stem] = self._load_flat(p)
            for d in sorted(x for x in mdir.iterdir() if x.is_dir()):  # public/locales/<lng>/*.json
                merged: dict = {}
                for p in sorted(d.glob("*.json")):
                    merged.update({f"{p.stem}.{k}": v for k, v in self._load_flat(p).items()})
                if merged:
                    locales[d.name] = merged
        if rtl_check and (set(locales) & RTL_LOCALES):
            self.rtl()
        if not locales or source not in locales:
            return
        rel_dir = mdir.relative_to(self.ctx.root).as_posix()
        src = locales[source]
        for loc, keys in locales.items():
            if loc == source:
                continue
            missing = sorted(set(src) - set(keys))
            extra = sorted(set(keys) - set(src))
            if missing:
                self.add("a11y.20", f"Locale '{loc}' is missing {len(missing)} key(s): {', '.join(missing[:10])}"
                         + (" …" if len(missing) > 10 else ""), file=f"{rel_dir}/{loc}", fix_hint="Add translations or a fallback")
            if extra:
                self.add("a11y.20", f"Locale '{loc}' has {len(extra)} key(s) not in '{source}': {', '.join(extra[:10])}",
                         file=f"{rel_dir}/{loc}", severity="info")
        for loc, keys in locales.items():
            for k, v in keys.items():
                if isinstance(v, str) and re.search(r"\{\s*\w+\s*,\s*(plural|selectordinal)\s*,", v) and not re.search(r"\bother\s*\{", v):
                    self.add("a11y.20", f"ICU plural without an `other` case: {loc}:{k}", file=f"{rel_dir}/{loc}")

    @staticmethod
    def _load_flat(p: Path) -> dict:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict = {}

        def walk(prefix: str, node) -> None:
            if isinstance(node, dict):
                if set(node) >= {"message"} and isinstance(node.get("message"), str):  # {message, description} format
                    out[prefix] = node["message"]
                    return
                for k, v in node.items():
                    walk(f"{prefix}.{k}" if prefix else k, v)
            else:
                out[prefix] = node
        walk("", data)
        return out

    def rtl(self) -> None:
        for rel, text in self.css:
            masked = mask_css_comments(text)
            n = len(PHYSICAL_CSS.findall(masked))
            if n:
                self.add("a11y.16", f"{n} physical-direction CSS declaration(s) in an app with RTL locales", file=rel,
                         fix_hint="margin-inline-start, padding-inline, text-align: start, inset-inline-start")
        for f in self.files:
            n = 0
            for t in tags(f):
                cls = t.attr("className") or t.attr("class")
                if isinstance(cls, str):
                    n += len(PHYSICAL_TW.findall(cls))
            if n:
                self.add("a11y.16", f"{n} physical-direction Tailwind class(es) (ml-/pr-/left-/text-left…)", f,
                         fix_hint="Use logical utilities: ms-/me-/ps-/pe-/start-/end-/text-start")

    def contrast_tokens(self) -> None:
        tokens = []
        for rel, text in self.css:
            tokens += extract_tokens(text, rel)
        if not tokens:
            self.report.skipped.append("Contrast: no CSS color tokens found (:root / @theme / .dark); check component colors manually")
            return
        checked = 0
        for scope in ("light", "dark"):
            if scope == "dark" and not any(t.scope == "dark" for t in tokens):
                continue
            table = resolve_scope(tokens, scope)
            for fg_k, bg_k in candidate_pairs(table):
                fg_v, fg_t = resolve_value(table, fg_k)
                bg_v, _ = resolve_value(table, bg_k)
                fg, bg = (parse_color(fg_v) if fg_v else None), (parse_color(bg_v) if bg_v else None)
                if not fg or not bg:
                    continue
                checked += 1
                ratio = contrast(fg, bg)
                if fg.alpha < 1 or bg.alpha < 1:
                    continue
                if ratio < 4.5:
                    self.add("a11y.06", f"[{scope}] `{fg_k}` on `{bg_k}` is {ratio:.2f}:1 (needs 4.5:1 for normal text)",
                             file=fg_t.file, line=fg_t.line, severity="error" if ratio < 3 else "warn",
                             fix_hint="Darken/lighten the foreground token; 3:1 is acceptable only for large text and UI parts")
        self.report.meta["contrast_pairs_checked"] = checked

    def run(self) -> None:
        for f in self.files:
            if f.jsx or f.rel.endswith((".html", ".mdx")):
                self.jsx_checks(f)
                self.l10n_formats(f)
        for rel, text in self.css:
            masked = mask_css_comments(text)
            for m in re.finditer(r"([^{}]+)\{[^{}]*outline\s*:\s*(none|0)\b[^{}]*\}", masked):
                selector = m.group(1).strip().split("\n")[-1]
                if ":focus:not(:focus-visible)" in selector:
                    continue  # the recommended pattern: hide the ring only for mouse focus
                if ":focus-visible" not in masked:
                    self.add("a11y.03", f"`outline: {m.group(2)}` on `{selector[:60]}` with no :focus-visible style in this file",
                             file=rel, line=text.count("\n", 0, m.start()) + 1,
                             fix_hint=":focus-visible { outline: 3px solid var(--color-accent); outline-offset: 2px; }")
        self.contrast_tokens()
        self.project()
        self.report.not_checked += self.rb.not_checked("a11y")
        self.report.not_checked.append("Runtime: axe + keyboard + screen reader pass (playwright-cli with assets/axe.spec.ts)")


def main() -> int:
    ap = build_parser(__doc__.splitlines()[0])
    args = ap.parse_args()
    ctx = make_context(args)
    report = Report(tool="audit_a11y_i18n", root=str(ctx.root))
    A11yAudit(ctx, RuleBook(SKILL), report).run()
    return finish(report, ctx)


if __name__ == "__main__":
    sys.exit(main())
