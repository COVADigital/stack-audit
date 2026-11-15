# Accessibility & Internationalization — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `a11y.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Every UI must be usable by keyboard, by screen reader, and in other languages. Target WCAG 2.2 AA, and run axe on every page before marking work done.

---

## 01. Semantic HTML
**What:** Use elements for their meaning. This gives you accessibility, SEO, and keyboard behavior for free.

```html
<!-- ❌ -->
<div class="btn" onclick="buy()">Buy</div>
<div class="nav">...</div>
<!-- ✅ -->
<button type="button" onclick="buy()">Buy</button>
<header>…</header>
<nav aria-label="Main">…</nav>
<main id="main">…</main>
<footer>…</footer>
<h1> → <h2> → <h3>  (no skipped levels)
```
**Rule:** Use `<button>` for actions and `<a href>` for navigation, have one `<h1>` per page, and wrap lists in `<ul>` or `<ol>`.

---

## 02. ARIA Roles
**What:** Attributes that add semantics when HTML can't express them. **The first rule of ARIA is not to use ARIA when native HTML works.**

```html
<!-- Tabs pattern -->
<div role="tablist" aria-label="Albums">
  <button role="tab" aria-selected="true" aria-controls="p1" id="t1">Singles</button>
  <button role="tab" aria-selected="false" aria-controls="p2" id="t2" tabindex="-1">EPs</button>
</div>
<div role="tabpanel" id="p1" aria-labelledby="t1">…</div>

<button aria-expanded="false" aria-controls="menu">Menu</button>
<svg aria-hidden="true" focusable="false">…</svg>
```
**Rule:** Follow the ARIA Authoring Practices Guide patterns, or use Radix or React Aria, which implement them.

---

## 03. Keyboard Navigation
**What:** Everything must be operable with Tab, Shift+Tab, Enter, Space, Esc, and the arrow keys.

Prefer a real `<button>` (§01). Only if you truly cannot, a custom element must be focusable and handle keys:

```tsx
// Last resort: custom interactive element
<div role="button" tabIndex={0}
  onClick={toggle}
  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } }}>
```
```css
/* Never remove focus without replacement */
:focus-visible { outline: 3px solid var(--color-accent); outline-offset: 2px; }
```
**Rule:** Never use `outline: none` without a visible replacement or a positive `tabindex`. Unplug the mouse and test.

---

## 04. Focus Management
**What:** Move focus deliberately after route changes, dialogs, and deletions.

```tsx
// After client navigation, focus the new page heading
const h1 = useRef<HTMLHeadingElement>(null);
useEffect(() => { h1.current?.focus(); }, [pathname]);
<h1 ref={h1} tabIndex={-1}>{title}</h1>

// After deleting an item, focus the next item or the list heading
```
**Rule:** Focus is never lost to `<body>`. Dialogs trap focus and restore it to the trigger when they close.

---

## 05. Screen Readers
**What:** Software (VoiceOver, NVDA, JAWS, TalkBack) that reads the accessibility tree aloud.

```html
<span class="sr-only">Opens in new tab</span>
<button aria-label="Close dialog"><XIcon aria-hidden="true" /></button>
<button aria-describedby="price-note">Buy</button><p id="price-note">Taxes included</p>
```
```css
/* Prefer Tailwind's built-in `sr-only` class. Hand-rolled equivalent: */
.sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0 0 0 0); clip-path:inset(50%); white-space:nowrap; border:0; }
```
**Rule:** Every interactive element has an accessible name. Test with VoiceOver (Cmd+F5) or NVDA.

---

## 06. Color Contrast
**WCAG AA:** 4.5:1 for normal text, 3:1 for large text (24px, or 18.66px bold) and for UI components and focus rings.

```css
/* #777 on #fff = 4.48:1 ❌   #767676 on #fff = 4.54:1 ✅ */
/* Dark theme: #ff6a00 on #0b0b0b ≈ 7:1 ✅ */
```
**Rule:** Check contrast with DevTools or the WebAIM checker. Never convey meaning by color alone (add an icon or text to errors).

---

## 07. Alt Text
```html
<img src="live.jpg" alt="Singer performing on stage under orange lights">  <!-- informative -->
<img src="divider.svg" alt="">                                                       <!-- decorative -->
<a href="/"><img src="logo.svg" alt="Artist name — home"></a>                        <!-- functional: describe the action -->
```
**Rule:** Describe the purpose, not "image of…". Decorative images get `alt=""`. Make alt text a required field in the CMS (Sanity schema validation).

---

## 08. Forms and Labels
```tsx
<label htmlFor="email">Email</label>
<input id="email" type="email" autoComplete="email" required
  aria-invalid={!!err} aria-describedby={err ? 'email-err' : 'email-hint'} />
<p id="email-hint">We'll send your receipt here.</p>
{err && <p id="email-err" role="alert">{err}</p>}

<fieldset><legend>Shipping speed</legend>
  <label><input type="radio" name="ship" value="std" /> Standard</label>
</fieldset>
```
**Rule:** Every input has a visible `<label>` (placeholders are not labels). Use the correct `type` and `autocomplete`, and associate errors with their fields.

---

## 09. Skip Links
```html
<a href="#main" class="skip-link">Skip to main content</a>
…
<main id="main" tabindex="-1">…</main>
```
```css
.skip-link { position:absolute; left:-9999px; }
.skip-link:focus { left:1rem; top:1rem; z-index:1000; background:#000; color:#fff; padding:.5rem 1rem; }
```
**Rule:** The skip link is the first focusable element on every page that has repeated navigation.

---

## 10. Reduced Motion
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important; animation-iteration-count: 1 !important;
    transition-duration: .01ms !important; scroll-behavior: auto !important;
  }
}
```
```ts
const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
// Framer Motion: useReducedMotion()
```
**Rule:** No autoplay parallax, motion-heavy hero videos, or flashing above three per second for users who prefer reduced motion. Provide a pause control for any auto-moving content longer than five seconds.

---

## 11. Live Regions
**What:** Announce dynamic changes (toasts, cart updates, search counts) without moving focus.

```html
<div aria-live="polite" aria-atomic="true" class="sr-only" id="status"></div>
<!-- urgent errors -->
<div role="alert">Payment failed. Check your card details.</div>
```
```ts
document.getElementById('status')!.textContent = `${n} results found`;
```
**Rule:** The region must exist in the DOM *before* its content changes. Use `polite` by default and `assertive` or `alert` only for errors.

---

## 12. Accessible Modals
```html
<dialog id="cart" aria-labelledby="cart-title">
  <h2 id="cart-title">Your cart</h2>
  …
  <button autofocus onclick="cart.close()">Close</button>
</dialog>
<script> cart.showModal(); /* native focus trap, Esc, inert background */ </script>
```
**Rule:** Use native `<dialog>` with `showModal()`, or Radix Dialog. It needs a title, Esc to close, a focus trap, focus returned on close, and an inert background.

---

## 13. Testing with axe
```ts
// Playwright
import AxeBuilder from '@axe-core/playwright';
test('home is accessible', async ({ page }) => {
  await page.goto('/');
  const r = await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa','wcag22aa']).analyze();
  expect(r.violations).toEqual([]);
});
// Unit: jest-axe → expect(await axe(container)).toHaveNoViolations()
// Lint: eslint-plugin-jsx-a11y
```
**Rule:** Run axe in CI on key pages. Automated tools catch roughly 30 to 40% of issues, so also test manually with a keyboard and a screen reader.

---

## 14. WCAG Levels
| Level | Meaning | Examples |
|---|---|---|
| **A** | Minimum | Alt text, keyboard access, no keyboard traps |
| **AA** | Legal / industry standard target | 4.5:1 contrast, visible focus, resize to 200%, consistent nav, target size ≥24px (2.2) |
| **AAA** | Enhanced | 7:1 contrast, sign language for media |

**Rule:** Target **WCAG 2.2 AA**. It's what the ADA, Section 508, and the EU Accessibility Act effectively require.

---

## 15. Internationalization (i18n)
**What:** Engineering the app so it can be translated and localized without code changes.

```tsx
// next-intl
// messages/en.json: { "cart": { "items": "{count, plural, one {# item} other {# items}}" } }
const t = useTranslations('cart');
<p>{t('items', { count })}</p>
<html lang={locale} dir={dir}>
```
**Rule:** No hard-coded user-facing strings. Every string goes through `t()`, and you set `lang` on `<html>`.

---

## 16. RTL Support
**What:** Right-to-left languages (Arabic, Hebrew) mirror the layout.

```css
/* ✅ Logical properties flip automatically */
.card { margin-inline-start: 1rem; padding-inline: 1rem; border-inline-start: 3px solid; text-align: start; }
/* ❌ margin-left / text-align: left */
[dir='rtl'] .icon-arrow { transform: scaleX(-1); }
```
**Rule:** Use CSS logical properties everywhere. Mirror directional icons, but don't mirror logos, media controls, or numbers.

---

## 17. Date and Number Formats
```ts
new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'America/New_York' }).format(d);
// "Nov 13, 2026, 8:04 PM"
new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(1234.5); // "1.234,50 €"
new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(-1, 'day');          // "yesterday"
```
**Rule:** Store UTC (ISO 8601) and money as integer cents. Format at display time with `Intl` and an explicit locale and time zone. Never build date strings by hand.

---

## 18. Pluralization
```ts
// ❌ `${n} item${n === 1 ? '' : 's'}`  — breaks in Russian, Arabic, Polish…
const pr = new Intl.PluralRules('ru');
pr.select(2); // "few"
// ICU MessageFormat in translation files:
// "{count, plural, =0 {No tickets} one {# ticket} other {# tickets}}"
```
**Rule:** Always use ICU plural rules. Languages have up to six plural forms.

---

## 19. Locale Routing
```text
/en/tour   /es/tour   /fr/tour
```
```ts
// proxy.ts (next-intl on Next.js 16; middleware.ts before)
export default createMiddleware({ locales: ['en','es','fr'], defaultLocale: 'en', localeDetection: true });
```
```html
<link rel="alternate" hreflang="en" href="https://site.com/en/tour">
<link rel="alternate" hreflang="es" href="https://site.com/es/tour">
<link rel="alternate" hreflang="x-default" href="https://site.com/en/tour">
```
**Rule:** Put the locale in the URL (good for SEO and shareable links), add `hreflang` alternates, remember the user's choice in a cookie, and don't force redirects based only on IP.

---

## 20. Translation Workflow
**Pipeline:**
1. Developers add keys to `en.json` (the source of truth) with context comments
2. CI checks for missing or unused keys (`i18n-check`, `eslint-plugin-i18next`)
3. Keys sync to a TMS (Crowdin, Lokalise, Tolgee), where translators get the context and screenshots
4. Translations come back as a PR, with review by native speakers
5. Pseudo-localization in development catches truncation and hard-coded strings

```json
{ "checkout.cta": { "message": "Pay now", "description": "Primary button on checkout; max 20 chars" } }
```
**Rule:** Use namespaced keys (`feature.element.action`) and never concatenate translated fragments. Leave about 30% room for text expansion (German).

---

## 21. WCAG 2.2 Additions
**Target Size (2.5.8, AA):** Interactive targets are at least 24×24 CSS px, or have equivalent spacing around them.
**Focus Not Obscured (2.4.11, AA):** A focused element is not entirely hidden by sticky headers, cookie banners, or chat widgets.
**Inline language:** Mark foreign-language phrases, for example `<span lang="es">gracias</span>`, so screen readers switch pronunciation.

```css
.icon-btn { min-width: 24px; min-height: 24px; }
html { scroll-padding-top: var(--header-height); }   /* keeps focused elements clear of a sticky header */
```
**Rule:** Check target size and focus visibility with sticky UI open, and mark the language of inline foreign text.
