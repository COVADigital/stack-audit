# Performance — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `perf.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Every feature ships within a performance budget. Measure before and after, and don't guess.

---

## 01. Core Web Vitals
**What:** Google's user-experience metrics: **LCP** (loading), **INP** (interactivity), and **CLS** (visual stability). They are measured at the 75th percentile.

| Metric | Good | Needs work | Poor |
|---|---|---|---|
| LCP | ≤ 2.5s | ≤ 4s | > 4s |
| INP | ≤ 200ms | ≤ 500ms | > 500ms |
| CLS | ≤ 0.1 | ≤ 0.25 | > 0.25 |

```ts
import { onLCP, onINP, onCLS } from 'web-vitals';
[onLCP, onINP, onCLS].forEach(fn => fn(m => navigator.sendBeacon('/vitals', JSON.stringify(m))));
```
**Rule:** Every public page must hit "Good" on all three.

---

## 02. LCP (Largest Contentful Paint)
**What:** The time until the largest visible element (usually the hero image or headline) renders.

```tsx
import Image from 'next/image';
// Next.js 16: `preload` replaces the deprecated `priority` prop
<Image src="/hero.webp" alt="Singer performing live" width={1600} height={900} preload />
```
**Fixes:** Preload the hero, avoid lazy-loading it, use a fast TTFB, and serve modern image formats.
**Next.js 16 notes:** Don't combine `preload` with `loading` or `fetchPriority`. If different images can be the LCP element at different viewport sizes, use `fetchPriority="high"` (or `loading="eager"`) on them instead of `preload`. Keep the LCP element outside `<Suspense>` boundaries so it ships in the static shell.
**Rule:** Never lazy-load the LCP element.

---

## 03. INP (Interaction to Next Paint)
**What:** The latency from a user interaction until the next frame paints, measured on the worst-ish interaction.

```tsx
// Keep input responsive; defer expensive work
const [query, setQuery] = useState('');
const deferred = useDeferredValue(query);
const results = useMemo(() => search(deferred), [deferred]);

// Or yield to the main thread
await scheduler.yield?.();
```
**Rule:** No task over 50ms on the main thread during an interaction. Split long tasks.

---

## 04. CLS (Cumulative Layout Shift)
**What:** How much visible content jumps around unexpectedly.

```html
<!-- Reserve space -->
<img src="a.jpg" width="800" height="450" alt="">
<div style="aspect-ratio:16/9"><iframe ...></iframe></div>
```
```css
.ad-slot { min-height: 250px; }
```
**Rule:** Every image, video, embed, and ad gets explicit dimensions or an `aspect-ratio`. Never insert content above existing content.

---

## 05. TTFB (Time to First Byte)
**What:** The time from the request until the first byte of the response arrives. It covers DNS, TLS, server processing, and the network.

```ts
// Measure in browser
const [nav] = performance.getEntriesByType('navigation');
console.log('TTFB', nav.responseStart - nav.requestStart);
```
**Fixes:** CDN caching, SSG or ISR, edge rendering, DB indexes, and avoiding waterfall fetches on the server.
**Rule:** Target TTFB under 800ms (under 200ms for cached pages).

---

## 06. Code Splitting
**What:** Split the JS bundle into chunks that load on demand.

```tsx
// Route-level: automatic in Next.js
// Component-level:
const Editor = dynamic(() => import('@/components/Editor'));
// Vanilla:
button.onclick = async () => { const { exportPdf } = await import('./pdf'); exportPdf(); };
```
**Rule:** Anything over 30KB that isn't needed on first paint gets dynamically imported.

---

## 07. Tree Shaking
**What:** Bundlers remove unused exports. This requires ES modules and side-effect-free code.

```ts
// ❌ pulls the whole library
import _ from 'lodash';
// ✅ only what you use
import debounce from 'lodash-es/debounce';
```
```json
// package.json of your own lib
{ "sideEffects": false }
```
**Rule:** Use named ESM imports and check bundle impact before adding a dependency.

---

## 08. Lazy Loading
**What:** Load resources only when they're about to be needed.

```html
<img src="gallery-5.jpg" loading="lazy" decoding="async" width="400" height="300" alt="">
<iframe src="https://www.youtube.com/embed/..." loading="lazy"></iframe>
```
```ts
const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) loadWidget(); }, { rootMargin: '200px' });
```
**Rule:** Lazy-load everything below the fold. Never lazy-load the above-the-fold content.

---

## 09. Image Optimization
**What:** The right format, size, and compression for each device.

```html
<picture>
  <source srcset="hero.avif" type="image/avif">
  <source srcset="hero.webp" type="image/webp">
  <img src="hero.jpg" srcset="hero-800.jpg 800w, hero-1600.jpg 1600w"
       sizes="(max-width: 768px) 100vw, 50vw" width="1600" height="900" alt="...">
</picture>
```
**Rule:** Use AVIF or WebP, responsive `srcset`, explicit dimensions, and never ship a 4000px image to a 400px slot.

---

## 10. Font Loading
**What:** Load web fonts without invisible text (FOIT) or big layout shifts (FOUT).

```tsx
// next/font: self-hosted, preloaded, size-adjusted fallback
import { Inter } from 'next/font/google';
const inter = Inter({ subsets: ['latin'], display: 'swap' });
```
```css
@font-face {
  font-family: 'Brand';
  src: url('/brand.woff2') format('woff2');
  font-display: swap;
  unicode-range: U+0000-00FF;
}
```
**Rule:** WOFF2 only, subset the font, self-host it, use `font-display: swap`, and limit yourself to two families.

---

## 11. Bundle Analysis
**What:** Visualize what is inside your JS bundles.

```bash
# Next.js 16.1+ (Turbopack is the default bundler)
npx next experimental-analyze            # interactive UI: filter by route, client/server, file type
npx next experimental-analyze --output   # static copy in .next/diagnostics/analyze (compare before/after)

# webpack builds only (the plugin produces nothing under Turbopack)
npm i -D @next/bundle-analyzer && ANALYZE=true next build --webpack
```
**Rule:** Run the analyzer before merging any PR that adds a dependency.

---

## 12. Prefetch and Preload
**What:** `preload` means "I need this now, on this page". `prefetch` means "I'll probably need this on the next page". `preconnect` warms up a connection.

```html
<link rel="preconnect" href="https://cdn.sanity.io">
<link rel="preload" href="/hero.avif" as="image" fetchpriority="high">
<link rel="prefetch" href="/checkout.js">
```
```tsx
<Link href="/shop" prefetch>Shop</Link>  // Next.js prefetches in viewport
```
**Rule:** Preload at most two or three critical resources. Over-preloading competes for bandwidth.

---

## 13. Compression
**What:** Compress text assets in transit with Brotli (best) or gzip.

```nginx
# Requires the ngx_brotli module. Vercel, Cloudflare and most reverse proxies
# (Traefik in Coolify, Caddy) compress for you — verify with the curl check below.
brotli on;
brotli_types text/html text/css application/javascript application/json image/svg+xml;
gzip on;
```
```bash
curl -sI -H 'Accept-Encoding: br' https://site.com/app.js | grep -i content-encoding
```
**Rule:** All text responses are Brotli- or gzip-encoded. Never re-compress images.

---

## 14. Debounce and Throttle
**What:** Debounce runs once after events stop. Throttle runs at most once every N ms.

```ts
function debounce<T extends (...a: any[]) => void>(fn: T, ms = 300) {
  let t: ReturnType<typeof setTimeout>;
  return (...a: Parameters<T>) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
function throttle<T extends (...a: any[]) => void>(fn: T, ms = 100) {
  let last = 0;
  return (...a: Parameters<T>) => { const now = Date.now(); if (now - last >= ms) { last = now; fn(...a); } };
}
search.addEventListener('input', debounce(e => fetchResults(e.target.value), 300));
window.addEventListener('scroll', throttle(updateProgress, 100), { passive: true });
```
**Rule:** Debounce search inputs. Throttle scroll and resize handlers, and make them passive.

---

## 15. Memoization
**What:** Cache the results of expensive computations or renders.

```tsx
const sorted = useMemo(() => [...items].sort(byPrice), [items]);
const onSelect = useCallback((id: string) => setSelected(id), []);
const Row = memo(function Row({ item }) { return <li>{item.name}</li>; });
```
**Rule:** Memoize only after profiling shows a problem. Never memoize something cheap. With the React Compiler enabled (`reactCompiler: true`), rely on it for new code; keep existing `useMemo`/`useCallback` unless you test their removal, because removing them can change compiled output.

---

## 16. Virtualized Lists
**What:** Render only the visible rows of a long list.

```tsx
import { useVirtualizer } from '@tanstack/react-virtual';
const v = useVirtualizer({ count: rows.length, getScrollElement: () => ref.current, estimateSize: () => 48 });
<div ref={ref} style={{ height: 600, overflow: 'auto' }}>
  <div style={{ height: v.getTotalSize(), position: 'relative' }}>
    {v.getVirtualItems().map(r => (
      <div key={r.key} style={{ position: 'absolute', top: 0, transform: `translateY(${r.start}px)` }}>
        {rows[r.index].name}
      </div>
    ))}
  </div>
</div>
```
**Rule:** Virtualize any list that can exceed about 200 items.

---

## 17. Web Workers
**What:** Run heavy JS off the main thread.

```ts
// worker.ts
self.onmessage = (e) => { const result = heavyParse(e.data); postMessage(result); };
// main.ts
const w = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
w.postMessage(csvText);
w.onmessage = (e) => render(e.data);
```
**Rule:** Move parsing, image processing, crypto, and big sorts into workers (Comlink makes the API nicer).

---

## 18. Performance Budgets
**What:** Hard limits that fail the build when they're exceeded.

```json
// lighthouserc.json
{
  "ci": {
    "assert": {
      "assertions": {
        "categories:performance": ["error", { "minScore": 0.9 }],
        "largest-contentful-paint": ["error", { "maxNumericValue": 2500 }],
        "total-byte-weight": ["warn", { "maxNumericValue": 500000 }]
      }
    }
  }
}
```
**Example budget:** JS under 170KB gzipped on initial load, LCP under 2.5s on a mid-tier mobile device over 4G, and a maximum of three third-party scripts.
**Rule:** Budgets live in the repo and are enforced in CI.

---

## 19. Lighthouse
**What:** Google's automated audit tool for Performance, Accessibility, Best Practices, and SEO.

```bash
npx lighthouse https://site.com --preset=desktop --output=html --output-path=./report.html
npx @lhci/cli autorun   # in CI
```
**Rule:** Lighthouse is *lab* data. Confirm with field data (RUM or CrUX) before declaring victory.

---

## 20. Real User Monitoring (RUM)
**What:** Collecting performance data from real users' browsers.

```ts
// app/web-vitals.tsx
'use client';
import { useReportWebVitals } from 'next/web-vitals';
export function WebVitals() {
  useReportWebVitals((m) => {
    navigator.sendBeacon('/api/rum', JSON.stringify({ name: m.name, value: m.value, page: location.pathname }));
  });
  return null;
}
```
**Tools:** Vercel Speed Insights, Sentry, Datadog RUM, Cloudflare Web Analytics.
**Rule:** Ship RUM with every production site and track the p75 per route.
