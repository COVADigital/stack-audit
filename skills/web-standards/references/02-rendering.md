# Rendering — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `ren.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Before building any page, decide *where* and *when* its HTML is produced (build time, request time, or client). Write the decision in the PR or the route's header comment (template: `assets/route-decision-header.txt`).

> **Two caching models exist in Next.js 16.** Check `next.config` for `cacheComponents: true` (the stack profile reports it):
> - **Cache Components (recommended for new apps):** everything is dynamic by default; opt into caching with `'use cache'` + `cacheLife()` + `cacheTag()`. The segment configs `dynamic`, `revalidate`, `fetchCache` **are build errors** in this mode, and `runtime = 'edge'` is not supported.
> - **Legacy model:** `export const revalidate`, `export const dynamic`, `fetch(..., { next: { tags } })`, `unstable_cache`.
> See `next16-cache-model.md` for the full map.

---

## 01. CSR vs SSR
**What:** Client-Side Rendering builds the HTML in the browser with JS. Server-Side Rendering sends ready-made HTML from the server.
**Trade-off:** CSR gives a fast server and a slow first paint with poor SEO. SSR gives a fast first paint and good SEO, but costs server CPU on every request.

```tsx
// CSR (React SPA)
function Profile() {
  const [user, setUser] = useState(null);
  useEffect(() => { fetch('/api/me').then(r => r.json()).then(setUser); }, []);
  return user ? <h1>{user.name}</h1> : <Spinner />;
}

// SSR (Next.js 16, Cache Components): dynamic by default.
// Reading cookies()/headers()/searchParams, or awaiting connection(), makes it per-request.
import { connection } from 'next/server';
export default async function Profile() {
  await connection();                    // explicit: render at request time
  const user = await getUser();
  return <h1>{user.name}</h1>;
}
// Legacy model only: export const dynamic = 'force-dynamic';
```
**Rule:** Use SSR or SSG for public and SEO pages. Reserve CSR for authenticated, highly interactive dashboards.

---

## 02. Static Generation (SSG)
**What:** HTML is generated once at build time and served from a CDN.
**Why:** It's the fastest and cheapest option, and the most cacheable.

```tsx
// app/blog/[slug]/page.tsx
export async function generateStaticParams() {
  const posts = await getAllPosts();
  return posts.map(p => ({ slug: p.slug }));
}
export default async function Post({ params }) {
  const post = await getPost((await params).slug);
  return <article>{post.title}</article>;
}
```
**Rule:** Default to SSG for marketing pages, docs, and blog posts.

---

## 03. Incremental Static Regeneration (ISR)
**What:** Static pages that rebuild in the background after a time window or on demand.
**Why:** You get SSG speed while content stays fresh, without a full rebuild.

```tsx
// Cache Components (Next.js 16)
import { cacheLife, cacheTag } from 'next/cache';
export async function getPosts() {
  'use cache';
  cacheLife('hours');
  cacheTag('posts');
  return db.select().from(posts);
}
// Legacy model: export const revalidate = 3600;

// On-demand (e.g., CMS webhook → app/api/revalidate/route.ts)
import { revalidateTag } from 'next/cache';
export async function POST(req: Request) {
  // verify the webhook signature first (08-security §10, OWASP Webhook_Security)
  revalidateTag('posts', 'max');   // Next 16: profile argument required; one-arg form is deprecated
  return Response.json({ ok: true });
}

// In a Server Action where the user must see their own change immediately:
// updateTag('posts')   — Server Actions only; the next read waits for fresh data
```
**Rule:** Use ISR / cached functions for CMS-driven content. Prefer tag-based on-demand revalidation over short timers. Route handlers and webhooks use `revalidateTag(tag, 'max')`; Server Actions that need read-your-own-writes use `updateTag(tag)`.

---

## 04. Streaming SSR
**What:** The server sends HTML in chunks as data resolves, instead of waiting for everything.
**Why:** The shell paints immediately and slow sections stream in later.

```tsx
export default function Page() {
  return (
    <>
      <Header />                       {/* sent immediately */}
      <Suspense fallback={<Skeleton />}>
        <SlowRecommendations />        {/* streamed when ready */}
      </Suspense>
    </>
  );
}
```
**Rule:** Wrap any slow data dependency in `<Suspense>` so it can't block the whole page.

---

## 05. Hydration
**What:** React attaches event handlers to server-rendered HTML so it becomes interactive.
**Pitfall:** Hydration mismatches happen when the server and client render different output (dates, `Math.random`, `window`).

```tsx
// ❌ Mismatch: server time ≠ client time
<p>{new Date().toLocaleTimeString()}</p>

// ✅ Render client-only values after mount
const [now, setNow] = useState<string | null>(null);
useEffect(() => setNow(new Date().toLocaleTimeString()), []);
<p>{now ?? '—'}</p>
```
**Rule:** Never read `window`, `localStorage`, or random or time values during render in SSR components.

---

## 06. Partial Hydration
**What:** Only interactive parts of the page get JS and hydrate. Static parts stay as plain HTML.
**Why:** Less JS shipped means faster interactivity.

```tsx
// Server Component (no JS shipped)
export default function Product({ p }) {
  return (
    <div>
      <h1>{p.name}</h1>
      <p>{p.description}</p>
      <AddToCart id={p.id} />   {/* only this hydrates */}
    </div>
  );
}
// AddToCart.tsx
'use client';
export function AddToCart({ id }) { /* ... */ }
```
**Rule:** Push `'use client'` as far down the component tree as possible.

---

## 07. Islands Architecture
**What:** A page is static HTML with isolated interactive "islands" that each hydrate on their own.
**Where:** Astro, Fresh, Eleventy with is-land.

```astro
---
import Counter from '../components/Counter.jsx';
---
<h1>Static heading</h1>
<Counter client:visible />   <!-- hydrates only when scrolled into view -->
```
**Rule:** For content-heavy sites with little interactivity, consider an islands framework.

---

## 08. React Server Components (RSC)
**What:** Components that run only on the server, can access the DB or secrets directly, and ship zero JS.
**Rules of thumb:** Server components can import client components, but not the reverse (pass server components in as `children` instead).

```tsx
// Server Component: data via the server-only DAL (07-architecture §21), no API route needed
import { getMyOrders } from '@/lib/dal/orders';
export default async function Orders() {
  const orders = await getMyOrders();   // auth check + Drizzle query live in the DAL
  return <OrderTable orders={orders} />;
}
```
**Rule:** Fetch data in server components. Mark a component `'use client'` only when it needs state, effects, or browser APIs.

---

## 09. Edge Rendering
**What:** Rendering at CDN edge locations close to the user, on a lightweight runtime.
**Limits:** No full Node APIs, small bundle limits, and the database may be far away.

```tsx
export const runtime = 'edge';   // legacy model only — not supported with Cache Components
export default function Page({ params }) {
  return <h1>Hello from the edge</h1>;
}
```
**Next.js 16:** `proxy.ts` (formerly `middleware.ts`) runs on the Node.js runtime, and Cache Components require Node.
**Rule:** Default to the Node.js runtime. Use `proxy.ts` for redirects and coarse auth gating, and platform/CDN features for geo and A/B routing. Keep DB-heavy work in regional Node functions near the database.

---

## 10. Critical Rendering Path
**What:** The browser's sequence: HTML → DOM → CSS → CSSOM → Render Tree → Layout → Paint.
**Optimize:** Inline critical CSS, defer non-critical JS, and preload key resources.

```html
<head>
  <style>/* critical above-the-fold CSS */</style>
  <link rel="preload" href="/fonts/inter.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="/main.css" media="print" onload="this.media='all'">
  <script src="/app.js" defer></script>
</head>
```
**Rule:** Nothing render-blocking in `<head>` unless it's critical.

---

## 11. Reflow and Repaint
**What:** A reflow recalculates layout (expensive). A repaint redraws pixels (cheaper).
**Triggers reflow:** Changing width, height, top, or font-size, or reading `offsetHeight`.

```css
/* ❌ Animating layout properties → reflow every frame */
.box { transition: left 300ms; }
/* ✅ Animate compositor-only properties */
.box { transition: transform 300ms; }
```
**Rule:** Animate only `transform` and `opacity`.

---

## 12. Virtual DOM
**What:** An in-memory tree representation of the UI. Frameworks diff it against the previous tree and apply the minimal set of real DOM changes.

```jsx
// You declare the target UI…
<ul>{items.map(i => <li key={i.id}>{i.name}</li>)}</ul>
// …React computes the minimal DOM ops (insert 1 <li>) when items changes.
```
**Rule:** Don't manipulate the DOM directly inside React-managed trees. Use refs only for imperative escape hatches.

---

## 13. Reconciliation
**What:** React's diffing algorithm. Different element types replace the subtree, and `key` identifies list items.

```jsx
// ❌ Index keys break state when list reorders
{todos.map((t, i) => <Todo key={i} {...t} />)}
// ✅ Stable unique keys
{todos.map(t => <Todo key={t.id} {...t} />)}

// Trick: change key to force a full remount/reset
<Form key={userId} />
```
**Rule:** Always use stable IDs as keys, never the array index for dynamic lists.

---

## 14. Layout Thrashing
**What:** Alternating DOM reads and writes in a loop, which forces a synchronous reflow on every iteration.

```js
// ❌ read/write/read/write
boxes.forEach(b => { b.style.width = b.parentNode.offsetWidth + 'px'; });

// ✅ batch reads, then batch writes
const widths = boxes.map(b => b.parentNode.offsetWidth);
requestAnimationFrame(() => boxes.forEach((b, i) => b.style.width = widths[i] + 'px'));
```
**Rule:** Batch reads before writes, and schedule writes in `requestAnimationFrame`.

---

## 15. Paint and Composite
**What:** Paint fills in pixels. Compositing combines layers on the GPU, and compositing alone is cheapest.

```css
.modal {
  will-change: transform;   /* promote to its own layer — use sparingly */
  transform: translateZ(0);
}
```
**Rule:** Promote only elements that are actively animating. Too many layers waste GPU memory.

---

## 16. Lazy Rendering
**What:** Defer rendering of offscreen or rarely used UI until it's needed.

```tsx
'use client';                       // `ssr: false` is only allowed in Client Components
import dynamic from 'next/dynamic';
const Chart = dynamic(() => import('./Chart'), { ssr: false, loading: () => <Skeleton/> });
```
```css
/* Browser-native: skip rendering offscreen sections */
.section { content-visibility: auto; contain-intrinsic-size: 800px; }
```
**Rule:** Lazy-render heavy below-the-fold components such as charts, editors, and maps.

---

## 17. Pre-rendering
**What:** Generating HTML ahead of a request, either at build time (SSG) or speculatively before the user navigates.

```html
<!-- Speculation Rules API: prerender likely next page -->
<script type="speculationrules">
{ "prerender": [{ "where": { "href_matches": "/products/*" }, "eagerness": "moderate" }] }
</script>
```
**Rule:** Prerender the most likely next navigation, such as checkout from the cart.

---

## 18. SEO and Rendering
**What:** Crawlers index HTML best. Content that appears only after JS runs may be delayed or missed.

```tsx
export async function generateMetadata({ params }) {
  const p = await getProduct((await params).slug);
  return {
    title: `${p.name} | Store`,
    description: p.summary,
    openGraph: { images: [p.image] },
    alternates: { canonical: `https://example.com/p/${p.slug}` },
  };
}
```
**Rule:** Indexable pages must render their main content and metadata server-side (`export const metadata` for static routes, `generateMetadata` for dynamic ones). Add JSON-LD structured data, and `app/sitemap.ts` + `app/robots.ts`.

---

## 19. Suspense Boundaries
**What:** Declarative loading states. A component that "suspends" shows the nearest fallback.

```tsx
<Suspense fallback={<PageSkeleton />}>
  <Header />
  <Suspense fallback={<FeedSkeleton />}>
    <Feed />
  </Suspense>
</Suspense>
// Next.js: app/dashboard/loading.tsx is an automatic Suspense boundary
```
**Rule:** Place boundaries around independent data regions, and pair each with an error boundary (`error.tsx`, which must be a Client Component). Add `app/global-error.tsx` for root-layout failures.

---

## 20. Choosing a Strategy
| Page type | Strategy |
|---|---|
| Marketing / docs / blog | SSG |
| CMS content that changes | ISR + on-demand revalidate |
| Personalized, SEO needed | SSR + streaming |
| Mostly static with personalized parts | Cache Components: static shell + dynamic holes inside `<Suspense>` |
| Logged-in dashboard | RSC shell + client islands / CSR |
| Geo / A-B / auth gate | `proxy.ts` (Node) or platform routing rules |
| Mostly static, few widgets | Islands |

**Decision flow:** Is it the same for every user? → SSG or ISR. Does it need fresh per-request data? → SSR. Is it heavy interaction behind auth? → CSR inside an RSC shell.

---

## Route decision header

Put this at the top of every `page.tsx` whose strategy isn't obvious (template in `assets/route-decision-header.txt`):

```tsx
/**
 * Rendering: static shell + streamed recommendations (Cache Components)
 * Cache:     getProduct → 'use cache', cacheLife('days'), tag product-{slug}; webhook revalidateTag(tag, 'max')
 * Personal:  cart badge via 'use cache: private' inside <Suspense>
 * Why:       public SEO page, content changes ~daily via CMS
 */
```
