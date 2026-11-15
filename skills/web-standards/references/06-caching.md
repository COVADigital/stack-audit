# Caching — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `cache.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** For every resource, decide: where is it cached, for how long, how is it invalidated, and what happens offline.

---

## 01. Browser Cache
**What:** The browser's HTTP cache, controlled by response headers.

```http
Cache-Control: public, max-age=31536000, immutable   # /_next/static/*
Cache-Control: no-cache                               # HTML (revalidate every time)
Cache-Control: no-store                               # sensitive data
```
**Rule:** Hashed assets are immutable and cached for a year. HTML always revalidates.

---

## 02. Service Workers
**What:** A JS proxy between the page and the network that can intercept, cache, and serve requests.

```js
// sw.js
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));
self.addEventListener('fetch', (e) => {
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
// register
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
```
**Rule:** Use a maintained library rather than hand-rolled logic: for Next.js App Router, Serwist (`@serwist/next`) is the common choice (community practice; `next-pwa` is no longer actively maintained). Always have a kill-switch plan for a bad service worker.

---

## 03. Cache API
**What:** Programmatic storage for Request/Response pairs, available in service workers and on the page.

```js
const cache = await caches.open('api-v1');
await cache.put('/api/config', new Response(JSON.stringify(config)));
const hit = await cache.match('/api/config');
await caches.delete('api-v0'); // cleanup old version
```
**Rule:** Name caches with versions and delete old ones in the `activate` handler.

---

## 04. IndexedDB
**What:** A transactional, async, structured database in the browser that can hold large amounts of data.

```ts
import { openDB } from 'idb';
const db = await openDB('app', 1, {
  upgrade(db) { db.createObjectStore('drafts', { keyPath: 'id' }); },
});
await db.put('drafts', { id: 'post-1', body: '...', updatedAt: Date.now() });
const draft = await db.get('drafts', 'post-1');
```
**Rule:** Use IndexedDB for offline data, large datasets, and blobs. Use the `idb` wrapper rather than the raw API.

---

## 05. LocalStorage
**What:** A synchronous, string-only key/value store of about 5MB that persists across sessions, per origin.

```ts
function load<T>(key: string, fallback: T): T {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
  catch { return fallback; }
}
localStorage.setItem('theme', 'dark');
```
**Rule:** Keep it small and non-sensitive (theme, UI preferences). It blocks the main thread, and any XSS can read it, so never store tokens there.

---

## 06. SessionStorage
**What:** Like localStorage, but scoped to one tab and cleared when the tab closes.

```ts
sessionStorage.setItem('checkout-step', '2');
sessionStorage.setItem('scroll:/shop', String(window.scrollY));
```
**Rule:** Use it for per-tab, temporary state such as wizard progress or scroll restoration.

---

## 07. Stale While Revalidate (SWR)
**What:** Serve the cached copy immediately, then fetch a fresh copy in the background for next time.

```http
Cache-Control: public, max-age=60, stale-while-revalidate=600
```
```js
// Workbox
registerRoute(({ url }) => url.pathname.startsWith('/api/catalog'),
  new StaleWhileRevalidate({ cacheName: 'catalog' }));
```
**Rule:** Use this for content where being slightly stale is fine (catalog, profiles). Never use it for balances or inventory at checkout.

---

## 08. CDN Caching
**What:** Edge servers cache responses close to users.

```http
Cache-Control: public, s-maxage=86400, stale-while-revalidate=60
CDN-Cache-Control: max-age=86400       # CDN-only override
Vary: Accept-Encoding
Surrogate-Key: product-42 catalog       # tag-based purge (Fastly/Cloudflare)
```
**Rule:** `s-maxage` applies to the CDN and `max-age` to browsers. Purge by tag, and avoid `Vary: Cookie` on cacheable pages. Next.js sets its own `Cache-Control` on prerendered and ISR routes, so verify headers on the deployed URL rather than trusting config.

---

## 09. Cache Busting
**What:** Force clients to fetch a new version by changing the URL.

```html
<!-- Content hash in filename (build tools do this) -->
<script src="/assets/app.3f9a2c1.js"></script>
<!-- Manual query version (fallback) -->
<link rel="stylesheet" href="/legacy.css?v=2026-11-13">
```
**Rule:** Let the bundler hash filenames. Never cache HTML long-term, because HTML is what points to the new hashes.

---

## 10. PWA Basics
**What:** A Progressive Web App is a manifest, a service worker, and HTTPS, which together make the site installable with offline support.

```json
// public/manifest.webmanifest
{
  "name": "My App", "short_name": "MyApp",
  "start_url": "/", "display": "standalone",
  "background_color": "#0b0b0b", "theme_color": "#ff6a00",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
  ]
}
```
```html
<link rel="manifest" href="/manifest.webmanifest">
```
**Rule:** Include an offline fallback page and maskable icons. Lighthouse no longer has a PWA category, so verify installability in Chrome DevTools → Application → Manifest instead.

---

## 11. Offline First
**What:** Design the app to read and write locally first, then sync with the network as an enhancement.

```ts
async function getNotes() {
  const local = await db.getAll('notes');       // instant
  syncInBackground();                            // network later
  return local;
}
```
**Rule:** Show connection status in the UI, never lose user input, and queue writes (see Networking #16).

---

## 12. Background Sync
**What:** A service worker API that retries queued work once connectivity returns, even if the tab has closed.

```js
// page
const reg = await navigator.serviceWorker.ready;
await reg.sync.register('sync-outbox');
// sw.js
self.addEventListener('sync', (e) => {
  if (e.tag === 'sync-outbox') e.waitUntil(flushOutbox());
});
// Workbox: new BackgroundSyncPlugin('outbox', { maxRetentionTime: 24 * 60 })
```
**Rule:** Feature-detect it, because it's Chromium-only. Fall back to an `online` event handler.

---

## 13. Precaching
**What:** Cache known assets during the service worker `install` step so they're available offline immediately.

```js
// Workbox injects the build manifest
import { precacheAndRoute } from 'workbox-precaching';
precacheAndRoute(self.__WB_MANIFEST);
```
**Rule:** Precache only the app shell and critical assets, not the whole media library.

---

## 14. App Shell
**What:** The minimal HTML, CSS, and JS for the UI chrome (header, nav, layout), cached so it loads instantly while content fills in.

```js
registerRoute(new NavigationRoute(createHandlerBoundToURL('/app-shell.html'), {
  denylist: [/^\/api\//],
}));
```
**Rule:** The shell must render meaningfully with zero network.

---

## 15. Cache Keys
**What:** The identifier a cache uses to store and look up entries. A wrong key means stale or leaked data.

```ts
// TanStack Query — include every input that changes the result
useQuery({ queryKey: ['orders', userId, { status, page }], queryFn: ... });

// Next.js 16 Cache Components: arguments become part of the cache key
async function getOrders(userId: string, status: string) {
  'use cache';
  cacheTag(`orders-${userId}`);
  return db.select().from(orders).where(and(eq(orders.userId, userId), eq(orders.status, status)));
}
// Read cookies()/headers() OUTSIDE the cached function and pass values in as arguments
// (or use 'use cache: private', which is never stored in a shared server cache).
// Legacy model: unstable_cache(fetchProducts, ['products'], { tags: ['products'] })
```
**Rule:** User-specific data must include the user ID in the key, and must never be in a shared CDN cache.

---

## 16. Versioned Assets
**What:** Every deploy produces uniquely named assets, and old versions stay available briefly so open tabs keep working.

```text
/_next/static/chunks/main-a1b2c3.js     ← build 41
/_next/static/chunks/main-d4e5f6.js     ← build 42
```
**Rule:** Keep the previous deploy's assets for at least 24 hours. Handle `ChunkLoadError` by reloading the page.

---

## 17. Storage Quotas
**What:** Browsers limit storage per origin and may evict data under storage pressure.

```ts
const { usage, quota } = await navigator.storage.estimate();
console.log(`${(usage! / 1e6).toFixed(1)}MB of ${(quota! / 1e6).toFixed(0)}MB`);
const persisted = await navigator.storage.persist(); // request eviction protection
```
**Rule:** Handle `QuotaExceededError`, set expiry on caches (Workbox `ExpirationPlugin`), and request persistence for important offline data.

---

## 18. Data Sync
**What:** Reconcile local and server data in both directions.

```ts
// Delta sync with a cursor
const { changes, cursor } = await api.sync({ since: localStorage.getItem('syncCursor') });
await db.bulkPut('items', changes);
localStorage.setItem('syncCursor', cursor);
```
**Rule:** Sync deltas rather than full datasets, include `updatedAt` and soft-delete flags (`deletedAt`), and make sync idempotent.

---

## 19. Conflict Resolution
**What:** Deciding what wins when the same record changed in two places.

| Strategy | How | Use for |
|---|---|---|
| Last-write-wins | Compare `updatedAt` | Simple settings |
| Server wins | Discard local | Prices, inventory |
| Field-level merge | Merge non-overlapping fields | Profiles |
| Ask user | Show diff UI | Documents |
| CRDT | Yjs / Automerge | Real-time collab |

```ts
if (local.version !== server.version) throw new ConflictError(server); // optimistic concurrency
```
**Rule:** Choose a strategy per entity and document it. Use version numbers rather than timestamps alone, because clocks drift.

---

## 20. Push Notifications
**What:** Server-initiated messages delivered through the service worker, even when the site is closed.

```js
// page — ask only after a user gesture with clear value
const sub = await reg.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY),
});
await fetch('/api/push/subscribe', { method: 'POST', body: JSON.stringify(sub) });
// sw.js
self.addEventListener('push', (e) => {
  const d = e.data.json();
  e.waitUntil(self.registration.showNotification(d.title, { body: d.body, icon: '/icon-192.png', data: d.url }));
});
self.addEventListener('notificationclick', (e) => { e.notification.close(); e.waitUntil(clients.openWindow(e.notification.data)); });
```
**Rule:** Never request permission on page load. Ask in context, after a user action. iOS requires the PWA to be installed to the home screen.

---

## 21. Next.js Cache Layers
Next.js has several caches that interact: request memoization, cached functions (`'use cache'`) or the data cache, the full route cache, and the client router cache. Before debugging "stale data" or choosing a revalidation API, read `next16-cache-model.md`.
**Rule:** For each cached thing, name the layer, the key, the lifetime (`cacheLife`), and the tag that invalidates it.
