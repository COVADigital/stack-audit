# Next.js 16 Cache Model

> **Verified:** 2026-11-13 against the Next.js v16.4.5 docs (context7 `/vercel/next.js/v16.4.5`). Check `next.config` for `cacheComponents: true`; the stack profile reports it.

## 1. Which model is this repo on?

| | **Cache Components** (`cacheComponents: true`) | **Legacy model** (flag off) |
|---|---|---|
| Default | Everything is **dynamic**; you opt into caching | Static where possible; you opt into dynamic |
| Cache a function/component | `'use cache'` + `cacheLife()` + `cacheTag()` | `fetch(url, { next: { revalidate, tags } })`, `unstable_cache` |
| Route-level time | `cacheLife('hours')` inside the cached scope | `export const revalidate = 3600` |
| Force request-time | Read `cookies()`/`headers()`/`searchParams`, or `await connection()` | `export const dynamic = 'force-dynamic'` |
| Segment configs `dynamic` / `revalidate` / `fetchCache` | **Build error**: delete them | Supported |
| `runtime = 'edge'` | **Not supported** (Node only) | Supported |
| Partial prerendering | Built in: static shell + dynamic parts inside `<Suspense>` | n/a |

**Rule:** Never mix the two models' advice. Detect the model first, then recommend only that model's APIs.

## 2. Cache layers (outer to inner)

1. **Client router cache:** RSC payloads kept in the browser for back/forward navigation and prefetching. Cleared by `router.refresh()`, by a Server Action's revalidation, and by `refresh()`.
2. **Prerendered / route output:** the static shell (or fully static route) produced at build time or after revalidation. Served from the CDN when cacheable.
3. **Cached functions / data:** `'use cache'` scopes (Cache Components) or the fetch data cache and `unstable_cache` (legacy). Keyed by the function's identity **plus its arguments**.
4. **Request memoization:** identical calls during one render are deduplicated. Wrap non-fetch data functions in React `cache()` for the same effect.

When data looks stale, work through these layers from 4 up to 1 and ask which one is serving the old value.

## 3. Cached function rules (Cache Components)

```ts
import { cacheLife, cacheTag } from 'next/cache';

export async function getProduct(slug: string) {
  'use cache';
  cacheLife('days');            // built-in profiles, or define custom ones in next.config
  cacheTag(`product-${slug}`);  // the tag you invalidate later
  return db.query.products.findFirst({ where: eq(products.slug, slug) });
}
```

- **Arguments are part of the key.** User-specific data must take the user ID as an argument.
- **Don't read `cookies()` / `headers()` inside `'use cache'`.** Read them outside and pass the values in, which is the pattern the docs prefer.
- **`'use cache: private'`** allows `cookies()`/`headers()` inside the scope. Results are reused only within a request and never stored in a shared server cache. Use it when you can't refactor the call site, for example a session helper.
- **`'use cache: remote'`** uses a platform-provided cache handler (network round trip, may cost money). Consider it for multi-instance self-hosting.

## 4. Invalidation: choose by behavior

| API | Where | Behavior | Use for |
|---|---|---|---|
| `updateTag(tag)` | **Server Actions only** | Expires now; the next read (including the action's own re-render) waits for fresh data | Read-your-own-writes: forms, settings, a user editing their own content |
| `revalidateTag(tag, 'max')` | Server Actions + Route Handlers | Stale-while-revalidate: stale data is served while fresh data loads in the background. **Profile argument required** (the one-argument form is deprecated) | CMS webhooks, background content updates |
| `revalidatePath(path)` | Server Actions + Route Handlers | Invalidates one URL path | One route affected; tagging is overkill |
| `refresh()` | Server Actions | Refetches the current route's RSC payload without invalidating caches | The view depends on state outside the cache |

**Rule:** Every mutation names the tags it invalidates and picks the API by the behavior it needs. Webhooks verify their signature before calling `revalidateTag`.

## 5. Self-hosting notes (Docker / Coolify)

- Each container replica has its **own** in-memory cache. With more than one replica, configure a shared cache handler (`'use cache: remote'` or a custom handler) or you will serve inconsistent data. (A single replica is fine.)
- `output: 'standalone'` writes to `.next/cache` at runtime. With a read-only root filesystem, mount a writable volume or tmpfs there (see `container-standards`).
- Verify `Cache-Control` on the deployed URL (the `probe_headers` check). Next.js sets its own headers on prerendered routes, and a reverse proxy can override them.

## 6. Migrating from the legacy model

1. Turn on `cacheComponents: true`.
2. Delete `dynamic` / `revalidate` / `fetchCache` exports. The build tells you where they are.
3. Move `fetch` `next.tags` and `unstable_cache` into `'use cache'` functions with `cacheTag` + `cacheLife`.
4. Replace one-argument `revalidateTag(tag)` with `revalidateTag(tag, 'max')`. Use `updateTag(tag)` in Server Actions that need read-your-own-writes.
5. Wrap request-time parts in `<Suspense>` so the static shell still prerenders.
