# Networking — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `net.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Every network call must handle loading, error, timeout, retry policy, and cancellation. Never write a bare `fetch()` with no error path.

---

## 01. REST vs GraphQL
**REST:** Resource URLs with HTTP verbs. It's simple and cacheable, but can over-fetch or under-fetch.
**GraphQL:** A single endpoint where the client asks for exactly the fields it needs. It's flexible but harder to cache and secure.

```http
GET /api/artists/42/releases?limit=5
```
```graphql
query { artist(id: 42) { name releases(limit: 5) { title year } } }
```
**Rule:** Default to REST, or to tRPC or Server Actions inside Next.js. Choose GraphQL when many clients need different shapes of the same data. Sanity's GROQ is a similar query-shaped approach.

---

## 02. HTTP Caching
**What:** `Cache-Control` headers tell browsers and CDNs what to store and for how long.

```http
# Hashed static asset — cache forever
Cache-Control: public, max-age=31536000, immutable
# HTML — always revalidate
Cache-Control: no-cache
# Private user data
Cache-Control: private, no-store
# CDN cache with SWR
Cache-Control: public, s-maxage=60, stale-while-revalidate=300
```
**Rule:** Every response gets an intentional `Cache-Control` header. Never leave it to the default.

---

## 03. ETags
**What:** A version fingerprint for a resource. The client sends `If-None-Match`, and the server replies `304 Not Modified` if nothing changed.

```ts
import { createHash } from 'crypto';
export async function GET(req: Request) {
  const data = JSON.stringify(await getProducts());
  const etag = `"${createHash('sha1').update(data).digest('hex')}"`;
  if (req.headers.get('if-none-match') === etag) return new Response(null, { status: 304 });
  return new Response(data, { headers: { ETag: etag, 'Cache-Control': 'no-cache' } });
}
```
**Rule:** Use ETags for API resources that change unpredictably.

---

## 04. Pagination
**Offset:** `?page=3&limit=20` is simple, but it's slow on large tables and items shift when data changes.
**Cursor:** `?after=abc123&limit=20` is stable and fast.

```ts
// Cursor-based (Drizzle)
import { asc, gt } from 'drizzle-orm';
const rows = await db.select().from(posts)
  .where(cursor ? gt(posts.id, cursor) : undefined)
  .orderBy(asc(posts.id))
  .limit(limit + 1);
const hasMore = rows.length > limit;
return { items: rows.slice(0, limit), nextCursor: hasMore ? rows[limit - 1].id : null };
```
**Rule:** Use cursor pagination for feeds and large datasets, and offset pagination for small admin tables with page numbers.

---

## 05. Infinite Scroll
**What:** Automatically load the next page as the user nears the bottom.

```tsx
const { data, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
  queryKey: ['feed'],
  queryFn: ({ pageParam }) => api.feed(pageParam),
  initialPageParam: null,
  getNextPageParam: (last) => last.nextCursor,
});
const sentinel = useRef(null);
useEffect(() => {
  const io = new IntersectionObserver(([e]) => e.isIntersecting && hasNextPage && fetchNextPage());
  if (sentinel.current) io.observe(sentinel.current);
  return () => io.disconnect();
}, [hasNextPage, fetchNextPage]);
```
**Rule:** Also provide a "Load more" button for accessibility and keyboard users, keep the footer reachable, and restore scroll position on back navigation.

---

## 06. Polling
**What:** Repeatedly request data at an interval.

```ts
useQuery({
  queryKey: ['job', id],
  queryFn: () => api.jobStatus(id),
  refetchInterval: (q) => q.state.data?.status === 'done' ? false : 2000,
  refetchIntervalInBackground: false,
});
```
**Rule:** Stop polling when the work is done or the tab is hidden, and back off the interval over time. Prefer SSE or WebSockets for frequent updates.

---

## 07. WebSockets
**What:** A persistent, bidirectional connection, used for chat, multiplayer, and live collaboration.

```ts
function connect() {
  const ws = new WebSocket('wss://api.example.com/live');
  ws.onmessage = (e) => handle(JSON.parse(e.data));
  ws.onclose = () => setTimeout(connect, backoff()); // reconnect
  return ws;
}
```
**Rule:** Authenticate the handshake, handle reconnects with backoff, send heartbeats, and validate every incoming message.

---

## 08. Server-Sent Events (SSE)
**What:** A one-way stream from server to client over HTTP, with automatic reconnect. Good for notifications and AI token streaming.

```ts
// Route handler
export async function GET() {
  let id: ReturnType<typeof setInterval>;
  const stream = new ReadableStream({
    start(c) {
      const enc = new TextEncoder();
      id = setInterval(() => c.enqueue(enc.encode(`data: ${JSON.stringify({ t: Date.now() })}\n\n`)), 1000);
    },
    cancel() { clearInterval(id); },   // runs on client disconnect; start()'s return value is ignored
  });
  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' } });
}
// Client
const es = new EventSource('/api/stream');
es.onmessage = (e) => console.log(JSON.parse(e.data));
```
**Rule:** Choose SSE over WebSockets when only the server needs to push.

---

## 09. Retries and Backoff
**What:** Retry transient failures with increasing delays plus random jitter.

```ts
async function fetchWithRetry(url: string, opts: RequestInit = {}, retries = 3) {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, opts);
      if (res.status >= 500 || res.status === 429) throw new Error(String(res.status));
      return res;
    } catch (err) {
      if (attempt >= retries) throw err;
      const delay = Math.min(1000 * 2 ** attempt, 10_000) * (0.5 + Math.random());
      await new Promise(r => setTimeout(r, delay));
    }
  }
}
```
**Rule:** Retry only idempotent requests (GET, PUT, DELETE, or POST with an idempotency key). Never retry 4xx errors other than 408 and 429.

---

## 10. Request Deduping
**What:** Collapse identical in-flight requests into one.

```ts
const inflight = new Map<string, Promise<any>>();
function dedupedFetch(url: string) {
  if (!inflight.has(url)) {
    inflight.set(url, fetch(url).then(r => r.json()).finally(() => inflight.delete(url)));
  }
  return inflight.get(url)!;
}
// React: cache() dedupes per request on the server; TanStack Query dedupes by key
```
**Rule:** Never let five components fire five identical requests.

---

## 11. Request Cancellation
**What:** Abort requests whose results are no longer needed.

```ts
useEffect(() => {
  const ctrl = new AbortController();
  fetch(`/api/search?q=${q}`, { signal: ctrl.signal })
    .then(r => r.json()).then(setResults)
    .catch(e => { if (e.name !== 'AbortError') setError(e); });
  return () => ctrl.abort();
}, [q]);
```
**Rule:** Cancel requests on unmount and when a newer request supersedes them. This prevents out-of-order race bugs.

---

## 12. Batching Requests
**What:** Combine many small requests into one.

```ts
// DataLoader pattern
const userLoader = new DataLoader(async (ids: readonly string[]) => {
  const users = await db.select().from(usersTable).where(inArray(usersTable.id, [...ids]));
  return ids.map(id => users.find(u => u.id === id));
});
await Promise.all([userLoader.load('1'), userLoader.load('2')]); // 1 query
```
**Rule:** Eliminate N+1 queries in loops by batching or by using `in` queries.

---

## 13. BFF Pattern (Backend for Frontend)
**What:** A server layer tailored to one frontend. It aggregates services, hides secrets, and shapes responses.

```ts
// app/api/dashboard/route.ts — one call for the client, three upstream
export async function GET() {
  const [user, orders, stats] = await Promise.all([
    userSvc.me(), orderSvc.recent(), statsSvc.summary(),
  ]);
  return Response.json({ name: user.name, orders: orders.slice(0, 5), revenue: stats.revenue });
}
```
**Rule:** Third-party API keys live in the BFF and never in the browser.

---

## 14. CORS
**What:** A browser rule that blocks cross-origin reads unless the server explicitly allows them.

```ts
// Allow-list, never wildcard with credentials
const ALLOWED = ['https://example.com', 'https://admin.example.com'];
export function corsHeaders(origin: string | null) {
  if (!origin || !ALLOWED.includes(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}
```
**Rule:** Never use `*` together with credentials. CORS does not protect your API from curl, so authentication is still required.

---

## 15. Handling Rate Limits
**What:** Respect `429 Too Many Requests` and the `Retry-After` header. Rate-limit your own API too.

```ts
if (res.status === 429) {
  const wait = Number(res.headers.get('Retry-After') ?? 1) * 1000;
  await sleep(wait);
}
// Server side (Upstash)
const rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, '10 s') });
const { success } = await rl.limit(ip);
if (!success) return new Response('Too many', { status: 429, headers: { 'Retry-After': '10' } });
```
**Rule:** Rate-limit every public endpoint, especially auth, forms, and AI calls.

---

## 16. Offline Queue
**What:** Queue mutations while offline and replay them when the connection returns.

```ts
async function submit(action: Action) {
  if (!navigator.onLine) { await idb.add('outbox', action); return; }
  await send(action);
}
window.addEventListener('online', async () => {
  for (const a of await idb.getAll('outbox')) { await send(a); await idb.delete('outbox', a.id); }
});
// Or Service Worker Background Sync (see Caching #12)
```
**Rule:** Give each queued action an idempotency key so replays can't double-submit.

---

## 17. Error Handling
**What:** Distinguish network errors, HTTP errors, and invalid payloads, and show useful UI for each.

```ts
class HttpError extends Error { constructor(public status: number, public body: unknown) { super(`HTTP ${status}`); } }
async function api<T>(url: string, schema: z.ZodType<T>, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) throw new HttpError(res.status, await res.json().catch(() => null));
  return schema.parse(await res.json()); // validate shape
}
```
Never return a caught error object, or its `message` / `detail` / `hint`, to the client. Postgres errors name tables, columns, constraints and sometimes values, and error-based SQL injection reads data back through exactly those messages.

**Rule:** Server code returns generic error messages, with details logged server-side. `fetch` does not throw on 4xx or 5xx, so always check `res.ok`. Validate responses with Zod, and log errors to Sentry. (Next.js `fetch` extensions such as `next: { tags }` apply only on the server, and only in the legacy caching model.)

---

## 18. Timeouts
**What:** Don't wait forever for a response.

```ts
const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
// Combine with user cancel
const signal = AbortSignal.any([AbortSignal.timeout(8000), userCtrl.signal]);
```
**Rule:** Every outbound request has a timeout: about 10s for user-facing calls, and less for server-to-server calls on a hot path.

---

## 19. API Contracts
**What:** A shared, typed definition of requests and responses (OpenAPI, Zod, tRPC, or GraphQL schema).

```ts
// shared/contracts/product.ts
export const Product = z.object({ id: z.string(), name: z.string(), price: z.number().int() });
export type Product = z.infer<typeof Product>;
// Server validates input, client validates output — same schema
```
```bash
npx openapi-typescript ./openapi.yaml -o src/api-types.ts
```
**Rule:** Use one source of truth for API shapes, version breaking changes (`/v2`), and never ship an untyped `any` response.

---

## 20. HTTP/2 and HTTP/3
**HTTP/2:** Multiplexes many requests over one TCP connection with header compression, so domain sharding and sprite hacks are no longer needed.
**HTTP/3:** Runs over QUIC (UDP), avoids TCP head-of-line blocking, connects faster, and handles network switches better on mobile.

```bash
curl -sI --http3 https://site.com | head -1
# Chrome DevTools → Network → right-click headers → enable "Protocol" column
```
**Rule:** Use a CDN or host with HTTP/3 enabled. Undo HTTP/1-era hacks such as bundling everything into one file or domain sharding.

---

## 21. Server Actions
**What:** Async server functions (`'use server'`) called from forms and client code. Next.js handles the transport as a POST to the page, and compares Origin to Host.
**Security model:** Each action is a public HTTP endpoint. Anyone can call it with any arguments, whatever your UI shows.

```ts
'use server';
export async function renameProject(input: unknown) {
  const session = await auth();                         // 1. authenticate
  if (!session) throw new Error('Unauthorized');
  const { id, name } = RenameProject.parse(input);      // 2. validate (shared Zod schema)
  const project = await getProject(id);
  if (project?.ownerId !== session.user.id) throw new Error('Forbidden'); // 3. authorize
  await db.update(projects).set({ name }).where(eq(projects.id, id));
  updateTag(`project-${id}`);                           // 4. invalidate (read-your-own-writes)
}
```
**Rule:** Authenticate, validate, and authorize inside every action, and rate-limit expensive ones. Return typed results, and never return raw DB errors.
