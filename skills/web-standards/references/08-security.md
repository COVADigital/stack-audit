# Security — 23 Concepts (Frontend / Web)

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `sec.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Treat all input as hostile and all secrets as radioactive. Security checks are blocking, so a feature isn't done until it passes them.

---

## 01. XSS (Cross-Site Scripting)
**What:** An attacker's script runs in your page, often by stealing sessions or acting as the user.

```tsx
// ❌ Raw HTML injection
<div dangerouslySetInnerHTML={{ __html: comment.body }} />
// ✅ Let React escape
<div>{comment.body}</div>
// ✅ If you must render HTML, sanitize
import DOMPurify from 'isomorphic-dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(cmsHtml) }} />
// ❌ javascript: URLs
<a href={userUrl}>  // validate: only http(s)
```
**Rule:** Never use `innerHTML`, `eval`, or `new Function` with untrusted data. Validate URL schemes. Use Portable Text renderers for Sanity rich text.

---

## 02. CSRF (Cross-Site Request Forgery)
**What:** Another site tricks the user's browser into sending an authenticated request to yours.

```ts
// Defenses (layered)
(await cookies()).set('session', token, { sameSite: 'lax', httpOnly: true, secure: true });   // cookies() is async
// Verify Origin on state-changing requests
const origin = req.headers.get('origin');
if (req.method !== 'GET' && origin !== process.env.APP_ORIGIN) return new Response('Forbidden', { status: 403 });
// Next.js Server Actions check Origin automatically
```
**Rule:** Use `SameSite=Lax` or `Strict` cookies, check Origin, and never change state on GET.

---

## 03. Content Security Policy (CSP)
**What:** A header that whitelists where scripts, styles, and frames can come from. It's the strongest XSS mitigation.

```ts
// proxy.ts (Next.js 16; middleware.ts before) — nonce-based strict CSP
// TRADE-OFF: nonces require dynamic rendering of every page that uses them (no SSG/ISR/CDN HTML caching).
// For mostly static sites, prefer a hash-based CSP or SRI, or accept the dynamic-rendering cost.
// 'unsafe-eval' is only needed in development (React debugging), never in production.
const nonce = btoa(crypto.randomUUID());
const csp = [
  `default-src 'self'`,
  `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
  `style-src 'self' 'unsafe-inline'`,
  `img-src 'self' https://cdn.sanity.io data: blob:`,
  `connect-src 'self' https://*.sanity.io`,
  `frame-src https://open.spotify.com https://www.youtube.com`,
  `frame-ancestors 'none'`, `base-uri 'self'`, `object-src 'none'`,
].join('; ');
res.headers.set('Content-Security-Policy', csp);
```
**Rule:** Start with `Content-Security-Policy-Report-Only`, fix violations, then enforce. No `'unsafe-eval'`.

---

## 04. CORS
**What:** The browser's cross-origin read policy. Misconfiguration exposes authenticated APIs to other sites. (Details are in Networking #14.)

```ts
// ❌ Reflecting any origin with credentials
res.headers.set('Access-Control-Allow-Origin', req.headers.get('origin'));
res.headers.set('Access-Control-Allow-Credentials', 'true');
// ✅ Explicit allow-list
```
**Rule:** CORS is not authentication. Use an explicit allow-list and add `Vary: Origin`.

---

## 05. Clickjacking
**What:** Your site is framed invisibly and users are tricked into clicking.

```http
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
```
**Rule:** Deny framing by default. Allow specific origins only for intentional embeds (for example, an embeddable widget).

---

## 06. Secure Cookies
```ts
(await cookies()).set('session', token, {
  httpOnly: true,     // JS can't read → XSS can't steal
  secure: true,       // HTTPS only
  sameSite: 'lax',    // CSRF protection
  path: '/',
  maxAge: 60 * 60 * 24 * 7,
});
// Prefix for extra guarantees
// __Host-session  → must be Secure, Path=/, no Domain
```
**Rule:** Session cookies are always `HttpOnly; Secure; SameSite`, and use the `__Host-` prefix where possible.

---

## 07. Token Storage
| Where | XSS risk | CSRF risk | Verdict |
|---|---|---|---|
| localStorage | ❌ readable | ✅ none | Avoid for auth |
| JS memory | ⚠️ readable while running | ✅ none | OK for short-lived access tokens |
| HttpOnly cookie | ✅ not readable | ⚠️ mitigate with SameSite | **Preferred** |

```ts
// BFF pattern: browser holds HttpOnly session cookie; server holds OAuth tokens
```
**Rule:** Never put refresh tokens in localStorage. Prefer server sessions or the BFF pattern.

---

## 08. OAuth with PKCE
**What:** Proof Key for Code Exchange protects the authorization-code flow for public clients (SPAs and mobile apps).

```ts
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
sessionStorage.setItem('pkce_verifier', verifier);
const state = crypto.randomUUID(); sessionStorage.setItem('oauth_state', state);
location.href = `${AUTH_URL}?response_type=code&client_id=${ID}&redirect_uri=${CB}` +
  `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&scope=openid profile`;
// Callback: verify state, then POST code + code_verifier to token endpoint
```
**Rule:** Always use PKCE with S256, always validate `state`, and never use the implicit flow. Prefer a library (Auth.js, Clerk, oidc-client-ts).

---

## 09. JWT Handling
```ts
import { jwtVerify } from 'jose';
const { payload } = await jwtVerify(token, JWKS, {
  issuer: 'https://auth.example.com',
  audience: 'api://cova',
  algorithms: ['RS256'],           // pin algorithm — never accept "none"
});
```
**Rules:**
- Verify the signature, `exp`, `iss`, and `aud` on the **server**. Decoding a token on the client is not verifying it.
- Keep access tokens short-lived (5 to 15 minutes) and rotate refresh tokens.
- JWT payloads are *readable*, so never put secrets or personal data in them.

---

## 10. Input Sanitization
**What:** Validate shape, then encode for the output context (HTML, SQL, URL, shell).

```ts
const Signup = z.object({
  email: z.email().max(254),                 // Zod 4 top-level formats
  name: z.string().trim().min(1).max(80),
  website: z.httpUrl().optional(),           // http(s) URLs only
});
const data = Signup.parse(await req.json());   // server-side, always

// SQL: parameterized only (Drizzle's sql`` tag parameterizes interpolations)
await db.execute(sql`SELECT * FROM users WHERE email = ${data.email}`);
// ❌ never sql.raw(userInput) or string concatenation
```
Three injections hide behind "it's parameterized":
- **Identifiers** (`ORDER BY`, column or table names) can't be parameters. Map them through an allow-list, never `sql.identifier(input)` or `sql.raw(input)`.
- **Mass assignment:** `db.insert(t).values(await req.json())` lets a client set `tenantId`, `role` or `isAdmin`. Parse into a schema that lists only the writable fields, then add server-owned fields yourself.
- **LIKE wildcards:** `%` and `_` in input turn a search into a match-everything scan. Escape them and cap the length.

**Rule:** Client-side validation is for user experience and server-side validation is for security, so do both. Use parameterized queries and never concatenate strings. Allow-list identifiers, write only the fields a schema permits, and escape LIKE patterns.

---

## 11. Dependency Audits
```bash
npm audit --audit-level=high
npx better-npm-audit audit
# lockfile always committed; CI uses `npm ci`
# Socket.dev / Snyk for supply-chain (typosquats, install scripts)
```
**Rule:** Fail CI on high or critical vulnerabilities, review new dependencies (maintainers, downloads, install scripts), and keep Dependabot on.

---

## 12. Subresource Integrity (SRI)
**What:** A hash that ensures a CDN-hosted file hasn't been tampered with.

```html
<script src="https://cdn.jsdelivr.net/npm/lib@1.2.3/dist/lib.min.js"
  integrity="sha384-Base64Hash..." crossorigin="anonymous"></script>
```
```bash
curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A
```
**Rule:** Any third-party `<script>` or `<link>` with a pinned version gets SRI, or self-host it instead.

---

## 13. HTTPS Everywhere
```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```
**Rule:** Use HTTPS only, enable HSTS, have no mixed content, redirect HTTP to HTTPS at the edge, and use TLS 1.2 or later.

---

## 14. Iframe Sandboxing
```html
<iframe src="https://user-embed.example.com"
  sandbox="allow-scripts allow-same-origin allow-popups"
  allow="encrypted-media; fullscreen"
  referrerpolicy="strict-origin-when-cross-origin"
  loading="lazy" title="Embedded player"></iframe>
```
**Rule:** Start with a bare `sandbox` and add permissions one at a time. Never combine `allow-scripts` with `allow-same-origin` for untrusted *same-origin* content.

---

## 15. Permissions Policy
**What:** A header that disables powerful browser features you don't use.

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self), usb=()
```
**Rule:** Deny everything by default and allow only what the product actually needs. Drop obsolete entries such as `interest-cohort` (FLoC no longer exists).

---

## 16. No Secrets in Frontend
**What:** Anything shipped to the browser is public: bundles, `NEXT_PUBLIC_*` variables, source maps.

```bash
# ❌ NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
# ✅ STRIPE_SECRET_KEY=sk_live_...  (server only)
# ✅ NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_...
```
```ts
import 'server-only';  // build error if imported by a client component
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
```
**Rule:** Secret keys live server-side behind an API route or BFF. Add `server-only` guards, and grep built bundles for `sk_`, `secret`, and `token`. Keep `productionBrowserSourceMaps` off unless the maps are access-controlled.

---

## 17. Auth Flows
**Checklist:**
- Hash passwords with Argon2id or bcrypt (cost of 12 or more), or better, use passkeys or a managed auth provider
- Rate-limit login, signup, and password reset
- Use generic errors ("Invalid email or password") to avoid user enumeration
- Make reset tokens single-use and short-lived, and store them hashed
- Regenerate the session ID on login and privilege change
- Offer MFA for admin accounts
- Do authorization checks **on the server, per request, per resource** (prevents IDOR)

- **Every Server Action is a public POST endpoint:** validate input, check the session, and authorize the resource inside each action, even if the UI only shows the button to admins
- With Better Auth (or another managed provider), hashing, sessions and rate limiting come from the library: the checklist becomes *verify the configuration*, not *build it*

```ts
const order = await db.query.orders.findFirst({ where: eq(orders.id, id) });
if (order?.userId !== session.user.id) notFound(); // ownership check (IDOR)
```

---

## 18. Session Timeout
```ts
const IDLE_MS = 30 * 60 * 1000, ABSOLUTE_MS = 12 * 60 * 60 * 1000;
if (now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
  await destroySession(session.id); redirect('/login?expired=1');
}
session.lastSeen = now; // sliding
```
**Rule:** Use both an idle timeout and an absolute timeout. Logout must invalidate the session server-side, not just delete the cookie. Use shorter timeouts for admin.

---

## 19. Security Headers
```ts
// next.config.ts
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];
export default { async headers() { return [{ source: '/(.*)', headers: securityHeaders }]; } };
```
**Rule:** Aim for an A or better on securityheaders.com. CSP is set in middleware (see #03).

---

## 20. Third-Party Scripts
**What:** Analytics, chat widgets, and pixels run with full access to your page.

```tsx
import Script from 'next/script';
<Script src="https://analytics.example.com/a.js" strategy="lazyOnload" />
// Prefer: server-side analytics, Partytown (web worker), or privacy-first tools (Plausible)
```
**Rule:** Inventory every third-party script with its owner and purpose, allow it in the CSP, use SRI where possible, load it lazily, and remove it when it's unused.

---

## 21. Server-Side Request Forgery (SSRF)
**What:** Your server fetches a URL that an attacker controls. This happens in link previews, image proxies, webhook "test" buttons, and importers. The attacker can reach internal services or cloud metadata (169.254.169.254).

```ts
const target = new URL(input.url);
if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) throw new Error('Blocked');
const res = await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(5000) });
```
**Rule:** Allow-list hosts and schemes, refuse redirects (or re-validate each hop), block private and link-local IP ranges after DNS resolution, and set timeouts and size limits.

---

## 22. Open Redirects
**What:** A `?next=`, `?returnTo=` or `?callbackUrl=` parameter sends the user wherever the link says. Attackers use your trusted domain to bounce victims to a phishing page, or to leak OAuth codes.

```ts
// ❌ redirect(searchParams.next)  ·  NextResponse.redirect(new URL(req.nextUrl.searchParams.get('to')!))
// ✅ accept only same-site relative paths
function safeNext(next: string | undefined) {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
}
redirect(safeNext((await searchParams).next));
```
**Rule:** Never redirect to a URL taken from the request. Accept only relative paths (not `//` or `/\`), or map an ID to an allow-listed destination.

---

## 23. Secure Randomness
**What:** `Math.random()` is predictable. Tokens, IDs in URLs, reset codes, nonces and invite codes made with it can be guessed.

```ts
// ❌ const token = Math.random().toString(36).slice(2);
// ✅
const token = crypto.randomUUID();                                      // Web Crypto, Node 19+ global
const code = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
```
**Rule:** Use `crypto.randomUUID()` / `crypto.getRandomValues()` (or `node:crypto` `randomBytes`) for any value that must not be guessed. Keep `Math.random()` for jitter, animation and sampling only.

---

## OWASP mapping

Each section links to the OWASP Cheat Sheet Series for depth (use the `owasp-security` skill to read the relevant section):

| § | OWASP cheat sheet(s) |
|---|---|
| 01 | Cross_Site_Scripting_Prevention, DOM_based_XSS_Prevention |
| 02 | Cross-Site_Request_Forgery_Prevention |
| 03 | Content_Security_Policy |
| 04 | HTTP_Headers |
| 05 | Clickjacking_Defense |
| 06 | Session_Management, Cookie_Theft_Mitigation |
| 07 | Session_Management, JSON_Web_Token |
| 08 | OAuth2 |
| 09 | JSON_Web_Token |
| 10 | Input_Validation, SQL_Injection_Prevention, Query_Parameterization |
| 11 | Vulnerable_Dependency_Management, NPM_Security |
| 12 | Third_Party_Javascript_Management |
| 13 | HTTP_Strict_Transport_Security, Transport_Layer_Security |
| 14 | HTML5_Security |
| 15 | HTTP_Headers |
| 16 | Secrets_Management, Nextjs_Security |
| 17 | Authentication, Authorization, Insecure_Direct_Object_Reference_Prevention, Password_Storage, Forgot_Password |
| 18 | Session_Management |
| 19 | HTTP_Headers |
| 20 | Third_Party_Javascript_Management |
| 21 | Server_Side_Request_Forgery_Prevention |
| 22 | Unvalidated_Redirects_and_Forwards |
| 23 | Cryptographic_Storage |
