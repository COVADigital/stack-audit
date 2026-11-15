# Architecture — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `arch.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Before writing code, place it: which feature, which layer, and which boundary. Follow the existing structure, and propose changes to it explicitly instead of drifting.

---

## 01. Component Design
**What:** Small, focused, composable components with clear props.

```tsx
// ✅ Single responsibility, typed, composable
type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost'; size?: 'sm' | 'md';
};
export function Button({ variant = 'primary', size = 'md', className, ...rest }: ButtonProps) {
  return <button className={cn(styles.base, styles[variant], styles[size], className)} {...rest} />;
}
```
**Principles:** Separate presentational and container components, prefer composition over configuration, and spread native props. In React 19, `ref` is a regular prop, so `forwardRef` is no longer needed for new components.
**Rule:** Split a component once it passes about 150 lines or does more than one job.

---

## 02. Design Systems
**What:** A shared set of tokens, components, patterns, and guidelines.

```css
/* Tailwind CSS 4: tokens live in CSS and generate utilities (bg-accent, rounded-md, font-sans) */
@import "tailwindcss";
@theme {
  --color-bg: #0b0b0b; --color-fg: #f5f5f5; --color-accent: #ff6a00;
  --radius-md: 10px; --font-sans: 'Inter', system-ui, sans-serif;
}
/* Without Tailwind: the same names as plain custom properties on :root */
```
**Rule:** No hard-coded colors or spacing in components. Use tokens only.

---

## 03. Atomic Design
**What:** Build UI in levels: Atoms → Molecules → Organisms → Templates → Pages.

```text
atoms/      Button, Input, Icon, Label
molecules/  SearchField (Input + Button), FormField (Label + Input + Error)
organisms/  Header, ProductCard, CheckoutForm
templates/  ShopLayout
pages/      /shop
```
**Rule:** Lower levels never import higher levels.

---

## 04. Monorepos
**What:** Several apps and packages in one repo with shared tooling.

```text
/apps
  /web          (Next.js — public site)
  /studio       (Sanity Studio)
/packages
  /ui           (shared components)
  /config       (eslint, tsconfig)
  /schemas      (zod contracts)
pnpm-workspace.yaml
turbo.json
```
```json
// turbo.json
{ "tasks": { "build": { "dependsOn": ["^build"], "outputs": [".next/**", "dist/**"] } } }
```
**Rule:** Use a monorepo when the apps share code. Tools: pnpm workspaces plus Turborepo or Nx.

---

## 05. Micro Frontends
**What:** Independently built and deployed frontend slices owned by separate teams.

```text
shell (routing, auth)
 ├── /shop      → team-commerce (deploys independently)
 ├── /account   → team-identity
 └── /blog      → team-content
```
**Rule:** This mostly solves an *organizational* problem. Don't use it on small teams, because the complexity cost is high.

---

## 06. Module Federation
**What:** A runtime mechanism for loading code from separately deployed builds. It's a common way to implement micro frontends.

```js
// remote webpack/rspack config
new ModuleFederationPlugin({
  name: 'shop', filename: 'remoteEntry.js',
  exposes: { './Cart': './src/Cart' },
  shared: { react: { singleton: true }, 'react-dom': { singleton: true } },
});
// host
remotes: { shop: 'shop@https://shop.example.com/remoteEntry.js' }
const Cart = React.lazy(() => import('shop/Cart'));
```
**Rule:** Share React as a singleton, version the remotes, and have a fallback for when a remote is down.

---

## 07. Folder Structure
**What:** A predictable layout so humans and agents know where things go.

```text
src/
  app/                 # routes only (thin)
  features/
    cart/
      components/
      hooks/
      api.ts
      store.ts
      types.ts
      index.ts         # public API of the feature
  components/ui/       # shared design-system components
  lib/                 # framework-agnostic utils (db, auth, fetcher)
  config/
tests/
```
**Rule:** Group by feature rather than by file type, and colocate tests and styles.

---

## 08. Feature Modules
**What:** Self-contained feature folders that expose a public API through `index.ts`.

```ts
// features/cart/index.ts
export { CartButton } from './components/CartButton';
export { useCart } from './store';
export type { CartItem } from './types';
// ❌ elsewhere: import { x } from '@/features/cart/components/internal/x'
// ✅           import { useCart } from '@/features/cart'
```
**Rule:** Features import other features only through their index. Enforce this with lint (see #18).

---

## 09. Routing
**What:** Mapping URLs to screens. It includes nested layouts, dynamic segments, and route groups.

```text
app/
  (marketing)/page.tsx           → /
  (marketing)/about/page.tsx     → /about
  (shop)/layout.tsx              → shared shop layout
  (shop)/products/[slug]/page.tsx → /products/:slug
  api/webhooks/sanity/route.ts   → POST /api/webhooks/sanity
  not-found.tsx
```
**Rule:** Keep route files thin: fetch data, then render feature components. Business logic lives in features.

---

## 10. Plugin Architecture
**What:** A core with defined extension points that third-party modules hook into.

```ts
interface Plugin { name: string; setup(api: CoreAPI): void | Promise<void>; }
class Core {
  private hooks = new Map<string, Function[]>();
  on(evt: string, fn: Function) { (this.hooks.get(evt) ?? this.hooks.set(evt, []).get(evt)!).push(fn); }
  emit(evt: string, ...a: unknown[]) { this.hooks.get(evt)?.forEach(fn => fn(...a)); }
  use(p: Plugin) { p.setup({ on: this.on.bind(this) }); }
}
core.use(analyticsPlugin); core.use(spotifyEmbedPlugin);
```
**Rule:** Use this where users or teams need to extend the product (link-in-bio block types, CMS blocks).

---

## 11. Shared Libraries
**What:** Code reused across apps: UI kits, utilities, and API clients.

```json
// packages/ui/package.json
{
  "name": "@cova/ui",
  "exports": { ".": "./src/index.ts", "./styles.css": "./src/styles.css" },
  "peerDependencies": { "react": "^19" }
}
```
**Rule:** Make React and other frameworks peer dependencies. Use semantic versioning with Changesets for published packages, and keep shared libraries free of app-specific logic.

---

## 12. Theming
**What:** Swappable visual identities (light and dark, per-artist brand) driven by tokens.

```css
:root { --bg: #fff; --fg: #111; --accent: #ff6a00; }
[data-theme='dark'] { --bg: #0b0b0b; --fg: #f5f5f5; }
[data-artist='nova'] { --accent: #c9a227; }
```
```tsx
<html data-theme={theme} data-artist={artistSlug} suppressHydrationWarning>
```
**Rule:** Themes change only token values. Set the theme before paint, with a blocking script or a cookie, to avoid a flash.

---

## 13. Feature Flags
**What:** Toggle features at runtime without deploying.

```ts
// lib/flags.ts
export const flags = {
  newCheckout: process.env.NEXT_PUBLIC_FLAG_NEW_CHECKOUT === 'true',
};
// usage
{flags.newCheckout ? <NewCheckout /> : <Checkout />}
// Hosted: Vercel Flags, LaunchDarkly, PostHog, Unleash
```
**Rule:** Every flag has an owner and a removal date. Remove dead flags quickly, because they turn into permanent branches.

---

## 14. Config-Driven UI
**What:** The UI is rendered from data or config instead of hard-coded JSX. This is how CMS page builders work.

```tsx
const blocks = {
  hero: HeroBlock, tourDates: TourDatesBlock, merchGrid: MerchGridBlock, spotify: SpotifyBlock,
} as const;
export function PageBuilder({ sections }: { sections: Section[] }) {
  return sections.map(s => {
    const C = blocks[s._type as keyof typeof blocks];
    return C ? <C key={s._key} {...s} /> : null;
  });
}
```
**Rule:** Validate the config with a schema, and handle unknown block types gracefully.

---

## 15. Separation of Concerns
**What:** Each module handles one concern: UI, data access, business rules, or side effects.

```tsx
// ❌ Component does fetch + business rule + UI
// ✅
// lib/pricing.ts       → pure rule: applyDiscount(cart, code)
// features/cart/api.ts → data access
// CartSummary.tsx      → presentation only
```
**Rule:** Business logic is plain, pure, testable TypeScript with no React imports.

---

## 16. Clean Architecture
**What:** Layered design in which dependencies point inward: UI → Application → Domain ← Infrastructure.

```text
domain/          entities + rules (no frameworks)
application/     use cases: placeOrder(), refundOrder()
infrastructure/  db (Prisma), payment (Stripe), email adapters
interface/       Next.js routes, React components
```
```ts
// application/placeOrder.ts — depends on interfaces, not Stripe directly
export async function placeOrder(deps: { payments: PaymentGateway; orders: OrderRepo }, input: OrderInput) { ... }
```
**Rule:** The domain never imports the framework or vendor SDKs. Wrap vendors in adapters so they can be swapped and mocked.

---

## 17. Code Ownership
**What:** Clear owners for each area, who review changes and are accountable for them.

```text
# .github/CODEOWNERS
/features/checkout/   @payments-team
/packages/ui/         @design-system
/infra/               @your-handle
```
**Rule:** Every directory has an owner, and an owner's review is required for sensitive paths.

---

## 18. Dependency Boundaries
**What:** Enforced rules about which modules may import which.

```js
// eslint.config.js (eslint-plugin-boundaries or import/no-restricted-paths)
rules: {
  'import/no-restricted-paths': ['error', { zones: [
    { target: './src/features/cart', from: './src/features/checkout' },
    { target: './src/domain', from: './src/infrastructure' },
    { target: './src/components/ui', from: './src/features' },
  ]}],
}
```
**Rule:** No circular dependencies (check with `madge --circular`), and the lint step must pass in CI. Next.js 16 removed `next lint`: run the ESLint CLI with a flat config (`eslint.config.mjs`); the codemod `npx @next/codemod@canary next-lint-to-eslint-cli .` migrates scripts.

---

## 19. Scalability
**What:** The architecture handles growth in users, data, features, and team size.

**Checklist:**
- Stateless servers (sessions in a DB or Redis), so they scale horizontally
- CDN and caching layers (see Caching)
- Background jobs for slow work (queues: Inngest, BullMQ, QStash)
- DB indexes, pagination, and no unbounded queries
- Feature modules, so the team can grow without everyone stepping on each other

**Rule:** Design for 10× current load, but don't build for 1000× until it's needed.

---

## 20. Documentation
**What:** READMEs, ADRs, inline docs, and diagrams that explain the *why*.

```markdown
<!-- docs/adr/0007-use-sanity-for-cms.md -->
# ADR 0007: Use Sanity as CMS
Status: Accepted · Date: 2026-08-24
## Context
Artist needs to edit tour dates & merch without a dev.
## Decision
Sanity v3 + GROQ, ISR via webhook revalidation.
## Consequences
+ Real-time editing, typed schemas  − Vendor lock-in, usage-based pricing
```
**Rule:** Each repo has a README covering setup, scripts, environment variables, and architecture. Every significant decision gets an ADR. Comment *why*, not *what*.

---

## 21. Data Access Layer and Server/Client Boundaries
**What:** One server-only module per domain that performs authorization *and* data access. Components and actions call it, and never call the DB directly.

```ts
// lib/dal/orders.ts
import 'server-only';                       // build error if imported from a Client Component
export async function getMyOrders() {
  const session = await verifySession();    // auth check lives next to the query
  return db.select().from(orders).where(eq(orders.userId, session.userId));
}
```
**Rule:** DB clients, secrets, and auth helpers import `server-only`. Browser-only modules import `client-only`. Pages, layouts, and Server Actions get data only through the DAL.
