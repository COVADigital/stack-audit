# State Management — 20 Concepts

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `state.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Classify every piece of state before writing it: local UI, global client, server cache, URL, form, or persisted. Put it in the right home.

---

## 01. Local vs Global State
**What:** Local state belongs to one component. Global state is shared across distant parts of the app.

```tsx
// Local: only this dropdown cares
const [open, setOpen] = useState(false);
// Global: theme, auth user, cart
const user = useAuthStore(s => s.user);
```
**Rule:** Start local, and lift state up or make it global only when two or more distant components need it.

---

## 02. Context API
**What:** React's built-in mechanism for passing values down the tree without props.
**Caveat:** Every consumer re-renders when the value changes.

```tsx
const ThemeCtx = createContext<'light' | 'dark'>('light');
export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const value = useMemo(() => ({ theme, setTheme }), [theme]);
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}
export const useTheme = () => useContext(ThemeCtx);
```
**Rule:** Use Context for low-frequency values (theme, locale, auth) and dependency injection, not for rapidly changing state.

---

## 03. Redux Toolkit
**What:** The official, opinionated Redux setup: slices, Immer, and RTK Query.

```ts
const cartSlice = createSlice({
  name: 'cart',
  initialState: { items: [] as Item[] },
  reducers: {
    add: (s, a: PayloadAction<Item>) => { s.items.push(a.payload); }, // Immer
    remove: (s, a: PayloadAction<string>) => { s.items = s.items.filter(i => i.id !== a.payload); },
  },
});
export const store = configureStore({ reducer: { cart: cartSlice.reducer } });
```
**Rule:** Use it for large teams or apps that need strict patterns, devtools time travel, and middleware.

---

## 04. Zustand
**What:** A minimal hook-based store with no providers and selective subscriptions.

```ts
import { create } from 'zustand';
type Cart = { items: Item[]; add: (i: Item) => void; total: () => number };
export const useCart = create<Cart>((set, get) => ({
  items: [],
  add: (i) => set((s) => ({ items: [...s.items, i] })),
  total: () => get().items.reduce((n, i) => n + i.price, 0),
}));
const count = useCart((s) => s.items.length); // re-renders only when length changes
```
**Rule:** This is the default choice for global client state in small and medium apps.

---

## 05. Server State
**What:** Data owned by the server (products, users, orders) that you *cache* on the client. It's async, shared, and can go stale.
**Key insight:** Server state is not the same as client state, so don't put API responses in Redux or Zustand by hand.

```tsx
// ❌ Manual
useEffect(() => { fetch('/api/products').then(r => r.json()).then(setProducts); }, []);
// ✅ Let a server-state lib own caching, dedupe, refetch
const { data } = useQuery({ queryKey: ['products'], queryFn: fetchProducts });
```
**Rule:** Server data goes in TanStack Query, SWR, or RSC. It never goes in a global client store.

---

## 06. TanStack Query
**What:** A library for fetching, caching, syncing, and updating server state.

```tsx
const qc = useQueryClient();
const { data, isPending, error } = useQuery({
  queryKey: ['product', id],
  queryFn: () => api.getProduct(id),
  staleTime: 60_000,
});
const mutation = useMutation({
  mutationFn: api.updateProduct,
  onSuccess: () => qc.invalidateQueries({ queryKey: ['product', id] }),
});
```
**Rule:** Build structured query keys (`['entity', id, filters]`) with a key factory per feature.

---

## 07. Normalized State
**What:** Store entities by ID in flat maps instead of nested, duplicated objects.

```ts
// ❌ Nested — updating an author means finding every post
{ posts: [{ id: 1, author: { id: 9, name: 'Ada' } }] }

// ✅ Normalized
{
  posts:   { byId: { 1: { id: 1, authorId: 9 } }, allIds: [1] },
  authors: { byId: { 9: { id: 9, name: 'Ada' } }, allIds: [9] },
}
// RTK: createEntityAdapter() does this for you
```
**Rule:** Normalize when the same entity appears in multiple places.

---

## 08. Derived State
**What:** Values computed from existing state. Don't store them, calculate them.

```tsx
// ❌ Stored duplicate that can drift
const [items, setItems] = useState([]);
const [total, setTotal] = useState(0);

// ✅ Derived
const total = items.reduce((n, i) => n + i.price * i.qty, 0);
```
**Rule:** If you can compute it from other state, don't `useState` it.

---

## 09. Immutability
**What:** Never mutate state in place. Create new objects so change detection works.

```ts
// ❌
state.user.name = 'Joe'; setState(state);
// ✅
setState(s => ({ ...s, user: { ...s.user, name: 'Joe' } }));
// ✅ with Immer
setState(produce(d => { d.user.name = 'Joe'; }));
// Arrays: toSorted(), toSpliced(), with() are non-mutating
const sorted = items.toSorted((a, b) => a.price - b.price);
```
**Rule:** No `.push`, `.sort`, or `.splice`, and no property assignment on state, unless you're inside Immer.

---

## 10. Optimistic Updates
**What:** Update the UI immediately, then roll back if the server fails.

```tsx
useMutation({
  mutationFn: api.likePost,
  onMutate: async (id) => {
    await qc.cancelQueries({ queryKey: ['post', id] });
    const prev = qc.getQueryData(['post', id]);
    qc.setQueryData(['post', id], (p: Post) => ({ ...p, likes: p.likes + 1 }));
    return { prev };
  },
  onError: (_e, id, ctx) => qc.setQueryData(['post', id], ctx?.prev),
  onSettled: (_d, _e, id) => qc.invalidateQueries({ queryKey: ['post', id] }),
});
// React 19 + Server Actions: useOptimistic()
```
**Rule:** Use optimistic updates for low-risk actions (likes, toggles, reorders). Never use them for payments. In an RSC + Server Actions app, prefer `useOptimistic`; use TanStack `onMutate` when the data lives in a client query cache.

---

## 11. Cache Invalidation
**What:** Marking cached data stale so it gets refetched after a change.

```ts
qc.invalidateQueries({ queryKey: ['products'] });             // all product queries
qc.invalidateQueries({ queryKey: ['products', { cat: 'tees' }] });
// Next.js server cache
revalidateTag('products', 'max'); revalidatePath('/shop');   // Next 16: profile argument required
updateTag('products');   // Server Actions needing read-your-own-writes
```
**Rule:** Every mutation declares which cache keys it invalidates.

---

## 12. Form State
**What:** Values, errors, touched and dirty flags, and submission status. Use a form library rather than a pile of `useState` calls.

```tsx
const schema = z.object({ email: z.email(), name: z.string().min(2) });   // Zod 4 top-level formats
const { register, handleSubmit, formState: { errors, isSubmitting } } =
  useForm({ resolver: zodResolver(schema) });
<form onSubmit={handleSubmit(onSubmit)}>
  <input {...register('email')} aria-invalid={!!errors.email} />
  {errors.email && <p role="alert">{errors.email.message}</p>}
</form>
```
**Rule:** Share one Zod schema between client validation and server validation. In the App Router, a Server Action with `useActionState` is the default form path; use React Hook Form for complex client-side forms.

---

## 13. URL as State
**What:** Put shareable UI state (filters, tabs, pagination, search) in the URL.

```tsx
'use client';
const params = useSearchParams(); const router = useRouter();
const page = Number(params.get('page') ?? 1);
const setPage = (p: number) => {
  const q = new URLSearchParams(params); q.set('page', String(p));
  router.push(`?${q}`, { scroll: false });
};
// Library: nuqs → const [page, setPage] = useQueryState('page', parseAsInteger.withDefault(1))
```
**Rule:** If a user would want to bookmark or share it, it belongs in the URL.

---

## 14. State Machines
**What:** Model state as explicit states and the transitions between them, which makes impossible states impossible.

```ts
type State =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: Data }
  | { status: 'error'; error: string };

// XState
const checkout = createMachine({
  initial: 'cart',
  states: {
    cart:     { on: { NEXT: 'shipping' } },
    shipping: { on: { NEXT: 'payment', BACK: 'cart' } },
    payment:  { on: { PAY: 'processing', BACK: 'shipping' } },
    processing: { on: { OK: 'done', FAIL: 'payment' } },
    done: { type: 'final' },
  },
});
```
**Rule:** Replace clusters like `isLoading`, `isError`, and `isSuccess` booleans with a discriminated union or a state machine.

---

## 15. Signals
**What:** Fine-grained reactive primitives. Only the code that reads a signal re-runs when it changes. Used by Solid, Preact, Angular, Vue (refs), and the TC39 proposal.

```ts
import { signal, computed, effect } from '@preact/signals';
const count = signal(0);
const double = computed(() => count.value * 2);
effect(() => console.log(double.value));
count.value++; // logs 2 — no component re-render needed
```
**Rule:** Know the model. In React, keep to React state unless a library deliberately bridges to signals. (Reference only; no automated checks.)

---

## 16. Avoiding Prop Drilling
**What:** Passing props through layers of components that don't use them.

```tsx
// ❌ <Page user> → <Layout user> → <Sidebar user> → <Avatar user>
// ✅ Composition: pass the rendered element
<Layout sidebar={<Sidebar avatar={<Avatar user={user} />} />} />
// ✅ Or Context / store for truly global data
```
**Rule:** Try composition (children or slots) first, then Context, then a store.

---

## 17. Selectors
**What:** Functions that pick or derive a slice of state so a component re-renders only when that slice changes.

```ts
// Zustand
const itemCount = useCart(s => s.items.length);
// Multiple values: useShallow to avoid new-object re-renders
const { add, remove } = useCart(useShallow(s => ({ add: s.add, remove: s.remove })));
// Redux memoized
const selectTotal = createSelector([(s) => s.cart.items], items => items.reduce(...));
```
**Rule:** Never subscribe to the whole store object.

---

## 18. Persisting State
**What:** Saving state across reloads in localStorage, IndexedDB, or cookies.

```ts
export const useCart = create(persist<Cart>(
  (set) => ({ items: [], add: (i) => set(s => ({ items: [...s.items, i] })) }),
  { name: 'cart-v1', version: 1, migrate: (old, v) => old as Cart, skipHydration: true },
));
// With SSR: skipHydration avoids a server/client mismatch; rehydrate after mount
// useEffect(() => { useCart.persist.rehydrate(); }, []);
```
**Rule:** Version persisted schemas, never persist secrets or tokens in localStorage, and handle SSR hydration mismatches.

---

## 19. Sync Across Tabs
**What:** Keep state consistent when the app is open in several tabs.

```ts
// storage event fires in OTHER tabs
window.addEventListener('storage', (e) => { if (e.key === 'cart-v1') useCart.persist.rehydrate(); });

// BroadcastChannel — explicit messaging
const bc = new BroadcastChannel('auth');
bc.postMessage({ type: 'logout' });
bc.onmessage = (e) => { if (e.data.type === 'logout') location.href = '/login'; };
```
**Rule:** Logout and login must sync across tabs, and the cart should too.

---

## 20. Choosing a Store
| Need | Use |
|---|---|
| Component-only UI | `useState` / `useReducer` |
| Shareable / bookmarkable | URL params (nuqs) |
| Server data | RSC fetch or TanStack Query / SWR |
| Forms | React Hook Form + Zod |
| Small global client state | Zustand / Jotai |
| Large team, strict patterns | Redux Toolkit |
| Complex flows | XState / discriminated unions |
| Low-frequency app config | Context |
