import { cookies } from 'next/headers'

export async function POST() {
  const store = await cookies()
  store.set('cart_session', crypto.randomUUID(), { path: '/' })
  return Response.json({ ok: true })
}
