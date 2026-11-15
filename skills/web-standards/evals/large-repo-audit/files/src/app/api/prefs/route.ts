import { cookies } from 'next/headers'

export async function POST() {
  const store = await cookies()
  store.set('theme', 'dark', { httpOnly: true, secure: true, sameSite: 'lax', path: '/' })
  return Response.json({ ok: true })
}
