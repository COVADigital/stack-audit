export async function getShipping() {
  const res = await fetch(`${process.env.API_URL}/shipping`, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`shipping request failed: ${res.status}`)
  return res.json()
}
