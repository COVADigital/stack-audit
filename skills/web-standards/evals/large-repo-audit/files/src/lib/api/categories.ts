export async function getCategories() {
  const res = await fetch(`${process.env.API_URL}/categories`, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`categories request failed: ${res.status}`)
  return res.json()
}
