export async function getProducts() {
  const res = await fetch(`${process.env.API_URL}/products`, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`products request failed: ${res.status}`)
  return res.json()
}
