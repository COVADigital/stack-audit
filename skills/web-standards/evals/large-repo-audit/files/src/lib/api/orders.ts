export async function getOrders(userId: string) {
  const res = await fetch(`${process.env.API_URL}/orders?user=${encodeURIComponent(userId)}`)
  return res.json()
}
