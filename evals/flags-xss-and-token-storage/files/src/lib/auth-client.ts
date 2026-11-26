'use client'

export async function login(email: string, password: string) {
  const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) })
  const { token } = await res.json()
  localStorage.setItem('token', token)
}
