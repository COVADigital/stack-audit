'use client'

export function rememberLogin(token: string) {
  localStorage.setItem('access_token', token)
}

export function currentToken() {
  return localStorage.getItem('access_token')
}
