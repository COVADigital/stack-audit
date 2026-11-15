// proxy.ts — nonce-based strict CSP (Next.js 16; this file was middleware.ts before 16)
// Based on the Next.js Content Security Policy guide (v16.4.5).
//
// TRADE-OFF (08-security §03): every page that uses the nonce must render dynamically
// (e.g. `await connection()`), so no SSG/ISR/CDN HTML caching for those routes.
// Start in Report-Only mode, fix violations, then switch the header name to enforce.
import { NextRequest, NextResponse } from 'next/server';

const REPORT_ONLY = true;

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const isDev = process.env.NODE_ENV === 'development';
  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ''};
    style-src 'self' 'nonce-${nonce}';
    img-src 'self' blob: data:;
    font-src 'self';
    connect-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `.replace(/\s{2,}/g, ' ').trim();
  // Add your real origins above, e.g. img-src https://cdn.sanity.io; frame-src https://open.spotify.com

  const headerName = REPORT_ONLY ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp); // Next.js reads the nonce from this request header

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set(headerName, csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
