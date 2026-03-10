import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Minimal Edge-safe middleware: cookie check only (no NextAuth — it crashes in Edge)
const SESSION_COOKIE = 'authjs.session-token';
const SESSION_COOKIE_SECURE = '__Secure-authjs.session-token';

function hasSession(req: NextRequest) {
  return req.cookies.has(SESSION_COOKIE) || req.cookies.has(SESSION_COOKIE_SECURE);
}

const PROTECTED_ROUTES = ['/dashboard', '/settings', '/team', '/pricing'];
const AUTH_ROUTES = ['/sign-in', '/sign-up'];

export function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  const loggedIn = hasSession(req);

  if (loggedIn && AUTH_ROUTES.some((r) => pathname.startsWith(r))) {
    return NextResponse.redirect(new URL('/dashboard', req.url));
  }
  if (!loggedIn && PROTECTED_ROUTES.some((r) => pathname.startsWith(r))) {
    const signIn = new URL('/sign-in', req.url);
    signIn.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(signIn);
  }
  if (
    pathname.startsWith('/api/') &&
    !pathname.startsWith('/api/auth') &&
    !pathname.includes('webhook') &&
    !loggedIn
  ) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Защищаем все пути кроме:
     * - _next/static, _next/image (статика)
     * - favicon.ico, sitemap.xml, robots.txt
     * - Публичные страницы (landing)
     */
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
};
