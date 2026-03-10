import { auth } from '@/auth';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// ─── Route protection rules ───────────────────────────────────────────────────
const PROTECTED_ROUTES = [
  '/dashboard',
  '/settings',
  '/team',
  '/pricing',  // требует авторизации для управления подпиской
];

const OWNER_ONLY_ROUTES = [
  '/settings/team',
  '/settings/billing',
];

const ADMIN_AND_OWNER_ROUTES = [
  '/dashboard/analytics',
];

const AUTH_ROUTES = ['/sign-in', '/sign-up'];

// ─── Middleware ───────────────────────────────────────────────────────────────
export default auth((req: NextRequest & { auth: any }) => {
  const { nextUrl, auth: session } = req as any;
  const pathname = nextUrl.pathname;
  const isLoggedIn = !!session?.user;
  const userRole = session?.user?.role as string | undefined;

  // 1. Redirect authenticated users away from auth pages
  if (isLoggedIn && AUTH_ROUTES.some((r) => pathname.startsWith(r))) {
    return NextResponse.redirect(new URL('/dashboard', nextUrl));
  }

  // 2. Protect routes — redirect to sign-in if not authenticated
  if (PROTECTED_ROUTES.some((r) => pathname.startsWith(r)) && !isLoggedIn) {
    const signInUrl = new URL('/sign-in', nextUrl);
    signInUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(signInUrl);
  }

  // 3. Owner-only routes
  if (OWNER_ONLY_ROUTES.some((r) => pathname.startsWith(r))) {
    if (!isLoggedIn) {
      return NextResponse.redirect(new URL('/sign-in', nextUrl));
    }
    if (userRole !== 'owner') {
      return NextResponse.redirect(new URL('/dashboard?error=forbidden', nextUrl));
    }
  }

  // 4. Admin + Owner routes
  if (ADMIN_AND_OWNER_ROUTES.some((r) => pathname.startsWith(r))) {
    if (!isLoggedIn) {
      return NextResponse.redirect(new URL('/sign-in', nextUrl));
    }
    if (userRole !== 'owner' && userRole !== 'admin') {
      return NextResponse.redirect(new URL('/dashboard?error=forbidden', nextUrl));
    }
  }

  // 5. Protect API routes (except auth and webhooks)
  if (
    pathname.startsWith('/api/') &&
    !pathname.startsWith('/api/auth') &&
    !pathname.startsWith('/api/webhooks') &&
    !isLoggedIn
  ) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return NextResponse.next();
});

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
