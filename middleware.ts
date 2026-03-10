import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const PROTECTED_ROUTES = ['/dashboard', '/settings', '/team'];
const AUTH_ROUTES = ['/sign-in', '/sign-up'];

export function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  
  // Check for session cookie
  const hasSession = req.cookies.has('authjs.session-token') || 
                     req.cookies.has('__Secure-authjs.session-token');

  // Redirect logged-in users away from auth pages
  if (hasSession && AUTH_ROUTES.some((r) => pathname.startsWith(r))) {
    return NextResponse.redirect(new URL('/dashboard', req.url));
  }
  
  // Redirect non-logged-in users to sign-in for protected routes
  if (!hasSession && PROTECTED_ROUTES.some((r) => pathname.startsWith(r))) {
    const signIn = new URL('/sign-in', req.url);
    signIn.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(signIn);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/settings/:path*',
    '/team/:path*',
    '/sign-in',
    '/sign-up',
  ],
};
