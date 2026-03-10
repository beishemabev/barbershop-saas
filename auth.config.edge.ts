import type { NextAuthConfig } from 'next-auth';

type UserRole = 'owner' | 'admin' | 'viewer';

/**
 * Edge-only config for middleware. NO providers (Google pulls Node deps).
 * Middleware only decodes existing JWT — sign-in uses auth.ts.
 */
export default {
  session: { strategy: 'jwt', maxAge: 30 * 24 * 60 * 60 },
  pages: { signIn: '/sign-in', error: '/sign-in', newUser: '/dashboard' },
  providers: [],
  callbacks: {
    jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.role = (user as any).role ?? 'owner';
      }
      return token;
    },
    session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.role = (token.role as UserRole) ?? 'owner';
      }
      return session;
    },
  },
} satisfies NextAuthConfig;
