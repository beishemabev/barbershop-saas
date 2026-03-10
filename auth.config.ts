import type { NextAuthConfig } from 'next-auth';
import Google from 'next-auth/providers/google';

type UserRole = 'owner' | 'admin' | 'viewer';

/**
 * Edge-compatible auth config for middleware.
 * No adapter, no Credentials, no db — only what's needed to decode JWT in Edge.
 */
export default {
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  pages: {
    signIn: '/sign-in',
    error: '/sign-in',
    newUser: '/dashboard',
  },
  providers: [
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? [
          Google({
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          }),
        ]
      : []),
  ],
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
