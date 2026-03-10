import NextAuth from 'next-auth';
import Google from 'next-auth/providers/google';
import Credentials from 'next-auth/providers/credentials';
import { DrizzleAdapter } from '@auth/drizzle-adapter';
import { db } from '@/lib/db/drizzle';
import { users, accounts, sessions, verificationTokens } from '@/lib/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import type { UserRole } from '@/lib/db/schema';
import authConfig from './auth.config';

// ─── Validation schema for credentials ───────────────────────────────────────
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// ─── NextAuth config (extends Edge-safe auth.config with adapter + Credentials) ─
export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  adapter: DrizzleAdapter(db, {
    usersTable: users,
    accountsTable: accounts,
    sessionsTable: sessions,
    verificationTokensTable: verificationTokens,
  }),

  providers: [
    ...(authConfig.providers as any),
    // ── Email + Password (Node-only, not in auth.config) ──────────────────────
    Credentials({
      name: 'credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        // 1. Validate input
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) return null;

        const { email, password } = parsed.data;

        // 2. Find user
        const [user] = await db
          .select()
          .from(users)
          .where(eq(users.email, email))
          .limit(1);

        if (!user || !user.passwordHash) return null;

        // 3. Check soft-delete
        if (user.deletedAt) return null;

        // 4. Verify password
        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) return null;

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: user.image,
          role: user.role,
        };
      },
    }),
  ],

  callbacks: {
    // ── JWT callback: inject role + id ────────────────────────────────────────
    async jwt({ token, user, trigger, session }) {
      // При первом входе user содержит данные из authorize/profile
      if (user) {
        token.id = user.id;
        token.role = (user as any).role ?? 'owner';
      }

      // При update сессии (например, смена роли)
      if (trigger === 'update' && session?.role) {
        token.role = session.role;
      }

      // Если роль не установлена — подтянуть из БД (для OAuth flow)
      if (!token.role && token.id) {
        const [dbUser] = await db
          .select({ role: users.role })
          .from(users)
          .where(eq(users.id, token.id as string))
          .limit(1);
        if (dbUser) token.role = dbUser.role;
      }

      return token;
    },

    // ── Session callback: expose role в клиентской сессии ────────────────────
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as UserRole;
      }
      return session;
    },

    // ── SignIn callback: блокировать удалённых пользователей ─────────────────
    async signIn({ user, account }) {
      // Для credentials проверка уже выполнена в authorize
      if (account?.provider === 'credentials') return true;

      // Для OAuth — проверить soft-delete
      if (user.email) {
        const [dbUser] = await db
          .select({ deletedAt: users.deletedAt })
          .from(users)
          .where(eq(users.email, user.email))
          .limit(1);

        if (dbUser?.deletedAt) return false;
      }

      return true;
    },
  },
});
