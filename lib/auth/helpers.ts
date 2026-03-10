import { auth } from '@/auth';
import { db } from '@/lib/db/drizzle';
import { users, teamMembers } from '@/lib/db/schema';
import { eq, and } from 'drizzle-orm';
import { redirect } from 'next/navigation';
import type { UserRole } from '@/lib/db/schema';

// ─── getCurrentUser ───────────────────────────────────────────────────────────
/**
 * Возвращает текущего пользователя из сессии.
 * Использовать в Server Components и Server Actions.
 */
export async function getCurrentUser() {
  const session = await auth();
  if (!session?.user?.id) return null;
  return session.user;
}

// ─── requireAuth ─────────────────────────────────────────────────────────────
/**
 * Требует аутентификации. Редиректит на /sign-in если не авторизован.
 * Возвращает гарантированно заполненный объект пользователя.
 */
export async function requireAuth() {
  const user = await getCurrentUser();
  if (!user) {
    redirect('/sign-in');
  }
  return user;
}

// ─── requireRole ─────────────────────────────────────────────────────────────
/**
 * Требует определённую роль. Редиректит на /dashboard если нет прав.
 *
 * @example
 * const user = await requireRole('owner');
 * const user = await requireRole(['owner', 'admin']);
 */
export async function requireRole(allowedRoles: UserRole | UserRole[]) {
  const user = await requireAuth();
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  if (!roles.includes(user.role as UserRole)) {
    redirect('/dashboard?error=forbidden');
  }

  return user;
}

// ─── getTeamRole ─────────────────────────────────────────────────────────────
/**
 * Возвращает роль пользователя в конкретной команде (barbershop).
 */
export async function getTeamRole(
  userId: string,
  teamId: number,
): Promise<UserRole | null> {
  const [member] = await db
    .select({ role: teamMembers.role })
    .from(teamMembers)
    .where(
      and(eq(teamMembers.userId, userId), eq(teamMembers.teamId, teamId)),
    )
    .limit(1);

  return (member?.role as UserRole) ?? null;
}

// ─── requireTeamRole ─────────────────────────────────────────────────────────
/**
 * Проверяет роль пользователя в команде. Выбрасывает Error если нет прав.
 * Использовать в API routes и Server Actions.
 */
export async function requireTeamRole(
  teamId: number,
  allowedRoles: UserRole | UserRole[],
) {
  const user = await requireAuth();
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  const teamRole = await getTeamRole(user.id!, teamId);

  if (!teamRole || !roles.includes(teamRole)) {
    throw new Error('Forbidden: insufficient team permissions');
  }

  return { user, teamRole };
}

// ─── getUserWithTeam ─────────────────────────────────────────────────────────
/**
 * Полные данные пользователя с командой из БД.
 */
export async function getUserWithTeam(userId: string) {
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user) return null;

  const [membership] = await db
    .select()
    .from(teamMembers)
    .where(eq(teamMembers.userId, userId))
    .limit(1);

  return { user, teamId: membership?.teamId ?? null, teamRole: membership?.role ?? null };
}
