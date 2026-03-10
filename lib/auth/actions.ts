'use server';

import { signIn, signOut } from '@/auth';
import { db } from '@/lib/db/drizzle';
import { users, teams, teamMembers, activityLogs } from '@/lib/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { redirect } from 'next/navigation';
import { AuthError } from 'next-auth';

// ─── Schemas ──────────────────────────────────────────────────────────────────
const registerSchema = z.object({
  name: z.string().min(2, 'Имя должно быть не менее 2 символов'),
  email: z.string().email('Некорректный email'),
  password: z
    .string()
    .min(8, 'Пароль минимум 8 символов')
    .regex(/[A-Z]/, 'Нужна хотя бы одна заглавная буква')
    .regex(/[0-9]/, 'Нужна хотя бы одна цифра'),
  barbershopName: z.string().min(2, 'Название барбершопа минимум 2 символа'),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export type ActionState = {
  error?: string;
  success?: string;
};

// ─── registerOwner ────────────────────────────────────────────────────────────
/**
 * Регистрация владельца барбершопа.
 * Создаёт пользователя (role: owner) + команду + членство.
 */
export async function registerOwner(
  _prevState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  // 1. Validate
  const parsed = registerSchema.safeParse({
    name: formData.get('name'),
    email: formData.get('email'),
    password: formData.get('password'),
    barbershopName: formData.get('barbershopName'),
  });

  if (!parsed.success) {
    return { error: parsed.error.errors[0].message };
  }

  const { name, email, password, barbershopName } = parsed.data;

  // 2. Check existing user
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (existing) {
    return { error: 'Пользователь с таким email уже существует' };
  }

  // 3. Hash password
  const hashedPassword = await bcrypt.hash(password, 12);

  // 4. Create user + team in transaction
  try {
    await db.transaction(async (tx) => {
      // Create user
      const [newUser] = await tx
        .insert(users)
        .values({
          name,
          email,
          password: hashedPassword,
          role: 'owner',
        })
        .returning({ id: users.id });

      // Create barbershop team
      const [newTeam] = await tx
        .insert(teams)
        .values({ name: barbershopName })
        .returning({ id: teams.id });

      // Add owner to team
      await tx.insert(teamMembers).values({
        userId: newUser.id,
        teamId: newTeam.id,
        role: 'owner',
      });

      // Log activity
      await tx.insert(activityLogs).values({
        teamId: newTeam.id,
        userId: newUser.id,
        action: 'OWNER_REGISTERED',
      });
    });
  } catch (err) {
    console.error('[registerOwner] DB error:', err);
    return { error: 'Ошибка при создании аккаунта. Попробуйте снова.' };
  }

  // 5. Auto sign-in after registration
  try {
    await signIn('credentials', {
      email,
      password,
      redirectTo: '/dashboard',
    });
  } catch (err) {
    if (err instanceof AuthError) {
      return { error: 'Регистрация прошла успешно, но войти не удалось. Войдите вручную.' };
    }
    throw err; // NEXT_REDIRECT — пропустить
  }

  return { success: 'Добро пожаловать!' };
}

// ─── loginWithCredentials ─────────────────────────────────────────────────────
export async function loginWithCredentials(
  _prevState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const parsed = loginSchema.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
  });

  if (!parsed.success) {
    return { error: 'Некорректные данные' };
  }

  const callbackUrl = (formData.get('callbackUrl') as string) || '/dashboard';

  try {
    await signIn('credentials', {
      email: parsed.data.email,
      password: parsed.data.password,
      redirectTo: callbackUrl,
    });
  } catch (err) {
    if (err instanceof AuthError) {
      switch (err.type) {
        case 'CredentialsSignin':
          return { error: 'Неверный email или пароль' };
        default:
          return { error: 'Ошибка входа. Попробуйте снова.' };
      }
    }
    throw err; // NEXT_REDIRECT
  }

  return { success: 'Вход выполнен' };
}

// ─── loginWithGoogle ──────────────────────────────────────────────────────────
export async function loginWithGoogle() {
  await signIn('google', { redirectTo: '/dashboard' });
}

// ─── logout ───────────────────────────────────────────────────────────────────
export async function logout() {
  await signOut({ redirectTo: '/' });
}
