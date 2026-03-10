'use client';

import { useActionState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { registerOwner } from '@/lib/auth/actions';
import { Scissors } from 'lucide-react';

export default function SignUpPage() {
  const [state, formAction, isPending] = useActionState(registerOwner, {});

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <Scissors className="h-8 w-8 text-zinc-900" />
          </div>
          <CardTitle className="text-2xl">Регистрация барбершопа</CardTitle>
          <CardDescription>Создайте аккаунт владельца</CardDescription>
        </CardHeader>

        <CardContent>
          {state?.error && (
            <div className="mb-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
              {state.error}
            </div>
          )}

          {state?.success && (
            <div className="mb-4 rounded-md bg-green-50 p-3 text-sm text-green-700">
              {state.success}
            </div>
          )}

          <form action={formAction} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Ваше имя</Label>
              <Input
                id="name"
                name="name"
                type="text"
                placeholder="Иван Петров"
                autoComplete="name"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="barbershopName">Название барбершопа</Label>
              <Input
                id="barbershopName"
                name="barbershopName"
                type="text"
                placeholder="BarberKing"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                placeholder="owner@barbershop.ru"
                autoComplete="email"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Пароль</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                minLength={8}
                required
              />
              <p className="text-xs text-gray-500">
                Минимум 8 символов, одна заглавная буква и одна цифра
              </p>
            </div>

            <Button type="submit" className="w-full" disabled={isPending}>
              {isPending ? 'Создание аккаунта...' : 'Создать аккаунт'}
            </Button>
          </form>
        </CardContent>

        <CardFooter className="flex justify-center">
          <p className="text-sm text-gray-600">
            Уже есть аккаунт?{' '}
            <Link href="/sign-in" className="font-medium text-zinc-900 hover:underline">
              Войти
            </Link>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
