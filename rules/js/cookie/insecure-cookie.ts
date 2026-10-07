import { cookies } from 'next/headers';
import { NextResponse, type NextRequest } from 'next/server';
import session from 'express-session';
import type { Response } from 'express';

// Next.js cookies() of next/headers in a Server Function or Route Handler: only the path has a
// default, so Secure and HttpOnly are off unless set.
export async function signIn(token: string) {
  const cookieStore = await cookies();
  // ruleid: js.insecure-cookie
  cookieStore.set('session', token);
  // ruleid: js.insecure-cookie
  cookieStore.set('session', token, { secure: true });
  // ruleid: js.insecure-cookie
  cookieStore.set({ name: 'session', value: token, httpOnly: true, path: '/' });
  // ok: js.insecure-cookie
  cookieStore.set('session', token, { secure: true, httpOnly: true, sameSite: 'lax' });
  // ok: js.insecure-cookie
  cookieStore.set({ name: 'session', value: token, httpOnly: true, secure: true });
  // ruleid: js.insecure-cookie
  (await cookies()).set('theme', 'dark', { maxAge: 31536000 });
}

// Deleting a cookie: delete(), an empty value, or maxAge 0.
export async function signOut() {
  const cookieStore = await cookies();
  // ok: js.insecure-cookie
  cookieStore.delete('session');
  // ok: js.insecure-cookie
  cookieStore.set('session', '');
  // ok: js.insecure-cookie
  cookieStore.set('session', 'value', { maxAge: 0 });
}

// NextResponse: response.cookies.set(); request.cookies.set() in middleware changes the request.
export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  // ruleid: js.insecure-cookie
  response.cookies.set('show-banner', 'false');
  // ok: js.insecure-cookie
  response.cookies.set('session', 'generated', { httpOnly: true, secure: true });
  // ok: js.insecure-cookie
  request.cookies.set('seen', '1');
  return response;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const response = NextResponse.json({ ok: true });
  // ruleid: js.insecure-cookie
  response.cookies.set({ name: 'session', value: body.token, secure: false, httpOnly: true });
  return response;
}

// Typed Express handlers and express-session imported as an ES module.
export function remember(res: Response, token: string) {
  // ruleid: js.insecure-cookie
  res.cookie('remember', token, { maxAge: 900000, httpOnly: true });
  // ok: js.insecure-cookie
  res.cookie('remember', token, { maxAge: 900000, httpOnly: true, secure: true });
}

// ruleid: js.insecure-cookie
export const sessions = session({ secret: 'keyboard cat', cookie: { httpOnly: true } });
// ok: js.insecure-cookie
export const secureSessions = session({ secret: 'keyboard cat', cookie: { secure: true } });
