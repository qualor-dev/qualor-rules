import { NextResponse } from 'next/server';
import { sessionStore } from './session-store.mjs';

// Next.js App Router route handlers (JavaScript) that await the redirect: `return await` is
// common, also inside try blocks. The file imports nothing named redirect.
export async function GET(request) {
  const next = request.nextUrl.searchParams.get('next') ?? '/';
  const mode = request.nextUrl.searchParams.get('mode');
  if (mode === 'a') {
    // ruleid: js.open-redirect
    return await NextResponse.redirect(next);
  }
  if (mode === 'b') {
    // ruleid: js.open-redirect
    return await Response.redirect(new URL(next, request.url), 302);
  }
  if (mode === 'c') {
    // ok: js.open-redirect
    return await NextResponse.redirect(new URL('/account', request.url));
  }
  try {
    const saved = await sessionStore.lookup(next);
    if (mode === 'd') {
      // ruleid: js.open-redirect
      return await NextResponse.redirect(new URL(next, request.url), 303);
    }
    if (mode === 'e') {
      // ruleid: js.open-redirect
      return await Response.redirect(request.nextUrl.searchParams.get('to') ?? '/');
    }
    // A value loaded with the request value as its key is stored data (Known limits).
    // ok: js.open-redirect
    return await NextResponse.redirect(new URL(saved, request.url));
  } catch {
    // ok: js.open-redirect
    return await NextResponse.redirect(new URL('/error', request.url));
  }
}

export async function POST(request) {
  const { next, code } = await request.json();
  if (code) {
    // A function among the arguments (the exact twin of the awaited-method sanitizer).
    // ruleid: js.open-redirect
    return await Response.redirect(next, [301, 302].find((c) => c === code));
  }
  try {
    // ruleid: js.open-redirect
    return await NextResponse.redirect(next);
  } catch {
    // ruleid: js.open-redirect
    return await Response.redirect(next, 302);
  }
}
