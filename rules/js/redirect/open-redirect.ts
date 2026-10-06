import express, { Request, Response as ExpressResponse } from 'express';
import { NextRequest, NextResponse } from 'next/server';
import { redirect, permanentRedirect as movedTo } from 'next/navigation';
import { pickTarget } from './targets';

const app = express();
const PORTAL: string = 'https://portal.example.com';
const portalBase: string = process.env.PORTAL_URL ?? 'https://portal.example.com';

// TypeScript: typed Express handlers.
app.get('/sso/:provider', (req: Request, res: ExpressResponse) => {
  const returnTo = String(req.query.returnTo);
  if (req.params.provider === 'none') {
    // ruleid: js.open-redirect
    return res.redirect(returnTo);
  }
  if (req.params.provider === 'path') {
    // ok: js.open-redirect
    return res.redirect(`${PORTAL}/sso/${req.params.provider}`);
  }
  const callback = `${portalBase}/callback?state=${req.query.state}`;
  // ok: js.open-redirect
  return res.redirect(callback);
});

// Next.js App Router route handlers: NextResponse.redirect, Response.redirect, redirect() and
// permanentRedirect() from next/navigation, and a Location header on a new Response.
export async function GET(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const next = request.nextUrl.searchParams.get('next') ?? '/';
  const mode = request.nextUrl.searchParams.get('mode');
  if (mode === 'a') {
    // ruleid: js.open-redirect
    return NextResponse.redirect(next);
  }
  if (mode === 'b') {
    // ruleid: js.open-redirect
    return NextResponse.redirect(new URL(next, request.url));
  }
  if (mode === 'c') {
    // ruleid: js.open-redirect
    return Response.redirect(new URL(next, request.nextUrl.origin), 307);
  }
  if (mode === 'd') {
    // ruleid: js.open-redirect
    redirect(next);
  }
  if (mode === 'e') {
    // ruleid: js.open-redirect
    movedTo(`https://${slug}.example.com/`);
  }
  if (mode === 'f') {
    // ok: js.open-redirect
    return NextResponse.redirect(new URL('/login', request.url));
  }
  if (mode === 'g') {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('from', request.nextUrl.pathname);
    // ok: js.open-redirect
    return NextResponse.redirect(loginUrl);
  }
  if (mode === 'h') {
    // ok: js.open-redirect
    redirect(`/posts/${slug}`);
  }
  if (mode === 'i') {
    const url = request.nextUrl.clone();
    url.pathname = '/dashboard';
    // ok: js.open-redirect
    return NextResponse.redirect(url);
  }
  if (mode === 'j') {
    const moved = request.nextUrl.clone();
    moved.host = request.nextUrl.searchParams.get('host') ?? 'example.com';
    // ruleid: js.open-redirect
    return NextResponse.redirect(moved);
  }
  if (mode === 'l') {
    // The query string of the request's own URL is request data, read in place, through a
    // variable or destructured.
    // ruleid: js.open-redirect
    return NextResponse.redirect(new URL(request.url).searchParams.get('to') ?? '/');
  }
  if (mode === 'm') {
    const own = new URL(request.url);
    const to = own.searchParams.get('to') ?? '/';
    // ruleid: js.open-redirect
    return NextResponse.redirect(new URL(to, request.url));
  }
  if (mode === 'n') {
    const { searchParams } = new URL(request.url);
    // ruleid: js.open-redirect
    redirect(searchParams.get('to') ?? '/');
  }
  if (mode === 'o') {
    const copy = request.nextUrl.clone();
    // ruleid: js.open-redirect
    return NextResponse.redirect(copy.searchParams.get('to') ?? '/');
  }
  if (mode === 'p') {
    // ruleid: js.open-redirect
    return NextResponse.redirect(await pickTarget(next));
  }
  if (mode === 'k') {
    // ruleid: js.open-redirect
    return NextResponse.redirect(new URL('/login', request.nextUrl.searchParams.get('base') ?? ''));
  }
  if (mode === 't') {
    // ruleid: js.open-redirect
    return new Response(null, { status: 302, headers: { Location: `https://${next}/` } });
  }
  // ok: js.open-redirect
  return NextResponse.redirect(new URL(`/posts/${encodeURIComponent(slug)}`, request.url));
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (body.kind === 'header') {
    // ruleid: js.open-redirect
    return new Response(null, { status: 302, headers: { Location: body.next } });
  }
  if (body.kind === 'fixed') {
    // ok: js.open-redirect
    return new Response(null, { status: 303, headers: { Location: '/thanks/' + body.id } });
  }
  const form = await request.formData();
  // ruleid: js.open-redirect
  return NextResponse.redirect(String(form.get('returnTo')), 303);
}

// The request's own URL is a clean base only when the request is named req or request.
export const PUT = async function (incoming: NextRequest) {
  // todook: js.open-redirect
  return NextResponse.redirect(new URL('/login', incoming.url));
};

// Server Functions (Server Actions) and page props are not in the request source block.
export async function navigate(data: FormData) {
  'use server';
  // todoruleid: js.open-redirect
  redirect(String(data.get('next')));
}

// A helper with a request-like parameter that is not a route handler.
export function toLogin(request: { url: string }) {
  // ok: js.open-redirect
  return NextResponse.redirect(request.url);
}

export default app;
