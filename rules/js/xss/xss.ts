import express, { Request, Response } from 'express';
import escapeHtml from 'escape-html';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { NextRequest } from 'next/server';
import { buildCard, buildBanner as banner } from './cards';
import * as widgets from './widgets';

const app = express();

// Functions imported by name, also renamed, are not other objects' methods.
app.get('/card/:id', async (req: Request, res: Response) => {
  // ruleid: js.xss
  res.send(await buildCard(req.params.id));
  const top = await banner(req.query.text as string);
  // ruleid: js.xss
  res.send(top);
  // A function called through a module object counts as another object's method.
  // todoruleid: js.xss
  res.send(await widgets.drawWidget(req.params.id));
  // A method named like a function the file imports by name is not taken for another object's.
  // todook: js.xss
  res.send(await widgets.buildCard(req.params.id));
});

// TypeScript: typed Express handlers.
app.get('/welcome/:name', (req: Request, res: Response) => {
  // ruleid: js.xss
  res.send(`<h1>Welcome, ${req.params.name}</h1>`);
  // ok: js.xss
  res.send(`<h1>Welcome, ${escapeHtml(req.params.name)}</h1>`);
  // ok: js.xss
  res.json({ name: req.params.name });
});

// Next.js Pages Router API routes.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js.xss
  res.status(200).send('<p>' + req.query.title + '</p>');
  // ok: js.xss
  res.status(200).json({ title: req.query.title });
}

// Next.js App Router route handlers answering with HTML.
export async function GET(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const q = request.nextUrl.searchParams.get('q') ?? '';
  // ruleid: js.xss
  return new Response(`<h1>${slug}</h1><p>${q}</p>`, { headers: { 'Content-Type': 'text/html' } });
}

export async function PUT(request: NextRequest) {
  const { name } = await request.json();
  // ruleid: js.xss
  return new Response('<p>Saved ' + name + '</p>', { headers: { 'content-type': 'text/html' } });
}

export async function POST(request: NextRequest) {
  const form = await request.formData();
  const title = String(form.get('title'));
  // ok: js.xss
  new Response(`<h1>${escapeHtml(title)}</h1>`, { headers: { 'Content-Type': 'text/html' } });
  // ok: js.xss
  new Response(title, { headers: { 'Content-Type': 'text/plain' } });
  // ok: js.xss
  return Response.json({ title });
}
