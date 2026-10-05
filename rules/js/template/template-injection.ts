import { Router, Request, Response } from 'express';
import * as ejs from 'ejs';
import Handlebars from 'handlebars';
import nunjucks from 'nunjucks';
import { template } from 'lodash';
import { renderString as njkString } from 'nunjucks';
import { NextRequest } from 'next/server';

const router = Router();

// TypeScript: typed Express handlers and ES module imports.
router.post('/ts/templates/:id', (req: Request, res: Response) => {
  const source = String(req.body.source);
  // ruleid: js.template-injection
  const a = ejs.render(source, { id: req.params.id });
  // ruleid: js.template-injection
  const b = template(req.body.lodash as string)({});
  // ruleid: js.template-injection
  const c = njkString(`{% set id = "${req.params.id}" %}{{ id }}`, {});
  // ok: js.template-injection
  const d = ejs.render('<b><%= id %></b>', { id: req.params.id });
  res.json({ a, b, c, d });
});

// A routes file without the view engine: the engine set in another file is not known here.
router.get('/ts/home', (req: Request, res: Response) => {
  // todoruleid: js.template-injection
  res.render('home', req.query);
});

// A view name with the .ejs extension is rendered with EJS whatever the default engine.
router.get('/ts/page', (req: Request, res: Response) => {
  // ruleid: js.template-injection
  res.render('page.ejs', req.query);
});

router.get('/ts/page-safe', (req: Request, res: Response) => {
  // ok: js.template-injection
  res.render('page.pug', { q: req.query.q });
});

// Next.js App Router route handlers.
export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.template-injection
  const html = Handlebars.compile(body.template)({ user: 'x' });
  // ok: js.template-injection
  const safe = Handlebars.compile('<p>{{user}}</p>')({ user: body.user });
  return new Response(html + safe, { headers: { 'Content-Type': 'text/html' } });
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ tpl: string }> }) {
  const { tpl } = await params;
  // ruleid: js.template-injection
  const out = nunjucks.renderString(tpl, {});
  const q = request.nextUrl.searchParams.get('q') ?? '';
  // ok: js.template-injection
  const fixed = nunjucks.renderString('{{ q }}', { q });
  return new Response(out + fixed);
}

// A helper with a request-like parameter that is not a route handler.
export function preview(request: { tpl: string }) {
  // ok: js.template-injection
  return ejs.render(request.tpl);
}

export default router;
