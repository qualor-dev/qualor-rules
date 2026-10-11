import { Router, Request, Response } from 'express';
import * as ejs from 'ejs';
import Handlebars from 'handlebars';
import nunjucks from 'nunjucks';
import { template } from 'lodash';
import { renderString as njkString } from 'nunjucks';
import { NextRequest } from 'next/server';
import * as pugNs from 'pug';
import * as njkNs from 'nunjucks';
import * as hbsNs from 'handlebars';
import * as lodashNs from 'lodash';
import * as helpersNs from './view-helpers';

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

router.get('/ts/page-spread', (req: Request, res: Response) => {
  // ruleid: js.template-injection
  res.render('page.ejs', { title: 'Page', ...req.body });
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

// Functions of these names that take no template source (namespace imports).
const blank = lodashNs.create();
router.post('/ts/engine-names', (req: Request, res: Response) => {
  const text = String(req.body.text);
  // ok: js.template-injection
  const a = njkNs.render(text, {});
  // ok: js.template-injection
  const b = njkNs.precompile(text);
  // ok: js.template-injection
  const c = hbsNs.template(text);
  // ok: js.template-injection
  const d = pugNs.renderString(text);
  // ok: js.template-injection
  const g = helpersNs.render(text);
  // ok: js.template-injection
  const i = blank.compile(text);
  // ok: js.template-injection
  const j = pugNs.compile('p= name', req.body);
  // ok: js.template-injection
  const k = pugNs.render('p= name', req.body);
  // ok: js.template-injection
  const o = helpersNs.compile(text);
  res.json({ a, b, c, d, g, i, j, k, o });
});

// Views rendered by another engine: a view name that is not .ejs, an app whose view engine is
// not EJS, and engines registered with other functions.
router.get('/ts/pug-view', (req: Request, res: Response) => {
  // ok: js.template-injection
  res.render('page.pug', req.query);
});
router.get('/ts/pug-view-spread', (req: Request, res: Response) => {
  // ok: js.template-injection
  res.render('page.pug', { ...req.body });
});
export function pugViews(site: any) {
  site.set('view engine', 'pug');
  site.set('views', 'ejs');
  site.engine('html', pugNs.renderFile);
  site.engine('htm', ejs.compile);
  site.get('/ts/site', (req: Request, res: Response) => {
    // ok: js.template-injection
    res.render('site', req.query);
  });
}
export function cjsViews(site: any) {
  const engine = require('ejs');
  site.engine('html', engine.__express);
  site.get('/ts/cjs-site', (req: Request, res: Response) => {
    // ruleid: js.template-injection
    res.render('site', req.query);
  });
}
export function ejsViews(site: any) {
  site.engine('html', ejs.renderFile);
  site.get('/ts/ejs-site', (req: Request, res: Response) => {
    // ruleid: js.template-injection
    res.render('site', req.query);
  });
}

export default router;
