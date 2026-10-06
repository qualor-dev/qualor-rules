import express, { Request, Response } from 'express';
import escapeStringRegexp from 'escape-string-regexp';
import { escapeRegExp as escapeLodash } from 'lodash-es';
import lodash from 'lodash';
import { NextRequest } from 'next/server';

const app = express();

// TypeScript: typed Express handlers.
app.get('/ts/search/:field', (req: Request, res: Response) => {
  const q = req.query.q as string;
  // ruleid: js.regex-injection
  const re = new RegExp(q, 'i');
  // ruleid: js.regex-injection
  const field = RegExp(`^${req.params.field}:`);
  // ok: js.regex-injection
  const safe = new RegExp(escapeStringRegexp(q));
  // ok: js.regex-injection
  const safe2 = new RegExp(`^${escapeLodash(req.params.field)}:`);
  // ok: js.regex-injection
  const safe3 = new RegExp(lodash.escapeRegExp(q), 'g');
  res.json({ re: re.source, field: field.source, safe: safe.source, safe2: safe2.source, safe3: safe3.source });
});

// Next.js App Router route handlers: the query string, the JSON body, and dynamic segments.
export async function GET(request: NextRequest, { params }: { params: Promise<{ word: string }> }) {
  const { word } = await params;
  // ruleid: js.regex-injection
  const byWord = new RegExp(`\\b${word}\\b`);
  const q = request.nextUrl.searchParams.get('q') ?? '';
  // ruleid: js.regex-injection
  const byQuery = new RegExp(q);
  // ok: js.regex-injection
  const subject = /^[a-z]+$/.test(q);
  return Response.json({ byWord: byWord.source, byQuery: byQuery.source, subject });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.regex-injection
  const re = new RegExp(body.pattern, body.flags);
  // ok: js.regex-injection
  const escaped = new RegExp(RegExp.escape(body.pattern));
  return Response.json({ re: re.source, escaped: escaped.source });
}

// A typed local helper with the common hand-written escape.
function escapePattern(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
const escapeTerm = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
app.get('/ts/escaped', (req: Request, res: Response) => {
  // ok: js.regex-injection
  const a = new RegExp(escapePattern(String(req.query.q)));
  // ok: js.regex-injection
  const b = new RegExp(`^${escapeTerm(String(req.query.q))}$`);
  // ruleid: js.regex-injection
  const c = new RegExp(String(req.query.q).replace(/[.*+?^${}()|[\]\\]/, '\\$&'));
  res.json([a.source, b.source, c.source]);
});

// A helper with a request-like parameter that is not a route handler.
export function compile(request: { pattern: string }) {
  // ok: js.regex-injection
  return new RegExp(request.pattern);
}

export default app;
