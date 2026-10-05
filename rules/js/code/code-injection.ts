import express, { Request, Response } from 'express';
import * as vm from 'node:vm';
import { runInContext as runIn, createContext } from 'vm';
import { NextRequest } from 'next/server';

const app = express();

// TypeScript: typed Express handlers and ES module imports of node:vm.
app.post('/ts/eval/:id', (req: Request, res: Response) => {
  const expr = String(req.body.expr);
  // ruleid: js.code-injection
  const value = eval(expr);
  // ruleid: js.code-injection
  const script = new vm.Script(`(${req.params.id})`);
  const ctx = createContext({});
  // ruleid: js.code-injection
  const other = runIn(req.query.code as string, ctx);
  // ok: js.code-injection
  const safe = runIn('1 + 1', ctx);
  res.json({ value, s: script.runInThisContext(), other, safe });
});

// Next.js App Router route handlers.
export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.code-injection
  const fn = new Function('input', body.source);
  // ok: js.code-injection
  const parsed = JSON.parse(body.payload);
  return Response.json({ out: fn(parsed) });
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ expr: string }> }) {
  const { expr } = await params;
  // ruleid: js.code-injection
  const value = vm.runInNewContext(expr);
  const q = request.nextUrl.searchParams.get('q') ?? '';
  // ruleid: js.code-injection
  const other = eval(q);
  // ok: js.code-injection
  const fixed = vm.runInNewContext('q.length', { q });
  return Response.json({ value, other, fixed });
}

// A helper with a request-like parameter that is not a route handler.
export function evaluate(request: { code: string }) {
  // ok: js.code-injection
  return eval(request.code);
}

export default app;
