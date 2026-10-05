import express, { Request, Response } from 'express';
import { NextRequest } from 'next/server';

const app = express();
const preferences: Record<string, Record<string, unknown>> = {};

// TypeScript: typed Express handlers.
app.patch('/ts/preferences/:group', (req: Request, res: Response) => {
  const group = req.params.group;
  // ruleid: js.prototype-pollution
  preferences[group][req.body.name as string] = req.body.value;
  // ok: js.prototype-pollution
  preferences.defaults[req.body.name as string] = req.body.value;
  res.json(preferences);
});

// Next.js App Router route handlers.
export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.prototype-pollution
  preferences[body.group][body.name] = body.value;
  const safe: Record<string, Record<string, unknown>> = Object.create(null);
  // ok: js.prototype-pollution
  safe[body.group][body.name] = body.value;
  return Response.json(preferences);
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ group: string }> }) {
  const { group } = await params;
  const name = request.nextUrl.searchParams.get('name') ?? 'x';
  // ruleid: js.prototype-pollution
  preferences[group][name] = true;
  return Response.json(preferences);
}

// A helper with a request-like parameter that is not a route handler.
export function apply(request: { group: string; name: string }) {
  // ok: js.prototype-pollution
  preferences[request.group][request.name] = true;
}

export default app;
