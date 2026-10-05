import express, { Request, Response } from 'express';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import * as fs from 'fs';
import nodeFs from 'node:fs';
import path from 'node:path';
import { basename, join } from 'node:path';
import { readFileSync as load } from 'fs';
import type { NextRequest } from 'next/server';

const app = express();
const ROOT = path.join(process.cwd(), 'storage');

// TypeScript: typed Express handlers and ES module imports of fs and fs/promises.
app.get('/storage/:name', async (req: Request, res: Response) => {
  // ruleid: js.path-traversal
  const data = await readFile(join(ROOT, req.params.name));
  // ruleid: js.path-traversal
  fs.unlinkSync(path.join(ROOT, String(req.query.old)));
  // ruleid: js.path-traversal
  nodeFs.mkdirSync(path.join(ROOT, req.body.folder), { recursive: true });
  // ruleid: js.path-traversal
  res.sendFile(path.resolve(ROOT, req.params.name));
  // ok: js.path-traversal
  res.sendFile(req.params.name, { root: ROOT });
  // ok: js.path-traversal
  await readFile(join(ROOT, basename(req.params.name)));
  res.end(data);
});

// A renamed import of an fs function.
app.get('/legacy/:name', (req: Request, res: Response) => {
  // ruleid: js.path-traversal
  res.send(load(path.join(ROOT, req.params.name)));
});

// Next.js App Router route handlers.
export async function GET(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  // ruleid: js.path-traversal
  const page = await readFile(path.join(ROOT, 'pages', slug + '.md'), 'utf8');
  const dir = request.nextUrl.searchParams.get('dir') ?? '';
  // ruleid: js.path-traversal
  const files = await readdir(path.join(ROOT, dir));
  // ok: js.path-traversal
  const index = await readdir(path.join(ROOT, 'pages'));
  return Response.json({ page, files, index });
}

export async function POST(request: NextRequest) {
  const form = await request.formData();
  const name = form.get('name') as string;
  // ruleid: js.path-traversal
  await writeFile(path.join(ROOT, name), 'draft');
  // ok: js.path-traversal
  await writeFile(path.join(ROOT, path.basename(name)), 'draft');
  const kinds: Record<string, string> = { note: 'notes.txt', todo: 'todo.txt' };
  // ok: js.path-traversal
  await writeFile(path.join(ROOT, kinds[name] ?? 'misc.txt'), 'draft');
  return Response.json({});
}

// A helper with a request-like parameter that is not a route handler.
export function readStored(request: { file: string }) {
  // ok: js.path-traversal
  return fs.readFileSync(path.join(ROOT, request.file));
}

export default app;
