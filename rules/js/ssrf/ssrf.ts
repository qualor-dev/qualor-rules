import express, { Request, Response } from 'express';
import axios from 'axios';
import got from 'got';
import * as https from 'node:https';
import { get } from 'node:http';
import { fetch as undiciFetch } from 'undici';
import type { NextRequest } from 'next/server';

const app = express();
const STATUS_API = 'https://status.example.com/api/';
const api = axios.create({ baseURL: STATUS_API });
const statusBase: string = process.env.STATUS_URL ?? 'https://status.example.com';

// TypeScript: typed Express handlers and ES module imports of the clients.
app.get('/check/:service', async (req: Request, res: Response) => {
  const target = String(req.query.target);
  // ruleid: js.ssrf
  await axios.head(target);
  // ruleid: js.ssrf
  await got.post(req.body.url, { json: { ping: true } });
  // ruleid: js.ssrf
  https.get(`https://${req.params.service}/health`, (r) => r.resume());
  // ruleid: js.ssrf
  get({ host: req.params.service, port: 8080, path: '/health' }, (r) => r.resume());
  // ruleid: js.ssrf
  await undiciFetch(req.body.url);
  // ok: js.ssrf
  await axios.head(STATUS_API + 'services/' + req.params.service);
  // ok: js.ssrf
  await api.get(`/services/${req.params.service}`);
  // ok: js.ssrf
  await got.get(`${STATUS_API}services/${req.params.service}`);
  const serviceUrl = `${statusBase}/services/${req.params.service}`;
  // ok: js.ssrf
  await got.get(serviceUrl);
  res.end();
});

// Next.js App Router route handlers.
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const source = request.nextUrl.searchParams.get('source') ?? '';
  // ruleid: js.ssrf
  const feed = await fetch(source);
  // ok: js.ssrf
  const item = await fetch(`https://cms.example.com/items/${id}`);
  // ruleid: js.ssrf
  await fetch('https://' + id + '.cms.example.com/items');
  return Response.json({ feed: await feed.text(), item: await item.json() });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.ssrf
  await fetch(body.callbackUrl, { method: 'POST', body: '{}' });
  // ok: js.ssrf
  await fetch('https://hooks.example.com/incoming/' + encodeURIComponent(body.channel));
  const hosts: Record<string, string> = { a: 'https://a.example.com/', b: 'https://b.example.com/' };
  // ok: js.ssrf
  await fetch(hosts[body.host] ?? 'https://a.example.com/');
  return Response.json({});
}

// A helper with a request-like parameter that is not a route handler.
export async function ping(request: { url: string }) {
  // ok: js.ssrf
  return fetch(request.url);
}

export default app;
