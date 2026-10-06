import express, { Request, Response } from 'express';
import { exec, spawn } from 'node:child_process';
import * as cp from 'child_process';
import childProcess from 'node:child_process';
import { promisify } from 'node:util';
import { execSync as sh } from 'child_process';
import type { NextRequest } from 'next/server';

const app = express();
const run = promisify(exec);

// TypeScript: typed Express handlers and ES module imports of node:child_process.
app.get('/logs/:service', async (req: Request, res: Response) => {
  // ruleid: js.command-injection
  exec(`journalctl -u ${req.params.service}`);
  // ruleid: js.command-injection
  cp.execSync('systemctl status ' + req.params.service);
  // ruleid: js.command-injection
  childProcess.exec('logrotate ' + req.query.conf);
  // ruleid: js.command-injection
  await run('journalctl -n ' + req.query.lines);
  // ok: js.command-injection
  spawn('journalctl', ['-u', req.params.service]);
  // ok: js.command-injection
  await run('uptime');
  res.end();
});

// A renamed import is not followed.
app.get('/disk/:mount', (req: Request, res: Response) => {
  // todoruleid: js.command-injection
  sh('df -h ' + req.params.mount);
  res.end();
});

// Next.js App Router route handlers.
export async function POST(request: NextRequest) {
  const body = await request.json();
  // ruleid: js.command-injection
  exec('ffmpeg -i ' + body.source + ' out.mp4');
  // ok: js.command-injection
  spawn('ffmpeg', ['-i', body.source, 'out.mp4']);
  const codecs: Record<string, string> = { video: 'libx264', audio: 'aac' };
  const codec = codecs[body.kind] ?? 'copy';
  // ok: js.command-injection
  exec('ffmpeg -i in.mov -c ' + codec + ' out.mp4');
  // A typed table with a request-data fallback is no allow-list.
  // ruleid: js.command-injection
  exec('ffmpeg -i in.mov -c ' + (codecs[body.kind] ?? body.codec) + ' out.mp4');
  // ruleid: js.command-injection
  cp.spawn('cmd.exe', ['/c', 'dir ' + body.folder]);
  const presets = { small: '640x360', large: '1920x1080' } as const;
  // ok: js.command-injection
  exec('ffmpeg -i in.mov -s ' + presets[body.size as keyof typeof presets] + ' out.mp4');
  return Response.json({});
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ host: string }> }) {
  const { host } = await params;
  // ruleid: js.command-injection
  cp.exec(`nslookup ${host}`);
  const domain = request.nextUrl.searchParams.get('domain');
  // ruleid: js.command-injection
  cp.spawnSync('whois', [domain], { shell: true });
  // ok: js.command-injection
  cp.spawnSync('whois', [domain]);
  return Response.json({});
}

// A helper with a request-like parameter that is not a route handler.
export function restart(request: { service: string }) {
  // ok: js.command-injection
  cp.execSync('systemctl restart ' + request.service);
}

export default app;
