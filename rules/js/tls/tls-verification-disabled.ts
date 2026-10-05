import https from 'node:https';
import * as tls from 'tls';
import { Agent as HttpsAgent } from 'https';
import { connect as http2Connect } from 'node:http2';
import { Agent, ProxyAgent as Proxy, fetch as undiciFetch } from 'undici';
import * as undici from 'undici';
import axios, { AxiosInstance } from 'axios';

// TypeScript: typed option objects, ES module imports (default, namespace, named and renamed).
export function typedClient(url: string): https.Agent {
  // ruleid: js.tls-verification-disabled
  const options: https.RequestOptions = { hostname: 'reports.internal', rejectUnauthorized: false };
  https.request(options).end();
  // ruleid: js.tls-verification-disabled
  return new HttpsAgent({ keepAlive: true, rejectUnauthorized: false });
}

export function typedSocket(host: string): tls.TLSSocket {
  // ruleid: js.tls-verification-disabled
  const options: tls.ConnectionOptions = { host, port: 443, rejectUnauthorized: false };
  return tls.connect(options);
}

export function grpc(authority: string) {
  // ruleid: js.tls-verification-disabled
  return http2Connect(authority, { rejectUnauthorized: false });
}

export const client: AxiosInstance = axios.create({
  // ruleid: js.tls-verification-disabled
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

export async function viaUndici(url: string) {
  // ruleid: js.tls-verification-disabled
  const dispatcher = new Agent({ connect: { rejectUnauthorized: false } });
  // ruleid: js.tls-verification-disabled
  const proxy = new Proxy({ uri: 'http://proxy.internal:3128', requestTls: { rejectUnauthorized: false } });
  // ruleid: js.tls-verification-disabled
  const pool = new undici.Pool(url, { connect: { rejectUnauthorized: false } });
  // ok: js.tls-verification-disabled
  const safe = new Agent({ connect: { ca: process.env.CA_PEM } });
  // undici's Agent (https's Agent is imported here as HttpsAgent): a top-level option of a
  // dispatcher is not a TLS option.
  // ok: js.tls-verification-disabled
  const top = new Agent({ keepAliveTimeout: 10, rejectUnauthorized: false });
  return undiciFetch(url, { dispatcher: safe }).then(() => [dispatcher, proxy, pool, top]);
}

export function safeTyped(url: string, verify: boolean) {
  // ok: js.tls-verification-disabled
  const options: https.RequestOptions = { hostname: 'reports.internal', rejectUnauthorized: true };
  // ok: js.tls-verification-disabled
  const socket = tls.connect({ host: 'db.internal', port: 443, rejectUnauthorized: verify });
  // ok: js.tls-verification-disabled
  const server = tls.createServer({ requestCert: true, rejectUnauthorized: false });
  return [https.get(url, options), socket, server];
}
