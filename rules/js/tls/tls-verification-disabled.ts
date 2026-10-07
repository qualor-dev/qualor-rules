import https from 'node:https';
import * as tls from 'tls';
import { Agent as HttpsAgent } from 'https';
import { connect as http2Connect } from 'node:http2';
import { Agent, ProxyAgent as Proxy, fetch as undiciFetch } from 'undici';
import * as undici from 'undici';
import axios, { AxiosInstance } from 'axios';
import WebSocket from 'ws';
import { Pool, PoolConfig } from 'pg';
import got from 'got';
import { MongoClient, MongoClientOptions } from 'mongodb';

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

// Other libraries, with ES module imports and typed option objects.
export async function otherTyped(url: string) {
  // ruleid: js.tls-verification-disabled
  const config: PoolConfig = { host: 'db.internal', ssl: { rejectUnauthorized: false } };
  const pool = new Pool(config);
  // ruleid: js.tls-verification-disabled
  const feed = new WebSocket('wss://feed.internal', { rejectUnauthorized: false });
  // ruleid: js.tls-verification-disabled
  const page = await got.get(url, { https: { rejectUnauthorized: false } });
  // ruleid: js.tls-verification-disabled
  const options: MongoClientOptions = { tlsAllowInvalidCertificates: true };
  const mongo = new MongoClient('mongodb://db.internal:27017', options);
  // ok: js.tls-verification-disabled
  const safe = new Pool({ ssl: { ca: process.env.CA_PEM } });
  return [pool, feed, page, mongo, safe];
}
