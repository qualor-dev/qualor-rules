const express = require('express');
const axios = require('axios');
const got = require('got');
const http = require('node:http');
const https = require('https');
const undici = require('undici');
const { request } = require('undici');

const app = express();
app.use(express.json());

const API_BASE = 'https://api.example.com';
const API_ROOT = 'https://api.example.com/v2/';
const API_HOST = 'api.example.com';
const config = { apiBase: process.env.API_BASE_URL };
const baseUrl = process.env.API_URL || 'https://api.example.com';
const scheme = 'https:';
const SCHEME = 'https:';
const SITE = 'https://www.example.com';

// The whole URL from the request.
app.get('/proxy', async (req, res) => {
  // ruleid: js.ssrf
  const r = await fetch(req.query.url);
  const target = req.body.callback;
  // ruleid: js.ssrf
  await axios.get(target);
  // ruleid: js.ssrf
  await axios.post(req.body.webhook, { ok: true });
  // ruleid: js.ssrf
  await got(req.query.feed);
  // ruleid: js.ssrf
  http.get(req.query.url, (resp) => resp.resume());
  // ruleid: js.ssrf
  await undici.request(req.get('X-Upstream'));
  // ruleid: js.ssrf
  await request(req.cookies.endpoint);
  // ruleid: js.ssrf
  await axios({ method: 'get', url: req.body.url });
  res.send(await r.text());
});

// Request data that sets the scheme or the host: at the start of the string, after a scheme
// alone, or after an origin without a path separator (`@evil.example` then names the host).
app.get('/tenants/:tenant', async (req, res) => {
  // ruleid: js.ssrf
  await fetch('https://' + req.query.host + '/status');
  // ruleid: js.ssrf
  await fetch(`https://${req.params.tenant}.example.com/api`);
  // ruleid: js.ssrf
  await fetch(`${req.query.base}/health`);
  // ruleid: js.ssrf
  await fetch(API_BASE + req.params.tenant);
  // ruleid: js.ssrf
  await got.get('https://api.example.com' + req.query.path);
  // ruleid: js.ssrf
  await axios.get(config.apiBase + req.query.path);
  // ruleid: js.ssrf
  await fetch(req.query.base + '/users/' + req.params.tenant);
  // ruleid: js.ssrf
  https.request({ hostname: req.query.host, path: '/status' }).end();
  res.end();
});

// A constant origin that ends with a path separator, then request data: only the path changes.
app.get('/users/:id', async (req, res) => {
  const id = req.params.id;
  // ok: js.ssrf
  await fetch('https://api.example.com/users/' + id);
  // ok: js.ssrf
  await fetch(`https://api.example.com/users/${id}?full=${req.query.full}`);
  // ok: js.ssrf
  await fetch(API_BASE + '/users/' + id);
  // ok: js.ssrf
  await fetch(API_ROOT + id);
  // ok: js.ssrf
  await fetch(`${API_BASE}/users/${id}`);
  // ok: js.ssrf
  await axios.get(process.env.API_BASE_URL + '/users/' + id);
  // ok: js.ssrf
  await axios.get(config.apiBase + '/users/' + id + '/posts');
  // ok: js.ssrf
  await axios.get('https://api.example.com/search', { params: { q: req.query.q } });
  // ok: js.ssrf
  http.get({ hostname: 'internal.example.com', path: '/users/' + id }, (resp) => resp.resume());
  // ok: js.ssrf
  await fetch('http://localhost:' + Number(req.query.port) + '/health');
  res.end();
});

// A lower-case base declared const from the environment with a literal default.
app.get('/members/:id', async (req, res) => {
  // ok: js.ssrf
  await fetch(baseUrl + '/members/' + req.params.id);
  const memberUrl = baseUrl + '/members/' + req.params.id;
  // ok: js.ssrf
  await fetch(memberUrl);
  const groupsUrl = `${baseUrl}/members/${req.params.id}/groups`;
  // ok: js.ssrf
  await fetch(groupsUrl);
  // ruleid: js.ssrf
  await fetch(baseUrl + req.query.path);
  const joinedUrl = baseUrl + req.query.path;
  // ruleid: js.ssrf
  await fetch(joinedUrl);
  const base = req.query.base;
  const fromRequest = base + '/members/' + req.params.id;
  // ruleid: js.ssrf
  await fetch(fromRequest);
  res.end();
});

// A scheme-only constant is no base: slashes (also '/\\' or a single '/') and the next part
// still name the host.
app.get('/schemes', async (req, res) => {
  const lower = scheme + '//' + req.query.host + '/status';
  // ruleid: js.ssrf
  await fetch(lower);
  const upper = SCHEME + '//' + req.query.host + '/status';
  // ruleid: js.ssrf
  await fetch(upper);
  // ruleid: js.ssrf
  await fetch(scheme + '//' + req.query.host + '/status');
  const templated = `${scheme}//${req.query.host}/status`;
  // ruleid: js.ssrf
  await fetch(templated);
  // ruleid: js.ssrf
  await fetch(`${SCHEME}//${req.query.host}/status`);
  const backslash = scheme + '/\\' + req.query.host;
  // ruleid: js.ssrf
  await fetch(backslash);
  const single = SCHEME + '/' + req.query.host;
  // ruleid: js.ssrf
  await fetch(single);
  const lowerSingle = scheme + '/' + req.query.host;
  // ruleid: js.ssrf
  await fetch(lowerSingle);
  // A base from the environment may be a scheme alone: '//' after it is no separator.
  const fromEnv = process.env.API_PROTOCOL + '//' + req.query.host + '/status';
  // ruleid: js.ssrf
  await fetch(fromEnv);
  res.end();
});

// A base with a host followed by '?', '#' or '/' and a path: the host has ended.
app.get('/site', async (req, res) => {
  const query = SITE + '?q=' + req.query.q;
  // ok: js.ssrf
  await fetch(query);
  const fragment = baseUrl + '#' + req.query.q;
  // ok: js.ssrf
  await fetch(fragment);
  const page = `${SITE}/pages/${req.query.page}`;
  // ok: js.ssrf
  await fetch(page);
  // Two slashes after a base are taken for a new host even when the base has one.
  const doubled = baseUrl + '//' + req.query.path;
  // todook: js.ssrf
  await fetch(doubled);
  res.end();
});

// A module base redeclared with request data in a nested block is no longer trusted anywhere.
const portal = 'https://portal.example.com';
app.get('/portal/:id', async (req, res) => {
  if (req.query.preview) {
    const portal = req.query.preview;
    const previewUrl = portal + '/items/' + req.params.id;
    // ruleid: js.ssrf
    await fetch(previewUrl);
  }
  const itemUrl = portal + '/items/' + req.params.id;
  // todook: js.ssrf
  await fetch(itemUrl);
  res.end();
});

// The same URLs built in a variable before the call.
app.get('/accounts/:id', async (req, res) => {
  const id = req.params.id;
  const accountUrl = 'https://api.example.com/accounts/' + id;
  // ok: js.ssrf
  await fetch(accountUrl);
  const postsUrl = `${API_BASE}/accounts/${id}/posts`;
  // ok: js.ssrf
  await fetch(postsUrl);
  const envUrl = process.env.API_BASE_URL + '/accounts/' + id;
  // ok: js.ssrf
  await axios.get(envUrl);
  const cfgUrl = `${config.apiBase}/accounts/${id}`;
  // ok: js.ssrf
  await got(cfgUrl);
  const constUrl = API_BASE + '/accounts/' + id;
  // ok: js.ssrf
  await got(constUrl);
  const hostUrl = 'https://' + req.query.host + '/status';
  // ruleid: js.ssrf
  await fetch(hostUrl);
  const baseUrl = `${req.query.base}/health`;
  // ruleid: js.ssrf
  await fetch(baseUrl);
  const joined = API_BASE + id;
  // ruleid: js.ssrf
  await fetch(joined);
  const tenantUrl = `https://${req.query.tenant}.example.com/`;
  // ruleid: js.ssrf
  await axios.get(tenantUrl);
  res.end();
});

// new URL(path, base): an absolute or protocol-relative path replaces the base.
app.get('/files', async (req, res) => {
  // ruleid: js.ssrf
  await fetch(new URL(req.query.path, API_BASE));
  const remote = new URL(req.query.url);
  // ruleid: js.ssrf
  await fetch(remote);
  // ok: js.ssrf
  await fetch(new URL('/files/' + req.query.name, API_BASE));
  // ok: js.ssrf
  await fetch(new URL(`/files/${req.query.name}`, API_BASE));
  const search = new URL('https://api.example.com/search');
  search.searchParams.set('q', req.query.q);
  // ok: js.ssrf
  await fetch(search);
  // A relative URL object takes its host from the base, here from the request.
  const relative = new URL('/api/data', req.query.base);
  // ruleid: js.ssrf
  await fetch(relative);
  // An absolute URL ignores its base.
  const absolute = new URL('https://api.example.com/data', req.query.base);
  // ok: js.ssrf
  await fetch(absolute);
  res.end();
});

// Clients with a fixed base URL: a relative path stays on that host, an absolute URL does not.
const client = axios.create({ baseURL: 'https://api.example.com/v1/' });
const github = got.extend({ prefixUrl: 'https://api.github.com' });

app.get('/repos/:owner/:repo', async (req, res) => {
  // ok: js.ssrf
  await client.get('/repos/' + req.params.owner + '/' + req.params.repo);
  // ok: js.ssrf
  await client.get(`/users/${req.params.owner}`);
  // ok: js.ssrf
  await github.get('repos/' + req.params.owner + '/' + req.params.repo);
  // ruleid: js.ssrf
  await client.get(req.query.next);
  // ruleid: js.ssrf
  await github(req.query.next);
  res.end();
});

// Allow-list lookups in literal tables yield only the table's values.
const SERVICES = { users: 'https://users.internal/', billing: 'https://billing.internal/' };
const MIRRORS = new Map([['eu', 'https://eu.example.com/'], ['us', 'https://us.example.com/']]);

app.get('/services/:name', async (req, res) => {
  // ok: js.ssrf
  await fetch(SERVICES[req.params.name] || SERVICES.users);
  // ok: js.ssrf
  await fetch(MIRRORS.get(req.query.region) + 'status');
  const scheme = req.query.secure === 'no' ? 'http://' : 'https://';
  // ok: js.ssrf
  await fetch(scheme + 'api.example.com/status');
  // A lookup with a fallback taken from the request is no allow-list.
  // ruleid: js.ssrf
  await fetch(SERVICES[req.params.name] || req.query.url);
  // ruleid: js.ssrf
  await fetch(MIRRORS.get(req.query.region) ?? req.query.mirror);
  res.end();
});

// Tables built from or filled with request data are no allow-lists.
const HOOKS = { audit: 'https://audit.internal/' };
app.post('/hooks', async (req, res) => {
  HOOKS[req.body.name] = req.body.url;
  // ruleid: js.ssrf
  await axios.post(HOOKS[req.body.name], req.body);
  const urls = [req.body.primary];
  // ruleid: js.ssrf
  await fetch(urls[0]);
  res.end();
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const NAMED = { docs: 'https://docs.example.com/it\'s/' };
const REGIONS = { eu: { api: 'https://eu.example.com/' } };
app.get('/named', async (req, res) => {
  // todook: js.ssrf
  await fetch(NAMED[req.query.site] || 'https://example.com/');
  // todook: js.ssrf
  await fetch(REGIONS.eu[req.query.kind] || 'https://example.com/');
  res.end();
});

// An allow-list check on the parsed host before the call is not recognised as a guard.
const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com']);
app.get('/image', async (req, res) => {
  const url = new URL(req.query.src);
  if (!ALLOWED_HOSTS.has(url.hostname)) return res.sendStatus(400);
  // todook: js.ssrf
  res.send(await (await fetch(url)).arrayBuffer());
});

// Two interpolations at the start of a template: the second sets the host unless the first is a
// constant origin that ends with a path separator.
// A scheme, then a constant host without a path separator: the next part still sets the host.
app.get('/scheme-host', async (req, res) => {
  // ruleid: js.ssrf
  await fetch('https://' + API_HOST + req.query.path);
  // ruleid: js.ssrf
  await fetch(`https://${API_HOST}${req.query.path}`);
  // ok: js.ssrf
  await fetch('https://' + API_HOST + '/items/' + req.query.id);
  // ok: js.ssrf
  await fetch(`https://${API_HOST}/items/${req.query.id}`);
  res.end();
});

app.get('/v2/:id', async (req, res) => {
  // ok: js.ssrf
  await fetch(`${API_ROOT}${req.params.id}`);
  // ruleid: js.ssrf
  await fetch(`${API_BASE}${req.params.id}`);
  res.end();
});

// A base taken from the request decides the host of a relative path.
app.get('/relative', async (req, res) => {
  // ruleid: js.ssrf
  await fetch(new URL('/status/' + req.query.id, req.query.base));
  res.end();
});

// Constant text without a path separator after a constant origin: the next part still sets the
// host. Two such constants in a row hide it.
app.get('/sub', async (req, res) => {
  // ruleid: js.ssrf
  await fetch(API_BASE + '.' + req.query.suffix + '/status');
  // todoruleid: js.ssrf
  await fetch('https://' + API_HOST + ':' + req.query.port + '/status');
  res.end();
});

// Concatenations of more than six parts are not split.
app.get('/long', async (req, res) => {
  // todoruleid: js.ssrf
  await fetch(req.query.host + '/a/' + 'b/' + 'c/' + 'd/' + 'e/' + 'f');
  res.end();
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/fetch', async (request, out) => {
  // todoruleid: js.ssrf
  out.send(await (await fetch(request.query.url)).text());
});

const router = { get: (path, done) => done({ query: { url: path } }) };
router.get('/archive/latest', (result) => {
  // todook: js.ssrf
  fetch(result.query.url);
});

// Look-alikes: get() of maps and caches, functions that are not handlers.
const cache = new Map();
app.get('/cached', async (req, res) => {
  // ok: js.ssrf
  const hit = cache.get(req.query.url);
  // ok: js.ssrf
  res.json({ hit, again: app.get(req.query.setting) });
});

function download(req, opts) {
  // ok: js.ssrf
  return fetch(req.query.url, opts);
}

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.get('/preview', async (request, reply) => {
  // ruleid: js.ssrf
  const page = await fetch(request.query.url);
  return reply.type('text/plain').send(await page.text());
});

fastify.get('/mirror/:host', async (request) => {
  // ruleid: js.ssrf
  return (await fetch(`https://${request.params.host}/status`)).status;
});

fastify.post('/notify/:id', async (request) => {
  // ruleid: js.ssrf
  await axios.post(request.body.webhook, { id: request.params.id });
  // ok: js.ssrf
  await axios.post('https://notify.example.com/v1/' + request.params.id, request.body);
  return {};
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/proxy/destructured', async ({ query }, res) => {
  // ruleid: js.ssrf
  const r = await fetch(query.url);
  res.send(await r.text());
});
fastify.post('/proxy/destructured', async (request) => {
  const { body: { target: where } } = request;
  // ruleid: js.ssrf
  return (await axios.get(where)).data;
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/proxy/defaults', async ({ query = {} }, res) => {
  // todoruleid: js.ssrf
  res.send(await (await fetch(query.url)).text());
});

module.exports = { app, fastify, download };
