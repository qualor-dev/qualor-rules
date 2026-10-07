const express = require('express');
const http = require('node:http');
const { pickNext, targetFor: resolveTarget } = require('./next-targets');
const { beginSignIn, rememberTarget } = require('./sign-in');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const SITE = 'https://www.example.com';
const SITE_ROOT = 'https://www.example.com/';
const SITE_HOST = 'www.example.com';
const config = { siteUrl: process.env.SITE_URL };
const appUrl = process.env.APP_URL || 'https://app.example.com';
const scheme = 'https:';
const SCHEME = 'https:';

// The whole target from the request: query, body, route parameter, header, cookie.
app.get('/login', (req, res) => {
  // ruleid: js.open-redirect
  res.redirect(req.query.next);
});

app.post('/logout', (req, res) => {
  const target = req.body.returnTo;
  // ruleid: js.open-redirect
  res.redirect(303, target);
});

app.get('/go/:target', (req, res) => {
  // ruleid: js.open-redirect
  res.redirect(301, req.params.target);
});

// The Referer header is request data like any other header: a link from another site sends the
// browser back there. Express 5 documents `req.get('Referrer') || '/'` as the replacement of
// 'back'.
app.get('/back', (req, res) => {
  // ruleid: js.open-redirect
  res.redirect(req.get('Referrer') || '/');
});

app.get('/resume', (req, res) => {
  // ruleid: js.open-redirect
  res.redirect(req.cookies.returnTo);
});

// The Location header set directly.
app.get('/location', (req, res) => {
  // ruleid: js.open-redirect
  res.location(req.query.url);
  res.sendStatus(302);
});

app.get('/headers', (req, res) => {
  const to = req.query.to;
  if (req.query.mode === 'set') {
    // ruleid: js.open-redirect
    res.set('Location', to);
  } else if (req.query.mode === 'header') {
    // ruleid: js.open-redirect
    res.header('location', to);
  } else if (req.query.mode === 'append') {
    // ruleid: js.open-redirect
    res.append('Location', to);
  } else if (req.query.mode === 'object') {
    // ruleid: js.open-redirect
    res.set({ Location: to, 'Cache-Control': 'no-store' });
  } else {
    // ruleid: js.open-redirect
    res.status(302).location(to);
  }
  res.status(302).end();
});

// Request data that sets the scheme or the host: at the start, after a scheme alone, or after an
// origin without a path separator (`@evil.example` then names the host).
app.get('/tenants/:tenant', (req, res) => {
  if (req.query.a) {
    // ruleid: js.open-redirect
    return res.redirect('https://' + req.query.host + '/home');
  }
  if (req.query.b) {
    // ruleid: js.open-redirect
    return res.redirect(`https://${req.params.tenant}.example.com/`);
  }
  if (req.query.c) {
    // ruleid: js.open-redirect
    return res.redirect(SITE + req.query.path);
  }
  if (req.query.d) {
    // ruleid: js.open-redirect
    return res.redirect(`${req.query.base}/home`);
  }
  if (req.query.e) {
    // ruleid: js.open-redirect
    return res.redirect(config.siteUrl + req.query.path);
  }
  if (req.query.f) {
    // ruleid: js.open-redirect
    return res.redirect(req.query.base + '/users/' + req.params.tenant);
  }
  // ruleid: js.open-redirect
  return res.redirect('https://' + SITE_HOST + req.query.path);
});

// A single "/" before request data: "//evil.example" and "/\evil.example" name another host.
app.get('/slash', (req, res) => {
  if (req.query.a) {
    // ruleid: js.open-redirect
    return res.redirect('/' + req.query.path);
  }
  if (req.query.b) {
    // ruleid: js.open-redirect
    return res.redirect(`/${req.query.path}`);
  }
  const dest = '/' + req.body.path;
  // ruleid: js.open-redirect
  return res.redirect(dest);
});

// A scheme-only constant is no base: the slashes after it and the next part name the host.
app.get('/schemes', (req, res) => {
  if (req.query.a) {
    const lower = scheme + '//' + req.query.host + '/home';
    // ruleid: js.open-redirect
    return res.redirect(lower);
  }
  if (req.query.b) {
    // ruleid: js.open-redirect
    return res.redirect(`${SCHEME}//${req.query.host}/home`);
  }
  // ruleid: js.open-redirect
  return res.redirect(scheme + '//' + req.query.host);
});

// Constants, and paths or URLs that start with a fixed origin and a path separator.
app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  switch (req.query.v) {
    case '1':
      // ok: js.open-redirect
      return res.redirect('/');
    case '2':
      // ok: js.open-redirect
      return res.redirect(301, 'https://www.example.com/welcome');
    case '3':
      // ok: js.open-redirect
      return res.redirect('/users/' + id);
    case '4':
      // ok: js.open-redirect
      return res.redirect(`/users/${id}/posts?page=${req.query.page}`);
    case '5':
      // ok: js.open-redirect
      return res.redirect(SITE + '/users/' + id);
    case '6':
      // ok: js.open-redirect
      return res.redirect(SITE_ROOT + id);
    case '7':
      // ok: js.open-redirect
      return res.redirect(`${SITE}/search?q=${req.query.q}`);
    case '8':
      // ok: js.open-redirect
      return res.redirect(config.siteUrl + '/users/' + id);
    case '9':
      // ok: js.open-redirect
      return res.redirect(appUrl + '/users/' + id);
    case '10':
      // ok: js.open-redirect
      return res.redirect('/search?q=' + req.query.q);
    case '11':
      // ok: js.open-redirect
      return res.redirect('?page=' + req.query.page);
    case '12':
      // ok: js.open-redirect
      return res.redirect('posts/' + req.query.slug);
    case '13':
      // ok: js.open-redirect
      return res.redirect('/users/' + Number(req.query.other));
    case '14':
      // ok: js.open-redirect
      return res.redirect(encodeURIComponent(req.query.slug));
    case '15':
      // ok: js.open-redirect
      return res.redirect(`${SITE}#${req.query.tab}`);
    default:
      // Express 4 sends 'back' to the Referer, the same target as the Referer line above; the
      // literal is not followed.
      // todoruleid: js.open-redirect
      return res.redirect('back');
  }
});

// The same fixed starts built in a variable first, and set as a header.
app.get('/accounts/:id', (req, res) => {
  const id = req.params.id;
  const accountUrl = 'https://www.example.com/accounts/' + id;
  const postsUrl = `${SITE}/accounts/${id}/posts`;
  const envUrl = process.env.SITE_URL + '/accounts/' + id;
  const baseUrl = appUrl + '/accounts/' + id;
  if (req.query.a) {
    // ok: js.open-redirect
    return res.redirect(accountUrl);
  }
  if (req.query.b) {
    // ok: js.open-redirect
    return res.redirect(postsUrl);
  }
  if (req.query.c) {
    // ok: js.open-redirect
    return res.redirect(envUrl);
  }
  if (req.query.d) {
    // ok: js.open-redirect
    res.location(baseUrl);
    return res.sendStatus(302);
  }
  // ok: js.open-redirect
  res.set('Location', '/accounts/' + id);
  // ok: js.open-redirect
  res.set('X-Requested-Next', req.query.next);
  // ok: js.open-redirect
  res.cookie('next', req.query.next);
  return res.sendStatus(302);
});

// A base taken from the request is no fixed origin.
app.get('/members/:id', (req, res) => {
  const site = req.query.site;
  const memberUrl = site + '/members/' + req.params.id;
  // ruleid: js.open-redirect
  res.redirect(memberUrl);
});

// Two slashes after a base are taken for a new host even when the base has one.
app.get('/doubled', (req, res) => {
  const doubled = appUrl + '//' + req.query.path;
  // todook: js.open-redirect
  res.redirect(doubled);
});

// A module base redeclared with request data in a nested block is no longer trusted in that
// function.
const portal = 'https://portal.example.com';
app.get('/portal/:id', (req, res) => {
  if (req.query.preview) {
    const portal = req.query.preview;
    const previewUrl = portal + '/items/' + req.params.id;
    // ruleid: js.open-redirect
    return res.redirect(previewUrl);
  }
  const itemUrl = portal + '/items/' + req.params.id;
  // todook: js.open-redirect
  return res.redirect(itemUrl);
});

// new URL(path, base): an absolute or protocol-relative path replaces the base.
app.get('/files', (req, res) => {
  if (req.query.a) {
    // ruleid: js.open-redirect
    return res.redirect(new URL(req.query.path, SITE).href);
  }
  if (req.query.b) {
    // ok: js.open-redirect
    return res.redirect(new URL('/files/' + req.query.name, SITE).href);
  }
  if (req.query.c) {
    const relative = new URL('/files/list', req.query.base);
    // ruleid: js.open-redirect
    return res.redirect(relative.toString());
  }
  const listing = new URL('https://www.example.com/files');
  listing.searchParams.set('q', req.query.q);
  // ok: js.open-redirect
  return res.redirect(listing.href);
});

// Allow-list lookups in literal tables yield only the table's values.
const DESTINATIONS = { home: '/', profile: '/me', docs: 'https://docs.example.com/' };
const PARTNERS = new Map([
  ['a', 'https://a.example.com/'],
  ['b', 'https://b.example.com/'],
]);

app.get('/to/:name', (req, res) => {
  if (req.query.a) {
    // ok: js.open-redirect
    return res.redirect(DESTINATIONS[req.params.name] || '/');
  }
  if (req.query.b) {
    // ok: js.open-redirect
    return res.redirect(PARTNERS.get(req.query.partner) ?? '/');
  }
  if (req.query.c) {
    const dest = req.query.lang === 'de' ? '/de/' : '/en/';
    // ok: js.open-redirect
    return res.redirect(dest);
  }
  if (req.query.d) {
    // A lookup with a fallback taken from the request is no allow-list.
    // ruleid: js.open-redirect
    return res.redirect(DESTINATIONS[req.params.name] || req.query.next);
  }
  // ruleid: js.open-redirect
  return res.redirect(PARTNERS.get(req.query.partner) ?? req.query.fallback);
});

const SECTIONS = Object.freeze({
  // the account pages
  account: '/account',
  /* billing lives on its own host */ billing: 'https://billing.example.com/',
});
app.get('/section', (req, res) => {
  // ok: js.open-redirect
  res.redirect(SECTIONS[req.query.section] ?? '/');
});

// Tables built from or filled with request data are no allow-lists.
const RETURNS = { home: '/' };
const HOPS = new Map([['a', '/a']]);
app.post('/returns', (req, res) => {
  RETURNS[req.body.key] = req.body.url;
  if (req.body.now) {
    // ruleid: js.open-redirect
    return res.redirect(RETURNS[req.body.key]);
  }
  if (req.body.hop) {
    HOPS.set(req.body.key, req.body.url);
    // ruleid: js.open-redirect
    return res.redirect(HOPS.get(req.body.key));
  }
  const queue = [req.body.first];
  // ruleid: js.open-redirect
  return res.redirect(queue[0]);
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const NAMED = { faq: '/it\'s/faq' };
const AREAS = { eu: { home: '/eu/' } };
app.get('/named', (req, res) => {
  if (req.query.a) {
    // todook: js.open-redirect
    return res.redirect(NAMED[req.query.page] || '/');
  }
  // todook: js.open-redirect
  return res.redirect(AREAS.eu[req.query.page] || '/');
});

// Data loaded or made by a service with a request value as its key is not request data; a promise
// helper returns what it is given.
const links = { findBySlug: async (slug) => ({ url: 'https://www.example.com/' + slug }) };
const sso = { signInUrl: async (provider, returnTo) => `https://idp.example.com/${provider}?state=${returnTo}` };
const normalizer = { clean: async (value) => value, format: async (value) => value };
app.get('/l/:slug', async (req, res) => {
  const link = await links.findBySlug(req.params.slug);
  if (req.query.a) {
    // ok: js.open-redirect
    return res.redirect(link.url);
  }
  if (req.query.b) {
    const url = await sso.signInUrl(req.params.slug, req.query.returnTo);
    // ok: js.open-redirect
    return res.redirect(url);
  }
  if (req.query.c) {
    const echoed = await Promise.resolve(req.query.next);
    // ruleid: js.open-redirect
    return res.redirect(echoed);
  }
  if (req.query.d) {
    // A formatter returns what it is given.
    const formatted = await normalizer.format(req.query.next);
    // ruleid: js.open-redirect
    return res.redirect(formatted);
  }
  // A method that returns the request value it is given is not followed.
  const cleaned = await normalizer.clean(req.query.next);
  // todoruleid: js.open-redirect
  return res.redirect(cleaned);
});

// Functions imported by name are not other objects' methods: their results stay request data.
// An awaited helper that is given the response writes its own answer, so its result is clean.
app.get('/next', async (req, res) => {
  if (req.query.a) {
    // ruleid: js.open-redirect
    return res.redirect(await pickNext(req.query.next));
  }
  if (req.query.b) {
    const target = await resolveTarget(req.query.next);
    // ruleid: js.open-redirect
    return res.redirect(target);
  }
  if (req.query.c) {
    const signIn = await beginSignIn(req.query.provider, req.query.returnTo, res);
    // ok: js.open-redirect
    return res.redirect(signIn);
  }
  // A helper given the response that returns the request value is not followed.
  const echoed = await rememberTarget(req.query.next, res);
  // todoruleid: js.open-redirect
  return res.redirect(echoed);
});

// An awaited sink is still a sink.
app.get('/await-sink', async (req, res) => {
  // ruleid: js.open-redirect
  await res.redirect(req.query.url);
});

// A sink inside a callback given to a helper that also takes the response is still a sink.
const { withSession, afterUpload, runStep } = require('./session');
app.get('/session-next', async (req, res) => {
  if (req.query.a) {
    await withSession(req, res, async () => {
      // ruleid: js.open-redirect
      res.redirect(req.query.next);
    });
  }
  if (req.query.b) {
    await afterUpload(req, res, function () {
      // ruleid: js.open-redirect
      res.redirect(req.body.next);
    });
  }
  if (req.query.c) {
    // ruleid: js.open-redirect
    await withSession(req, res, () => res.redirect(req.query.c));
  }
  if (req.query.d) {
    await runStep(res, {
      done: function () {
        // ruleid: js.open-redirect
        res.redirect(req.query.d);
      },
    });
  }
  await runStep(res, {
    done() {
      // ruleid: js.open-redirect
      res.redirect(req.query.step);
    },
  });
});

// A sink inside a callback given to an awaited method of another object is still a sink.
const txdb = { transaction: async (work) => work({}) };
const jobQueue = { run: async (r, jobs) => jobs.map((job) => job()) };
app.post('/tx-next', async (req, res) => {
  if (req.query.a) {
    await txdb.transaction(async (t) => {
      // ruleid: js.open-redirect
      res.redirect(req.body.next);
    });
  }
  if (req.query.b) {
    // ruleid: js.open-redirect
    await jobQueue.run(res, [() => res.redirect(req.body.then)]);
  }
  await txdb.transaction({
    done() {
      // ruleid: js.open-redirect
      res.redirect(req.query.step);
    },
  });
});

// The value of an awaited call that is given a callback stays stored data, and so does a lookup
// awaited inside the callback.
const pageCache = { wrap: async (key, build) => build() };
const Items = { find: (query) => ({ sort: async (compare) => [] }) };
app.get('/cached/:key', async (req, res) => {
  if (req.query.a) {
    const page = await pageCache.wrap(req.params.key, async () => '/home');
    // ok: js.open-redirect
    return res.redirect(page);
  }
  if (req.query.b) {
    const rows = await Items.find({ q: req.query.q }).sort((a, b) => a.n - b.n);
    // ok: js.open-redirect
    return res.redirect(rows[0].url);
  }
  if (req.query.c) {
    return txdb.transaction(async (t) => {
      const user = await t.users.findOne({ id: req.params.key });
      // ok: js.open-redirect
      res.redirect(user.home);
    });
  }
  const target = await runStep(res, req.query.step, () => '/done');
  // ok: js.open-redirect
  return res.redirect(target);
});

// A function called through a module object counts as another object's method.
const helpers = require('./redirect-helpers');
app.get('/module-next', async (req, res) => {
  const target = await helpers.nextTarget(req.query.next);
  // todoruleid: js.open-redirect
  return res.redirect(target);
});

// Location headers built from templates.
app.get('/header-templates/:host', (req, res) => {
  if (req.query.a) {
    // ruleid: js.open-redirect
    return res.setHeader('Location', `https://${req.query.host}/home`).end();
  }
  if (req.query.b) {
    // ruleid: js.open-redirect
    return res.set('Location', `//${req.params.host}`).end();
  }
  if (req.query.c) {
    // ruleid: js.open-redirect
    return res.writeHead(302, { Location: `https://${req.query.host}/` }).end();
  }
  // ok: js.open-redirect
  res.setHeader('Location', `/users/${req.query.id}`);
  return res.end();
});

// Checks before the call are not followed: the checked value is still reported, also a check in
// the argument itself.
app.get('/included', (req, res) => {
  // todook: js.open-redirect
  res.redirect(['/a', '/b'].includes(req.query.to) ? req.query.to : '/');
});

// encodeURIComponent() is clean also where its value becomes the host.
app.get('/encoded-host', (req, res) => {
  // todoruleid: js.open-redirect
  res.redirect('https://' + encodeURIComponent(req.query.host) + '/home');
});

app.get('/checked', (req, res) => {
  const next = String(req.query.next || '/');
  if (next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\')) {
    // todook: js.open-redirect
    return res.redirect(next);
  }
  return res.redirect('/');
});

app.get('/checked-host', (req, res) => {
  try {
    if (new URL(req.query.url).host !== 'www.example.com') {
      return res.status(400).end('Unsupported redirect');
    }
  } catch (e) {
    return res.status(400).end('Invalid url');
  }
  // todook: js.open-redirect
  res.redirect(req.query.url);
});

// The Host header is request data here, so a redirect to the host the browser asked for is
// reported.
app.use((req, res, next) => {
  if (req.secure) return next();
  // todook: js.open-redirect
  return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
});

// A scheme and a constant host followed by another constant without a separator hide the part
// after them.
app.get('/port', (req, res) => {
  // todoruleid: js.open-redirect
  res.redirect('https://' + SITE_HOST + ':' + req.query.port + '/home');
});

// Concatenations of more than six parts are not split.
app.get('/long', (req, res) => {
  // todoruleid: js.open-redirect
  res.redirect(req.query.host + '/a/' + 'b/' + 'c/' + 'd/' + 'e/' + 'f');
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/continue', (request, out) => {
  // todoruleid: js.open-redirect
  out.redirect(request.query.next);
});

const router = { get: (path, done) => done({ query: { next: path } }) };
router.get('/archive/latest', (result) => {
  // todook: js.open-redirect
  return Response.redirect(result.query.next);
});

// Look-alikes: redirect() and location() of other objects, Location on an outgoing request, and
// functions that are not handlers.
const nav = { redirect: (to) => to, location: (to) => to };
app.get('/look-alikes', async (req, res) => {
  // ok: js.open-redirect
  nav.redirect(req.query.next);
  // ok: js.open-redirect
  nav.location(req.query.next);
  // ok: js.open-redirect
  const outgoing = new Headers({ Location: req.query.next });
  res.json({ outgoing: [...outgoing.keys()] });
});

function audit(req, log) {
  // ok: js.open-redirect
  log.redirect(req.query.next);
}

// Node http and the Next.js Pages Router: (req, res) handlers.
http
  .createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/out') {
      // ruleid: js.open-redirect
      res.writeHead(302, { Location: url.searchParams.get('to') });
      return res.end();
    }
    if (url.pathname === '/out2') {
      // ruleid: js.open-redirect
      res.setHeader('Location', url.searchParams.get('to'));
      res.statusCode = 302;
      return res.end();
    }
    // ok: js.open-redirect
    res.writeHead(302, { Location: '/items/' + url.searchParams.get('id') });
    return res.end();
  })
  .listen(0);

function pagesHandler(req, res) {
  if (req.method === 'POST') {
    // ruleid: js.open-redirect
    return res.redirect(307, req.body.next);
  }
  // ok: js.open-redirect
  return res.redirect(307, '/');
}

// Fastify: reply.redirect(url[, code]) and the Location header.
const fastify = require('fastify')();

fastify.get('/fastify/login', async (request, reply) => {
  // ruleid: js.open-redirect
  return reply.redirect(request.query.next);
});

fastify.get('/fastify/go/:target', async (request, reply) => {
  // ruleid: js.open-redirect
  return reply.redirect(request.params.target, 301);
});

fastify.post('/fastify/form', async (request, reply) => {
  // ruleid: js.open-redirect
  return reply.code(302).header('Location', request.body.returnTo).send();
});

fastify.post('/fastify/headers', async (request, reply) => {
  // ruleid: js.open-redirect
  reply.headers({ location: request.body.returnTo });
  return reply.code(302).send();
});

fastify.get('/fastify/items/:id', async (request, reply) => {
  // ok: js.open-redirect
  return reply.redirect('/items/' + request.params.id, 301);
});

// Awaited sinks, and a sign-in helper given the reply that returns the identity provider's URL.
fastify.get('/fastify/awaited', async (request, reply) => {
  if (request.query.a) {
    // ruleid: js.open-redirect
    return await reply.redirect(request.query.url);
  }
  if (request.query.b) {
    // ruleid: js.open-redirect
    return await reply.code(302).header('location', request.query.to).send();
  }
  const url = await beginSignIn(request.query.provider, request.query.returnTo, reply);
  // ok: js.open-redirect
  return await reply.code(302).header('location', url).send();
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/login/destructured', ({ query }, res) => {
  // ruleid: js.open-redirect
  res.redirect(query.next);
});
app.get('/logout/destructured', (req, res) => {
  const { query: { returnTo: back } } = req;
  // ruleid: js.open-redirect
  res.redirect(back);
  // ok: js.open-redirect
  res.redirect('/');
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/login/defaults', ({ query = {} }, res) => {
  // todoruleid: js.open-redirect
  res.redirect(query.next);
});

module.exports = { app, fastify, audit, pagesHandler };
