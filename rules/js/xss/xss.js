const express = require('express');
const http = require('node:http');
const escapeHtml = require('escape-html');
const he = require('he');
const validator = require('validator');
const sanitizeHtml = require('sanitize-html');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const app = express();
app.use(express.json());
const purify = createDOMPurify(new JSDOM('').window);

// res.send() of a string answers with Content-Type text/html.
app.get('/hello', (req, res) => {
  // ruleid: js.xss
  res.send('Hello ' + req.query.name);
});

app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  // ruleid: js.xss
  res.status(404).send(`<p>No user ${id}</p>`);
});

app.post('/comments', (req, res) => {
  const { author, text } = req.body;
  const html = '<li><b>' + author + '</b>: ' + text + '</li>';
  // ruleid: js.xss
  res.send(html);
  // ok: js.xss
  res.send('<li><b>' + escapeHtml(author) + '</b>: ' + escapeHtml(text) + '</li>');
});

app.get('/search', (req, res) => {
  // ruleid: js.xss
  res.send(`<h1>Results for ${req.get('X-Search')}</h1>`);
  // ruleid: js.xss
  res.send(req.cookies.banner);
  // ok: js.xss
  res.send('<h1>Results for ' + he.encode(req.query.q) + '</h1>');
  // ok: js.xss
  res.send('<h1>Results for ' + validator.escape(req.query.q) + '</h1>');
  // ok: js.xss
  res.send(sanitizeHtml(req.query.bio));
  // ok: js.xss
  res.send(purify.sanitize(req.query.bio));
});

// HTML set explicitly as the content type.
app.get('/page', (req, res) => {
  // ruleid: js.xss
  res.type('html').send(req.query.body);
  // ruleid: js.xss
  res.status(200).type('text/html').send('<div>' + req.query.body + '</div>');
});

// Node http and Express responses written with res.write()/res.end(): HTML when the content type
// says so, or when the text is visibly HTML.
app.get('/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  // ruleid: js.xss
  res.write('<p>' + req.query.msg + '</p>');
  // ruleid: js.xss
  res.end(req.query.footer);
});

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const name = url.searchParams.get('name');
  res.writeHead(200, { 'Content-Type': 'text/html' });
  // ruleid: js.xss
  res.end(`<h1>Hello ${name}</h1>`);
});

http.createServer((req, res) => {
  // ruleid: js.xss
  res.end('<p>You asked for ' + req.url + '</p>');
  // ok: js.xss
  res.end(JSON.stringify({ path: req.url }));
});

// JSON responses, other content types, numbers and constants are not HTML.
app.get('/api/users/:id', (req, res) => {
  // ok: js.xss
  res.json({ id: req.params.id, q: req.query.q });
  // ok: js.xss
  res.send({ id: req.params.id });
  // ok: js.xss
  res.send([req.query.a, req.query.b]);
  // ok: js.xss
  res.jsonp({ name: req.query.name });
  // ok: js.xss
  res.send('Created item ' + Number(req.params.id));
  // ok: js.xss
  res.send('<p>Saved</p>');
});

app.get('/plain', (req, res) => {
  res.type('text/plain');
  // ok: js.xss
  res.send('You searched for ' + req.query.q);
});

app.get('/csv', (req, res) => {
  res.set('Content-Type', 'text/csv');
  // ok: js.xss
  res.send(req.query.column + ',total\n');
});

app.get('/text', (req, res) => {
  // ok: js.xss
  res.type('txt').send(req.query.q);
  // ok: js.xss
  res.status(400).type('json').send(JSON.stringify({ error: req.query.q }));
});

// res.render() passes the data to an autoescaping template engine.
app.get('/profile/:name', (req, res) => {
  // ok: js.xss
  res.render('profile', { name: req.params.name, bio: req.query.bio });
});

// A whole parsed request object is sent as JSON.
app.post('/echo', (req, res) => {
  // ok: js.xss
  res.send(req.body);
});

// Values that Express sends as JSON or as bytes: objects and arrays held in a variable, Buffers,
// and booleans.
app.post('/echo-json', (req, res) => {
  const out = { echo: req.body.text, at: Date.now() };
  // ok: js.xss
  res.send(out);
  const list = [req.query.a, req.query.b];
  // ok: js.xss
  res.status(200).send(list);
});

// An object variable that is later given an HTML string is still taken for JSON.
app.get('/reassigned', (req, res) => {
  let body = { ok: true };
  body = '<p>' + req.query.msg + '</p>';
  // todoruleid: js.xss
  res.send(body);
});

app.get('/bytes', (req, res) => {
  // ok: js.xss
  res.send(Buffer.from(req.query.data, 'base64'));
  // ok: js.xss
  res.send(req.query.flag === 'yes');
  // ok: js.xss
  res.send(!req.query.flag);
});

// Data loaded with the request value as a key is not request data.
const users = { findById: async (id) => ({ id, name: 'Ann' }) };
app.get('/accounts/:id', async (req, res) => {
  const user = await users.findById(req.params.id);
  // ok: js.xss
  res.send(user);
});

// Allow-list lookups in literal tables yield only the table's values.
const GREETINGS = { en: 'Hello', de: 'Hallo' };
app.get('/greet', (req, res) => {
  // ok: js.xss
  res.send('<p>' + (GREETINGS[req.query.lang] || 'Hello') + '</p>');
  // A lookup with a fallback taken from the request is no allow-list.
  // ruleid: js.xss
  res.send('<p>' + (GREETINGS[req.query.lang] || req.query.lang) + '</p>');
});

// Tables built from or filled with request data are no allow-lists.
app.get('/labels', (req, res) => {
  const labels = { title: req.query.title };
  // ruleid: js.xss
  res.send('<h1>' + labels['title'] + '</h1>');
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const QUOTES = { motto: 'it\'s fine' };
const NESTED = { en: { title: 'Welcome' } };
app.get('/motto', (req, res) => {
  // todook: js.xss
  res.send('<p>' + (QUOTES[req.query.key] || '') + '</p>');
  // todook: js.xss
  res.send('<p>' + (NESTED.en[req.query.key] || '') + '</p>');
});

// A content type set through an object of headers is not seen.
app.get('/headers', (req, res) => {
  res.set({ 'Content-Type': 'text/plain' });
  // todook: js.xss
  res.send(req.query.q);
});

// A response without a content type written with res.end() is HTML only if it looks like HTML.
app.get('/raw', (req, res) => {
  // todoruleid: js.xss
  res.end(req.query.page);
});

// Awaited functions, renderers and promise helpers given request data return request data.
const render = async (title) => `<h1>${title}</h1>`;
const { marked } = require('marked');
const i18n = { translate: async (text, values) => text + values.name };
app.get('/rendered', async (req, res) => {
  const page = await render(req.query.title);
  // ruleid: js.xss
  res.send(page);
  // ruleid: js.xss
  res.send(await marked.parse(req.query.md));
  const echoed = await Promise.resolve(req.query.v);
  // ruleid: js.xss
  res.send('<p>' + echoed + '</p>');
  const msg = await i18n.translate('Hello ', { name: req.query.name });
  // ruleid: js.xss
  res.send('<p>' + msg + '</p>');
});

// An awaited method of another object (a service, model or client) loads data: the request value
// is only its key. A method of such an object that returns the request value is missed.
const store = { echo: async (value) => value };
app.get('/echoed', async (req, res) => {
  // todoruleid: js.xss
  res.send(await store.echo(req.query.v));
});

// Functions imported by name are not other objects' methods: their results stay request data.
// An awaited helper that is given the response writes its own answer, so its result is clean.
const { decorate, framePage: frame } = require('./page-helpers');
const { loadCard, echoCard } = require('./cards');
app.get('/decorated/:id', async (req, res) => {
  if (req.query.a) {
    // ruleid: js.xss
    return res.send(await decorate(req.query.title));
  }
  if (req.query.b) {
    const framed = await frame(req.query.body);
    // ruleid: js.xss
    return res.send(framed);
  }
  if (req.query.c) {
    const card = await loadCard(req.params.id, res);
    // ok: js.xss
    return res.send(card);
  }
  // A helper given the response that returns the request value is not followed.
  const echoed = await echoCard(req.query.title, res);
  // todoruleid: js.xss
  return res.send('<p>' + echoed + '</p>');
});

// A sink inside a callback given to a helper that also takes the response is still a sink.
const { withSession, afterUpload, runStep } = require('./session');
app.get('/session-page', async (req, res) => {
  if (req.query.a) {
    await withSession(req, res, async () => {
      // ruleid: js.xss
      res.send('<h1>' + req.query.name + '</h1>');
    });
  }
  if (req.query.b) {
    await afterUpload(req, res, function () {
      // ruleid: js.xss
      res.send('<p>' + req.body.title + '</p>');
    });
  }
  if (req.query.c) {
    // ruleid: js.xss
    await withSession(req, res, () => res.send('<p>' + req.query.c + '</p>'));
  }
  if (req.query.d) {
    await runStep(res, {
      done: function () {
        // ruleid: js.xss
        res.send('<p>' + req.query.d + '</p>');
      },
    });
  }
  await runStep(res, {
    done() {
      // ruleid: js.xss
      res.send(`<p>${req.query.step}</p>`);
    },
  });
});

// A sink inside a callback given to an awaited method of another object is still a sink.
const txdb = { transaction: async (work) => work({}) };
const jobQueue = { run: async (r, jobs) => jobs.map((job) => job()) };
app.post('/tx-page', async (req, res) => {
  if (req.query.a) {
    await txdb.transaction(async (t) => {
      // ruleid: js.xss
      res.send('<p>Saved ' + req.body.title + '</p>');
    });
  }
  if (req.query.b) {
    // ruleid: js.xss
    await jobQueue.run(res, [() => res.send('<i>' + req.body.c + '</i>')]);
  }
  await txdb.transaction({
    done() {
      // ruleid: js.xss
      res.send(`<b>${req.query.step}</b>`);
    },
  });
});

// The value of an awaited call that is given a callback stays stored data, and so does a lookup
// awaited inside the callback.
const pageCache = { wrap: async (key, build) => build() };
const Items = { find: (query) => ({ sort: async (compare) => [] }) };
app.get('/cached/:key', async (req, res) => {
  const page = await pageCache.wrap(req.params.key, async () => '<p>built</p>');
  // ok: js.xss
  res.send(page);
  const rows = await Items.find({ q: req.query.q }).sort((a, b) => a.n - b.n);
  // ok: js.xss
  res.send('<ul>' + rows.join('') + '</ul>');
  await txdb.transaction(async (t) => {
    const user = await t.users.findOne({ id: req.params.key });
    // ok: js.xss
    res.send('<p>' + user.bio + '</p>');
  });
  const card = await runStep(res, req.query.step, () => 'done');
  // ok: js.xss
  res.send(card);
});

// An awaited sink is still a sink.
app.get('/await-send', async (req, res) => {
  if (req.query.a) {
    // ruleid: js.xss
    await res.send('<p>' + req.query.name + '</p>');
  }
  // ruleid: js.xss
  await res.status(200).send(`<h1>${req.query.title}</h1>`);
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/legacy', (request, out) => {
  // todoruleid: js.xss
  out.send('<p>' + request.query.msg + '</p>');
});

const client = { get: (path, done) => done({ query: { msg: path } }) };
client.get('/status', (result) => {
  // todook: js.xss
  return new Response('<p>' + result.query.msg + '</p>', { headers: { 'Content-Type': 'text/html' } });
});

// Look-alikes: send() of sockets and mailers, functions that are not handlers.
const socket = { send: (m) => m };
app.get('/notify', (req, res) => {
  // ok: js.xss
  socket.send('<p>' + req.query.msg + '</p>');
  res.end();
});

function reply(req, out) {
  // ok: js.xss
  out.send('<p>' + req.query.msg + '</p>');
}

// Fastify: plain strings are sent as text/plain; HTML when the reply says so.
const fastify = require('fastify')();

fastify.get('/fhello', async (request, reply) => {
  // ok: js.xss
  return reply.send('Hello ' + request.query.name);
});

fastify.get('/fpage/:slug', async (request, reply) => {
  // ruleid: js.xss
  return reply.type('text/html').send(`<h1>${request.params.slug}</h1>`);
});

fastify.post('/fpreview', async (request, reply) => {
  reply.header('content-type', 'text/html; charset=utf-8');
  // ruleid: js.xss
  return reply.send('<div>' + request.body.content + '</div>');
});

fastify.get('/fhtml', async (request, reply) => {
  reply.type('text/html');
  // ruleid: js.xss
  return `<p>${request.query.text}</p>`;
});

// A Fastify handler whose reply is named res is taken for an Express handler; Fastify sends the
// string as text/plain.
fastify.get('/fres', async (req, res) => {
  // todook: js.xss
  return res.send('Hello ' + req.query.name);
});

// Awaited sinks of the reply are still sinks.
fastify.get('/fawait/:slug', async (request, reply) => {
  // ruleid: js.xss
  return await reply.type('text/html').send(`<h1>${request.params.slug}</h1>`);
});

fastify.get('/fsafe', async (request, reply) => {
  // ok: js.xss
  return reply.type('text/html').send('<p>' + escapeHtml(request.query.text) + '</p>');
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/hello/destructured', ({ query }, res) => {
  // ruleid: js.xss
  res.send('Hello ' + query.name);
  // ok: js.xss
  res.send('Hello ' + escapeHtml(query.name));
});
app.get('/bye/destructured', (req, res) => {
  const { params: { name: who } } = req;
  // ruleid: js.xss
  res.send(`<p>Bye ${who}</p>`);
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/hello/defaults', ({ query = {} }, res) => {
  // todoruleid: js.xss
  res.send('Hello ' + query.name);
});

// The results of other rules' sinks. What exec()/execSync() print and what readFileSync() reads
// are not request data: request data in the command is js.command-injection's finding, a
// request-chosen file js.path-traversal's. A fixed program given request data as an argument may
// print it back, and a page fetched from a URL the request chooses is the attacker's content.
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const childProcess = require('node:child_process');
const { exec, execSync, execFile, execFileSync } = require('child_process');
const axios = require('axios');
const got = require('got');
const execAsync = util.promisify(childProcess.exec);
const PAGES = '/srv/pages';
const jobs = require('./job-queue');
const API_BASE = 'https://api.example.com';
const SCHEME = 'https:';
const pagesOrigin = 'https://pages.example.com';
const config = { pagesBase: process.env.PAGES_URL };
const linkTo = (href) => '<a href="' + href + '">' + href + '</a>';

app.get('/tools/ls', (req, res) => {
  // ok: js.xss
  exec('ls -l ' + req.query.dir, (err, stdout) => res.send('<pre>' + stdout + '</pre>'));
  // ruleid: js.xss
  exec('ls -l ' + req.query.dir, (err, stdout) => res.send('<pre>' + stdout + '</pre><p>' + req.query.dir + '</p>'));
});

app.get('/tools/cat', (req, res) => {
  const out = execSync('cat ' + req.query.file);
  // ok: js.xss
  res.send('<pre>' + out.toString() + '</pre>');
  // ok: js.xss
  res.send(childProcess.execSync(`du -sh ${req.query.dir}`).toString());
});

app.get('/tools/uptime', async (req, res) => {
  const { stdout } = await execAsync('uptime -p ' + req.query.flags);
  // ok: js.xss
  res.send('<p>' + stdout + '</p>');
});

app.get('/tools/echo', (req, res) => {
  // ruleid: js.xss
  res.send(execFileSync('echo', [req.query.msg]).toString());
  // A request-chosen program is js.command-injection's finding; its output is reported again.
  // todook: js.xss
  res.send(execFileSync(req.query.tool, ['--version']).toString());
  // The output execFile() hands to its callback, from the argument list: stdout and stderr, with
  // or without options, through the module object too.
  // ruleid: js.xss
  execFile('echo', [req.query.msg], (err, stdout) => res.send(stdout));
  childProcess.execFile('echo', ['-n', req.query.msg], { timeout: 1000 }, function (err, stdout) {
    // ruleid: js.xss
    res.send('<pre>' + stdout + '</pre>');
  });
  const lsArgs = ['-l', req.query.dir];
  execFile('ls', lsArgs, (err, stdout, stderr) => {
    // ruleid: js.xss
    res.send('<pre>' + stderr + '</pre>');
  });
  // A fixed program with constant arguments, a request-chosen program (js.command-injection's
  // finding), request data in the options only, and execFile() of another object.
  // ok: js.xss
  execFile('date', ['+%F'], (err, stdout) => res.send(stdout));
  // ok: js.xss
  execFile(req.query.tool, ['--version'], (err, stdout) => res.send(stdout));
  // ok: js.xss
  execFile('ls', { cwd: path.join(PAGES, req.query.dir) }, (err, stdout) => res.send(stdout));
  // ok: js.xss
  childProcess.execFile('ls', { cwd: path.join(PAGES, req.query.dir) }, (err, stdout) => res.send(stdout));
  // ok: js.xss
  jobs.execFile('echo', [req.query.msg], (err, out) => res.send(out));
  // ruleid: js.xss
  require('node:child_process').execFile('echo', [req.query.msg], (err, stdout) => res.send(stdout));
  require('child_process').execFile('echo', [req.query.msg], (err, stdout, stderr) => {
    // ruleid: js.xss
    res.send(stderr);
  });
  // ruleid: js.xss
  require('child_process').execFile('echo', [req.query.msg], { timeout: 500 }, (err, stdout) => res.send(stdout));
  // ruleid: js.xss
  require('child_process').execFile('echo', [req.query.msg], { timeout: 500 }, (err, stdout, stderr) => res.send(stderr));
  // ok: js.xss
  require('./job-queue').execFile('echo', [req.query.msg], (err, out) => res.send(out));
  // ok: js.xss
  require('node:child_process').execFile('ls', { cwd: path.join(PAGES, req.query.dir) }, (err, stdout) => res.send(stdout));
  // An options object held in a variable in the argument list's place is taken for arguments.
  const lsOptions = { cwd: path.join(PAGES, req.query.dir) };
  // todook: js.xss
  execFile('ls', lsOptions, (err, stdout) => res.send(stdout));
  // A callback passed by name, and the output streams of spawn(), are not followed.
  const sendOutput = (err, out) => res.send(out);
  // todoruleid: js.xss
  execFile('echo', [req.query.msg], sendOutput);
  const child = childProcess.spawn('echo', [req.query.msg]);
  // todoruleid: js.xss
  child.stdout.on('data', (chunk) => res.send(chunk));
});

app.get('/pages/:name', (req, res) => {
  // ok: js.xss
  res.send(fs.readFileSync(path.join(PAGES, req.params.name), 'utf8'));
  // ruleid: js.xss
  fs.readFile(path.join(PAGES, req.params.name), 'utf8', (err, page) => res.send(page + '<p>' + req.params.name + '</p>'));
});

app.get('/preview', async (req, res) => {
  const r = await fetch(req.query.url);
  // ruleid: js.xss
  res.send(await r.text());
  const { data } = await axios.get(req.query.url);
  // ruleid: js.xss
  res.send(data);
  const viaScheme = await fetch('https://' + req.query.host + '/status');
  // ruleid: js.xss
  res.send(await viaScheme.text());
  const fixed = await fetch('https://api.example.com/pages/' + encodeURIComponent(req.query.id));
  // ok: js.xss
  res.send(await fixed.text());
  const own = await fetch(`/pages/${req.query.id}`);
  // ok: js.xss
  res.send(await own.text());
  const { data: card } = await axios.get('https://api.example.com/cards/' + req.query.id);
  // ok: js.xss
  res.send(card);
  // Only a URL that visibly starts with request data keeps the page request data: a URL built
  // from a fixed origin in a variable, a constant URL with request data in the body, a template on
  // a constant base, and got's promise shortcut on a fixed origin are that service's data.
  const pageUrl = 'https://api.example.com/pages/' + req.query.id;
  const { data: stored } = await axios.get(pageUrl);
  // ok: js.xss
  res.send(stored);
  const { data: hook } = await axios.post(API_BASE + '/notify', { name: req.query.name });
  // ok: js.xss
  res.send(hook);
  const { data: item } = await axios.get(`${API_BASE}/items/${req.query.id}`);
  // ok: js.xss
  res.send(item);
  const shortcut = await got(`https://api.example.com/items/${req.query.id}`).json();
  // ok: js.xss
  res.send(shortcut);
  const hostPage = await axios.get(`https://${req.query.host}/status`);
  // ruleid: js.xss
  res.send(hostPage.data);
  // A request-chosen URL held in a variable first is not recognised.
  const target = req.query.url;
  const { data: chosen } = await axios.get(target);
  // todoruleid: js.xss
  res.send(chosen);
  // An origin held in a constant or a configuration value, given to fetch(), axios() or got()
  // itself, is fixed when a path, query or fragment separator follows it.
  const viaConstant = await fetch(API_BASE + '/pages/' + req.query.id);
  // ok: js.xss
  res.send(await viaConstant.text());
  const viaTemplate = await fetch(`${API_BASE}/pages/${req.query.id}`);
  // ok: js.xss
  res.send(await viaTemplate.text());
  const viaEnv = await fetch(process.env.PAGES_URL + '?id=' + req.query.id + '&v=' + req.query.v);
  // ok: js.xss
  res.send(await viaEnv.text());
  const { data: viaConfig } = await axios(config.pagesBase + '/pages/' + req.query.id + '?lang=' + req.query.lang + '&raw=1');
  // ok: js.xss
  res.send(viaConfig);
  const viaLocal = await fetch(pagesOrigin + '#' + req.query.id + '-top');
  // ok: js.xss
  res.send(await viaLocal.text());
  const viaConfigTemplate = await fetch(`${config.pagesBase}/pages/${req.query.id}`);
  // ok: js.xss
  res.send(await viaConfigTemplate.text());
  // Only the HTTP clients' own calls: another function given such a URL returns text with the
  // request value in it.
  // ruleid: js.xss
  res.send(linkTo(API_BASE + '/pages/' + req.query.id));
  // ruleid: js.xss
  res.send(linkTo(`${API_BASE}/pages/${req.query.id}`));
  // ruleid: js.xss
  res.send(linkTo(`${config.pagesBase}/pages/${req.query.id}`));
  // Without a separator after the origin, `@evil.example` names another host; after `//` or `/\`
  // the request value is the host; a constant that holds only a scheme fixes no host.
  const noSeparator = await fetch(API_BASE + req.query.path);
  // ruleid: js.xss
  res.send(await noSeparator.text());
  const noSeparatorTemplate = await fetch(`${API_BASE}${req.query.path}`);
  // ruleid: js.xss
  res.send(await noSeparatorTemplate.text());
  const doubleSlash = await fetch(API_BASE + '//' + req.query.host);
  // ruleid: js.xss
  res.send(await doubleSlash.text());
  const schemeOnly = await fetch(SCHEME + '/' + req.query.host + '/status');
  // ruleid: js.xss
  res.send(await schemeOnly.text());
  const schemeOnlyTemplate = await fetch(`${SCHEME}/${req.query.host}/status`);
  // ruleid: js.xss
  res.send(await schemeOnlyTemplate.text());
  const chosenBase = req.query.base;
  const viaChosen = await fetch(chosenBase + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaChosen.text());
  const viaChosenTemplate = await fetch(`${chosenBase}/pages/${req.query.id}`);
  // ruleid: js.xss
  res.send(await viaChosenTemplate.text());
  // Only the parts after the separator are cleaned: an origin that holds request data, under
  // any name, keeps the page request data.
  const BASE = req.query.base;
  const viaUpper = await fetch(BASE + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaUpper.text());
  const pageConfig = { base: req.query.base };
  const viaRequestConfig = await fetch(pageConfig.base + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaRequestConfig.text());
  const pageSettings = req.body;
  const viaRequestSettings = await fetch(`${pageSettings.base}/pages/${req.query.id}`);
  // ruleid: js.xss
  res.send(await viaRequestSettings.text());
  process.env.CMS_URL = req.query.cms;
  const viaRequestEnv = await fetch(process.env.CMS_URL + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaRequestEnv.text());
  // A request value as a fallback of the origin, or between the origin and the separator.
  const viaFallback = await fetch((req.query.base || API_BASE) + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaFallback.text());
  const viaSegment = await fetch(API_BASE + req.query.seg + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaSegment.text());
  const viaSegmentQuery = await fetch(API_BASE + req.query.seg + '?q=' + req.query.q);
  // ruleid: js.xss
  res.send(await viaSegmentQuery.text());
  // Request data sent to a fixed origin in the options does not make its answer request data.
  const posted = await fetch(API_BASE + '/pages/' + req.query.id, { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await posted.text());
  const postedTemplate = await fetch(`${API_BASE}/pages/${req.query.id}`, { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await postedTemplate.text());
  const postedConfig = await fetch(`${config.pagesBase}/pages/${req.query.id}`, { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await postedConfig.text());
  const longTemplate = await fetch(`${API_BASE}/pages/${req.query.id}?lang=${req.query.lang}&v=${req.query.v}`);
  // ok: js.xss
  res.send(await longTemplate.text());
  // Every length the rule cleans, with the options too, keeps an origin's request data.
  const upperRaw = await fetch(BASE + '/pages/' + req.query.id + '/raw');
  // ruleid: js.xss
  res.send(await upperRaw.text());
  const configQuery = await fetch(pageConfig.base + '?id=' + req.query.id + '&v=' + req.query.v);
  // ruleid: js.xss
  res.send(await configQuery.text());
  const envLong = await fetch(process.env.CMS_URL + '/p/' + req.query.id + '?v=' + req.query.v + '&raw=1');
  // ruleid: js.xss
  res.send(await envLong.text());
  const upperPosted = await fetch(BASE + '/pages/' + req.query.id, { method: 'POST' });
  // ruleid: js.xss
  res.send(await upperPosted.text());
  const settingsPosted = await fetch(`${pageSettings.base}/pages/${req.query.id}`, { method: 'POST' });
  // ruleid: js.xss
  res.send(await settingsPosted.text());
  // A base that is neither a configured origin by its name nor a literal with a host.
  const mirror = pickMirror();
  const viaMirror = await fetch(mirror + '/pages/' + req.query.id);
  // ruleid: js.xss
  res.send(await viaMirror.text());
  const postedRaw = await fetch(API_BASE + '/pages/' + req.query.id + '/raw', { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await postedRaw.text());
  const postedQuery = await fetch(API_BASE + '?id=' + req.query.id + '&v=' + req.query.v, { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await postedQuery.text());
  const postedLong = await fetch(API_BASE + '/p/' + req.query.id + '?v=' + req.query.v + '&raw=1', { method: 'POST', body: req.body.text });
  // ok: js.xss
  res.send(await postedLong.text());
  const configTwo = await fetch(`${config.pagesBase}/pages/${req.query.id}?v=${req.query.v}`);
  // ok: js.xss
  res.send(await configTwo.text());
  const configThree = await fetch(`${config.pagesBase}/pages/${req.query.id}?lang=${req.query.lang}&v=${req.query.v}`);
  // ok: js.xss
  res.send(await configThree.text());
  const literalTwo = await fetch(`${API_BASE}/pages/${req.query.id}?v=${req.query.v}`);
  // ok: js.xss
  res.send(await literalTwo.text());
  // More than three interpolations, or more than four parts, after the origin are not cleaned.
  const longerTemplate = await fetch(`${API_BASE}/pages/${req.query.id}/${req.query.rev}?lang=${req.query.lang}&v=${req.query.v}`);
  // todook: js.xss
  res.send(await longerTemplate.text());
  const longerConcat = await fetch(API_BASE + '/pages/' + req.query.id + '/' + req.query.rev + '?v=' + req.query.v);
  // todook: js.xss
  res.send(await longerConcat.text());
  // The options of a call to a fixed origin are cleaned as a whole, and a client default set from
  // the request is not seen: a request-chosen proxy or a response transform that returns request
  // data is missed.
  const viaProxy = await fetch(API_BASE + '/pages/' + req.query.id, { dispatcher: makeProxy(req.query.proxy) });
  // todoruleid: js.xss
  res.send(await viaProxy.text());
  const { data: transformed } = await axios(API_BASE + '/pages/' + req.query.id, { transformResponse: [() => req.query.html] });
  // todoruleid: js.xss
  res.send(transformed);
  axios.defaults.proxy = { host: req.query.proxyHost, port: 8080 };
  const { data: viaDefaults } = await axios(API_BASE + '/pages/' + req.query.id);
  // todoruleid: js.xss
  res.send(viaDefaults);
});

// An origin set from the request outside a handler (a constructor given the request) is not
// request data there, so it is taken for a configured origin.
class PageClient {
  constructor(req) {
    this.base = req.query.base;
  }

  async show(req, res) {
    const page = await fetch(this.base + '/pages/' + req.params.id);
    // todoruleid: js.xss
    res.send(await page.text());
  }
}
app.get('/client/:id', (req, res) => new PageClient(req).show(req, res));

// The request-chosen URL is recognised by the names of the request value: under another name
// (a handler parameter, a renamed or nested destructured field) the page is taken for stored data.
app.get('/preview/named', async (r, res) => {
  const { data } = await axios.get(r.query.url);
  // todoruleid: js.xss
  res.send(data);
});
app.get('/preview/renamed', async ({ query: q, params: { site } }, res) => {
  const { data } = await axios.get(q.url);
  // todoruleid: js.xss
  res.send(data);
  const { data: home } = await axios.get(site);
  // todoruleid: js.xss
  res.send(home);
});

module.exports = { app, server, fastify, reply };
