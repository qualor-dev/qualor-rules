const express = require('express');
const fs = require('fs');
const fsp = require('node:fs/promises');
const { readFileSync, createReadStream, unlink } = require('node:fs');
const path = require('path');

const app = express();
app.use(express.json());

const UPLOADS = path.join(__dirname, 'uploads');

// express.static serves a fixed directory: no path from the request reaches the file system.
// ok: js.path-traversal
app.use('/assets', express.static(path.join(__dirname, 'public')));

// res.sendFile and res.download without the root option: the path is used as given.
app.get('/files/:name', (req, res) => {
  // ruleid: js.path-traversal
  res.sendFile(path.join(UPLOADS, req.params.name));
});

app.get('/download', (req, res) => {
  const file = req.query.file;
  // ruleid: js.path-traversal
  res.download('/srv/reports/' + file);
  // ruleid: js.path-traversal
  res.download(`/srv/reports/${req.query.file}`, 'report.pdf');
});

// With the root option Express checks that the path resolves inside root.
app.get('/docs/:name', (req, res, next) => {
  // ok: js.path-traversal
  res.sendFile(req.params.name, { root: UPLOADS, dotfiles: 'deny' });
  // ok: js.path-traversal
  res.download(req.params.name, 'doc.pdf', { root: path.join(__dirname, 'docs') });
});

app.get('/manuals/:name', (req, res, next) => {
  const options = {
    root: path.join(__dirname, 'manuals'),
    dotfiles: 'deny',
  };
  const fileName = req.params.name;
  // ok: js.path-traversal
  res.sendFile(fileName, options, (err) => {
    if (err) next(err);
  });
});

const SEND_OPTIONS = { root: path.join(__dirname, 'shared'), maxAge: '1d' };
app.get('/shared/:name', (req, res) => {
  // ok: js.path-traversal
  res.sendFile(req.params.name, SEND_OPTIONS);
});

// A root option taken from the request is not checked: any root counts as safe.
app.get('/themes/:name', (req, res) => {
  // todoruleid: js.path-traversal
  res.sendFile('index.html', { root: req.query.theme });
});

// The fs functions: reading, writing, streaming, listing and deleting.
app.get('/read', (req, res) => {
  // ruleid: js.path-traversal
  const text = fs.readFileSync(path.join(UPLOADS, req.query.name), 'utf8');
  // ruleid: js.path-traversal
  createReadStream(path.resolve(UPLOADS, req.query.name)).pipe(res);
  // ruleid: js.path-traversal
  const head = readFileSync(UPLOADS + '/' + req.get('X-File'));
  res.send({ text, head });
});

app.post('/notes', async (req, res) => {
  const { title, body } = req.body;
  const target = path.join(__dirname, 'notes', title + '.txt');
  // ruleid: js.path-traversal
  await fsp.writeFile(target, body);
  // ok: js.path-traversal
  await fsp.writeFile(path.join(__dirname, 'notes', 'latest.txt'), body);
  // ruleid: js.path-traversal
  fs.appendFile(path.join(__dirname, 'logs', req.cookies.log), body, () => {});
  res.status(201).end();
});

app.delete('/uploads/:name', (req, res) => {
  // ruleid: js.path-traversal
  unlink(path.join(UPLOADS, req.params.name), () => res.end());
  // ruleid: js.path-traversal
  fs.promises.rm(path.join(UPLOADS, req.params.name), { force: true });
});

app.get('/list', async (req, res) => {
  // ruleid: js.path-traversal
  const entries = await fsp.readdir(path.join(UPLOADS, req.query.dir));
  // ok: js.path-traversal
  const all = await fsp.readdir(UPLOADS);
  res.json({ entries, all });
});

// Moving and copying: both paths are checked.
app.post('/move', (req, res) => {
  // ruleid: js.path-traversal
  fs.renameSync(path.join(UPLOADS, 'tmp.bin'), path.join(UPLOADS, req.body.to));
  // ruleid: js.path-traversal
  require('fs').copyFileSync(req.body.from, path.join(UPLOADS, 'copy.bin'));
  res.end();
});

// path.basename keeps only the last segment of the name: no directory can be named.
app.get('/avatars/:name', (req, res) => {
  const safeName = path.basename(req.params.name);
  // ok: js.path-traversal
  res.sendFile(path.join(UPLOADS, 'avatars', safeName));
  // ok: js.path-traversal
  fs.readFileSync(path.join(UPLOADS, path.basename(req.query.file)));
  res.end();
});

// Numbers and allow-list lookups yield no path segments.
const REPORTS = { monthly: 'monthly.pdf', yearly: 'yearly.pdf' };
const THEMES = new Map([['dark', 'dark.css'], ['light', 'light.css']]);
const LOCALES = Object.freeze({
  en: 'en.json', // the default
  /* German */ de: 'de.json',
});

app.get('/pick', (req, res) => {
  const page = Number.parseInt(req.query.page, 10);
  // ok: js.path-traversal
  fs.readFileSync(path.join(UPLOADS, 'page-' + page + '.html'));
  // ok: js.path-traversal
  res.download(path.join(__dirname, 'reports', REPORTS[req.query.kind] || 'monthly.pdf'));
  // ok: js.path-traversal
  fs.createReadStream(path.join(__dirname, 'themes', THEMES.get(req.query.theme) ?? 'light.css'));
  // ok: js.path-traversal
  fs.readFileSync(path.join(__dirname, 'locales', LOCALES[req.query.lang]));
  // A lookup with a fallback taken from the request is no allow-list.
  // ruleid: js.path-traversal
  res.download(path.join(__dirname, 'reports', REPORTS[req.query.kind] || req.query.file));
  // ruleid: js.path-traversal
  fs.readFileSync(path.join(__dirname, 'themes', THEMES.get(req.query.theme) ?? req.query.theme));
  const mode = req.query.mode === 'full' ? 'full.txt' : 'short.txt';
  // ok: js.path-traversal
  fs.readFileSync(path.join(__dirname, mode));
  res.end();
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const TITLES = { faq: 'it\'s-faq.html' };
const SECTIONS = { help: { intro: 'intro.html', faq: 'faq.html' } };

app.get('/sections', (req, res) => {
  // todook: js.path-traversal
  res.sendFile(path.join(__dirname, 'pages', TITLES[req.query.page] || 'index.html'));
  // todook: js.path-traversal
  res.sendFile(path.join(__dirname, 'pages', SECTIONS.help[req.query.page] || 'index.html'));
});

// Tables built from or filled with request data are no allow-lists.
const SAVED = { readme: 'README.md' };
app.post('/saved', (req, res) => {
  SAVED[req.body.key] = req.body.file;
  // ruleid: js.path-traversal
  res.sendFile(path.join(__dirname, SAVED[req.body.key]));
});

app.get('/parts', (req, res) => {
  const parts = [UPLOADS, req.query.name];
  // ruleid: js.path-traversal
  fs.readFileSync(parts.join('/'));
  const recent = [];
  recent.push(req.query.name);
  // ruleid: js.path-traversal
  fs.readFileSync(path.join(UPLOADS, recent[0]));
  res.end();
});

// A resolve-and-prefix check before the call is not recognised as a guard.
app.get('/checked', (req, res) => {
  const full = path.resolve(UPLOADS, req.query.name);
  if (!full.startsWith(UPLOADS + path.sep)) return res.sendStatus(403);
  // todook: js.path-traversal
  res.send(fs.readFileSync(full));
});

// A record looked up in a server-side store with a request value as the key carries the key's
// taint, and a ternary that returns the request value after an includes() check is no allow-list.
const sessions = new Map();
app.post('/avatar', (req, res) => {
  const user = sessions.get(req.cookies.session);
  // todook: js.path-traversal
  fs.writeFileSync(path.join(UPLOADS, user.id + '.png'), req.body.image);
  const ext = ['png', 'jpg'].includes(req.query.ext) ? req.query.ext : 'png';
  // todook: js.path-traversal
  fs.writeFileSync(path.join(UPLOADS, 'avatar.' + ext), req.body.image);
  res.end();
});

// Metadata calls (stat, access, exists, realpath) are not sinks: realpath is the documented way
// to canonicalise a path, and the others only tell whether a file exists.
app.get('/exists', (req, res) => {
  // todoruleid: js.path-traversal
  res.json({ exists: fs.existsSync(path.join(UPLOADS, req.query.name)) });
});

// fs-extra and other file libraries are not sinks.
const fse = require('fs-extra');
app.get('/extra', async (req, res) => {
  // todoruleid: js.path-traversal
  res.json(await fse.readJson(path.join(UPLOADS, req.query.name)));
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/raw', (request, out) => {
  // todoruleid: js.path-traversal
  out.send(fs.readFileSync(path.join(UPLOADS, request.query.name)));
});

const http = { get: (url, done) => done({ query: { name: url } }) };
http.get('/archive/latest', (result) => {
  // todook: js.path-traversal
  fs.readFileSync(path.join(UPLOADS, result.query.name));
});

// Look-alikes: readFile and sendFile of other objects, functions that are not handlers.
const cache = { readFile: (name) => name };
const mailer = { sendFile: (name) => name };

app.get('/other', (req, res) => {
  // ok: js.path-traversal
  cache.readFile(req.query.name);
  // ok: js.path-traversal
  mailer.sendFile(req.query.name);
  // ok: js.path-traversal
  res.send(path.join(UPLOADS, req.query.name));
});

function loadTemplate(req, opts) {
  // ok: js.path-traversal
  return fs.readFileSync(path.join(__dirname, 'templates', req.params.name), opts);
}

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.get('/exports/:name', async (request, reply) => {
  // ruleid: js.path-traversal
  const stream = fs.createReadStream(path.join(UPLOADS, request.params.name));
  return reply.type('application/octet-stream').send(stream);
});

fastify.post('/imports', async (request) => {
  // ruleid: js.path-traversal
  await fsp.writeFile(path.join(UPLOADS, request.body.name), request.body.content);
  // ok: js.path-traversal
  await fsp.writeFile(path.join(UPLOADS, 'import.json'), request.body.content);
  return {};
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/files/destructured/:name', ({ params: { name } }, res) => {
  // ruleid: js.path-traversal
  res.sendFile(path.join(UPLOADS, name));
  // ok: js.path-traversal
  res.sendFile(path.join(UPLOADS, path.basename(name)));
});
fastify.get('/files/destructured', async (request) => {
  const { query: { file: wanted } } = request;
  // ruleid: js.path-traversal
  return fs.readFileSync(path.join(UPLOADS, wanted), 'utf8');
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/files/defaults', ({ query = {} }, res) => {
  // todoruleid: js.path-traversal
  res.sendFile(path.join(UPLOADS, query.name));
});

module.exports = { app, fastify, loadTemplate };
