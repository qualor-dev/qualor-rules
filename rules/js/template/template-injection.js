const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const _ = require('lodash');
const template = require('lodash.template');
const { compile: compilePug } = require('pug');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const env = new nunjucks.Environment(new nunjucks.FileSystemLoader('views'));
const configured = nunjucks.configure('views', { autoescape: true });
const hbs = Handlebars.create();

// Request data as the template source: EJS, Pug, Handlebars, Nunjucks, lodash.
app.get('/preview', (req, res) => {
  // ruleid: js.template-injection
  res.send(ejs.render(req.query.tpl, { user: 'guest' }));
});

app.post('/emails/:id', (req, res) => {
  const body = req.body.template;
  // ruleid: js.template-injection
  const fn = ejs.compile(body, { async: false });
  // ruleid: js.template-injection
  const html = pug.render('p Hello ' + req.body.greeting);
  // ruleid: js.template-injection
  const card = pug.compile(`h1 ${req.params.id}`);
  // ruleid: js.template-injection
  const client = pug.compileClient(body);
  // ruleid: js.template-injection
  const own = compilePug(req.body.layout);
  res.json({ a: fn({}), html, card: card({}), client, own: own({}) });
});

app.post('/hbs', (req, res) => {
  const source = req.body.source;
  // ruleid: js.template-injection
  const view = Handlebars.compile(source);
  // ruleid: js.template-injection
  const spec = Handlebars.precompile(req.body.source);
  // ruleid: js.template-injection
  const other = hbs.compile(req.get('X-Template'));
  res.json({ out: view({}), spec, other: other({}) });
});

app.get('/njk', (req, res) => {
  // ruleid: js.template-injection
  const a = nunjucks.renderString(req.query.tpl, { name: 'x' });
  // ruleid: js.template-injection
  const b = env.renderString(req.cookies.layout, {});
  // ruleid: js.template-injection
  const c = new nunjucks.Template(req.query.tpl).render({});
  // ruleid: js.template-injection
  const d = configured.renderString('{{ x }}' + req.query.suffix, { x: 1 });
  // ruleid: js.template-injection
  const e = nunjucks.compile(req.query.tpl);
  res.send([a, b, c, d, e.render({})].join(''));
});

app.get('/lodash', (req, res) => {
  // ruleid: js.template-injection
  const compiled = _.template(req.query.tpl);
  // ruleid: js.template-injection
  const other = template('<p><%= x %></p>' + req.query.extra);
  res.send(compiled({ x: 1 }) + other({ x: 2 }));
});

// EJS: a request object passed whole as the data of a view lets the client set render options
// (the EJS docs name `res.render('index', req.query)`).
app.get('/', (req, res) => {
  // ruleid: js.template-injection
  res.render('index', req.query);
});

app.post('/profile', (req, res) => {
  if (req.body.page) {
    // ruleid: js.template-injection
    return res.render('settings', { title: 'Settings', ...req.body });
  }
  if (req.body.inline) {
    // ruleid: js.template-injection
    return res.send(ejs.render('<p><%= name %></p>', { ...req.query }));
  }
  // ruleid: js.template-injection
  return res.send(ejs.render('<p><%= name %></p>', req.body));
});

app.post('/file', (req, res) => {
  // ruleid: js.template-injection
  ejs.renderFile(path.join(__dirname, 'views', 'card.ejs'), req.body, (err, html) => res.send(html));
});

// EJS options from the request.
app.get('/delims', (req, res) => {
  // ruleid: js.template-injection
  res.send(ejs.render('<?= name ?>', { name: 'x' }, { delimiter: req.query.d }));
});

// Safe forms: request data as values for a fixed template, templates loaded from files, views
// rendered by name with a data object.
const GREETING = '<p>Hello <%= name %></p>';
const TEMPLATES = { short: 'Hi {{name}}', long: 'Hello there, {{name}}' };
app.get('/safe/:name', (req, res) => {
  const name = req.params.name;
  // ok: js.template-injection
  res.render('profile', { name, q: req.query.q });
  // ok: js.template-injection
  const a = ejs.render(GREETING, { name });
  // ok: js.template-injection
  const b = ejs.compile(fs.readFileSync(path.join(__dirname, 'views/mail.ejs'), 'utf8'))({ name });
  // ok: js.template-injection
  const c = pug.renderFile(path.join(__dirname, 'views/card.pug'), { name });
  // ok: js.template-injection
  const d = Handlebars.compile('Hello {{name}}')({ name: req.query.name });
  // ok: js.template-injection
  const e = nunjucks.render('index.html', { name: req.query.name });
  // ok: js.template-injection
  const f = _.template('hello <%- user %>')({ user: req.query.user });
  // ok: js.template-injection
  const g = Handlebars.compile(TEMPLATES[req.query.kind] || TEMPLATES.short)({ name });
  // ok: js.template-injection
  const h = ejs.render(GREETING, { name: req.body.name }, { delimiter: '%' });
  // ok: js.template-injection
  const i = pug.render('p Page ' + Number(req.query.page));
  // ok: js.template-injection
  const j = ejs.renderFile(path.join(__dirname, 'views/card.ejs'), { body: req.body });
  res.json({ a, b, c, d, e, f, g, h, i, j });
});

// A lookup with a fallback taken from the request is no allow-list.
app.get('/kinds', (req, res) => {
  // ruleid: js.template-injection
  res.send(Handlebars.compile(TEMPLATES[req.query.kind] || req.query.custom)({}));
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const QUOTED = { a: 'It\'s {{x}}' };
const NESTED = { mail: { a: 'Hi {{x}}' } };
app.get('/tables', (req, res) => {
  // todook: js.template-injection
  const a = Handlebars.compile(QUOTED[req.query.k] || '{{x}}');
  // todook: js.template-injection
  const b = Handlebars.compile(NESTED.mail[req.query.k] || '{{x}}');
  res.send(a({ x: 1 }) + b({ x: 2 }));
});

// A request object copied into a variable before it is passed as the data of a view is not
// followed.
app.get('/copied', (req, res) => {
  const locals = req.query;
  // todoruleid: js.template-injection
  res.render('index', locals);
});

// Look-alikes: compile() and render() of other objects, functions that are not handlers.
const schemas = { compile: (s) => s };
const view = { render: (s) => s };
app.post('/look-alikes', (req, res) => {
  // ok: js.template-injection
  const validate = schemas.compile(req.body.schema);
  // ok: js.template-injection
  const out = view.render(req.body.text);
  // ok: js.template-injection
  const wrapped = _.escape(req.body.text);
  res.json({ validate, out, wrapped });
});

function renderPreview(req, opts) {
  // ok: js.template-injection
  return ejs.render(req.query.tpl, opts);
}

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/mail', (request, out) => {
  // todoruleid: js.template-injection
  out.send(ejs.render(request.query.tpl));
});

const router = { get: (p, done) => done({ query: { tpl: p } }) };
router.get('/<%= 1 %>', (result) => {
  // todook: js.template-injection
  return ejs.render(result.query.tpl);
});

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.post('/fastify/render', async (request, reply) => {
  // ruleid: js.template-injection
  return reply.type('text/html').send(nunjucks.renderString(request.body.tpl, {}));
});

fastify.get('/fastify/:tpl', async (request) => {
  // ruleid: js.template-injection
  return pug.render(request.params.tpl);
});

fastify.get('/fastify-safe/:name', async (request) => {
  // ok: js.template-injection
  return pug.render('p= name', { name: request.params.name });
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/preview/destructured', ({ query: { tpl } }, res) => {
  // ruleid: js.template-injection
  res.send(ejs.render(tpl, { user: 'guest' }));
});
fastify.post('/preview/destructured', async (request) => {
  const { body: { source: markup } } = request;
  // ruleid: js.template-injection
  return pug.render(markup, { user: 'guest' });
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/preview/defaults', ({ query = {} }, res) => {
  // todoruleid: js.template-injection
  res.send(ejs.render(query.tpl, { user: 'guest' }));
});

module.exports = { app, fastify, renderPreview };
