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

fastify.get('/fsafe', async (request, reply) => {
  // ok: js.xss
  return reply.type('text/html').send('<p>' + escapeHtml(request.query.text) + '</p>');
});

module.exports = { app, server, fastify, reply };
