const express = require('express');
const { Pool } = require('pg');
const mysql = require('mysql2/promise');

const app = express();
const pool = new Pool();

app.get('/orders', async (req, res) => {
  const customer = req.query.customer;
  // ruleid: js.sql-injection
  const a = await pool.query("SELECT * FROM orders WHERE customer = '" + customer + "'");
  // ruleid: js.sql-injection
  const b = await pool.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  const sql = 'DELETE FROM orders WHERE note = ' + req.body.note;
  // ruleid: js.sql-injection
  await pool.query(sql);
  // ruleid: js.sql-injection
  await pool.query({ text: 'SELECT * FROM orders WHERE customer = ' + customer });
  // ok: js.sql-injection
  const c = await pool.query('SELECT * FROM orders WHERE customer = $1', [customer]);
  // ok: js.sql-injection
  const d = await pool.query({ text: 'SELECT * FROM orders WHERE id = $1', values: [req.params.id] });
  // ok: js.sql-injection
  const e = await pool.query('SELECT count(*) FROM orders');
  res.json({ a, b, c, d, e });
});

app.post('/search', async (req, res) => {
  const conn = await mysql.createConnection({});
  // ruleid: js.sql-injection
  const [rows] = await conn.query('SELECT * FROM items WHERE name = "' + req.body.name + '"');
  // ruleid: js.sql-injection
  await conn.execute(`SELECT * FROM items WHERE sku = '${req.query.sku}'`);
  // ok: js.sql-injection
  const [safe] = await conn.execute('SELECT * FROM items WHERE name = ?', [req.body.name]);
  const sort = req.query.sort === 'price' ? 'price' : 'name';
  // ok: js.sql-injection
  const [sorted] = await conn.query('SELECT * FROM items ORDER BY ' + sort);
  // ok: js.sql-injection
  await conn.query('SELECT * FROM items WHERE id = ' + Number.parseInt(req.query.id, 10));
  res.json({ rows, safe, sorted });
});

async function report(req, res) {
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM reports WHERE name = '" + req.body.name + "'");
  res.end();
}

app.get('/report', report);

// Express route parameters (`/users/:id`), headers and the URL reach the handler on `req`.
const util = require('node:util');
const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  // ruleid: js.sql-injection
  await pool.query(`SELECT * FROM users WHERE id = '${id}'`);
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM visits WHERE agent = '" + req.get('User-Agent') + "'");
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO visits (path) VALUES ('" + req.originalUrl + "')");
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM sessions WHERE token = '" + req.cookies.session + "'");
  let text = 'SELECT * FROM users';
  text += " WHERE name = '" + req.query.name + "'";
  // ruleid: js.sql-injection
  await pool.query(text);
  // ok: js.sql-injection
  await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  // ok: js.sql-injection
  await pool.query('SELECT * FROM users WHERE id = ' + Number(req.params.id));
  res.end();
});

// node-postgres: a client checked out of the pool runs any query text it is given.
router.put('/users/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    // ruleid: js.sql-injection
    await client.query(util.format("UPDATE users SET name = '%s' WHERE id = 1", req.body.name));
    // ok: js.sql-injection
    await client.query('UPDATE users SET name = $1 WHERE id = $2', [req.body.name, req.params.id]);
  } finally {
    client.release();
  }
  res.end();
});

// mysql2: the `{ sql, values }` form and a pool.
const mysqlPool = mysql.createPool({});

router.get('/items/:sku', async (req, res) => {
  // ruleid: js.sql-injection
  await mysqlPool.query({ sql: "SELECT * FROM items WHERE sku = '" + req.params.sku + "'" });
  // ruleid: js.sql-injection
  await mysqlPool.execute(util.format("SELECT * FROM items WHERE sku = '%s'", req.params.sku));
  // ok: js.sql-injection
  await mysqlPool.execute({ sql: 'SELECT * FROM items WHERE sku = ?', values: [req.params.sku] });
  // ok: js.sql-injection
  await mysqlPool.query('SELECT * FROM items WHERE sku = ?', [req.params.sku]);
  res.end();
});

// Knex: the query builder binds values; only the *Raw methods take SQL text.
const knex = require('knex')({ client: 'pg' });

router.get('/products', async (req, res) => {
  // ok: js.sql-injection
  await knex('products').where('name', req.query.name);
  // ok: js.sql-injection
  await knex('products').where({ name: req.query.name }).select('id');
  // ok: js.sql-injection
  await knex.raw('select * from products where name = ?', [req.query.name]);
  // ok: js.sql-injection
  await knex('products').whereRaw('name = ?', [req.query.name]);
  // ruleid: js.sql-injection
  await knex.raw("select * from products where name = '" + req.query.name + "'");
  // ruleid: js.sql-injection
  await knex('products').whereRaw(`name = '${req.query.name}'`);
  // ruleid: js.sql-injection
  await knex('products').orderByRaw(req.query.sort);
  res.end();
});

// Sequelize: replacements and bind parameters; model finders bind their values.
const { Sequelize, QueryTypes, DataTypes } = require('sequelize');

const sequelize = new Sequelize('sqlite::memory:');
const Project = sequelize.define('project', { status: DataTypes.STRING });

router.get('/projects', async (req, res) => {
  // ok: js.sql-injection
  await sequelize.query('SELECT * FROM projects WHERE status = :status', {
    replacements: { status: req.query.status },
    type: QueryTypes.SELECT,
  });
  // ok: js.sql-injection
  await sequelize.query('SELECT * FROM projects WHERE status = $1', { bind: [req.query.status] });
  // ok: js.sql-injection
  await Project.findAll({ where: { status: req.query.status } });
  // ruleid: js.sql-injection
  await sequelize.query(`SELECT * FROM projects WHERE status = '${req.query.status}'`, { type: QueryTypes.SELECT });
  res.end();
});

// Prisma: the $queryRaw tagged template binds its values; the *Unsafe methods take SQL text.
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

router.post('/accounts', async (req, res) => {
  // ok: js.sql-injection
  await prisma.$queryRaw`SELECT * FROM accounts WHERE email = ${req.body.email}`;
  // ok: js.sql-injection
  await prisma.$queryRawUnsafe('SELECT * FROM accounts WHERE email = $1', req.body.email);
  // ruleid: js.sql-injection
  await prisma.$queryRawUnsafe(`SELECT * FROM accounts WHERE email = '${req.body.email}'`);
  // ruleid: js.sql-injection
  await prisma.$executeRawUnsafe("DELETE FROM accounts WHERE email = '" + req.body.email + "'");
  res.end();
});

// Methods called query/execute that run no SQL are not sinks.
class PlaceOrder {
  async execute(input) {
    return input;
  }
}

const placeOrder = new PlaceOrder();
const apollo = { query: async (options) => options };
const GET_DOG = 'query GetDog($breed: String!) { dog(breed: $breed) { id } }';

router.post('/checkout', async (req, res) => {
  // ok: js.sql-injection
  const order = await placeOrder.execute(req.body);
  // ok: js.sql-injection
  const dog = await apollo.query({ query: GET_DOG, variables: { breed: req.body.breed } });
  res.json({ order, dog });
});

// A connection from another module, given query text that is not visibly SQL: not followed.
const db = require('./db');

router.get('/audit', async (req, res) => {
  // todoruleid: js.sql-injection
  await db.query(util.format("SELECT * FROM audit WHERE actor = '%s'", req.query.actor));
  res.end();
});

// Functions with two parameters that are not request handlers: their first parameter is no request.
const config = require('config');

async function cached(cache, key) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM cache WHERE value = '" + cache.get(key) + "'");
}

async function setting(cfg, name) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM settings WHERE value = '" + cfg.get(name) + "'");
}

async function handleUrl(u, x) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM links WHERE url = '" + u.url + "' AND kind = '" + x + "'");
}

const files = [{ path: 'a.txt' }];
files.reduce((acc, file) => {
  // ok: js.sql-injection
  pool.query("INSERT INTO paths (path) VALUES ('" + acc.path + "')");
  return file;
}, {});

app.get('/settings', async (req, res) => {
  res.json(await Promise.all([cached(new Map(), 'k'), setting(config, 'theme'), handleUrl(new URL('https://qualor.dev'), 1)]));
});

// Next.js App Router route handlers: functions named after an HTTP method take the request.
async function GET(request) {
  const { searchParams } = new URL(request.url);
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM posts WHERE slug = '" + searchParams.get('slug') + "'");
  return Response.json({});
}

async function POST(request, { params }) {
  const { slug } = await params;
  // ruleid: js.sql-injection
  await pool.query("UPDATE posts SET likes = likes + 1 WHERE slug = '" + slug + "'");
  // ok: js.sql-injection
  await pool.query('UPDATE posts SET likes = likes + 1 WHERE slug = $1', [slug]);
  return Response.json({});
}

// A function that is not named after an HTTP method is no route handler.
async function lookup(request) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM posts WHERE slug = '" + request.url + "'");
}

module.exports = { GET, POST, lookup };

// Next.js Pages Router API routes: `export default function handler(req, res)`; dynamic segments
// arrive in req.query.
async function handler(req, res) {
  // ruleid: js.sql-injection
  await pool.query(`SELECT * FROM posts WHERE id = '${req.query.pid}'`);
  // ok: js.sql-injection
  await pool.query('SELECT * FROM posts WHERE id = $1', [req.query.pid]);
  res.status(200).json({});
}

module.exports.handler = handler;

// Fastify: handlers `(request, reply)` and handlers that take only the request.
const fastify = require('fastify')({ logger: true });

fastify.get('/invoices/:id', async (request, reply) => {
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM invoices WHERE id = '" + request.params.id + "'");
  // ok: js.sql-injection
  await pool.query('SELECT * FROM invoices WHERE id = $1', [request.params.id]);
  return reply.send({});
});

fastify.get('/invoices', async (request) => {
  const { status } = request.query;
  // ruleid: js.sql-injection
  return pool.query(`SELECT * FROM invoices WHERE status = '${status}'`);
});

fastify.post('/invoices', { schema: {} }, async function (request) {
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO invoices (note) VALUES ('" + request.body.note + "')");
  // ok: js.sql-injection
  await pool.query('INSERT INTO invoices (note) VALUES ($1)', [request.body.note]);
  return {};
});

fastify.route({
  method: 'DELETE',
  url: '/invoices/:id',
  handler: async (request) => {
    // ruleid: js.sql-injection
    await pool.query("DELETE FROM invoices WHERE id = '" + request.params.id + "'");
    // ok: js.sql-injection
    await pool.query('DELETE FROM invoices WHERE id = ' + Number(request.params.id));
    return {};
  },
});

fastify.get('/raw', async (request) => {
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO hits (agent) VALUES ('" + request.headers['user-agent'] + "')");
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO hits (url) VALUES ('" + request.raw.url + "')");
  return {};
});

// A callback with one parameter given to a method that is not a route registration.
const loaders = new Map();
loaders.set('/reports', (entry) => entry);
// A client method named like a route shorthand, given a path and a one-parameter callback, looks
// like a Fastify route: its parameter is taken for the request.
const client = { get: (path, done) => done({ query: path }) };
client.get('/reports', (result) => {
  // todook: js.sql-injection
  pool.query("SELECT * FROM reports WHERE name = '" + result.query + "'");
});
[{ query: 'a' }].forEach((item) => {
  // ok: js.sql-injection
  pool.query("SELECT * FROM reports WHERE name = '" + item.query + "'");
});

// Sequelize: literal() inserts its text unescaped; escape() quotes a value.
const { literal } = require('sequelize');

router.get('/projects/sorted', async (req, res) => {
  // ruleid: js.sql-injection
  await Project.findAll({ where: sequelize.literal("status = '" + req.query.status + "'") });
  // ruleid: js.sql-injection
  await Project.findAll({ order: Sequelize.literal(req.query.sort) });
  // ruleid: js.sql-injection
  await Project.findAll({ attributes: [[literal(`(SELECT count(*) FROM tasks WHERE owner = '${req.query.owner}')`), 'n']] });
  // ok: js.sql-injection
  await Project.findAll({ order: sequelize.literal('max(age) DESC') });
  // ok: js.sql-injection
  await Project.findAll({ where: sequelize.literal('status = ' + sequelize.escape(req.query.status)) });
  // ok: js.sql-injection
  await Project.findAll({ where: sequelize.where(sequelize.fn('lower', sequelize.col('status')), req.query.status) });
  res.end();
});

// literal() of another library is no SQL sink.
const css = { literal: (text) => text };

router.get('/style', (req, res) => {
  // ok: js.sql-injection
  res.send(css.literal(req.query.color));
});

// A handler is recognised by the name of its second parameter (res, reply, next, ...): one whose
// second parameter has another name is not a source.
app.get('/exports', async (request, out) => {
  // todoruleid: js.sql-injection
  await pool.query("SELECT * FROM exports WHERE label = '" + request.query.label + "'");
  out.end();
});

// Handlers that destructure the request: in the parameter list (also renamed or nested) or in a
// declaration (also with a default value).
router.get('/shelves/:shelf', async ({ query, params: { shelf } }, res) => {
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM books WHERE shelf = '" + shelf + "'");
  // ruleid: js.sql-injection
  await pool.query(`SELECT * FROM books WHERE title = '${query.title}'`);
  // ok: js.sql-injection
  await pool.query('SELECT * FROM books WHERE shelf = $1', [shelf]);
  res.end();
});

router.post('/shelves', async function addBook({ body: { title: bookTitle }, headers }, res, next) {
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO books (title) VALUES ('" + bookTitle + "')");
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO agents (name) VALUES ('" + headers['user-agent'] + "')");
  // ok: js.sql-injection
  await pool.query('INSERT INTO books (title) VALUES ($1)', [bookTitle]);
  next();
});

// A field with a default value in the parameter list is not matched by OpenGrep's object
// patterns, so it is no source.
async function emptyCart({ cookies = {} }, res) {
  // todoruleid: js.sql-injection
  await pool.query("DELETE FROM carts WHERE session = '" + cookies.cart + "'");
  res.end();
}

router.delete('/cart', emptyCart);

router.get('/shelves/search', async (req, res) => {
  const { query: { author }, body } = req;
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM books WHERE author = '" + author + "'");
  // ruleid: js.sql-injection
  await pool.query("SELECT * FROM books WHERE isbn = '" + body.isbn + "'");
  let { originalUrl: visited } = req;
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO visits (path) VALUES ('" + visited + "')");
  const { body: { note = '' } = {}, headers: { referer: from = '' } } = req;
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO notes (text, source) VALUES ('" + note + "', '" + from + "')");
  const { method } = req;
  // ok: js.sql-injection
  await pool.query("INSERT INTO visits (method) VALUES ('" + method + "')");
  const { query: defaultTitle } = { query: 'all' };
  // ok: js.sql-injection
  await pool.query("SELECT * FROM books WHERE title = '" + defaultTitle + "'");
  res.end();
});

router.post('/shelves/notes', async ({ body: { note: text = '' } }, res) => {
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO notes (text) VALUES ('" + text + "')");
  res.end();
});

router.get('/shelves/count', async ({ method }, res) => {
  // ok: js.sql-injection
  res.json(await pool.query("SELECT count(*) FROM visits WHERE method = '" + method + "'"));
});

// Functions that destructure their first parameter but are no handlers.
function describeBook({ title }, options) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM books WHERE title = '" + title + "' LIMIT " + options.limit);
}

function summarize({ query }, options) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM reports WHERE name = '" + query + "' LIMIT " + options.limit);
}

[{ query: 'a' }].map(({ query }) => {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM reports WHERE name = '" + query + "'");
});

app.get('/shelves/export', async ({ query }, out) => {
  // todoruleid: js.sql-injection
  await pool.query("SELECT * FROM exports WHERE shelf = '" + query.shelf + "'");
  out.end();
});

// Fastify handlers that take only the request and destructure it.
fastify.post('/notes', async ({ body: { text: noteText } }) => {
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO notes (text) VALUES ('" + noteText + "')");
  // ok: js.sql-injection
  await pool.query('INSERT INTO notes (text) VALUES ($1)', [noteText]);
  return {};
});

fastify.get('/notes', async (request) => {
  const { query: { tag } } = request;
  // ruleid: js.sql-injection
  return pool.query("SELECT * FROM notes WHERE tag = '" + tag + "'");
});

fastify.route({
  method: 'PUT',
  url: '/notes/:id',
  handler: async ({ params, body }) => {
    // ruleid: js.sql-injection
    await pool.query("UPDATE notes SET text = '" + body.text + "' WHERE id = " + params.id);
    return {};
  },
});

// A one-parameter callback is a Fastify handler only after a route method and a path literal.
const store = { find: (key, done) => done({ query: key }) };
store.find('/notes', ({ query }) => {
  // ok: js.sql-injection
  pool.query("SELECT * FROM notes WHERE tag = '" + query + "'");
});
client.get('reports', ({ query }) => {
  // ok: js.sql-injection
  pool.query("SELECT * FROM reports WHERE name = '" + query + "'");
});
client.get('/reports/latest', ({ query }) => {
  // todook: js.sql-injection
  pool.query("SELECT * FROM reports WHERE name = '" + query + "'");
});

// Next.js App Router handlers that destructure the request or the context.
async function PUT(request, ctx) {
  const { url } = request;
  const { params } = ctx;
  const { slug } = await params;
  // ruleid: js.sql-injection
  await pool.query("INSERT INTO visits (url) VALUES ('" + url + "')");
  // ruleid: js.sql-injection
  await pool.query("UPDATE posts SET views = views + 1 WHERE slug = '" + slug + "'");
  return Response.json({});
}

async function PATCH({ nextUrl }, { params: { id } }) {
  // ruleid: js.sql-injection
  await pool.query("UPDATE posts SET tag = '" + nextUrl.searchParams.get('tag') + "' WHERE id = 1");
  // ruleid: js.sql-injection
  await pool.query("UPDATE posts SET draft = false WHERE id = '" + id + "'");
  return Response.json({});
}

async function HEAD({ method }) {
  // ok: js.sql-injection
  await pool.query("INSERT INTO visits (method) VALUES ('" + method + "')");
  return new Response(null);
}

async function preview({ url }) {
  // ok: js.sql-injection
  return pool.query("SELECT * FROM previews WHERE url = '" + url + "'");
}

module.exports.next = { PUT, PATCH, HEAD, preview, describeBook, summarize };

app.use(router);
