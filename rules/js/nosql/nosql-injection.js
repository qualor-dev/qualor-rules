const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const mongoose = require('mongoose');
const User = require('../models/user.model');
const { Order } = require('./models');

const app = express();
app.use(express.json());
const client = new MongoClient('mongodb://localhost:27017');
const db = client.db('shop');
const users = db.collection('users');

// MongoDB driver: a JSON body or an extended (qs) query string can carry operator objects such
// as {"$ne": null} in place of a value.
app.post('/login', async (req, res) => {
  // ruleid: js.nosql-injection
  const user = await users.findOne({ email: req.body.email, password: req.body.password });
  const { name } = req.body;
  // ruleid: js.nosql-injection
  await users.find({ name }).toArray();
  // ruleid: js.nosql-injection
  await db.collection('sessions').deleteMany({ token: req.body.token });
  // ruleid: js.nosql-injection
  await users.updateOne({ email: req.query.email }, { $set: { seen: true } });
  // ruleid: js.nosql-injection
  await users.countDocuments(req.body);
  const filter = req.body.filter;
  // ruleid: js.nosql-injection
  await users.find(filter).toArray();
  // ok: js.nosql-injection
  await users.findOne({ email: String(req.body.email) });
  // ok: js.nosql-injection
  await users.findOne({ email: { $eq: req.body.email } });
  // ok: js.nosql-injection
  await users.find({ age: Number(req.query.age) }).toArray();
  // ok: js.nosql-injection
  await users.findOne({ _id: new ObjectId(req.body.id) });
  const email = String(req.body.email);
  // ok: js.nosql-injection
  await users.findOne({ email });
  const age = Number(req.query.age);
  // ok: js.nosql-injection
  await users.find({ age }).toArray();
  const byEq = { email: { $eq: req.body.email } };
  // ok: js.nosql-injection
  await users.findOne(byEq);
  const byId = { _id: new ObjectId(req.body.id) };
  // ok: js.nosql-injection
  await users.findOne(byId);
  // ok: js.nosql-injection
  await users.findOne({ email: 'admin@example.com' });
  // ok: js.nosql-injection
  await users.find({ label: 'user-' + req.body.label }).toArray();
  // ok: js.nosql-injection
  await users.find({ label: `user-${req.body.label}` }).toArray();
  res.json({ user });
});

// Route parameters, headers and the URL are strings: as plain values they cannot carry operators.
app.get('/users/:id', async (req, res) => {
  // ok: js.nosql-injection
  const one = await users.findOne({ username: req.params.id });
  // ok: js.nosql-injection
  const two = await users.findOne({ agent: req.get('User-Agent') });
  res.json({ one, two });
});

// Request strings in server-side JavaScript: $where, $function and $accumulator.
app.get('/search/:field', async (req, res) => {
  // ruleid: js.nosql-injection
  await users.find({ $where: "this.name == '" + req.query.name + "'" }).toArray();
  // ruleid: js.nosql-injection
  await users.find({ $where: `this.${req.params.field} > 0` }).toArray();
  const code = 'function () { return this.tag === "' + req.params.field + '"; }';
  // ruleid: js.nosql-injection
  await users.find({ $expr: { $function: { body: code, args: [], lang: 'js' } } }).toArray();
  await users.aggregate([
    {
      $group: {
        _id: '$team',
        total: {
          $accumulator: {
            init: 'function () { return 0; }',
            // ruleid: js.nosql-injection
            accumulate: 'function (s, v) { return s + v.' + req.query.metric + '; }',
            accumulateArgs: ['$$ROOT'],
            merge: 'function (a, b) { return a + b; }',
            lang: 'js',
          },
        },
      },
    },
  ]).toArray();
  // ok: js.nosql-injection
  await users.find({ $where: 'this.credits > this.debits' }).toArray();
  // ok: js.nosql-injection
  await users.find({ $where: 'this.age > ' + Number(req.query.age) }).toArray();
  res.end();
});

// Aggregation: the $match stage takes a query filter.
app.post('/report', async (req, res) => {
  // ruleid: js.nosql-injection
  const rows = await users.aggregate([{ $match: { team: req.body.team } }, { $count: 'n' }]).toArray();
  // ruleid: js.nosql-injection
  await users.aggregate([{ $match: req.body.match }]).toArray();
  // ok: js.nosql-injection
  await users.aggregate([{ $match: { team: String(req.body.team) } }]).toArray();
  res.json(rows);
});

// Mongoose: models defined in this file or imported from a models module.
const Product = mongoose.model('Product', new mongoose.Schema({ name: String, owner: String }));

app.post('/products', async (req, res) => {
  // ruleid: js.nosql-injection
  const p = await Product.findOne({ owner: req.body.owner });
  // ruleid: js.nosql-injection
  await User.find({ role: req.query.role }).exec();
  // ruleid: js.nosql-injection
  await Order.deleteOne({ code: req.body.code });
  // ruleid: js.nosql-injection
  await User.where({ email: req.body.email }).findOne();
  // ruleid: js.nosql-injection
  await User.findOneAndUpdate({ resetToken: req.body.token }, { password: 'x' });
  // ruleid: js.nosql-injection
  await Product.$where('this.owner === "' + req.body.owner + '"').exec();
  // ok: js.nosql-injection
  await Product.findOne(mongoose.sanitizeFilter({ owner: req.body.owner }));
  const clean = mongoose.sanitizeFilter(req.body.filter);
  // ok: js.nosql-injection
  await Product.find(clean);
  // ok: js.nosql-injection
  await Product.find({ owner: req.body.owner }).setOptions({ sanitizeFilter: true });
  // ok: js.nosql-injection
  await Product.find({ owner: req.body.owner }, null, { sanitizeFilter: true });
  // ok: js.nosql-injection
  await User.findById(req.body.id);
  // ok: js.nosql-injection
  await User.findOne({ _id: new mongoose.Types.ObjectId(req.body.id) });
  // ok: js.nosql-injection
  await Product.$where('this.owner === this.maker').exec();
  // ok: js.nosql-injection
  await User.find({ status: 'active' }).where('age').gte(18);
  res.json(p);
});

// Mongoose's query builder: conditions set on the model or on a query made from it.
app.post('/members', async (req, res) => {
  // ruleid: js.nosql-injection
  const m = await User.where('email').equals(req.body.email);
  // ruleid: js.nosql-injection
  await User.where('nickname', req.body.nickname);
  // ruleid: js.nosql-injection
  await Product.find().where({ owner: req.body.owner });
  // ruleid: js.nosql-injection
  await Product.find({ public: true }).or([{ owner: req.body.owner }, { maker: 'acme' }]);
  // ruleid: js.nosql-injection
  await User.find().sort('name').where('team').equals(req.query.team);
  // ruleid: js.nosql-injection
  await Product.find().where(req.body.conditions).limit(10);
  // ruleid: js.nosql-injection
  await users.distinct('team', { owner: req.body.owner });
  // ok: js.nosql-injection
  await User.where('email').equals(String(req.body.email));
  // ok: js.nosql-injection
  await User.find().where('age').gte(18).lte(65);
  // ok: js.nosql-injection
  await users.distinct('team', { owner: { $eq: req.body.owner } });
  res.json(m);
});

// where() and and() of an object that is no model or query.
const builder = { where: (cond) => cond, and: (list) => list };
app.post('/builder', (req, res) => {
  // ok: js.nosql-injection
  builder.where({ name: req.body.name });
  // ok: js.nosql-injection
  builder.and([{ name: req.body.name }]);
  res.end();
});

// A type check before the query is not recognised as a guard.
app.post('/check', async (req, res) => {
  if (typeof req.body.email !== 'string') return res.sendStatus(400);
  // todook: js.nosql-injection
  const u = await users.findOne({ email: req.body.email });
  res.json(u);
});

// $where with a value converted by String() is still JavaScript built from the request: String()
// counts as a conversion that removes operators, so this is not reported.
app.get('/legacy', async (req, res) => {
  // todoruleid: js.nosql-injection
  await users.find({ $where: "this.name == '" + String(req.query.name) + "'" }).toArray();
  res.end();
});

// Look-alikes: find/findOne of arrays, Sequelize and Prisma-style options, other libraries.
const list = [{ id: 1 }];
const cache = new Map();

app.post('/other', async (req, res) => {
  // ok: js.nosql-injection
  const item = list.find((x) => x.id === req.body.id);
  // ok: js.nosql-injection
  const row = await User.findOne({ where: { email: req.body.email } });
  // ok: js.nosql-injection
  const hit = cache.get(req.body.key);
  // ok: js.nosql-injection
  const found = [req.body].filter((x) => x.name);
  res.json({ item, row, hit, found });
});

// Functions that are not request handlers: their parameters are no request.
async function byEmail(input, options) {
  // ok: js.nosql-injection
  return users.findOne({ email: input.body.email, flags: options });
}

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.post('/accounts/login', async (request, reply) => {
  // ruleid: js.nosql-injection
  const account = await users.findOne({ login: request.body.login });
  // ok: js.nosql-injection
  await users.findOne({ login: String(request.body.login) });
  return reply.send(account);
});

fastify.get('/accounts/:id', async (request) => {
  // ruleid: js.nosql-injection
  await users.find({ $where: 'this.ref == "' + request.params.id + '"' }).toArray();
  // ok: js.nosql-injection
  return users.findOne({ ref: request.params.id });
});

// A route whose body schema types the field as a string: Fastify answers 400 to an object.
fastify.post('/accounts/claim', {
  schema: { body: { type: 'object', properties: { code: { type: 'string' } } } },
}, async (request) => {
  // ok: js.nosql-injection
  return users.findOne({ code: request.body.code });
});

fastify.route({
  method: 'POST',
  url: '/accounts/verify',
  schema: { body: { type: 'object', properties: { token: { type: 'string' } } } },
  handler: async (request, reply) => {
    // ok: js.nosql-injection
    return reply.send(await users.findOne({ token: request.body.token }));
  },
});

// A route registered inside the handler of a route with a body schema has no schema itself.
fastify.post('/accounts/batch', {
  schema: { body: { type: 'object', properties: { ids: { type: 'array' } } } },
}, async (request) => {
  fastify.get('/accounts/batch/status', async (req) => {
    // ruleid: js.nosql-injection
    return users.findOne({ batch: req.query.batch });
  });
  return { queued: request.body.ids.length };
});

// The same with route() registering a route of another instance.
const admin = require('fastify')();
fastify.route({
  method: 'POST',
  url: '/accounts/merge',
  schema: { body: { type: 'object', properties: { into: { type: 'string' } } } },
  handler: async () => {
    admin.post('/accounts/merge/preview', async (req) => {
      // ruleid: js.nosql-injection
      return users.findOne({ owner: req.body.owner });
    });
    return { merged: true };
  },
});

// Body schemas are not read: one that allows an object for the field is left out too.
fastify.post('/accounts/query', {
  schema: { body: { type: 'object', properties: { filter: { type: 'object' } } } },
}, async (request) => {
  // todoruleid: js.nosql-injection
  return users.find(request.body.filter).toArray();
});

// A schema given as a variable is not seen.
const renameSchema = { body: { type: 'object', properties: { name: { type: 'string' } } } };
fastify.post('/accounts/rename', { schema: renameSchema }, async (request) => {
  // todook: js.nosql-injection
  return users.findOne({ name: request.body.name });
});

// Fastify's default query parser gives strings; query values are reported anyway.
fastify.get('/accounts/lookup', async (request) => {
  // todook: js.nosql-injection
  return users.findOne({ login: request.query.login });
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.post('/accounts/export', async (request, out) => {
  // todoruleid: js.nosql-injection
  out.json(await users.findOne({ owner: request.body.owner }));
});

const http = { post: (path, done) => done({ body: { id: path } }) };
http.post('/accounts/sync', (result) => {
  // todook: js.nosql-injection
  users.findOne({ ref: result.body.id });
});

fastify.route({
  method: 'POST',
  url: '/accounts/search',
  handler: async (request) => {
    // ruleid: js.nosql-injection
    return Product.find({ owner: request.body.owner });
  },
});

// Handlers that destructure the request: the body and the query string can still carry operators.
app.post('/login/destructured', async ({ body: { email, password } }, res) => {
  // ruleid: js.nosql-injection
  res.json(await users.findOne({ email, password }));
});
app.post('/users/destructured', async (req, res) => {
  const { body: filter, params: { id } } = req;
  // ruleid: js.nosql-injection
  await users.find(filter).toArray();
  // ok: js.nosql-injection
  res.json(await users.findOne({ ref: id }));
});
fastify.post('/accounts/destructured', async ({ body }) => {
  // ruleid: js.nosql-injection
  return users.findOne({ login: body.login });
});
fastify.post('/accounts/destructured/claim', {
  schema: { body: { type: 'object', properties: { code: { type: 'string' } } } },
}, async ({ body: { code } }) => {
  // ok: js.nosql-injection
  return users.findOne({ code });
});
fastify.route({
  method: 'POST',
  url: '/accounts/destructured/search',
  handler: async ({ query }) => {
    // ruleid: js.nosql-injection
    return users.find(query.filter).toArray();
  },
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.post('/login/defaults', async ({ body = {} }, res) => {
  // todoruleid: js.nosql-injection
  res.json(await users.findOne({ email: body.email }));
});

module.exports = { app, fastify, byEmail };
