const express = require('express');
const vm = require('node:vm');
const { runInNewContext: runSandboxed, Script } = require('vm');

const app = express();
app.use(express.json());

// eval(): request data as the code, in place, through a variable, or built into a string.
app.get('/calc', (req, res) => {
  // ruleid: js.code-injection
  const result = eval(req.query.expr);
  res.json({ result });
});

app.post('/rules/:name', (req, res) => {
  const condition = req.body.condition;
  // ruleid: js.code-injection
  const matches = eval('(' + condition + ')');
  // ruleid: js.code-injection
  eval(`globalThis.rules['${req.params.name}'] = ${matches}`);
  res.json({ matches });
});

app.get('/indirect', (req, res) => {
  // ruleid: js.code-injection
  const value = (0, eval)(req.get('X-Expression'));
  // ruleid: js.code-injection
  const other = globalThis.eval(req.cookies.snippet);
  res.json({ value, other });
});

// new Function() and Function(): every argument is code (parameter names and the body).
app.post('/formula', (req, res) => {
  // ruleid: js.code-injection
  const fn = new Function('row', 'return ' + req.body.formula);
  // ruleid: js.code-injection
  const fn2 = Function(req.body.param, 'return 1');
  const body = `return ${req.query.body};`;
  // ruleid: js.code-injection
  const fn3 = new Function(body);
  res.json({ a: fn({}), b: fn2(), c: fn3() });
});

// node:vm: the code argument of runInNewContext, runInContext, runInThisContext,
// compileFunction and new vm.Script.
app.post('/sandbox', (req, res) => {
  const code = req.body.code;
  const context = vm.createContext({ input: 1 });
  // ruleid: js.code-injection
  const a = vm.runInNewContext(code, { input: 2 });
  // ruleid: js.code-injection
  const b = vm.runInContext(code, context);
  // ruleid: js.code-injection
  const c = vm.runInThisContext(req.query.code);
  // ruleid: js.code-injection
  const d = vm.compileFunction(code, ['input']);
  // ruleid: js.code-injection
  const script = new vm.Script(req.body.script);
  // ruleid: js.code-injection
  const e = runSandboxed(code);
  // ruleid: js.code-injection
  const compiled = new Script('input + ' + req.query.offset);
  res.json({ a, b, c, d: d(1), e, s: script.runInNewContext(), t: compiled.runInNewContext({ input: 1 }) });
});

// Safe forms: JSON.parse() for data, functions given to timers, constant code, request data passed
// as values (call arguments, the sandbox's context object), numbers, allow-lists.
const FORMULAS = { double: 'x * 2', square: 'x * x' };
app.post('/safe', (req, res) => {
  // ok: js.code-injection
  const data = JSON.parse(req.body.json);
  // ok: js.code-injection
  setTimeout(() => res.json({ data }), Number(req.query.delay));
  // ok: js.code-injection
  const sum = eval('1 + 2');
  // ok: js.code-injection
  const add = new Function('a', 'b', 'return a + b');
  // ok: js.code-injection
  const added = add(req.body.a, req.body.b);
  // ok: js.code-injection
  const scaled = vm.runInNewContext('x * factor', { x: req.body.x, factor: 2 });
  // ok: js.code-injection
  const offset = eval('10 + ' + Number(req.query.offset));
  // ok: js.code-injection
  const picked = vm.runInNewContext(FORMULAS[req.query.formula] || 'x', { x: 3 });
  // ok: js.code-injection
  const bounded = new Function('x', 'return x * ' + parseInt(req.query.factor, 10));
  return { sum, added, scaled, offset, picked, bounded };
});

// Node.js timers throw a TypeError when the callback is not a function, so a string given to
// setTimeout() or setInterval() is never run as code on the server.
app.get('/timer', (req, res) => {
  // ok: js.code-injection
  setTimeout(req.query.code, 10);
  // ok: js.code-injection
  setInterval(req.query.code, 1000);
  res.end();
});

// A lookup with a fallback taken from the request, and a table filled with request data, are no
// allow-lists.
const SNIPPETS = { one: '1', two: '2' };
app.post('/snippets', (req, res) => {
  // ruleid: js.code-injection
  const v = eval(SNIPPETS[req.body.name] || req.body.code);
  SNIPPETS[req.body.name] = req.body.code;
  // ruleid: js.code-injection
  const w = eval(SNIPPETS[req.body.name]);
  res.json({ v, w });
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const QUOTED = { greet: 'it\'s' };
const NESTED = { math: { half: 'x / 2' } };
app.get('/tables', (req, res) => {
  // todook: js.code-injection
  const a = vm.runInNewContext(QUOTED[req.query.k] || '0', { x: 1 });
  // todook: js.code-injection
  const b = vm.runInNewContext(NESTED.math[req.query.k] || '0', { x: 1 });
  res.json({ a, b });
});

// A check of the code before the call is not followed: the value is still reported.
app.get('/checked', (req, res) => {
  const expr = String(req.query.expr);
  if (/^[0-9+\-*/ ().]+$/.test(expr)) {
    // todook: js.code-injection
    return res.json({ value: eval(expr) });
  }
  return res.status(400).end();
});

// Look-alikes: eval-named methods of other libraries, a Script class of another module, and
// functions that are not handlers.
const redis = { eval: async (script, keys, ...args) => [script, keys, args] };
const math = { evaluate: (expr) => expr };
class Script2 {
  constructor(source) {
    this.source = source;
  }
}
app.get('/look-alikes', async (req, res) => {
  // ok: js.code-injection
  const r = await redis.eval('return redis.call("GET", KEYS[1])', 1, req.query.key);
  // ok: js.code-injection
  const m = math.evaluate(req.query.expr);
  // ok: js.code-injection
  const s = new Script2(req.query.source);
  res.json({ r, m, s });
});

function preview(req, opts) {
  // ok: js.code-injection
  return eval(req.query.code);
}

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/run', (request, out) => {
  // todoruleid: js.code-injection
  out.json(eval(request.query.code));
});

const router = { get: (path, done) => done({ query: { code: path } }) };
router.get('/1 + 1', (result) => {
  // todook: js.code-injection
  return eval(result.query.code);
});

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.post('/fastify/eval', async (request, reply) => {
  // ruleid: js.code-injection
  return reply.send({ value: eval(request.body.expr) });
});

fastify.get('/fastify/fn/:body', async (request) => {
  // ruleid: js.code-injection
  return new Function(request.params.body)();
});

fastify.get('/fastify/safe', async (request) => {
  // ok: js.code-injection
  return vm.runInNewContext('a * 2', { a: Number(request.query.a) });
});

// Node http handlers.
const http = require('node:http');
http
  .createServer((req, res) => {
    // ruleid: js.code-injection
    res.end(String(vm.runInNewContext(decodeURIComponent(req.url.slice(1)))));
  })
  .listen(0);

module.exports = { app, fastify, preview };
