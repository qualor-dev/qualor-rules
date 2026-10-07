const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

const settings = {};
const counters = {};

// A key from the request selects an object, and a second key or property is written on it:
// with "__proto__" (or "constructor" then "prototype") the write lands on Object.prototype.
app.post('/settings', (req, res) => {
  const { section, key, value } = req.body;
  // ruleid: js.prototype-pollution
  settings[section][key] = value;
  res.json(settings);
});

app.post('/settings/:section/:key', (req, res) => {
  // ruleid: js.prototype-pollution
  settings[req.params.section][req.params.key] = req.body.value;
  res.json(settings);
});

app.get('/count', (req, res) => {
  const bucket = req.query.bucket;
  // ruleid: js.prototype-pollution
  counters[bucket].total = (counters[bucket].total || 0) + 1;
  res.json(counters);
});

app.post('/deep', (req, res) => {
  const parts = String(req.body.path).split('.');
  // ruleid: js.prototype-pollution
  settings[parts[0]][parts[1]][parts[2]] = req.body.value;
  res.json(settings);
});

app.get('/hits/:page', (req, res) => {
  if (req.query.by) {
    // ruleid: js.prototype-pollution
    counters[req.params.page][req.query.by] += 1;
  } else {
    // ruleid: js.prototype-pollution
    counters[req.params.page].hits++;
  }
  res.end();
});

app.post('/headers', (req, res) => {
  const name = req.get('X-Section');
  // ruleid: js.prototype-pollution
  settings[name]['enabled'] = true;
  res.end();
});

app.post('/keys', (req, res) => {
  for (const group of Object.keys(req.body)) {
    // ruleid: js.prototype-pollution
    settings[group].updatedAt = Date.now();
  }
  res.end();
});

// Safe forms: a target without a prototype, a Map, a constant first key, a number, an allow-list
// of keys, and a single computed write (it changes only that object's own prototype).
const ALLOWED_SECTIONS = { ui: 'ui', mail: 'mail' };
app.post('/safe', (req, res) => {
  const { section, key, value } = req.body;
  const store = Object.create(null);
  store.ui = Object.create(null);
  // ok: js.prototype-pollution
  store[section][key] = value;
  const map = new Map([['ui', new Map()]]);
  // ok: js.prototype-pollution
  map.get(section).set(key, value);
  // ok: js.prototype-pollution
  settings.ui[key] = value;
  // ok: js.prototype-pollution
  counters[Number(req.query.slot)].total = 1;
  // ok: js.prototype-pollution
  settings[ALLOWED_SECTIONS[section]][key] = value;
  const flat = {};
  // ok: js.prototype-pollution
  flat[key] = value;
  const nullProto = { __proto__: null, ui: {} };
  // ok: js.prototype-pollution
  nullProto[section][key] = value;
  res.json({ ok: true });
});

// lodash guards its merges: merge and mergeWith since 4.17.5/4.17.11, defaultsDeep since 4.17.12;
// its path setter (baseSet, behind set and setWith) blocks "constructor" and "prototype" as
// path keys (lodash changelog, v4.18.0).
app.post('/merge', (req, res) => {
  // ok: js.prototype-pollution
  const merged = _.merge({}, settings, req.body);
  // ok: js.prototype-pollution
  const filled = _.defaultsDeep({}, req.body, settings);
  // ok: js.prototype-pollution
  const copied = Object.assign({}, req.body);
  // ok: js.prototype-pollution
  _.set(settings, req.body.path, req.body.value);
  res.json({ merged, filled, copied });
});

// A key checked against a literal allow-list before the write: includes() on a const array, has()
// on a const Set, as the condition or as an early return.
const ALLOWED_KEYS = ['theme', 'lang'];
const SECTION_SET = new Set(['ui', 'mail']);
const OPEN_KEYS = ['theme'];
OPEN_KEYS.push(process.env.EXTRA_KEY);
const QUOTED_KEYS = ['it\'s', 'theme'];
app.post('/allowed', (req, res) => {
  if (ALLOWED_KEYS.includes(req.body.section)) {
    // ok: js.prototype-pollution
    settings[req.body.section].value = req.body.value;
  }
  if (!ALLOWED_KEYS.includes(req.body.other)) {
    // ruleid: js.prototype-pollution
    settings[req.body.other].value = req.body.value;
  }
  if (OPEN_KEYS.includes(req.body.extra)) {
    // A list the file changes is no allow-list.
    // ruleid: js.prototype-pollution
    settings[req.body.extra].value = req.body.value;
  }
  if (QUOTED_KEYS.includes(req.body.quoted)) {
    // Lists whose strings hold escaped quotes are not recognised.
    // todook: js.prototype-pollution
    settings[req.body.quoted].value = req.body.value;
  }
  const { area, key } = req.body;
  if (!SECTION_SET.has(area)) return res.status(400).end();
  // ok: js.prototype-pollution
  settings[area][key] = req.body.value;
  return res.end();
});

// The check covers the key only where it is known to be in the list: the then-block or the code
// after an early return, up to a reassignment of the key. Not the else branch.
app.post('/allowed-branches', (req, res) => {
  let section = req.body.section;
  if (ALLOWED_KEYS.includes(section)) {
    // ok: js.prototype-pollution
    settings[section].value = req.body.value;
  } else {
    // ruleid: js.prototype-pollution
    settings[section].value = req.body.value;
  }
  if (ALLOWED_KEYS.includes(section) && req.body.value) {
    // ok: js.prototype-pollution
    settings[section].value = req.body.value;
  } else {
    // ruleid: js.prototype-pollution
    settings[section].value = null;
  }
  if (ALLOWED_KEYS.includes(section)) {
    let note = req.body.note;
    note = String(note);
    // ok: js.prototype-pollution
    settings[section].note = note;
    if (SECTION_SET.has(req.body.area)) {
      // ok: js.prototype-pollution
      settings[section].area = req.body.area;
    } else {
      // ok: js.prototype-pollution
      settings[section].area = 'ui';
    }
    section = req.body.other;
    // ruleid: js.prototype-pollution
    settings[section].value = req.body.value;
  }
  let area = req.body.area;
  if (!SECTION_SET.has(area)) return res.status(400).end();
  // ok: js.prototype-pollution
  settings[area].enabled = true;
  area = req.body.other;
  // ruleid: js.prototype-pollution
  settings[area].enabled = true;
  // A key normalised before the check stays checked.
  let lang = req.body.lang;
  lang = lang.trim();
  if (!ALLOWED_KEYS.includes(lang)) throw new Error('unknown key');
  // ok: js.prototype-pollution
  settings[lang].value = req.body.value;
  // A reassignment inside a nested block (an if or a loop after the check) is not seen.
  if (req.body.override) {
    lang = req.body.override;
  }
  // todoruleid: js.prototype-pollution
  settings[lang].value = req.body.value;
  res.end();
});

// A lookup with a fallback taken from the request is no allow-list.
app.post('/fallback', (req, res) => {
  // ruleid: js.prototype-pollution
  settings[ALLOWED_SECTIONS[req.body.section] || req.body.section][req.body.key] = req.body.value;
  res.end();
});

// A deny-list check of the key before the write is not followed: the write is still reported.
app.post('/checked', (req, res) => {
  const { section, key, value } = req.body;
  if (section === '__proto__' || section === 'constructor' || section === 'prototype') {
    return res.status(400).end();
  }
  // todook: js.prototype-pollution
  settings[section][key] = value;
  return res.end();
});

// Writes through an object first taken from the request in a variable, path setters written as
// loops, and recursive merge helpers are not followed.
app.post('/via-variable', (req, res) => {
  const target = settings[req.body.section];
  // todoruleid: js.prototype-pollution
  target[req.body.key] = req.body.value;
  res.end();
});

function setByPath(object, path, value) {
  const names = path.split('.');
  const last = names.pop();
  let current = object;
  for (const name of names) {
    if (typeof current[name] !== 'object') current[name] = {};
    current = current[name];
  }
  current[last] = value;
}

app.post('/path', (req, res) => {
  // todoruleid: js.prototype-pollution
  setByPath(settings, req.body.path, req.body.value);
  res.end();
});

function deepMerge(target, source) {
  for (const name in source) {
    if (typeof source[name] === 'object' && source[name] !== null) {
      if (typeof target[name] !== 'object') target[name] = {};
      deepMerge(target[name], source[name]);
    } else {
      target[name] = source[name];
    }
  }
  return target;
}

app.post('/merge-own', (req, res) => {
  // todoruleid: js.prototype-pollution
  res.json(deepMerge(settings, JSON.parse(req.body.patch)));
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const QUOTED = { a: 'it\'s' };
const NESTED = { ui: { theme: 'theme' } };
app.post('/tables', (req, res) => {
  // todook: js.prototype-pollution
  settings[QUOTED[req.body.k] || 'a'].x = 1;
  // todook: js.prototype-pollution
  settings[NESTED.ui[req.body.k] || 'a'].x = 1;
  res.end();
});

// Look-alikes: computed reads, writes into arrays by index, and functions that are not handlers.
app.get('/reads', (req, res) => {
  // ok: js.prototype-pollution
  const value = settings[req.query.section][req.query.key];
  const rows = [[0, 0], [0, 0]];
  // ok: js.prototype-pollution
  rows[0][Number(req.query.col)] = 1;
  res.json({ value, rows });
});

function store(req, out) {
  // ok: js.prototype-pollution
  settings[req.body.section][req.body.key] = req.body.value;
}

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.post('/prefs', (request, out) => {
  // todoruleid: js.prototype-pollution
  settings[request.body.section][request.body.key] = request.body.value;
  out.end();
});

const router = { post: (path, done) => done({ body: { section: path } }) };
router.post('/ui', (result) => {
  // todook: js.prototype-pollution
  settings[result.body.section].seen = true;
});

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.post('/fastify/settings', async (request, reply) => {
  // ruleid: js.prototype-pollution
  settings[request.body.section][request.body.key] = request.body.value;
  return reply.send(settings);
});

fastify.get('/fastify/:section', async (request) => {
  // ruleid: js.prototype-pollution
  counters[request.params.section][request.query.key] = 1;
  return counters;
});

// Fastify's JSON parser rejects "__proto__" and "constructor" keys by default, so keys of a
// Fastify JSON body cannot reach the prototype; they are still reported.
fastify.post('/fastify/keys', async (request) => {
  for (const group of Object.keys(request.body)) {
    // todook: js.prototype-pollution
    settings[group].touched = true;
  }
  return settings;
});

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.post('/settings/destructured', ({ body: { section, key, value } }, res) => {
  // ruleid: js.prototype-pollution
  settings[section][key] = value;
  res.end();
});
fastify.post('/counters/destructured', async (request) => {
  const { params: { group: g }, body } = request;
  // ruleid: js.prototype-pollution
  counters[g][body.name] = 1;
  return {};
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.post('/settings/defaults', ({ signedCookies = {} }, res) => {
  // todoruleid: js.prototype-pollution
  settings[signedCookies.section][signedCookies.key] = 1;
  res.end();
});

module.exports = { app, fastify, store, setByPath };
