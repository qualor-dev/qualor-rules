const express = require('express');
const http = require('node:http');
const _ = require('lodash');
const { escapeRegExp } = require('lodash');
const escapeOne = require('lodash/escapeRegExp');
const escapeStandalone = require('lodash.escaperegexp');
const { normalizeTerm, cleanTerm: tidyTerm } = require('./search-helpers');

const app = express();
app.use(express.json());

const ARTICLES = ['first post', 'second post'];

// Express: query strings, route parameters, bodies, headers and cookies as the pattern, in place,
// through a variable, and built into a string.
app.get('/search', (req, res) => {
  // ruleid: js.regex-injection
  const pattern = new RegExp(req.query.q, 'i');
  res.json(ARTICLES.filter((a) => pattern.test(a)));
});

app.get('/grep/:expr', (req, res) => {
  // ruleid: js.regex-injection
  const re = RegExp(req.params.expr);
  res.json(ARTICLES.filter((a) => re.test(a)));
});

app.post('/validate', (req, res) => {
  const rule = req.body.rule;
  // ruleid: js.regex-injection
  const ok = new RegExp(rule).test(req.body.value);
  // ruleid: js.regex-injection
  const starts = new RegExp('^' + req.body.prefix).test('some text');
  // ruleid: js.regex-injection
  const whole = new RegExp(`^${req.body.word}$`, 'u');
  res.json({ ok, starts, whole: whole.test('word') });
});

app.get('/highlight', (req, res) => {
  const term = String(req.cookies.term);
  // A length check does not stop a short catastrophic pattern such as (a+)+$.
  if (term.length > 40) {
    return res.status(400).end();
  }
  // ruleid: js.regex-injection
  const marked = 'some text'.replace(new RegExp(term, 'g'), '<mark>$&</mark>');
  res.send(marked);
});

app.get('/split', (req, res) => {
  // ruleid: js.regex-injection
  const parts = 'a,b;c'.split(new RegExp(`[${req.get('X-Separators')}]`));
  // ruleid: js.regex-injection
  const any = new RegExp(req.headers['x-words'].split(',').join('|'));
  // ruleid: js.regex-injection
  const global = new globalThis.RegExp(req.query.g);
  res.json({ parts, any: any.source, global: global.source });
});

// A pattern sent to the database still runs there (MongoDB evaluates a RegExp value).
app.get('/users', async (req, res) => {
  // ruleid: js.regex-injection
  const filter = { name: new RegExp(req.query.name, 'i') };
  res.json(filter);
});

// Safe forms: escaped input, request data as the subject of a constant pattern, includes(),
// request data as flags only, numbers.
app.get('/safe', (req, res) => {
  const q = String(req.query.q);
  // ok: js.regex-injection
  const a = new RegExp(RegExp.escape(q), 'i');
  // ok: js.regex-injection
  const b = new RegExp('^' + _.escapeRegExp(req.query.prefix));
  // ok: js.regex-injection
  const c = new RegExp(`\\b${escapeRegExp(req.query.word)}\\b`);
  // ok: js.regex-injection
  const d = RegExp(escapeOne(req.query.term) + '$');
  // ok: js.regex-injection
  const e = new RegExp(escapeStandalone(req.query.other));
  // ok: js.regex-injection
  const f = /^[a-z0-9-]+$/.test(req.query.slug);
  // ok: js.regex-injection
  const g = new RegExp('^[a-z]+$').test(req.query.name);
  // ok: js.regex-injection
  const h = req.query.text.replace(/\s+/g, ' ');
  // ok: js.regex-injection
  const i = ARTICLES.filter((x) => x.includes(req.query.q));
  // ok: js.regex-injection
  const j = new RegExp('^[a-z]+$', req.query.flags);
  // ok: js.regex-injection
  const k = new RegExp('^.{' + Number(req.query.n) + '}$');
  // ok: js.regex-injection
  const l = new RegExp('\\d{' + parseInt(req.query.digits, 10) + '}');
  res.json({ a: a.source, b: b.source, c: c.source, d: d.source, e: e.source, f, g, h, i, j: j.source, k: k.source, l: l.source });
});

// Allow-lists: the request only picks one of the file's constant patterns.
const FILTERS = {
  // Patterns a client may pick.
  digits: '\\d+',
  words: '\\w+', // the default
};
const SEPARATORS = Object.freeze({ csv: '[,;]', space: '\\s+' });
const KINDS = new Map([
  ['date', '\\d{4}-\\d{2}-\\d{2}'],
  ['time', '\\d{2}:\\d{2}'],
]);
const ORDER = ['^a', '^b'];
app.get('/filter', (req, res) => {
  // ok: js.regex-injection
  const a = new RegExp(FILTERS[req.query.kind]);
  // ok: js.regex-injection
  const b = new RegExp(SEPARATORS[req.query.sep] || '\\s+');
  // ok: js.regex-injection
  const c = new RegExp(KINDS.get(req.query.kind));
  // ok: js.regex-injection
  const d = new RegExp(ORDER[Number(req.query.i)]);
  // ok: js.regex-injection
  const e = new RegExp(req.query.mode === 'strict' ? '^[a-z]+$' : '[a-z]+');
  res.json([a, b, c, d, e].map((r) => r.source));
});

// A lookup with a request-data fallback, and a table filled with request data, are no allow-lists.
const SAVED = { recent: '20\\d\\d' };
app.post('/saved', (req, res) => {
  // ruleid: js.regex-injection
  const a = new RegExp(FILTERS[req.body.kind] || req.body.pattern);
  // ruleid: js.regex-injection
  const b = new RegExp(KINDS.get(req.body.kind) ?? req.body.pattern);
  SAVED[req.body.name] = req.body.pattern;
  // ruleid: js.regex-injection
  const c = new RegExp(SAVED[req.body.name]);
  res.json([a, b, c].map((r) => r.source));
});

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const QUOTED = { name: '[a-z\'-]+' };
const NESTED = { date: { iso: '\\d{4}-\\d{2}-\\d{2}' } };
app.get('/tables', (req, res) => {
  // todook: js.regex-injection
  const a = new RegExp(QUOTED[req.query.k] || '^$');
  // todook: js.regex-injection
  const b = new RegExp(NESTED.date[req.query.k] || '^$');
  res.json([a.source, b.source]);
});

// A value checked against a literal allow-list (a const array or Set of string literals the file
// never changes) with an early return or throw is one of those strings afterwards.
const SORT_FIELDS = ['title', 'author', 'date'];
const LANGS = Object.freeze(['en', 'de']);
const MODES = new Set(['prefix', 'suffix']);
const OPEN_FIELDS = ['title'];
OPEN_FIELDS.push('body');
app.get('/sorted', (req, res) => {
  const field = String(req.query.field);
  if (!SORT_FIELDS.includes(field)) return res.status(400).end();
  // ok: js.regex-injection
  const a = new RegExp(`^${field}:`);
  if (!LANGS.includes(req.query.lang)) {
    return res.status(400).end();
  }
  // ok: js.regex-injection
  const b = new RegExp(req.query.lang + '$');
  if (!MODES.has(req.query.mode)) throw new Error('unknown mode');
  // ok: js.regex-injection
  const c = new RegExp(req.query.mode);
  res.json([a, b, c].map((r) => r.source));
});

app.get('/sorted2', (req, res) => {
  // A list the file changes, and a check that does not return, are no allow-lists.
  if (!OPEN_FIELDS.includes(req.query.field)) return res.status(400).end();
  // ruleid: js.regex-injection
  const a = new RegExp(req.query.field);
  if (!SORT_FIELDS.includes(req.query.other)) {
    res.status(400);
  }
  // ruleid: js.regex-injection
  const b = new RegExp(req.query.other);
  // The check as the condition of an if around the use is not followed.
  if (SORT_FIELDS.includes(req.query.third)) {
    // todook: js.regex-injection
    const c = new RegExp(req.query.third);
    return res.json([a.source, b.source, c.source]);
  }
  return res.json([a.source, b.source]);
});

// The check covers the value up to its next assignment: a value given another request value after
// the check is request data again. A value normalised before the check stays checked.
app.get('/sorted3', (req, res) => {
  let q = req.query.q;
  q = q.trim();
  if (!SORT_FIELDS.includes(q)) return res.status(400).end();
  // ok: js.regex-injection
  const a = new RegExp(`^${q}:`);
  q = req.query.other;
  // ruleid: js.regex-injection
  const b = new RegExp(q);
  let mode = req.query.mode;
  if (!MODES.has(mode)) throw new Error('unknown mode');
  // ok: js.regex-injection
  const c = new RegExp(mode);
  // An assignment inside a nested block after the check is not seen.
  if (req.query.custom) {
    mode = req.query.custom;
  }
  // todoruleid: js.regex-injection
  const d = new RegExp(mode);
  // A destructuring assignment after the check is not seen either.
  let [term] = [req.query.term];
  if (!SORT_FIELDS.includes(term)) return res.status(400).end();
  [term] = [req.query.other];
  // todoruleid: js.regex-injection
  const e = new RegExp(term);
  res.json([a, b, c, d, e].map((r) => r.source));
});

// A sink inside a callback given to an awaited method of another object is still a sink.
const txdb = { transaction: async (work) => work({}) };
const jobQueue = { run: async (r, jobs) => jobs.map((job) => job()) };
app.get('/tx-search', async (req, res) => {
  const found = [];
  await txdb.transaction(async (t) => {
    // ruleid: js.regex-injection
    found.push(new RegExp(req.query.q).source);
  });
  // ruleid: js.regex-injection
  await jobQueue.run(res, [() => found.push(new RegExp(req.query.r).source)]);
  await txdb.transaction({
    done() {
      // ruleid: js.regex-injection
      found.push(new RegExp(req.query.s).source);
    },
  });
  res.json(found);
});

// The value of an awaited call that is given a callback stays stored data, and so does a lookup
// awaited inside the callback.
const pageCache = { wrap: async (key, build) => build() };
const Items = { find: (query) => ({ sort: async (compare) => [] }) };
app.get('/cached/:key', async (req, res) => {
  const page = await pageCache.wrap(req.params.key, async () => '^built$');
  // ok: js.regex-injection
  const a = new RegExp(page);
  const rows = await Items.find({ q: req.query.q }).sort((x, y) => x.n - y.n);
  // ok: js.regex-injection
  const b = new RegExp(rows[0].pattern);
  await txdb.transaction(async (t) => {
    const saved = await t.filters.findOne({ id: req.params.key });
    // ok: js.regex-injection
    res.json(new RegExp(saved.pattern).source);
  });
  res.json([a.source, b.source]);
});

// An element of a request array reached through a callback parameter is not followed.
app.post('/filters', (req, res) => {
  // todoruleid: js.regex-injection
  const compiled = req.body.filters.map((filter) => new RegExp(filter.pattern));
  res.json(compiled.length);
});

// Data loaded with a request value as its key is not request data; a function imported by name
// and an awaited formatter return what they are given, so their results stay request data.
const Filter = { findById: async (id) => ({ pattern: '^' + id.length + '$' }) };
const text = { format: async (value) => value, clean: async (value) => value };
app.get('/stored/:id', async (req, res) => {
  const saved = await Filter.findById(req.params.id);
  // ok: js.regex-injection
  const a = new RegExp(saved.pattern);
  // ruleid: js.regex-injection
  const b = new RegExp(await normalizeTerm(req.query.q));
  const tidy = await tidyTerm(req.query.q);
  // ruleid: js.regex-injection
  const c = new RegExp(tidy);
  // ruleid: js.regex-injection
  const d = new RegExp(await text.format(req.query.q));
  // A method of another object that returns the request value it is given is not followed.
  const cleaned = await text.clean(req.query.q);
  // todoruleid: js.regex-injection
  const e = new RegExp(cleaned);
  res.json([a, b, c, d, e].map((r) => r.source));
});

// A pattern validated first by a constant pattern and a pattern stripped to letters and digits are
// not followed: the value is still reported. The common hand-written escape is escaping: a global
// replace() whose character class holds every syntax character of regular expressions
// (^ $ \ . * + ? ( ) [ ] { } |), with the "\\$&" replacement (a backslash before the whole match),
// inline or in a local helper that only returns it.
function escapeForPattern(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
app.get('/checked', (req, res) => {
  const word = String(req.query.word);
  if (!/^[\w ]+$/.test(word)) {
    return res.status(400).end();
  }
  // todook: js.regex-injection
  const a = new RegExp(`\\b${word}\\b`);
  // todook: js.regex-injection
  const b = new RegExp(req.query.q.replace(/[^a-z0-9]/gi, ''));
  // ok: js.regex-injection
  const c = new RegExp(String(req.query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  // ok: js.regex-injection
  const d = new RegExp(escapeForPattern(req.query.q));
  res.json([a, b, c, d].map((r) => r.source));
});

const quoteForPattern = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const literalPattern = function (value) {
  return `${value}`.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
};
const wordPattern = (value) => {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};
app.get('/escaped', (req, res) => {
  // ok: js.regex-injection
  const a = new RegExp(`^${quoteForPattern(req.query.q)}$`, 'i');
  // ok: js.regex-injection
  const b = new RegExp(literalPattern(req.query.q) + '$');
  // ok: js.regex-injection
  const c = new RegExp(`\\b${wordPattern(req.query.q)}\\b`);
  // A helper declared after its use is not followed.
  // todook: js.regex-injection
  const d = new RegExp(escapeDeclaredLater(req.query.q));
  // The characters in another order, escaped inside the class, with more characters, and with
  // other flags and quotes.
  // ok: js.regex-injection
  const e = new RegExp(req.query.q.replace(/[\\^$.*+?()[\]{}|\-\/]/gu, "\\$&"));
  // ok: js.regex-injection
  const f = new RegExp(req.query.q.replaceAll(/[\|\\\{\}\(\)\[\]\^\$\+\*\?\.]/g, `\\$&`));
  res.json([a, b, c, d, e, f].map((r) => r.source));
});
function escapeDeclaredLater(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// An escape that misses a syntax character, replaces only the first match, uses a negated class
// or another replacement, and a helper that may return the value unescaped are no escaping.
function escapeSome(value) {
  return value.replace(/[.*+?^$]/g, '\\$&');
}
const searchTools = { escapeForPattern: (value) => value.trim() };
function escapeLong(value) {
  if (value.length < 3) return value;
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
app.get('/half-escaped', (req, res) => {
  // ruleid: js.regex-injection
  const a = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]]/g, '\\$&'));
  // ruleid: js.regex-injection
  const b = new RegExp(req.query.q.replace(/[.*+?^${}()[\]\\]/g, '\\$&'));
  // ruleid: js.regex-injection
  const c = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/, '\\$&'));
  // ruleid: js.regex-injection
  const d = new RegExp(req.query.q.replace(/[^.*+?${}()|[\]\\]/g, '\\$&'));
  // ruleid: js.regex-injection
  const e = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '$&'));
  // ruleid: js.regex-injection
  const f = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$1'));
  // ruleid: js.regex-injection
  const g = new RegExp(escapeSome(req.query.q));
  // ruleid: js.regex-injection
  const h = new RegExp(escapeLong(req.query.q));
  // ruleid: js.regex-injection
  const i = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + req.query.tail);
  // ruleid: js.regex-injection
  const j = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]x/g, '\\$&'));
  // A method of another object named like the local helper is not the helper.
  // ruleid: js.regex-injection
  const k = new RegExp(searchTools.escapeForPattern(req.query.q));
  // With the sticky flag (y), replace() stops at the first character that is not in the class.
  // ruleid: js.regex-injection
  const l = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/gy, '\\$&'));
  res.json([a, b, c, d, e, f, g, h, i, j, k, l].map((r) => r.source));
});

// Other ways to write the same escape are not recognised: a replacement function, a pattern held
// in a constant, a helper of another module, and a class whose range holds every syntax character.
// A call chained after an escape written in place is not checked: one that takes the escapes out
// again is missed.
const SPECIAL = /[.*+?^${}()|[\]\\]/g;
const { escapeText } = require('./regex-text');
app.get('/escaped-otherwise', (req, res) => {
  // todook: js.regex-injection
  const a = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, (m) => '\\' + m));
  // todook: js.regex-injection
  const b = new RegExp(req.query.q.replace(SPECIAL, '\\$&'));
  // todook: js.regex-injection
  const c = new RegExp(escapeText(req.query.q));
  // todook: js.regex-injection
  const d = new RegExp(req.query.q.replace(/[!-~]/g, '\\$&'));
  // todoruleid: js.regex-injection
  const e = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\/g, ''));
  res.json([a, b, c, d, e].map((r) => r.source));
});

// String methods that turn a string argument into a pattern (match, matchAll, search) are not
// followed: their receivers have no type, and search/match are common method names of other
// libraries. A MongoDB $regex query operator is not in the rule either.
const Article = { find: async (query) => [query] };
app.get('/implicit', async (req, res) => {
  // todoruleid: js.regex-injection
  const a = 'first post'.match(req.query.q);
  // todoruleid: js.regex-injection
  const b = 'second post'.search(req.query.q);
  // todoruleid: js.regex-injection
  const c = await Article.find({ title: { $regex: req.query.q } });
  res.json({ a, b, c });
});

// Look-alikes: another library's regular expression class, and a function that is not a handler.
const RE2 = require('re2');
app.get('/re2', (req, res) => {
  // ok: js.regex-injection
  const re = new RE2(req.query.q);
  res.json(ARTICLES.filter((a) => re.test(a)));
});

function buildFilter(req, options) {
  // ok: js.regex-injection
  return new RegExp(req.query.q, options.flags);
}

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/find', (request, out) => {
  // todoruleid: js.regex-injection
  out.json(new RegExp(request.query.q).source);
});

const router = { get: (path, done) => done({ query: { q: path } }) };
router.get('/[a-z]+', (result) => {
  // todook: js.regex-injection
  return new RegExp(result.query.q);
});

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.get('/fastify/search', async (request, reply) => {
  // ruleid: js.regex-injection
  return reply.send(ARTICLES.filter((a) => new RegExp(request.query.q).test(a)));
});

fastify.post('/fastify/match/:field', async (request) => {
  // ruleid: js.regex-injection
  const re = new RegExp(request.body.pattern + request.params.field);
  // ok: js.regex-injection
  const safe = new RegExp(RegExp.escape(request.body.pattern));
  return { re: re.source, safe: safe.source };
});

// Node http handlers.
http
  .createServer((req, res) => {
    const term = new URL(req.url, 'http://localhost').searchParams.get('term');
    // ruleid: js.regex-injection
    res.end(String(new RegExp(term).test('some text')));
  })
  .listen(0);

// Handlers that destructure the request (parameter list or declaration) give request data too.
app.get('/search/destructured', ({ query: { q } }, res) => {
  // ruleid: js.regex-injection
  res.json(ARTICLES.filter((a) => new RegExp(q, 'i').test(a)));
});
fastify.get('/search/destructured', async (request) => {
  const { query: { term: needle } } = request;
  // ruleid: js.regex-injection
  return ARTICLES.filter((a) => RegExp(needle).test(a));
});

// A field with a default value in a destructured parameter is no source (Known limits).
app.get('/search/defaults', ({ query = {} }, res) => {
  // todoruleid: js.regex-injection
  res.json(ARTICLES.filter((a) => new RegExp(query.q).test(a)));
});

module.exports = { app, fastify, buildFilter };
