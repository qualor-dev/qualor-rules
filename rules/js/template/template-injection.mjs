import express from 'express';
import ejs from 'ejs';
import pug from 'pug';
import nunjucks from 'nunjucks';
import Handlebars from 'handlebars';
import _ from 'lodash';
import helpers from './view-helpers.js';
import { escape } from 'lodash';
import { escape as esc } from 'lodash';

// EJS registered as the engine of .html views.
const app = express();
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');

app.get('/page', (req, res) => {
  // ruleid: js.template-injection
  res.render('page', req.query);
});

app.post('/page', (req, res) => {
  // ruleid: js.template-injection
  res.render('page', { title: 'Page', ...req.body });
});

app.get('/page-safe', (req, res) => {
  // ok: js.template-injection
  res.render('page', { q: req.query.q, user: req.body.user });
});

// Functions of these names that take no template source (default imports).
const blank = _.create();
app.post('/engine-names', (req, res) => {
  const text = req.body.text;
  // ok: js.template-injection
  const a = nunjucks.render(text, {});
  // ok: js.template-injection
  const b = nunjucks.precompile(text);
  // ok: js.template-injection
  const c = Handlebars.template(text);
  // ok: js.template-injection
  const d = pug.renderString(text);
  // ok: js.template-injection
  const g = helpers.render(text);
  // (a module's default export called directly, not lodash.template's)
  // ok: js.template-injection
  const h = helpers(text);
  // ok: js.template-injection
  const i = blank.compile(text);
  // ok: js.template-injection
  const j = pug.compile('p= name', req.body);
  // ok: js.template-injection
  const k = pug.render('p= name', req.body);
  // ok: js.template-injection
  const m = escape(text);
  // ok: js.template-injection
  const n = esc(text);
  // ok: js.template-injection
  const o = helpers.compile(text);
  // ok: js.template-injection
  const p = _(text);
  res.json({ a, b, c, d, g, h, i, j, k, m, n, o, p });
});

export default app;
