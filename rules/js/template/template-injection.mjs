import express from 'express';
import ejs from 'ejs';

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

export default app;
