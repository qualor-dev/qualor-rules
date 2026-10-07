const express = require('express');
const session = require('express-session');
const cookieSession = require('cookie-session');
const fastify = require('fastify')();

const app = express();
const config = { cookieSecure: process.env.NODE_ENV === 'production' };

// Express res.cookie(name, value, options): Secure and HttpOnly are off unless the options set them.
app.post('/login', (req, res) => {
  const token = 'generated';
  // ruleid: js.insecure-cookie
  res.cookie('session', token);
  // ruleid: js.insecure-cookie
  res.cookie('session', token, { maxAge: 900000 });
  // ruleid: js.insecure-cookie
  res.cookie('session', token, { httpOnly: true });
  // ruleid: js.insecure-cookie
  res.cookie('session', token, { secure: true });
  // ruleid: js.insecure-cookie
  res.cookie('session', token, { secure: true, httpOnly: false });
  // ruleid: js.insecure-cookie
  res.cookie('session', token, { secure: false, httpOnly: true });
  // ok: js.insecure-cookie
  res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'lax' });
  // ok: js.insecure-cookie
  res.cookie('session', token, { 'secure': true, 'httpOnly': true });
  // A flag decided by configuration is reviewed where it is decided.
  // ok: js.insecure-cookie
  res.cookie('session', token, { secure: config.cookieSecure, httpOnly: true });
  // ruleid: js.insecure-cookie
  res.status(201).cookie('access_token', `Bearer ${token}`, { expires: new Date(Date.now() + 8 * 3600000) }).redirect(301, '/admin');
  // ok: js.insecure-cookie
  res.status(201).cookie('access_token', token, { secure: true, httpOnly: true }).redirect(301, '/admin');
  res.end();
});

// Options built in a variable first; flags set on it before the call count.
const SESSION_COOKIE = { secure: true, httpOnly: true, sameSite: 'strict' };
const PREFERENCE_COOKIE = { maxAge: 31536000000 };

app.post('/session', (req, res) => {
  // ok: js.insecure-cookie
  res.cookie('session', 'generated', SESSION_COOKIE);
  // ruleid: js.insecure-cookie
  res.cookie('theme', 'dark', PREFERENCE_COOKIE);
  const opts = { maxAge: 3600000, httpOnly: true };
  // ruleid: js.insecure-cookie
  res.cookie('remember', '1', opts);
  const hardened = { maxAge: 3600000 };
  hardened.secure = true;
  hardened.httpOnly = true;
  // ok: js.insecure-cookie
  res.cookie('remember', '1', hardened);
  const half = { maxAge: 3600000 };
  half.secure = true;
  // ruleid: js.insecure-cookie
  res.cookie('remember', '1', half);
  const prod = { httpOnly: true };
  if (config.cookieSecure) {
    prod.secure = true;
  }
  // ok: js.insecure-cookie
  res.cookie('session', 'generated', prod);
  // Options spread from another object are decided there.
  // ok: js.insecure-cookie
  res.cookie('session', 'generated', { ...SESSION_COOKIE, maxAge: 60000 });
  res.end();
});

// A cookie that is being deleted holds nothing.
app.post('/logout', (req, res) => {
  // ok: js.insecure-cookie
  res.clearCookie('session');
  // ok: js.insecure-cookie
  res.cookie('session', '', { expires: new Date(0) });
  // ok: js.insecure-cookie
  res.cookie('session', '', { maxAge: 0 });
  res.end();
});

// A helper that takes the response first.
function setAuthCookie(res, token) {
  // ruleid: js.insecure-cookie
  res.cookie('auth', token, { path: '/' });
}

// Look-alikes: jQuery's cookie plugin in the browser and other objects' cookie() methods.
function lookAlikes($, jar) {
  // ok: js.insecure-cookie
  $.cookie('seen', '1', { expires: 7 });
  // ok: js.insecure-cookie
  jar.cookie('seen', '1');
}

// express-session: HttpOnly is on by default, Secure is off unless cookie.secure is set.
// ruleid: js.insecure-cookie
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
// ruleid: js.insecure-cookie
app.use(session({ secret: 'keyboard cat', cookie: { maxAge: 60000 } }));
// ruleid: js.insecure-cookie
app.use(session({ secret: 'keyboard cat', cookie: { secure: true, httpOnly: false } }));
// ok: js.insecure-cookie
app.use(session({ secret: 'keyboard cat', cookie: { secure: true } }));
// ok: js.insecure-cookie
app.use(session({ secret: 'keyboard cat', cookie: { secure: 'auto', httpOnly: true } }));

// The express-session docs' pattern: Secure set on the options in production.
const sess = { secret: 'keyboard cat', cookie: {} };
if (app.get('env') === 'production') {
  app.set('trust proxy', 1);
  sess.cookie.secure = true;
}
// ok: js.insecure-cookie
app.use(session(sess));
const devSession = { secret: 'keyboard cat', cookie: { maxAge: 60000 } };
// ruleid: js.insecure-cookie
app.use(session(devSession));

// cookie-session: Secure follows the connection by default, HttpOnly is on by default; only an
// explicit false turns either off.
// ok: js.insecure-cookie
app.use(cookieSession({ name: 'session', keys: ['key1', 'key2'], maxAge: 24 * 60 * 60 * 1000 }));
// ruleid: js.insecure-cookie
app.use(cookieSession({ name: 'session', keys: ['key1'], secure: false }));
// ruleid: js.insecure-cookie
app.use(cookieSession({ name: 'session', keys: ['key1'], httpOnly: false }));

// Fastify @fastify/cookie: reply.setCookie (and its alias reply.cookie); flags unset by default.
fastify.register(require('@fastify/cookie'), { secret: 'my-secret' });
fastify.get('/fastify/login', async (request, reply) => {
  // ruleid: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/' });
  // ruleid: js.insecure-cookie
  reply.cookie('session', 'generated', { path: '/', httpOnly: true });
  // ok: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/', secure: 'auto', httpOnly: true });
  // ok: js.insecure-cookie
  reply.clearCookie('session', { path: '/' });
  return reply.send({ ok: true });
});

// Known limits.
const cookieDefaults = require('./cookie-defaults');
function limits(res, options) {
  // Options passed in or imported are not followed.
  // todoruleid: js.insecure-cookie
  res.cookie('session', 'generated', options);
  // todoruleid: js.insecure-cookie
  res.cookie('session', 'generated', cookieDefaults);
  // A Set-Cookie header written by hand is not parsed.
  // todoruleid: js.insecure-cookie
  res.setHeader('Set-Cookie', 'session=generated; Path=/');
  // Options in a variable whose literal holds no cookie option are not followed.
  const blank = {};
  // todoruleid: js.insecure-cookie
  res.cookie('session', 'generated', blank);
  // An assignment of false after the literal counts as deciding the flag.
  const relaxed = { httpOnly: true };
  relaxed.secure = false;
  // todoruleid: js.insecure-cookie
  res.cookie('session', 'generated', relaxed);
  // A cookie deleted with an expiry in the past other than the epoch is reported.
  // todook: js.insecure-cookie
  res.cookie('session', '', { expires: new Date(1) });
}

module.exports = { app, fastify, setAuthCookie, lookAlikes, limits };
