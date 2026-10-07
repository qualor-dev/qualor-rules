import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import session from 'express-session';

const app = Fastify();

// @fastify/cookie's parseOptions modify the serialization of every cookie the replies set: with
// both flags set there, reply.setCookie() needs no flags of its own.
await app.register(fastifyCookie, { secret: 'my-secret', parseOptions: { httpOnly: true, secure: true, sameSite: 'lax' } });

app.get('/session', async (request, reply) => {
  // ok: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/' });
  // ok: js.insecure-cookie
  reply.cookie('theme', 'dark');
  // A flag given false in the call overrides them, but the file's parseOptions hide it.
  // todoruleid: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/', secure: false });
  return reply.send({ ok: true });
});

// The plugin's options do not reach other libraries.
// ruleid: js.insecure-cookie
export const sessions = session({ secret: 'keyboard cat' });
