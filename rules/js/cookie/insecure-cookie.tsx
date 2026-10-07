// Another module of a Fastify app (a .tsx file only so that the test runner reads it).
import type { FastifyInstance } from 'fastify';
import formBody from '@fastify/formbody';

// parseOptions of another plugin do not set cookie flags.
export async function app(fastify: FastifyInstance) {
  await fastify.register(formBody, { parseOptions: { secure: true, httpOnly: true } });
  fastify.get('/form', async (request, reply) => {
    // ruleid: js.insecure-cookie
    reply.setCookie('sid', 'v', { path: '/' });
    // ok: js.insecure-cookie
    reply.setCookie('sid', 'v', { path: '/', secure: true, httpOnly: true });
    return 'ok';
  });
}

// A route module of an app that registers @fastify/cookie with both flags in parseOptions in
// another file: those defaults are not seen here.
export async function routes(fastify: FastifyInstance) {
  fastify.get('/login', async (request, reply) => {
    // todook: js.insecure-cookie
    reply.setCookie('session', 'generated', { path: '/' });
    return 'ok';
  });
}
