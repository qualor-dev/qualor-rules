// A second module of the same app (a .jsx file only so that the test runner reads it).
const fastify = require('fastify')();

// parseOptions that set only one flag: the other still comes from the call, which is not combined
// with them, so a call that sets the missing flag itself is reported too.
fastify.register(require('@fastify/cookie'), { parseOptions: { secure: true } });

fastify.get('/session', async (request, reply) => {
  // ruleid: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/' });
  // todook: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/', httpOnly: true });
  // ok: js.insecure-cookie
  reply.setCookie('session', 'generated', { path: '/', httpOnly: true, secure: true });
  return reply.send({ ok: true });
});
