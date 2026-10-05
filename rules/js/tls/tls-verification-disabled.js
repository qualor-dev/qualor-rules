const fs = require('node:fs');
const https = require('https');
const tls = require('node:tls');
const http2 = require('node:http2');
const { Agent: HttpsAgent, request: httpsRequest } = require('node:https');
const { connect } = require('tls');
const axios = require('axios');
const undici = require('undici');
const { Agent, Client, Pool, ProxyAgent, buildConnector, setGlobalDispatcher } = require('undici');

const CA = fs.readFileSync('/etc/ssl/private-ca.pem');
const SKIP_VERIFY = false;

// https: request(), get() and Agent with rejectUnauthorized: false, in place, in an options object
// built first, set on that object afterwards, and through constants.
function fetchReport(url, done) {
  // ruleid: js.tls-verification-disabled
  https.request(url, { method: 'POST', rejectUnauthorized: false }, done).end();
  // ruleid: js.tls-verification-disabled
  https.get({ hostname: 'reports.internal', path: '/daily', rejectUnauthorized: false }, done);
  // ruleid: js.tls-verification-disabled
  https.get(url, { rejectUnauthorized: SKIP_VERIFY }, done);
}

function builtOptions(done) {
  // ruleid: js.tls-verification-disabled
  const options = {
    hostname: 'billing.internal',
    port: 443,
    path: '/invoices',
    rejectUnauthorized: false,
  };
  const req = https.request(options, done);
  req.end();
}

function patchedOptions(done) {
  const options = { hostname: 'billing.internal', path: '/' };
  // ruleid: js.tls-verification-disabled
  options.rejectUnauthorized = false;
  return https.get(options, done);
}

function mergedOptions(done) {
  const options = { hostname: 'billing.internal', path: '/' };
  // ruleid: js.tls-verification-disabled
  Object.assign(options, { timeout: 5000, rejectUnauthorized: false });
  return https.get(options, done);
}

// The module required in place: options in place are seen, an options object built first is
// not.
// todoruleid: js.tls-verification-disabled
const LEGACY_TLS = { servername: 'ledger.internal', rejectUnauthorized: false };
function inlineRequire(url, done) {
  // ruleid: js.tls-verification-disabled
  require('node:https').get(url, { rejectUnauthorized: false }, done);
  return require('tls').connect(9443, 'ledger.internal', LEGACY_TLS);
}

function makeAgent() {
  const insecure = false;
  // ruleid: js.tls-verification-disabled
  const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: insecure });
  // ruleid: js.tls-verification-disabled
  const other = new HttpsAgent({
    keepAlive: true,
    rejectUnauthorized: false,
  });
  // ruleid: js.tls-verification-disabled
  httpsRequest('https://example.com/', { rejectUnauthorized: false }).end();
  return [agent, other];
}

// The global agent and an agent's options changed after it is made.
// ruleid: js.tls-verification-disabled
https.globalAgent.options.rejectUnauthorized = false;
function relaxAgent() {
  const agent = new https.Agent({ keepAlive: true });
  // ruleid: js.tls-verification-disabled
  agent.options.rejectUnauthorized = false;
  return agent;
}

// A trusted CA or an identity check does not count while rejectUnauthorized is false: the
// connection goes on whatever the verification finds.
function pinnedButOff(url, done) {
  // ruleid: js.tls-verification-disabled
  https.get(url, { ca: CA, rejectUnauthorized: false }, done);
  // ruleid: js.tls-verification-disabled
  return tls.connect(443, 'pinned.internal', {
    rejectUnauthorized: false,
    checkServerIdentity: (host, cert) => (cert.fingerprint256 === 'AA:BB' ? undefined : new Error('mismatch')),
  });
}

// tls.connect() (all signatures) and http2.connect().
function rawTls(port, host) {
  // ruleid: js.tls-verification-disabled
  const a = tls.connect({ host, port, rejectUnauthorized: false });
  // ruleid: js.tls-verification-disabled
  const b = tls.connect(port, host, { rejectUnauthorized: false }, () => b.write('ping'));
  // ruleid: js.tls-verification-disabled
  const c = connect(port, { rejectUnauthorized: false });
  // ruleid: js.tls-verification-disabled
  const session = http2.connect('https://grpc.internal:8443', { rejectUnauthorized: false });
  return [a, b, c, session];
}

// A literal false inside a configuration branch is reported: the program itself carries the off
// switch.
function configured(config) {
  if (config.allowSelfSigned) {
    // ruleid: js.tls-verification-disabled
    return new https.Agent({ rejectUnauthorized: false });
  }
  return new https.Agent({ ca: CA });
}

// NODE_TLS_REJECT_UNAUTHORIZED = '0' turns off verification for every TLS connection of the
// process (and of a child process given that environment).
// ruleid: js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
function allowSelfSigned(config) {
  if (config.devProxy) {
    // ruleid: js.tls-verification-disabled
    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  }
  // ruleid: js.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
  // ruleid: js.tls-verification-disabled
  Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '0' });
  const { spawn } = require('node:child_process');
  // ruleid: js.tls-verification-disabled
  return spawn('node', ['sync.js'], { env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' } });
}

// axios: an https.Agent given as httpsAgent.
// ruleid: js.tls-verification-disabled
const api = axios.create({ baseURL: 'https://api.internal/', httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
async function getStatus() {
  // ruleid: js.tls-verification-disabled
  return axios.get('https://status.internal/', { httpsAgent: new HttpsAgent({ rejectUnauthorized: false }) });
}

// undici: the connect options of Agent, Client and Pool, ProxyAgent's requestTls and proxyTls,
// and buildConnector().
function undiciClients() {
  // ruleid: js.tls-verification-disabled
  setGlobalDispatcher(new Agent({ connect: { rejectUnauthorized: false } }));
  // ruleid: js.tls-verification-disabled
  const client = new Client('https://localhost:3000', { connect: { rejectUnauthorized: false, ca: CA } });
  // ruleid: js.tls-verification-disabled
  const pool = new undici.Pool('https://db.internal', { connections: 4, connect: { rejectUnauthorized: false } });
  const proxy = new ProxyAgent({
    uri: 'https://proxy.internal:3128',
    // ruleid: js.tls-verification-disabled
    requestTls: { rejectUnauthorized: false },
    // ruleid: js.tls-verification-disabled
    proxyTls: { rejectUnauthorized: false },
  });
  // ruleid: js.tls-verification-disabled
  const connector = buildConnector({ rejectUnauthorized: false });
  const poolOptions = {
    connections: 2,
    // ruleid: js.tls-verification-disabled
    connect: { rejectUnauthorized: false },
  };
  const shared = new Pool('https://ledger.internal', poolOptions);
  return [client, pool, proxy, connector, shared];
}

async function fetchWithDispatcher(url) {
  // ruleid: js.tls-verification-disabled
  const dispatcher = new undici.Agent({ connect: { rejectUnauthorized: false } });
  return fetch(url, { dispatcher });
}

// Safe: verification on (the default or true), a private CA, a pinning identity check.
function safeClients(url, done) {
  // ok: js.tls-verification-disabled
  https.get(url, done);
  // ok: js.tls-verification-disabled
  https.get(url, { rejectUnauthorized: true }, done);
  // ok: js.tls-verification-disabled
  const agent = new https.Agent({ ca: CA, keepAlive: true });
  // ok: js.tls-verification-disabled
  const socket = tls.connect(443, 'pinned.internal', {
    ca: CA,
    checkServerIdentity: (host, cert) => {
      const err = tls.checkServerIdentity(host, cert);
      if (err) return err;
      return cert.fingerprint256 === 'AA:BB' ? undefined : new Error('certificate mismatch');
    },
  });
  // ok: js.tls-verification-disabled
  const client = new Client('https://localhost:3000', { connect: { ca: CA } });
  // ok: js.tls-verification-disabled
  const session = http2.connect('https://grpc.internal:8443', { ca: CA });
  // ok: js.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
  // ok: js.tls-verification-disabled
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  // ok: js.tls-verification-disabled
  const warned = process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0';
  return [agent, socket, client, session, warned];
}

// Judgement: a value from configuration (settings, the environment, a parameter, a value that
// differs by branch) is not reported; the deployment decides and can keep verification on.
function fromConfig(config, url, insecure, done) {
  // ok: js.tls-verification-disabled
  https.get(url, { rejectUnauthorized: config.tls.verify }, done);
  // ok: js.tls-verification-disabled
  https.get(url, { rejectUnauthorized: process.env.TLS_VERIFY !== 'false' }, done);
  // ok: js.tls-verification-disabled
  const agent = new https.Agent({ rejectUnauthorized: !insecure });
  // ok: js.tls-verification-disabled
  const other = new https.Agent({ rejectUnauthorized: insecure ? false : true });
  let verify = true;
  if (config.allowSelfSigned) {
    verify = false;
  }
  // ok: js.tls-verification-disabled
  const socket = tls.connect(443, 'db.internal', { rejectUnauthorized: verify });
  // ok: js.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = config.tlsRejectUnauthorized;
  return [agent, other, socket];
}

// Servers: rejectUnauthorized: false there only means "do not require a client certificate".
function servers(handler) {
  const key = fs.readFileSync('server-key.pem');
  const cert = fs.readFileSync('server-cert.pem');
  // ok: js.tls-verification-disabled
  https.createServer({ key, cert, requestCert: true, rejectUnauthorized: false }, handler).listen(8443);
  // ok: js.tls-verification-disabled
  tls.createServer({ key, cert, requestCert: true, rejectUnauthorized: false }, (s) => s.end()).listen(8444);
  // ok: js.tls-verification-disabled
  http2.createSecureServer({ key, cert, rejectUnauthorized: false }).listen(8445);
  // ok: js.tls-verification-disabled
  const serverOptions = { key, cert, requestCert: true, rejectUnauthorized: false };
  return https.createServer(serverOptions, handler);
}

// Look-alikes: the same option given to APIs that do not do TLS or do not take it (plain http,
// net, fetch() init, axios request config, undici's top-level options, request()), and modules
// of the application named like Node's.
const http = require('node:http');
const net = require('node:net');
const localTls = require('./tls');
function lookAlikes(url, done) {
  // ok: js.tls-verification-disabled
  http.get(url, { rejectUnauthorized: false }, done);
  // ok: js.tls-verification-disabled
  const plain = new http.Agent({ keepAlive: true, rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const sock = net.connect({ port: 6379, rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const res = fetch(url, { rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const viaAxios = axios.get(url, { rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const top = new Agent({ keepAliveTimeout: 10, rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const viaUndici = undici.request(url, { rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const local = localTls.connect({ rejectUnauthorized: false });
  // ok: js.tls-verification-disabled
  const settings = { rejectUnauthorized: false, retries: 3 };
  return [plain, sock, res, viaAxios, top, viaUndici, local, settings];
}

// Known limits.
const { Client: PgClient } = require('pg');
const WebSocket = require('ws');
const sharedTls = require('./shared-tls-options');
const { globalAgent } = require('node:https');
function knownLimits(url, options, verify = false) {
  // An options object from another module or a parameter is not followed.
  // todoruleid: js.tls-verification-disabled
  https.get(url, sharedTls.insecure);
  // Other libraries' TLS options (pg, ws, nodemailer, got, ...) are not in this rule.
  // todoruleid: js.tls-verification-disabled
  const db = new PgClient({ ssl: { rejectUnauthorized: false } });
  // todoruleid: js.tls-verification-disabled
  const ws = new WebSocket('wss://feed.internal', { rejectUnauthorized: false });
  // A host name check that accepts any host, with the chain still verified, is a narrower
  // weakness (CWE-297) than this rule's; it is not reported.
  // todoruleid: js.tls-verification-disabled
  https.get(url, { checkServerIdentity: () => undefined });
  // A parameter whose default is false is configurable by the caller; it is not reported.
  // todoruleid: js.tls-verification-disabled
  const agent = new https.Agent({ rejectUnauthorized: verify });
  // The options of the global agent imported by name, changed later, are not followed (only
  // https.globalAgent and agents made with new https.Agent() are).
  // todoruleid: js.tls-verification-disabled
  globalAgent.options.rejectUnauthorized = false;
  // A spread of an options object declared before is not followed.
  const insecureTls = { rejectUnauthorized: false };
  // todoruleid: js.tls-verification-disabled
  const socket = tls.connect({ host: 'x.internal', port: 443, ...insecureTls });
  return [db, ws, agent, socket];
}

// The bracket form of NODE_TLS_REJECT_UNAUTHORIZED is matched as text: a constant is not followed
// there, and a block comment line that does not start with * still counts.
const TLS_OFF = '0';
function bracketForms() {
  // todoruleid: js.tls-verification-disabled
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = TLS_OFF;
  /*
  // todook: js.tls-verification-disabled
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  */
  // ok: js.tls-verification-disabled
  // process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  // ok: js.tls-verification-disabled
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '1';
}

// A client that turns verification off and checks the certificate itself, as the tls docs
// describe for 'secureConnect' (tlsSocket.authorized), is still reported.
function selfChecked(host) {
  // todook: js.tls-verification-disabled
  const socket = tls.connect(443, host, { ca: CA, rejectUnauthorized: false }, () => {
    if (!socket.authorized) {
      socket.destroy(new Error(String(socket.authorizationError)));
    }
  });
  return socket;
}

module.exports = { api, getStatus, fetchReport, mergedOptions, inlineRequire, builtOptions, patchedOptions, makeAgent, relaxAgent, pinnedButOff, rawTls, configured, allowSelfSigned, undiciClients, fetchWithDispatcher, safeClients, fromConfig, servers, lookAlikes, knownLimits, selfChecked };
