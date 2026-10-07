const express = require('express');
const { exec, execSync, execFile, spawn, spawnSync, execFileSync } = require('child_process');
const childProcess = require('node:child_process');
const util = require('node:util');

const app = express();
app.use(express.json());

// exec and execSync run their command through a shell.
app.get('/ping', (req, res) => {
  // ruleid: js.command-injection
  exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout));
});

app.get('/files/:dir', (req, res) => {
  const dir = req.params.dir;
  // ruleid: js.command-injection
  const out = execSync(`ls -la ${dir}`);
  // ruleid: js.command-injection
  childProcess.exec('du -sh ' + req.params.dir);
  // ruleid: js.command-injection
  require('child_process').execSync('wc -l ' + req.get('X-File'));
  // ok: js.command-injection
  execFile('ls', ['-la', dir], (err, stdout) => res.send(stdout));
  // ok: js.command-injection
  spawn('ls', ['-la', req.params.dir]);
  // ok: js.command-injection
  execSync('ls -la /var/data');
  res.send(out);
});

app.post('/convert', (req, res) => {
  const { input, format } = req.body;
  const cmd = 'convert ' + input + ' out.' + format;
  // ruleid: js.command-injection
  execSync(cmd);
  // ruleid: js.command-injection
  exec(util.format('gzip %s', req.body.file));
  // ruleid: js.command-injection
  childProcess.execSync(`tar -czf backup.tgz ${req.cookies.folder}`, { cwd: '/tmp' });
  // ok: js.command-injection
  execFileSync('convert', [input, 'out.png']);
  const size = Number.parseInt(req.body.size, 10);
  // ok: js.command-injection
  execSync('head -c ' + size + ' /dev/urandom');
  const mode = req.body.mode === 'fast' ? 'fast' : 'safe';
  // ok: js.command-injection
  execSync('backup --mode ' + mode);
  res.end();
});

// spawn, spawnSync, execFile and execFileSync run a shell only with the shell option: then the
// arguments are joined into a command line.
app.get('/grep', (req, res) => {
  // ruleid: js.command-injection
  spawn('grep', ['-r', req.query.pattern, '.'], { shell: true });
  // ruleid: js.command-injection
  spawnSync('find', ['.', '-name', req.query.name], { shell: '/bin/bash' });
  // ruleid: js.command-injection
  execFile('git', ['log', req.query.ref], { shell: true }, () => {});
  const args = ['-n', req.query.count];
  // ruleid: js.command-injection
  childProcess.execFileSync('tail', args, { shell: true });
  // ok: js.command-injection
  spawn('grep', ['-r', req.query.pattern, '.'], { shell: false });
  // ok: js.command-injection
  spawn('grep', ['-r', req.query.pattern, '.'], { cwd: '/srv' });
  // ok: js.command-injection
  spawn('grep -r TODO .', { shell: true });
  res.end();
});

// The program itself taken from the request runs whatever the client names.
app.post('/run', (req, res) => {
  // ruleid: js.command-injection
  spawn(req.body.program, ['--version']);
  // ruleid: js.command-injection
  execFile(req.body.program, [], () => {});
  // ruleid: js.command-injection
  childProcess.fork(req.body.script);
  // ok: js.command-injection
  childProcess.fork('./workers/resize.js', [req.body.image]);
  res.end();
});

// util.promisify(exec), as in the Node.js documentation.
const execAsync = util.promisify(require('node:child_process').exec);
const pexec = util.promisify(exec);

app.get('/version/:tool', async (req, res) => {
  // ruleid: js.command-injection
  const { stdout } = await execAsync(req.params.tool + ' --version');
  // ruleid: js.command-injection
  await pexec(`which ${req.params.tool}`);
  // ok: js.command-injection
  await execAsync('node --version');
  res.send(stdout);
});

// Allow-list lookups in tables declared const in this file yield only the table's values.
const RUNNERS = { list: 'ls', where: 'pwd' };
const SORTS = new Map([['size', '-S'], ['time', '-t']]);
const PAGERS = ['less', 'more'];

app.get('/runner', (req, res) => {
  // ok: js.command-injection
  execFile(RUNNERS[req.query.op] || 'true', ['-1'], () => res.end());
  const flag = SORTS.get(req.query.sort) ?? '';
  // ok: js.command-injection
  exec('ls ' + flag);
  // ok: js.command-injection
  spawn(PAGERS[req.query.pager], ['README.md']);
  // ruleid: js.command-injection
  exec('ls ' + req.query.sort + ' ' + flag);
});

// A lookup with a request-data fallback is no allow-list: when the key is missing, the request
// value itself runs. A constant fallback, or another lookup of a literal table, stays clean.
app.get('/runner-fallback', (req, res) => {
  // ruleid: js.command-injection
  execFile(RUNNERS[req.query.op] || req.query.program, [], () => res.end());
  // ruleid: js.command-injection
  exec('ls ' + (SORTS.get(req.query.sort) ?? req.query.flags));
  const pager = PAGERS[req.query.pager] ?? req.body.pager;
  // ruleid: js.command-injection
  spawn(pager, ['README.md']);
  // ruleid: js.command-injection
  exec(RUNNERS[req.query.op] ? RUNNERS[req.query.op] : req.query.op);
  const typed = req.query.cmd;
  // ruleid: js.command-injection
  exec(RUNNERS[req.query.op] || typed);
  let tool = RUNNERS[req.query.op];
  tool ||= req.query.tool;
  // ruleid: js.command-injection
  exec(tool);
  let order = SORTS.get(req.query.sort);
  order ??= req.query.sort;
  // ruleid: js.command-injection
  exec('ls ' + order);
  // ok: js.command-injection
  exec(RUNNERS[req.query.op] || RUNNERS.list);
  // ok: js.command-injection
  exec('ls ' + (SORTS.get(req.query.sort) ?? ''));
  // ok: js.command-injection
  spawn(PAGERS[req.query.pager] ?? PAGERS[0], ['README.md']);
});

// Tables built from or filled with request data are no allow-lists.
const LAST = {};

app.post('/tables', (req, res) => {
  const pieces = [req.query.folder, '-h'];
  // ruleid: js.command-injection
  exec('du ' + pieces[0]);
  const job = { script: req.body.script };
  // ruleid: js.command-injection
  exec(job['script']);
  const fields = { ...req.query };
  // ruleid: js.command-injection
  execSync('echo ' + fields[req.query.key]);
  const vars = new Map([['target', req.query.target]]);
  // ruleid: js.command-injection
  exec('make ' + vars.get('target'));
  LAST[req.body.slot] = req.body.command;
  // ruleid: js.command-injection
  exec(LAST[req.body.slot]);
  const pending = [];
  pending.push(req.body.task);
  // ruleid: js.command-injection
  execSync(pending[0]);
  const named = new Map();
  named.set('job', req.body.job);
  // ruleid: js.command-injection
  exec(named.get('job'));
  const PRESETS = { quick: 'ls' };
  PRESETS[req.body.name] = req.body.cmd;
  // ruleid: js.command-injection
  exec(PRESETS[req.query.preset]);
  res.end();
});

// A literal table that the file writes to, in another function or a nested block, is no
// allow-list.
const ALIASES = { up: 'uptime' };
app.post('/alias', (req, res) => {
  ALIASES[req.body.name] = req.body.cmd;
  res.end();
});
app.get('/alias/:name', (req, res) => {
  // ruleid: js.command-injection
  exec(ALIASES[req.params.name]);
  res.end();
});

const SHORTCUTS = { disk: 'df -h' };
app.post('/shortcut', (req, res) => {
  if (req.body.save) {
    SHORTCUTS[req.body.label] = req.body.command;
  }
  // ruleid: js.command-injection
  execSync(SHORTCUTS[req.body.label]);
  res.end();
});

// Literal allow-lists written with comments, across lines or frozen.
const ARCHIVERS = {
  zip: 'zip -r', // the default
  /* streaming */ tar: 'tar -czf',
};
const SIGNALS = Object.freeze({ stop: 'SIGTERM', kill: 'SIGKILL' });
const LEVELS = [
  'info',
  'debug', // verbose
];

// Tables whose strings hold escaped quotes, and nested tables, are not recognised.
const GREETINGS = { formal: 'echo \'good day\'' };
const GROUPS = { net: { ip: 'ip addr', routes: 'ip route' } };

app.get('/presets', (req, res) => {
  // ok: js.command-injection
  exec(ARCHIVERS[req.query.kind] + ' out.archive data');
  // ok: js.command-injection
  exec('kill -s ' + SIGNALS[req.query.sig] + ' 1234');
  // ok: js.command-injection
  exec('logger -p user.' + LEVELS[req.query.level] + ' started');
  // todook: js.command-injection
  exec(GREETINGS[req.query.style] || 'true');
  // todook: js.command-injection
  exec(GROUPS.net[req.query.view] || 'true');
  res.end();
});

// A shell program given its command flag runs the next argument as a command line.
app.get('/script', (req, res) => {
  // ruleid: js.command-injection
  spawn('sh', ['-c', req.query.script]);
  // ruleid: js.command-injection
  execFileSync('/bin/bash', ['-c', 'echo ' + req.query.msg]);
  // ok: js.command-injection
  spawn('sh', ['-c', 'ls -la /srv']);
  // ok: js.command-injection
  spawn('sh', ['-c', 'du -sh -- "$1"', 'sh', req.query.folder]);
  // ruleid: js.command-injection
  spawn('powershell.exe', ['-NoProfile', '-Command', 'Get-Item ' + req.query.item]);
  // An argument array built before the call is not followed.
  const shellArgs = ['-c', req.query.script];
  // todoruleid: js.command-injection
  spawn('sh', shellArgs);
  // ok: js.command-injection
  spawn('bash', ['./scripts/build.sh', req.query.target]);
  // ruleid: js.command-injection
  spawn('bash', ['-lc', 'make ' + req.query.target]);
  // ok: js.command-injection
  spawn('bash', ['-l', './scripts/deploy.sh', req.query.target]);
  res.end();
});

// cmd.exe runs everything after /c (or /k) as one command line, also after other switches such
// as /d and /s, so request data in any later element is part of the command.
app.get('/cmd', (req, res) => {
  // ruleid: js.command-injection
  spawn('cmd.exe', ['/c', 'dir', req.query.folder]);
  // ruleid: js.command-injection
  spawn('cmd', ['/d', '/s', '/c', 'type', req.query.file]);
  // ruleid: js.command-injection
  execFileSync('C:\\Windows\\System32\\cmd.exe', ['/C', 'echo', req.query.msg]);
  // ruleid: js.command-injection
  spawnSync('CMD.EXE', ['/k', 'cd', '/d', req.query.dir]);
  // ruleid: js.command-injection
  childProcess.spawn('cmd.exe', ['/c', 'convert.bat', req.query.input, 'out.png']);
  // ok: js.command-injection
  spawn('cmd.exe', ['/c', 'my.bat']);
  // ok: js.command-injection
  spawn('cmdtool', ['/c', req.query.folder]);
  res.end();
});

// PowerShell (pwsh, powershell.exe; parameter names in any case): every element after -Command
// (-c) is part of the command; the first string after -CommandWithArgs (-cwa) is the command and
// the later ones fill $args; the element after -EncodedCommand (-e, -ec) is the command in
// Base64; the element after -File (-f) is the script to run. After -File and its script, or
// after a .ps1 script given to pwsh without it (File is pwsh's default parameter), the elements
// are the script's parameters.
app.get('/pwsh', (req, res) => {
  // ruleid: js.command-injection
  spawn('pwsh', ['-NoProfile', '-Command', 'Get-ChildItem', req.query.path]);
  // ruleid: js.command-injection
  execFile('pwsh.exe', ['-c', 'Get-Item', '-Path', req.query.path], () => {});
  // ruleid: js.command-injection
  spawnSync('powershell', ['-NonInteractive', '-COMMAND', `Get-Item ${req.query.item}`]);
  // ruleid: js.command-injection
  childProcess.spawn('C:\\Program Files\\PowerShell\\7\\pwsh.exe', ['-NoLogo', '-Command', req.query.cmd]);
  // ruleid: js.command-injection
  spawn('pwsh', ['-CommandWithArgs', req.query.script, 'first']);
  const encoded = Buffer.from('Get-Item ' + req.query.item, 'utf16le').toString('base64');
  // ruleid: js.command-injection
  spawn('powershell.exe', ['-NoProfile', '-EncodedCommand', encoded]);
  // ruleid: js.command-injection
  spawnSync('pwsh', ['-ec', Buffer.from(req.query.script, 'utf16le').toString('base64')]);
  // ruleid: js.command-injection
  spawn('pwsh', ['-NoProfile', '-File', req.query.script]);
  // ok: js.command-injection
  spawn('pwsh', ['-cwa', '$args | ForEach-Object { Get-Item -LiteralPath $_ }', req.query.path]);
  // ok: js.command-injection
  spawn('pwsh', ['-NoProfile', '-File', './scripts/report.ps1', '-Name', req.query.name]);
  // ok: js.command-injection
  spawn('powershell.exe', ['-File', 'C:\\scripts\\report.ps1', '-c', req.query.name]);
  // ok: js.command-injection
  spawn('pwsh', ['-f', './scripts/report.ps1', '-Command', req.query.name, '-e', req.query.env]);
  // ok: js.command-injection
  spawn('pwsh', ['-NoProfile', './scripts/rotate.ps1', '-e', req.query.env, '-c', req.query.name]);
  // ok: js.command-injection
  spawn('powershell', ['-ExecutionPolicy', req.query.policy, '-File', './scripts/tool.ps1']);
  // ok: js.command-injection
  spawn('pwsh', ['-WorkingDirectory', req.query.dir, '-Command', 'Get-ChildItem']);
  // ok: js.command-injection
  spawn('pwsh', ['-NoProfile', '-Command', 'Get-Date']);
  // After the command of -cwa, every element fills $args, also one that reads like a parameter.
  // ok: js.command-injection
  spawn('pwsh', ['-cwa', 'Write-Output $args', '-c', req.query.name]);
  // The first positional element is pwsh's File parameter: the script to run. It may follow
  // switches, or parameters with their values.
  // ruleid: js.command-injection
  spawn('pwsh', [req.query.script]);
  // ruleid: js.command-injection
  spawn('pwsh', ['-NoProfile', '-NonInteractive', req.query.script, 'first']);
  // ruleid: js.command-injection
  spawnSync('pwsh.exe', ['-ExecutionPolicy', 'Bypass', req.query.script]);
  // ok: js.command-injection
  spawn('pwsh', ['./scripts/report.ps1', req.query.name]);
  // ok: js.command-injection
  spawn('pwsh', ['-NoProfile', './scripts/report.ps1', '-NoExit', req.query.name]);
  // about_PowerShell_exe names no default parameter for powershell.exe, so a -c after a script
  // given without -File is taken for -Command there.
  // ruleid: js.command-injection
  spawn('powershell.exe', ['./scripts/report.ps1', '-c', req.query.name]);
  // Shortened parameter names that the documentation does not list are not recognised.
  // todoruleid: js.command-injection
  spawn('pwsh', ['-Comm', req.query.cmd]);
  // todoruleid: js.command-injection
  spawn('powershell', ['-enc', req.query.encoded]);
  res.end();
});

// Sources are the request block of the SQL rule: a handler is recognised by the name of its
// second parameter, and a one-parameter callback after a path literal is taken for a route.
app.get('/archive', (request, out) => {
  // todoruleid: js.command-injection
  execSync('zip -r out.zip ' + request.query.dir);
  out.end();
});

const http = { get: (path, done) => done({ query: { name: path } }) };
http.get('/archive/latest', (result) => {
  // todook: js.command-injection
  execSync('zip -r latest.zip ' + result.query.name);
});

// Options built before the call: the shell setting is not followed.
app.get('/list', (req, res) => {
  const options = { shell: true };
  // todoruleid: js.command-injection
  spawn('ls', [req.query.dir], options);
  res.end();
});

// An allow-list check before the call is not recognised as a guard.
const TOOLS = ['git', 'node'];
app.get('/which', (req, res) => {
  if (!TOOLS.includes(req.query.tool)) return res.sendStatus(400);
  // todook: js.command-injection
  execSync('which ' + req.query.tool);
  res.end();
});

// Look-alikes: exec of regular expressions, SQLite and other objects.
const Database = require('better-sqlite3');
const db = new Database('app.db');
const runner = { exec: (s) => s };

app.post('/other', (req, res) => {
  // ok: js.command-injection
  const m = /^(\w+)$/.exec(req.body.name);
  // ok: js.command-injection
  db.exec('CREATE TABLE IF NOT EXISTS t (x)');
  // ok: js.command-injection
  runner.exec(req.body.name);
  res.json({ m });
});

// Functions that are not request handlers: their parameters are no request.
function archive(job, opts) {
  // ok: js.command-injection
  execSync('tar -czf out.tgz ' + job.query.dir + opts);
}

// Fastify: (request, reply) handlers and handlers that take only the request.
const fastify = require('fastify')();

fastify.post('/jobs/:name', async (request, reply) => {
  // ruleid: js.command-injection
  exec('run-job ' + request.params.name);
  // ok: js.command-injection
  execFile('run-job', [request.params.name]);
  return reply.send({});
});

fastify.post('/jobs', async (request) => {
  // ruleid: js.command-injection
  execSync(`run-job ${request.body.name}`);
  return {};
});

module.exports = { app, fastify, archive };
