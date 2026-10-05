// OpenGrep of package.json's version in a qualor/scanner image, for hosts without it (Windows).
//
//   node tools/scanner.mjs test                         (npm run test:docker)
//     `npm ci` and `npm test` on a copy of this tree inside the image (the tree is mounted read-only).
//   node tools/scanner.mjs probe [--recall] [--only a,b] <rule.yml|directory>...     (npm run probe --)
//     Runs the named rules on the REFERENCE.md projects of their languages (`use` noise; --recall adds
//     the recall sets) and on qualor-cc's local main, each cloned at its pinned commit into the main
//     tree's git-ignored .tmp/ (shared by all worktrees), and prints every finding. Exits 1 when a
//     rule reports anything on qualor-cc.
//   node tools/scanner.mjs scan <rule.yml|directory>... -- <file|directory>...       (npm run scan --)
//     Runs the named rules on files of this tree (a reviewer's probe files under .tmp/, say) and
//     prints every finding.
//
// JSON results go to .tmp/probe/<run>/ of this tree. QUALOR_SCANNER_IMAGE names the image (default
// qualor/scanner:6b1); QUALOR_CC names the qualor-cc repository (default ../qualor-cc next to the
// main tree). Containers are named qr-<mode>-<pid> and run with --rm. tools/measure.mjs reuses the
// exported parts.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { referenceProjects } from './backlog.mjs';
import { LANGS } from './rules.mjs';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pinned = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).opengrep;
const image = process.env.QUALOR_SCANNER_IMAGE || 'qualor/scanner:6b1';
// The engine scans every file Qualor scans (tests too) and files up to 1 MiB (qualor-cc's
// MAX_ANALYZED_BYTES); git in the container must accept the mounted repositories.
const SCAN = ['--json', '--disable-version-check', '--no-rewrite-rule-ids', '--quiet', '--x-ignore-semgrepignore-files', '--max-target-bytes', '1048576'];
const GIT_SAFE = ['-e', 'GIT_CONFIG_COUNT=1', '-e', 'GIT_CONFIG_KEY_0=safe.directory', '-e', 'GIT_CONFIG_VALUE_0=*'];
/** How many qualor-cc clones (one per main SHA) the probe keeps. */
const KEEP_QUALOR_CC = 2;

/** `s` quoted for sh. */
export const sq = (s) => `'${String(s).replaceAll("'", "'\\''")}'`;
/** `p` relative to `base`, with `/`. */
const relTo = (base, p) => path.relative(base, path.resolve(p)).split(path.sep).join('/');

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, ...opts });
  if (r.error) throw new Error(`${cmd}: ${r.error.message}`);
  return r;
}

export function git(args) {
  const r = run('git', args);
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr.trim()}`);
  return r.stdout.trim();
}

function docker(args) {
  return spawnSync('docker', args, { stdio: ['ignore', 'inherit', 'inherit'] }).status;
}

/** The main working tree (the parent of the common .git directory), also from a linked worktree. */
export function mainTree() {
  return path.dirname(git(['-C', root, 'rev-parse', '--path-format=absolute', '--git-common-dir']));
}

export function checkImage() {
  const r = run('docker', ['run', '--rm', '--name', `qr-version-${process.pid}`, '--entrypoint', 'opengrep', image, '--version']);
  if (r.status !== 0 || r.stdout.trim() !== pinned) {
    throw new Error(
      `${image}: opengrep --version must print ${pinned}, got ${JSON.stringify(r.stdout.trim() || r.stderr.trim())}; ` +
        `set QUALOR_SCANNER_IMAGE to a qualor/scanner image with OpenGrep ${pinned}`,
    );
  }
}

/**
 * The rules named on the command line, as --config arguments, and their languages: files or
 * directories under rules/, or a scratch rule file (.yml) under .tmp/ such as a reviewer's mutant.
 */
export function configs(list, base = root) {
  if (list.length === 0) throw new Error('name at least one rule file or directory under rules/ (or a .yml file under .tmp/)');
  const langs = new Set();
  const args = [];
  for (const c of list) {
    const r = relTo(base, path.resolve(base, c));
    const full = path.join(base, r);
    const ok = /^rules(\/|$)/.test(r) ? existsSync(full) : /^\.tmp\/.+\.ya?ml$/.test(r) && existsSync(full) && statSync(full).isFile();
    if (!ok) throw new Error(`${c} is not a rule file or directory under rules/, or a .yml file under .tmp/`);
    const lang = r.startsWith('rules/') ? r.split('/')[1] : undefined;
    for (const l of lang ? [lang] : Object.keys(LANGS)) langs.add(l);
    args.push('--config', `/src/${r}`);
  }
  return { args, langs };
}

/** The options of `probe`: --recall, --only a,b (each a REFERENCE.md project or qualor-cc), the rules. */
export function probeArgs(argv, projects) {
  let recall = false;
  let only;
  const list = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--recall') recall = true;
    else if (argv[i] === '--only') {
      only = new Set((argv[++i] ?? '').split(',').filter(Boolean));
      const known = new Set([...projects, 'qualor-cc']);
      const unknown = [...only].filter((p) => !known.has(p));
      if (only.size === 0 || unknown.length > 0) throw new Error(`--only: unknown project(s) ${unknown.join(', ') || '(none given)'}; known: ${[...known].join(', ')}`);
    } else list.push(argv[i]);
  }
  return { recall, only, list };
}

/** A fresh directory for this run's JSON results. */
export function outDir() {
  const out = path.join(root, '.tmp', 'probe', new Date().toISOString().replace(/[:.]/g, '-'));
  mkdirSync(out, { recursive: true });
  return out;
}

/** One OpenGrep JSON result, or undefined when the scan wrote none. */
export function readResult(file) {
  return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : undefined;
}

/** The lines `report` prints for one result: a summary, each finding, and the scan errors. */
export function reportLines(res, label) {
  if (res === undefined) return [`${label}: no result (see its .err file)`];
  const findings = res.results ?? [];
  const errors = res.errors ?? [];
  const lines = [`${label}: ${findings.length} finding(s), ${res.paths?.scanned?.length ?? 0} files scanned, ${errors.length} error(s)`];
  for (const f of findings) {
    const code = (f.extra?.lines ?? '').split('\n')[0].trim().slice(0, 120);
    lines.push(`  ${f.check_id}  ${f.path}:${f.start.line}  ${code}`);
  }
  for (const e of errors) lines.push(`  warning: ${e.type ?? 'error'} ${e.path ?? ''} (files OpenGrep could not analyse are not covered)`.trimEnd());
  return lines;
}

/** Moves a finished clone into place; a concurrent run may have done it first. */
function settle(tmp, dest) {
  try {
    renameSync(tmp, dest);
  } catch {
    rmSync(tmp, { recursive: true, force: true });
    if (!existsSync(dest)) throw new Error(`could not move ${tmp} to ${dest}`);
  }
}

/** A shallow clone of a REFERENCE.md project at its pinned commit in `cache/ref/<project>`. */
export function referenceClone(cache, p) {
  const dest = path.join(cache, 'ref', p.project);
  if (existsSync(dest)) {
    if (run('git', ['-C', dest, 'rev-parse', 'HEAD']).stdout.trim() === p.commit) return dest;
    rmSync(dest, { recursive: true, force: true });
  }
  const tmp = path.join(cache, 'ref', `.${p.project}-${process.pid}`);
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(path.dirname(tmp), { recursive: true });
  console.error(`cloning ${p.repository} at ${p.commit}`);
  git(['init', '-q', tmp]);
  git(['-C', tmp, 'fetch', '-q', '--depth', '1', `${p.repository}.git`, p.commit]);
  git(['-C', tmp, '-c', 'core.longpaths=true', '-c', 'advice.detachedHead=false', 'checkout', '-q', 'FETCH_HEAD']);
  settle(tmp, dest);
  return dest;
}

/** A clone of qualor-cc's local main in `cache/qualor-cc-<sha>`, and the paths Qualor excludes there. */
function qualorCcClone(cache, main) {
  const repo = path.resolve(process.env.QUALOR_CC || path.join(main, '..', 'qualor-cc'));
  const sha = git(['-C', repo, 'rev-parse', 'refs/heads/main']);
  const name = `qualor-cc-${sha.slice(0, 12)}`;
  const dest = path.join(cache, name);
  if (!existsSync(dest)) {
    const tmp = path.join(cache, `.qualor-cc-${process.pid}`);
    rmSync(tmp, { recursive: true, force: true });
    git(['clone', '-q', '--no-checkout', repo, tmp]);
    git(['-C', tmp, '-c', 'core.longpaths=true', '-c', 'advice.detachedHead=false', 'checkout', '-q', '--detach', sha]);
    settle(tmp, dest);
  }
  // Keep the newest clones only (one per qualor-cc main SHA).
  const old = readdirSync(cache)
    .filter((d) => /^qualor-cc-[0-9a-f]{12}$/.test(d) && d !== name)
    .map((d) => ({ d, t: statSync(path.join(cache, d)).mtimeMs }))
    .sort((a, b) => b.t - a.t)
    .slice(KEEP_QUALOR_CC - 1);
  for (const { d } of old) rmSync(path.join(cache, d), { recursive: true, force: true });
  // Qualor scans itself without these paths (qualor.yml sources.exclude): fixtures are vulnerable on purpose.
  const config = parse(readFileSync(path.join(dest, 'qualor.yml'), 'utf8'));
  return { dir: dest, sha, excludes: config?.sources?.exclude ?? [] };
}

/**
 * Scans `targets` ({ name, dir under cache, excludes }) with the --config `args` in one container;
 * each result lands in `<out>/<name>.json` (stderr in `.err`).
 */
export function scanTargets(args, targets, cache, out) {
  const lines = ['set -u'];
  for (const t of targets) {
    const dir = `/cache/${relTo(cache, t.dir)}`;
    const scan = [...args, ...SCAN, ...t.excludes.flatMap((e) => ['--exclude', e]), '--output', `/out/${t.name}.json`, '.'];
    lines.push(`cd ${sq(dir)} && opengrep scan ${scan.map(sq).join(' ')} >/dev/null 2>/out/${t.name}.err || echo "${t.name}: opengrep exited $?" >&2`);
  }
  const status = docker(['run', '--rm', '--name', `qr-probe-${process.pid}`, '-e', 'HOME=/tmp', ...GIT_SAFE, '-v', `${root}:/src:ro`, '-v', `${cache}:/cache:ro`, '-v', `${out}:/out`, '--entrypoint', 'sh', image, '-c', lines.join('\n')]);
  if (status !== 0) throw new Error(`docker exited ${status}`);
}

function test() {
  checkImage();
  const script = [
    'set -e',
    'mkdir /tmp/r',
    'tar -C /src --exclude=./node_modules --exclude=./.tmp --exclude=./.git --exclude=./dist -cf - . | tar -C /tmp/r -xf -',
    'cd /tmp/r',
    'npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1',
    'npm test',
  ].join('\n');
  return docker(['run', '--rm', '--name', `qr-test-${process.pid}`, '-e', 'HOME=/tmp', '-v', `${root}:/src:ro`, '--entrypoint', 'sh', image, '-c', script]) ?? 1;
}

function probe(argv) {
  const projects = referenceProjects(root);
  const { recall, only, list } = probeArgs(argv, projects.map((p) => p.project));
  const { args, langs } = configs(list);
  checkImage();
  const main = mainTree();
  const cache = path.join(main, '.tmp');
  const targets = [];
  for (const p of projects) {
    if (!langs.has(p.lang) || (p.use === 'recall' && !recall && !only?.has(p.project)) || (only && !only.has(p.project))) continue;
    targets.push({ name: p.project, dir: referenceClone(cache, p), excludes: [] });
  }
  if (!only || only.has('qualor-cc')) {
    const cc = qualorCcClone(cache, main);
    targets.push({ name: 'qualor-cc', label: `qualor-cc (main ${cc.sha.slice(0, 12)})`, dir: cc.dir, excludes: cc.excludes });
  }
  const out = outDir();
  scanTargets(args, targets, cache, out);
  let failed = false;
  for (const t of targets) {
    const res = readResult(path.join(out, `${t.name}.json`));
    for (const l of reportLines(res, t.label ?? t.name)) console.log(l);
    if (res === undefined) failed = true;
    if (t.name === 'qualor-cc' && (res?.results?.length ?? 0) > 0) {
      console.log('  qualor-cc must have zero findings: rework the rule (.claude/skills/write-rules/rule-procedure.md).');
      failed = true;
    }
  }
  console.log(`results: ${out}`);
  return failed ? 1 : 0;
}

function scan(argv) {
  const dash = argv.indexOf('--');
  if (dash < 0 || dash === argv.length - 1) throw new Error('scan: <rule.yml|directory>... -- <file|directory>...');
  const { args } = configs(argv.slice(0, dash));
  const targets = argv.slice(dash + 1).map((t) => {
    const r = relTo(root, t);
    if (r.startsWith('..') || path.isAbsolute(r) || !existsSync(path.join(root, r))) throw new Error(`${t} is not a file or directory of this tree`);
    return r;
  });
  checkImage();
  const out = outDir();
  // Named targets under the git-ignored .tmp/ must still be scanned.
  const cmd = ['scan', ...args, ...SCAN, '--no-git-ignore', '--output', '/out/scan.json', ...targets];
  const script = `cd /src && opengrep ${cmd.map(sq).join(' ')} >/dev/null 2>/out/scan.err || echo "opengrep exited $?" >&2`;
  const status = docker(['run', '--rm', '--name', `qr-scan-${process.pid}`, '-e', 'HOME=/tmp', ...GIT_SAFE, '-v', `${root}:/src:ro`, '-v', `${out}:/out`, '--entrypoint', 'sh', image, '-c', script]);
  if (status !== 0) throw new Error(`docker exited ${status}`);
  const res = readResult(path.join(out, 'scan.json'));
  for (const l of reportLines(res, targets.join(' '))) console.log(l);
  return res === undefined ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  try {
    if (mode === 'test') process.exit(test());
    else if (mode === 'probe') process.exit(probe(rest));
    else if (mode === 'scan') process.exit(scan(rest));
    else throw new Error('usage: node tools/scanner.mjs test | probe [--recall] [--only a,b] <rules>... | scan <rules>... -- <paths>...');
  } catch (err) {
    console.error(`scanner: ${err.message}`);
    process.exit(1);
  }
}
