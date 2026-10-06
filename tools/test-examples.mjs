// `npm run test:examples`: the example on every rule page (docs/rules/<lang>/<name>.md) does what
// the page says. The noncompliant block, written to a file of its language, must get at least one
// finding of the page's rule, and the compliant block no finding of any rule, when OpenGrep runs
// every rule of rules/ on them. Needs the OpenGrep version package.json pins (OPENGREP names the binary, default
// `opengrep` on PATH), like tools/test-rules.mjs.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { docRules, examples, FENCES } from './docs.mjs';

/**
 * The example files of every page: `{ id, page, kind: 'noncompliant'|'compliant', file, code }`,
 * `file` relative to the directory they are written to. Pages without both blocks are left to
 * `npm run docs -- --check`.
 */
export function exampleCases(root) {
  const cases = [];
  for (const rule of docRules(root)) {
    const full = path.join(root, rule.page);
    if (!existsSync(full)) continue;
    const ex = examples(readFileSync(full, 'utf8'));
    for (const kind of ['noncompliant', 'compliant']) {
      const ext = ex[kind] && FENCES[rule.lang][ex[kind].fence];
      if (ext === undefined) continue;
      cases.push({ id: rule.id, page: rule.page, kind, file: `${rule.lang}/${rule.name}/${kind}${ext}`, code: ex[kind].code });
    }
  }
  return cases;
}

/** The problems of one OpenGrep JSON result over the example files written to `dir`. */
export function exampleProblems(result, cases, dir) {
  const rel = (p) => path.relative(dir, path.resolve(dir, p)).split(path.sep).join('/');
  const found = new Map();
  for (const r of result.results ?? []) {
    const key = `${rel(r.path)}\0${r.check_id}`;
    found.set(key, [...(found.get(key) ?? []), r.start?.line]);
  }
  const problems = [];
  for (const e of result.errors ?? []) {
    if (e.path !== undefined && cases.some((c) => c.file === rel(e.path))) {
      problems.push(`${rel(e.path)}: OpenGrep could not analyse it (${e.type ?? 'error'}): fix the example`);
    }
  }
  for (const c of cases) {
    if (c.kind === 'noncompliant' && !found.has(`${c.file}\0${c.id}`)) problems.push(`${c.page}: the noncompliant example gets no ${c.id} finding`);
    if (c.kind !== 'compliant') continue;
    // A compliant example must be clean for every rule, not only for its own.
    for (const [key, lines] of found) {
      const [file, id] = key.split('\0');
      if (file === c.file) problems.push(`${c.page}: the compliant example gets ${id} findings on lines ${lines.join(', ')} of its code block`);
    }
  }
  if (cases.length === 0) problems.push('no example was tested');
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pinned = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).opengrep;
  const bin = process.env.OPENGREP || 'opengrep';
  const version = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (version.status !== 0 || version.stdout.trim() !== pinned) {
    console.error(`test-examples: ${bin} --version must print ${pinned}, got ${JSON.stringify(version.stdout?.trim())}`);
    process.exit(1);
  }
  const cases = exampleCases(root);
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-examples-'));
  let problems;
  try {
    for (const c of cases) {
      mkdirSync(path.dirname(path.join(dir, c.file)), { recursive: true });
      writeFileSync(path.join(dir, c.file), c.code);
    }
    const run = spawnSync(
      bin,
      // Each example is a few lines: a per-file timeout only measures host load (parallel runs time
      // out at OpenGrep's default 5 s), so it is generous here.
      ['scan', '--json', '--disable-version-check', '--no-rewrite-rule-ids', '--quiet', '--x-ignore-semgrepignore-files', '--no-git-ignore', '--timeout', '120', '--config', 'rules/', dir],
      { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    );
    let result;
    try {
      result = JSON.parse(run.stdout);
    } catch {
      console.error(`test-examples: opengrep exited ${run.status} without JSON:\n${run.stderr}`);
      process.exit(1);
    }
    problems = exampleProblems(result, cases, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  for (const p of problems) console.error(p);
  const pages = new Set(cases.map((c) => c.page)).size;
  console.log(problems.length === 0 ? `test-examples: ok (${pages} pages, OpenGrep ${pinned})` : `test-examples: ${problems.length} problem(s)`);
  process.exit(problems.length === 0 ? 0 : 1);
}
