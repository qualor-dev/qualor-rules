// `npm run test:prefilter [-- <rule.yml|directory>...] [--table]`: every rule's prefilter, the CNF
// of literal words OpenGrep uses to skip files without them (rule-procedure.md step 3,
// "Performance"). OpenGrep 1.30 builds it again for every target file, so a rule whose prefilter is
// None, large or slow to build costs every scan (pack 2026.10.2, LOG.md 2026-10-07). For each rule
// file under rules/ the anchors are expanded (opengrep-core does not read them), then
// `opengrep-core -prefilter_of_rules` must give Some, at most MAX_BYTES of JSON, and build within
// the time budget (budgetFor: the best of RUNS runs, rules one after another, scaled to the host's
// load so a busy host does not fail it). ALLOWED lists the rules allowed to break one limit while
// their BACKLOG.md row is open.
//
// Needs the OpenGrep version package.json pins (OPENGREP names the binary, default `opengrep` on
// PATH, as in tools/test-rules.mjs). OPENGREP_CORE names opengrep-core; by default it is the one
// OpenGrep unpacks into $XDG_CACHE_HOME (or $HOME/.cache)/opengrep/v<version>/semgrep/bin/, and a
// one-line scan unpacks it first when it is missing. --table prints every rule's numbers.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'yaml';
import { BACKLOG_HEADER, parseTable } from './backlog.mjs';
import { ruleFiles } from './rules.mjs';

/**
 * Build-time budget on an idle host. A plain rule builds in ~0.1 s (75–150 ms in the scanner image,
 * process start included; a one-pattern rule 77 ms) and the goal for a rule is ≤ 0.2 s; twice that
 * still fails the rules of the 2026.10.2 slowdown (0.42–2.0 s).
 */
export const BUDGET_MS = 400;
/**
 * On a busy or slow host every build slows by about the same factor (a 2-CPU container with 4–6
 * busy loops: a one-pattern rule 77 → 210–307 ms, a plain Go rule 140 → 396–693 ms, while each rule
 * keeps its ratio to the one-pattern rule: plain rules 1–2.3, the slow ones 5.3–19). So a run over
 * BUDGET_MS is compared with LOAD_RATIO times a one-pattern rule's build (best of RUNS) timed right
 * after it.
 */
export const LOAD_RATIO = 5;
/** Size budget of the prefilter's JSON: a few kB is the norm, 20 kB the most. */
export const MAX_BYTES = 20 * 1024;
/** Runs per rule; the best counts (a run within its budget ends the series). */
export const RUNS = 3;

/** The time budget of one run, given the one-pattern rule's build `refMs` timed with it. */
export const budgetFor = (refMs) => Math.max(BUDGET_MS, Math.round(LOAD_RATIO * refMs));

/**
 * Rules allowed to break one limit ('none': no prefilter; 'size': over MAX_BYTES) while their
 * BACKLOG.md row is not done. The check fails when a listed rule no longer breaks its limit, so
 * the list shrinks as the rows are done: remove the entry in the commit that does the row.
 */
export const ALLOWED = Object.freeze({
  'js.ssrf': { limit: 'none', row: 'js.ssrf#prefilter' },
  'js.template-injection': { limit: 'none', row: 'js.template-injection#prefilter' },
  'python.xss': { limit: 'none', row: 'python.xss#prefilter' },
  'java.xss': { limit: 'none', row: 'java.xss#prefilter' },
  'java.command-injection': { limit: 'none', row: 'java.command-injection#prefilter' },
  'java.open-redirect': { limit: 'none', row: 'java.open-redirect#prefilter' },
  'go.xss': { limit: 'none', row: 'go.xss#prefilter' },
  // Found by this check on 2026-10-07: the 2026-10-06 survey missed the files with anchors.
  'java.xxe': { limit: 'none', row: 'java.xxe#prefilter' },
  'python.code-injection': { limit: 'none', row: 'python.code-injection#prefilter' },
  'python.command-injection': { limit: 'none', row: 'python.command-injection#prefilter' },
  'python.unsafe-deserialization': { limit: 'none', row: 'python.unsafe-deserialization#prefilter' },
  'python.path-traversal': { limit: 'none', row: 'python.path-traversal#prefilter' },
  'python.open-redirect': { limit: 'none', row: 'python.open-redirect#prefilter' },
  'python.regex-injection': { limit: 'none', row: 'python.regex-injection#prefilter' },
  'python.sql-injection': { limit: 'none', row: 'python.sql-injection#prefilter' },
  'python.ssrf': { limit: 'none', row: 'python.ssrf#prefilter' },
  'python.template-injection': { limit: 'none', row: 'python.template-injection#prefilter' },
  'python.xpath-injection': { limit: 'none', row: 'python.xpath-injection#prefilter' },
  'go.tls-verification-disabled': { limit: 'size', row: 'go.tls-verification-disabled#prefilter-size' },
  'java.zip-slip': { limit: 'size', row: 'java.zip-slip#prefilter-size' },
  'js.xss': { limit: 'size', row: 'js.xss#prefilter-size' },
});

/** A rule file's text with its YAML anchors and aliases expanded (opengrep-core ignores them). */
export function expandAnchors(text) {
  const doc = parse(text, { maxAliasCount: -1, merge: true });
  return stringify(doc, { aliasDuplicateObjects: false, lineWidth: 0 });
}

/** The opengrep-core that OpenGrep `pinned` unpacks, or the one OPENGREP_CORE names. */
export function corePath(env, home, pinned) {
  if (env.OPENGREP_CORE) return env.OPENGREP_CORE;
  const cache = env.XDG_CACHE_HOME || path.join(home, '.cache');
  return path.join(cache, 'opengrep', `v${pinned}`, 'semgrep', 'bin', 'opengrep-core');
}

/**
 * The prefilter of rule `id` from `opengrep-core -prefilter_of_rules` stdout:
 * `{ filter: 'some' | 'none', bytes }`, or `{ error }`.
 */
export function parsePrefilter(stdout, id) {
  if (stdout.trim() === '') return { error: 'no output (a YAML anchor left in the file makes opengrep-core print nothing)' };
  let json;
  try {
    json = JSON.parse(stdout);
  } catch {
    return { error: `not JSON: ${JSON.stringify(stdout.slice(0, 80))}` };
  }
  const entry = Array.isArray(json) && json.length === 1 ? json[0] : undefined;
  if (entry?.rule_id !== id) return { error: `want one entry for ${id}, got ${JSON.stringify(stdout.slice(0, 80))}` };
  const bytes = Buffer.byteLength(stdout.trim());
  if (entry.filter === 'None') return { filter: 'none', bytes };
  if (Array.isArray(entry.filter) && entry.filter[0] === 'Some') return { filter: 'some', bytes };
  return { error: `unknown filter ${JSON.stringify(entry.filter).slice(0, 80)}` };
}

/** The rule files of `files` (root-relative, `/`) at or below the `wanted` paths (all when none). */
export function selectRuleFiles(files, wanted) {
  if (wanted.length === 0) return files;
  const out = new Set();
  for (const w of wanted) {
    const p = w.replace(/\/+$/, '');
    const hit = files.filter((f) => f === p || f.startsWith(`${p}/`));
    if (hit.length === 0) throw new Error(`${w} names no rule file under rules/`);
    for (const f of hit) out.add(f);
  }
  return files.filter((f) => out.has(f));
}

const kB = (bytes) => `${(bytes / 1024).toFixed(1)} kB`;

/**
 * The problems of the measured `results` ({ id, ms, budget, filter, bytes } or { id, error }; `ms`
 * is the run that came closest to its `budget`). `rows`: BACKLOG.md rows ({ id, status });
 * `allowed`: ALLOWED; `complete`: every rule was measured.
 */
export function prefilterProblems(results, { allowed = ALLOWED, rows = [], complete = true, maxBytes = MAX_BYTES } = {}) {
  const problems = [];
  const status = new Map(rows.map((r) => [r.id, r.status]));
  const seen = new Set();
  for (const r of results) {
    seen.add(r.id);
    if (r.error !== undefined) {
      problems.push(`${r.id}: opengrep-core gave no prefilter: ${r.error}`);
      continue;
    }
    const allow = Object.hasOwn(allowed, r.id) ? allowed[r.id] : undefined;
    const none = r.filter === 'none';
    const big = !none && r.bytes > maxBytes;
    if (none && allow?.limit !== 'none') {
      problems.push(`${r.id}: prefilter None: OpenGrep matches every file of the language in full (rule-procedure.md "Performance")`);
    }
    if (big && allow?.limit !== 'size') problems.push(`${r.id}: prefilter ${kB(r.bytes)}, budget ${kB(maxBytes)}`);
    const budget = r.budget ?? BUDGET_MS;
    if (r.ms > budget) problems.push(`${r.id}: prefilter build ${Math.round(r.ms)} ms (best of ${RUNS}), budget ${budget} ms`);
    if (allow !== undefined && !(allow.limit === 'none' ? none : big)) {
      problems.push(`${r.id}: ALLOWED (tools/prefilter.mjs) lets it break the ${allow.limit} limit, but it no longer does: remove the entry and mark ${allow.row} done`);
    }
  }
  for (const [id, allow] of Object.entries(allowed)) {
    if (!['none', 'size'].includes(allow.limit)) problems.push(`${id}: ALLOWED limit must be none or size, got ${JSON.stringify(allow.limit)}`);
    if (allow.row?.split('#')[0] !== id) problems.push(`${id}: ALLOWED row ${JSON.stringify(allow.row)} must be a BACKLOG.md row ${id}#<topic>`);
    else if (!status.has(allow.row)) problems.push(`${id}: ALLOWED names BACKLOG.md row ${allow.row}, which does not exist`);
    else if (status.get(allow.row) === 'done') problems.push(`${id}: ALLOWED names BACKLOG.md row ${allow.row}, which is done: fix the rule or reopen the row`);
    if (complete && !seen.has(id)) problems.push(`${id}: in ALLOWED but no rule file has this id`);
  }
  return problems;
}

/** A Markdown table of the measured results. */
export function resultTable(results, allowed = ALLOWED) {
  const lines = ['| rule | build ms | budget ms | size | prefilter | allowed |', '|---|---|---|---|---|---|'];
  for (const r of results) {
    if (r.error !== undefined) lines.push(`| ${r.id} | – | – | – | error: ${r.error} | |`);
    else lines.push(`| ${r.id} | ${Math.round(r.ms)} | ${r.budget ?? BUDGET_MS} | ${r.bytes} B | ${r.filter === 'none' ? 'None' : 'Some'} | ${allowed[r.id]?.limit ?? ''} |`);
  }
  return lines.join('\n');
}

function check(cmd, args, label) {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  if (r.error) throw new Error(`${label}: ${r.error.message}`);
  return r;
}

/** A one-pattern rule: unpacks opengrep-core, and its build is the yardstick of the host's load. */
const REFERENCE_RULE = 'rules:\n  - id: reference\n    languages: [javascript]\n    severity: INFO\n    message: x\n    pattern: reference()\n';

/** opengrep-core of the pinned OpenGrep, unpacked by a one-line scan when it is missing. */
function locateCore(bin, pinned, reference, work) {
  const core = corePath(process.env, process.env.HOME || homedir(), pinned);
  if (!existsSync(core) && !process.env.OPENGREP_CORE) {
    writeFileSync(path.join(work, 'a.js'), 'x = 1;\n');
    check(bin, ['scan', '--config', reference, '--disable-version-check', '--quiet', '--json', path.join(work, 'a.js')], bin);
  }
  if (!existsSync(core)) {
    throw new Error(`no opengrep-core at ${core}: set OPENGREP_CORE to the opengrep-core of OpenGrep ${pinned}`);
  }
  const v = check(core, ['-version'], core);
  if (!v.stdout.includes(`version: ${pinned}`)) throw new Error(`${core} -version must print ${pinned}, got ${JSON.stringify(v.stdout.trim())}`);
  return core;
}

/** One build of the prefilter of `file`: `{ ms, stdout }` or `{ error }`. */
function build(core, file) {
  const start = process.hrtime.bigint();
  const r = spawnSync(core, ['-prefilter_of_rules', file], { encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024 });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  if (r.error) throw new Error(`${core}: ${r.error.message}`);
  if (r.status !== 0) return { error: `exit ${r.status}: ${r.stderr.trim().split('\n').slice(-2).join(' ')}` };
  return { ms, stdout: r.stdout };
}

/**
 * Up to RUNS builds of the prefilter of `file` (all of them when `all`); a run over BUDGET_MS is
 * followed by builds of the `reference` rule that set its budget. Keeps the run closest to its budget.
 */
function measure(core, file, id, reference, all) {
  let best;
  let stdout = '';
  for (let i = 0; i < RUNS; i++) {
    const run = build(core, file);
    if (run.error !== undefined) return { id, error: run.error };
    stdout = run.stdout;
    let budget = BUDGET_MS;
    if (run.ms > budget) {
      // The best of RUNS reference builds: a single one is noisy, and a high one lets a slow rule pass.
      const refs = Array.from({ length: RUNS }, () => build(core, reference)).filter((r) => r.error === undefined);
      if (refs.length > 0) budget = budgetFor(Math.min(...refs.map((r) => r.ms)));
    }
    if (best === undefined || run.ms - budget < best.ms - best.budget) best = { ms: run.ms, budget };
    if (!all && best.ms <= best.budget) break;
  }
  return { id, ...best, ...parsePrefilter(stdout, id) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const argv = process.argv.slice(2);
  const table = argv.includes('--table');
  const wanted = argv.filter((a) => a !== '--table').map((a) => path.relative(root, path.resolve(a)).split(path.sep).join('/'));
  const pinned = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).opengrep;
  const bin = process.env.OPENGREP || 'opengrep';
  const work = mkdtempSync(path.join(tmpdir(), 'qualor-rules-prefilter-'));
  let problems;
  let results;
  let failure;
  try {
    const version = spawnSync(bin, ['--version'], { encoding: 'utf8' });
    if (version.status !== 0 || version.stdout.trim() !== pinned) {
      throw new Error(`${bin} --version must print ${pinned}, got ${JSON.stringify(version.stdout?.trim())}`);
    }
    const files = selectRuleFiles(ruleFiles(root), wanted);
    const reference = path.join(work, 'reference.yml');
    writeFileSync(reference, REFERENCE_RULE);
    const core = locateCore(bin, pinned, reference, work);
    mkdirSync(path.join(work, 'rules'));
    results = [];
    for (const f of files) {
      const expanded = expandAnchors(readFileSync(path.join(root, f), 'utf8'));
      const id = parse(expanded)?.rules?.[0]?.id ?? f;
      const out = path.join(work, 'rules', `${f.split('/').slice(1).join('_')}`);
      writeFileSync(out, expanded);
      results.push(measure(core, out, id, reference, table));
    }
    const rows = parseTable(readFileSync(path.join(root, 'BACKLOG.md'), 'utf8'), BACKLOG_HEADER) ?? [];
    problems = prefilterProblems(results, { rows, complete: wanted.length === 0 });
  } catch (err) {
    failure = err.message;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  if (failure !== undefined) {
    console.error(`prefilter: ${failure}`);
    process.exit(1);
  }
  if (table) console.log(resultTable(results));
  for (const p of problems) console.error(p);
  console.log(
    problems.length === 0
      ? `prefilter: ok (${results.length} rules; Some, at most ${kB(MAX_BYTES)}, built in at most ${BUDGET_MS} ms or ${LOAD_RATIO} times a one-pattern rule, best of ${RUNS}; OpenGrep ${pinned})`
      : `prefilter: ${problems.length} problem(s)`,
  );
  process.exit(problems.length === 0 ? 0 : 1);
}
