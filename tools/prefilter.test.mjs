import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse, parseDocument, visit } from 'yaml';
import { BACKLOG_HEADER, parseTable } from './backlog.mjs';
import { ALLOWED, BUDGET_MS, KILL_MS, LOAD_RATIO, MAX_BYTES, budgetFor, buildOutcome, corePath, expandAnchors, measure, parsePrefilter, prefilterProblems, resultTable, selectRuleFiles } from './prefilter.mjs';
import { ruleFiles } from './rules.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rows = parseTable(readFileSync(path.join(root, 'BACKLOG.md'), 'utf8'), BACKLOG_HEADER);

const hasAlias = (text) => {
  let found = false;
  visit(parseDocument(text), {
    Alias: () => {
      found = true;
      return visit.BREAK;
    },
  });
  return found;
};

test('expandAnchors keeps the data and drops every anchor and alias', () => {
  const text = 'a: &x\n  - pattern: f($X)\n  - pattern: g($X)\nb:\n  - *x\n  - *x\n';
  const out = expandAnchors(text);
  assert.deepEqual(parse(out), parse(text, { maxAliasCount: -1 }));
  assert.equal(hasAlias(out), false);
  assert.doesNotMatch(out, /&x/);
});

test('expandAnchors keeps every rule of the repository the same', () => {
  let anchored = 0;
  for (const f of ruleFiles(root)) {
    const text = readFileSync(path.join(root, f), 'utf8');
    if (hasAlias(text)) anchored++;
    const out = expandAnchors(text);
    assert.equal(hasAlias(out), false, f);
    assert.deepEqual(parse(out), parse(text, { maxAliasCount: -1 }), f);
  }
  assert.ok(anchored > 0, 'some rule uses anchors');
});

test('expandAnchors does not fold long lines', () => {
  const long = `rules:\n  - id: x\n    pattern-regex: ${'a'.repeat(200)}\n`;
  assert.equal(expandAnchors(long).split('\n').filter((l) => l.includes('a'.repeat(200))).length, 1);
});

test('corePath: OPENGREP_CORE, then XDG_CACHE_HOME, then HOME/.cache', () => {
  assert.equal(corePath({ OPENGREP_CORE: '/x/core' }, '/home/n', '1.30.0'), '/x/core');
  assert.equal(corePath({ XDG_CACHE_HOME: '/c' }, '/home/n', '1.30.0'), path.join('/c', 'opengrep', 'v1.30.0', 'semgrep', 'bin', 'opengrep-core'));
  assert.equal(corePath({}, '/home/node', '1.30.0'), path.join('/home/node', '.cache', 'opengrep', 'v1.30.0', 'semgrep', 'bin', 'opengrep-core'));
});

test('parsePrefilter reads Some, None and the size', () => {
  const some = '[{"rule_id":"go.weak-hash","filter":["Some",["Or",[["Pred",["Idents",["md5"]]]]]]}]\n';
  assert.deepEqual(parsePrefilter(some, 'go.weak-hash'), { filter: 'some', bytes: some.trim().length });
  assert.deepEqual(parsePrefilter('[{"rule_id":"go.xss","filter":"None"}]\n', 'go.xss'), { filter: 'none', bytes: 38 });
});

test('parsePrefilter refuses empty, foreign and malformed output', () => {
  assert.match(parsePrefilter('', 'go.xss').error, /anchor/);
  assert.match(parsePrefilter('oops', 'go.xss').error, /not JSON/);
  assert.match(parsePrefilter('[{"rule_id":"go.ssrf","filter":"None"}]', 'go.xss').error, /want one entry for go\.xss/);
  assert.match(parsePrefilter('[]', 'go.xss').error, /want one entry/);
  assert.match(parsePrefilter('[{"rule_id":"go.xss","filter":["Maybe"]}]', 'go.xss').error, /unknown filter/);
  assert.equal(parsePrefilter('[{"rule_id":"go.xss"}]', 'go.xss').error, 'unknown filter undefined');
});

test('selectRuleFiles takes files and directories, and refuses a path without rules', () => {
  const files = ['rules/go/xss/xss.yml', 'rules/go/ssrf/ssrf.yml', 'rules/js/xss/xss.yml'];
  assert.deepEqual(selectRuleFiles(files, []), files);
  assert.deepEqual(selectRuleFiles(files, ['rules/go/']), files.slice(0, 2));
  assert.deepEqual(selectRuleFiles(files, ['rules/js/xss/xss.yml', 'rules/go/xss']), ['rules/go/xss/xss.yml', 'rules/js/xss/xss.yml']);
  assert.throws(() => selectRuleFiles(files, ['rules/python']), /names no rule file/);
  assert.throws(() => selectRuleFiles(files, ['rules/go/x']), /names no rule file/);
});

test('budgetFor: BUDGET_MS, or LOAD_RATIO times the one-pattern rule on a busy host', () => {
  assert.equal(budgetFor(0), BUDGET_MS);
  assert.equal(budgetFor(77), BUDGET_MS);
  assert.equal(budgetFor(210), LOAD_RATIO * 210);
  assert.equal(budgetFor(80), BUDGET_MS);
  assert.equal(budgetFor(100.2), 501);
});

const SOME = '[{"rule_id":"go.x","filter":["Some",["Pred",["Idents",["x"]]]]}]\n';
const REF = 'reference.yml';

/** A builder that answers the rule's and the reference's builds from two scripts, and counts them. */
function scripted(rule, ref = []) {
  const calls = { rule: 0, ref: 0 };
  const next = (list, i) => {
    const step = list[Math.min(i, list.length - 1)];
    return typeof step === 'number' ? { ms: step, stdout: SOME } : step;
  };
  const builder = (file) => (file === REF ? next(ref, calls.ref++) : next(rule, calls.rule++));
  return { builder, calls };
}
const judge = (r) => prefilterProblems([r], { allowed: {}, rows: [], complete: false });

test('measure: a slow run then a fast one passes (best of 3), and the reference is built only for the slow run', () => {
  const { builder, calls } = scripted([900, 120], [80]);
  const r = measure(builder, 'go.yml', 'go.x', REF, false);
  assert.deepEqual(r, { id: 'go.x', ms: 120, budget: BUDGET_MS, fastest: 120, filter: 'some', bytes: SOME.trim().length });
  assert.deepEqual(calls, { rule: 2, ref: 3 });
  assert.deepEqual(judge(r), []);
});

test('measure: no reference build when the first run is within BUDGET_MS', () => {
  const { builder, calls } = scripted([BUDGET_MS], [80]);
  assert.equal(measure(builder, 'go.yml', 'go.x', REF, false).ms, BUDGET_MS);
  assert.deepEqual(calls, { rule: 1, ref: 0 });
});

test('measure: a slow rule on an idle host fails after three runs', () => {
  const { builder, calls } = scripted([700], [90, 80, 80]);
  const r = measure(builder, 'go.yml', 'go.x', REF, false);
  assert.equal(r.ms, 700);
  assert.equal(r.budget, BUDGET_MS);
  assert.deepEqual(calls, { rule: 3, ref: 9 });
  assert.match(judge(r).join('\n'), /go\.x: prefilter build 700 ms \(best of 3\), budget 400 ms/);
});

test('measure: on a busy host a run within 5 references passes and one over fails', () => {
  // Reference 250 ms (best of its three builds): budget 1,250 ms.
  const busy = scripted([700], [300, 250, 260]);
  const pass = measure(busy.builder, 'go.yml', 'go.x', REF, false);
  assert.deepEqual([pass.ms, pass.budget], [700, 1250]);
  assert.deepEqual(busy.calls, { rule: 1, ref: 3 });
  assert.deepEqual(judge(pass), []);
  const slow = scripted([3000], [250]);
  const fail = measure(slow.builder, 'go.yml', 'go.x', REF, false);
  assert.deepEqual([fail.ms, fail.budget], [3000, 1250]);
  assert.deepEqual(slow.calls, { rule: 3, ref: 9 });
  assert.match(judge(fail).join('\n'), /build 3000 ms \(best of 3\), budget 1250 ms/);
  // The line is LOAD_RATIO times the reference: 4.99 passes, 5.01 fails.
  assert.deepEqual(judge(measure(scripted([499], [100]).builder, 'go.yml', 'go.x', REF, false)), []);
  assert.equal(judge(measure(scripted([501], [100]).builder, 'go.yml', 'go.x', REF, false)).length, 1);
});

test('measure: the run closest to its budget is judged; --table runs all three and keeps the fastest', () => {
  // 600 ms with a 1,000 ms budget beats 450 ms with a 400 ms budget.
  const { builder, calls } = scripted([450, 600, 900], [80, 80, 80, 200, 200, 200, 80]);
  const r = measure(builder, 'go.yml', 'go.x', REF, true);
  assert.deepEqual([r.ms, r.budget, r.fastest], [600, 1000, 450]);
  assert.deepEqual(calls, { rule: 3, ref: 9 });
  const fast = scripted([100, 90, 95]);
  assert.deepEqual(measure(fast.builder, 'go.yml', 'go.x', REF, true).fastest, 90);
  assert.deepEqual(fast.calls, { rule: 3, ref: 0 });
});

test('measure: a failed or killed build is the rule\'s error and is not retried', () => {
  for (const error of ['exit 2: oops', 'killed by SIGSEGV', 'build over 30 s (killed)']) {
    const { builder, calls } = scripted([{ error }, 100]);
    assert.deepEqual(measure(builder, 'go.yml', 'go.x', REF, false), { id: 'go.x', error });
    assert.deepEqual(calls, { rule: 1, ref: 0 });
  }
  // A later failure also ends the series.
  const late = scripted([700, { error: 'exit 2: oops' }], [80]);
  assert.deepEqual(measure(late.builder, 'go.yml', 'go.x', REF, false), { id: 'go.x', error: 'exit 2: oops' });
});

test('measure: failed reference builds leave the budget at BUDGET_MS', () => {
  const none = measure(scripted([700], [{ error: 'exit 1: x' }]).builder, 'go.yml', 'go.x', REF, false);
  assert.equal(none.budget, BUDGET_MS);
  // The ones that worked still count.
  const some = measure(scripted([700], [{ error: 'exit 1: x' }, 200]).builder, 'go.yml', 'go.x', REF, false);
  assert.equal(some.budget, 1000);
});

test('buildOutcome: timeout, signal, exit status, success', () => {
  assert.deepEqual(buildOutcome({ error: Object.assign(new Error('t'), { code: 'ETIMEDOUT' }), signal: 'SIGKILL' }, 30000, 'core'), { error: `build over ${KILL_MS / 1000} s (killed)` });
  assert.throws(() => buildOutcome({ error: Object.assign(new Error('spawn core ENOENT'), { code: 'ENOENT' }) }, 1, 'core'), /core: spawn core ENOENT/);
  assert.deepEqual(buildOutcome({ status: null, signal: 'SIGSEGV', stderr: 'a\nb\nc\n' }, 5, 'core'), { error: 'killed by SIGSEGV: b c' });
  assert.deepEqual(buildOutcome({ status: null, signal: 'SIGSEGV', stderr: '' }, 5, 'core'), { error: 'killed by SIGSEGV' });
  assert.deepEqual(buildOutcome({ status: 2, signal: null, stderr: 'oops\n' }, 5, 'core'), { error: 'exit 2: oops' });
  assert.deepEqual(buildOutcome({ status: 0, signal: null, stdout: SOME, stderr: '' }, 5, 'core'), { ms: 5, stdout: SOME });
});

const ok = (id, extra = {}) => ({ id, ms: 100, filter: 'some', bytes: 2000, ...extra });
const opts = (extra = {}) => ({ allowed: {}, rows: [], complete: true, ...extra });

test('a rule within every limit passes', () => {
  assert.deepEqual(prefilterProblems([ok('go.weak-hash')], opts()), []);
  assert.deepEqual(prefilterProblems([ok('go.weak-hash', { ms: BUDGET_MS, bytes: MAX_BYTES })], opts()), []);
});

test('None, size and build time each fail', () => {
  assert.match(prefilterProblems([ok('go.xss', { filter: 'none', bytes: 39 })], opts()).join('\n'), /go\.xss: prefilter None/);
  assert.match(prefilterProblems([ok('go.insecure-cookie', { bytes: 6500415 })], opts()).join('\n'), /go\.insecure-cookie: prefilter 6500\.4 kB, budget 20\.0 kB/);
  assert.match(prefilterProblems([ok('js.nosql-injection', { ms: BUDGET_MS + 1 })], opts()).join('\n'), /js\.nosql-injection: prefilter build 401 ms \(best of 3\), budget 400 ms/);
  assert.equal(prefilterProblems([ok('go.ssrf', { ms: 592, bytes: 66626 })], opts()).length, 2);
  // A run on a busy host is held to the budget measured with it.
  assert.deepEqual(prefilterProblems([ok('go.command-injection', { ms: 693, budget: 1535 })], opts()), []);
  assert.match(prefilterProblems([ok('js.nosql-injection', { ms: 3305, budget: 1050 })], opts()).join('\n'), /build 3305 ms \(best of 3\), budget 1050 ms/);
  assert.match(prefilterProblems([{ id: 'go.xss', error: 'no output' }], opts()).join('\n'), /go\.xss: opengrep-core gave no prefilter: no output/);
});

test('ALLOWED lets a rule with an open row break its one limit, and only that one', () => {
  const rowsOpen = [{ id: 'go.xss#prefilter', status: 'todo' }, { id: 'go.ssrf#prefilter-size', status: 'in-progress' }];
  const allowed = { 'go.xss': { limit: 'none', row: 'go.xss#prefilter' }, 'go.ssrf': { limit: 'size', row: 'go.ssrf#prefilter-size' } };
  const none = ok('go.xss', { filter: 'none', bytes: 39 });
  assert.deepEqual(prefilterProblems([none, ok('go.ssrf', { bytes: 66626 })], opts({ allowed, rows: rowsOpen })), []);
  // Time is never allowed.
  assert.match(prefilterProblems([{ ...none, ms: 900 }, ok('go.ssrf', { bytes: 66626 })], opts({ allowed, rows: rowsOpen })).join('\n'), /go\.xss: prefilter build 900 ms/);
  // A 'size' entry does not allow None.
  assert.match(prefilterProblems([none, ok('go.ssrf', { filter: 'none', bytes: 40 })], opts({ allowed, rows: rowsOpen })).join('\n'), /go\.ssrf: prefilter None/);
});

test('ALLOWED fails when a listed rule no longer needs it', () => {
  const allowed = { 'go.xss': { limit: 'none', row: 'go.xss#prefilter' } };
  const rowsOpen = [{ id: 'go.xss#prefilter', status: 'todo' }];
  assert.match(prefilterProblems([ok('go.xss')], opts({ allowed, rows: rowsOpen })).join('\n'), /go\.xss: ALLOWED .* no longer does: remove the entry and mark go\.xss#prefilter done/);
  const size = { 'go.ssrf': { limit: 'size', row: 'go.ssrf#prefilter-size' } };
  assert.match(prefilterProblems([ok('go.ssrf')], opts({ allowed: size, rows: [{ id: 'go.ssrf#prefilter-size', status: 'todo' }] })).join('\n'), /no longer does/);
});

test('ALLOWED needs an open BACKLOG.md row of the same rule and an existing rule', () => {
  const none = ok('go.xss', { filter: 'none', bytes: 39 });
  const allowed = { 'go.xss': { limit: 'none', row: 'go.xss#prefilter' } };
  assert.match(prefilterProblems([none], opts({ allowed })).join('\n'), /row go\.xss#prefilter, which does not exist/);
  assert.match(prefilterProblems([none], opts({ allowed, rows: [{ id: 'go.xss#prefilter', status: 'done' }] })).join('\n'), /which is done/);
  assert.match(prefilterProblems([none], opts({ allowed: { 'go.xss': { limit: 'none', row: 'go.ssrf#prefilter' } } })).join('\n'), /must be a BACKLOG\.md row go\.xss#prefilter…/);
  // A row of the same rule about something else does not justify it.
  const other = { 'go.xss': { limit: 'none', row: 'go.xss#bind-in-comparison' } };
  assert.match(prefilterProblems([none], opts({ allowed: other, rows: [{ id: 'go.xss#bind-in-comparison', status: 'todo' }] })).join('\n'), /must be a BACKLOG\.md row go\.xss#prefilter…/);
  assert.match(prefilterProblems([none], opts({ allowed: { 'go.xss': { limit: 'slow', row: 'go.xss#prefilter' } }, rows: [{ id: 'go.xss#prefilter', status: 'todo' }] })).join('\n'), /limit must be none or size/);
  // A rule that is not measured: an error in a full run, nothing when only some rules ran.
  const rowsOpen = [{ id: 'go.xss#prefilter', status: 'todo' }];
  assert.match(prefilterProblems([], opts({ allowed, rows: rowsOpen })).join('\n'), /go\.xss: in ALLOWED but no rule file/);
  assert.deepEqual(prefilterProblems([], opts({ allowed, rows: rowsOpen, complete: false })), []);
});

test('every ALLOWED entry names an open BACKLOG.md row and an existing rule', () => {
  const ids = ruleFiles(root).map((f) => parse(readFileSync(path.join(root, f), 'utf8'), { maxAliasCount: -1 }).rules[0].id);
  // Measured as breaking their limit, so only the entries themselves are checked here.
  const results = ids.map((id) => (ALLOWED[id]?.limit === 'none' ? ok(id, { filter: 'none', bytes: 40 }) : ok(id, { bytes: ALLOWED[id] ? MAX_BYTES + 1 : 2000 })));
  assert.deepEqual(prefilterProblems(results, { rows }), []);
});

test('resultTable has one row per rule', () => {
  const t = resultTable([ok('go.weak-hash'), ok('go.xss', { filter: 'none', bytes: 39 }), { id: 'js.x', error: 'no output' }], { 'go.xss': { limit: 'none' } });
  assert.match(t, /\| go\.weak-hash \| 100 \| 100 \| 400 \| 2000 B \| Some \| {2}\|/);
  assert.match(t, /\| go\.xss \| 100 \| 100 \| 400 \| 39 B \| None \| none \|/);
  assert.match(t, /\| js\.x \| – \| – \| – \| – \| error: no output \| \|/);
  assert.match(resultTable([ok('go.ssrf', { ms: 600, budget: 1000, fastest: 450 })], {}), /\| go\.ssrf \| 450 \| 600 \| 1000 \| 2000 B \| Some \| {2}\|/);
});
