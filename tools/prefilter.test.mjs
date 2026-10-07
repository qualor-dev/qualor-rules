import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse, parseDocument, visit } from 'yaml';
import { BACKLOG_HEADER, parseTable } from './backlog.mjs';
import { ALLOWED, BUDGET_MS, LOAD_RATIO, MAX_BYTES, budgetFor, corePath, expandAnchors, parsePrefilter, prefilterProblems, resultTable, selectRuleFiles } from './prefilter.mjs';
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
  // The plain and slow rules measured with 4 and 6 busy loops on 2 CPUs (budgetFor's comment).
  assert.ok(396 <= budgetFor(210) && 693 <= budgetFor(307));
  assert.ok(1610 > budgetFor(210) && 2809 > budgetFor(307));
});

const ok = (id, extra = {}) => ({ id, ms: 100, filter: 'some', bytes: 2000, ...extra });
const opts = (extra = {}) => ({ allowed: {}, rows: [], complete: true, ...extra });

test('a rule within every limit passes', () => {
  assert.deepEqual(prefilterProblems([ok('go.weak-hash')], opts()), []);
  assert.deepEqual(prefilterProblems([ok('go.weak-hash', { ms: BUDGET_MS, bytes: MAX_BYTES })], opts()), []);
});

test('None, size and build time each fail', () => {
  assert.match(prefilterProblems([ok('go.xss', { filter: 'none', bytes: 39 })], opts()).join('\n'), /go\.xss: prefilter None/);
  assert.match(prefilterProblems([ok('go.insecure-cookie', { bytes: 6500415 })], opts()).join('\n'), /go\.insecure-cookie: prefilter 6348\.1 kB, budget 20\.0 kB/);
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
  assert.match(prefilterProblems([none], opts({ allowed: { 'go.xss': { limit: 'none', row: 'go.ssrf#prefilter' } } })).join('\n'), /must be a BACKLOG\.md row go\.xss#<topic>/);
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
  assert.match(t, /\| go\.weak-hash \| 100 \| 400 \| 2000 B \| Some \| {2}\|/);
  assert.match(t, /\| go\.xss \| 100 \| 400 \| 39 B \| None \| none \|/);
  assert.match(t, /\| js\.x \| – \| – \| – \| error: no output \| \|/);
});
