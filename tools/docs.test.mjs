import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { docRules, docsState, examples, handWritten, OWASP, renderIndex, renderPage, SECTIONS, TODO } from './docs.mjs';
import { exampleCases, exampleProblems } from './test-examples.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PAGE = 'docs/rules/python/sql-injection.md';
const RULE = 'rules/python/sql/sql-injection.yml';

/** A copy of the parts of the repository the docs are built from. */
function copyTree() {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-docs-'));
  for (const f of ['package.json', 'rules', 'docs']) cpSync(path.join(root, f), path.join(dir, f), { recursive: true });
  return dir;
}

const problems = (dir) => docsState(dir).problems.join('\n');
const edit = (dir, file, change) => writeFileSync(path.join(dir, file), change(readFileSync(path.join(dir, file), 'utf8')));

test('every rule has a current, written page, and the index is current', () => {
  assert.deepEqual(docsState(root).problems, []);
  assert.equal(docRules(root).length, docsState(root).files.size - 1);
});

test('every OWASP category a rule names has a link', () => {
  for (const r of docRules(root)) {
    for (const o of r.meta.owasp ?? []) assert.ok(Object.hasOwn(OWASP, o), `${r.file}: ${o}`);
  }
});

test('regenerating keeps the hand-written sections and rewrites the rest', () => {
  const dir = copyTree();
  const before = readFileSync(path.join(dir, PAGE), 'utf8');
  // A changed rule: the generated header follows, the prose stays.
  edit(dir, RULE, (s) => s.replace('severity: high', 'severity: medium'));
  assert.match(problems(dir), /docs\/rules\/python\/sql-injection\.md: out of date/);
  const [rule] = docRules(dir).filter((r) => r.page === PAGE);
  const after = renderPage(rule, before);
  assert.match(after, /Severity: Medium/);
  assert.deepEqual(handWritten(after), handWritten(before));
  // Text outside the markers is not kept: it is generated.
  const tampered = before.replace('## References', '## References\n\nA stray line.');
  assert.doesNotMatch(renderPage(rule, tampered), /A stray line/);
});

test('reports a rule without a page, a page without a rule and an unwritten section', () => {
  let dir = copyTree();
  rmSync(path.join(dir, PAGE));
  assert.match(problems(dir), /rules\/python\/sql\/sql-injection\.yml: no page docs\/rules\/python\/sql-injection\.md/);

  dir = copyTree();
  writeFileSync(path.join(dir, 'docs/rules/python/no-such-rule.md'), '# x\n');
  assert.match(problems(dir), /docs\/rules\/python\/no-such-rule\.md: no rule/);
  mkdirSync(path.join(dir, 'docs/rules/ruby'));
  assert.match(problems(dir), /docs\/rules\/ruby: not a language directory/);

  dir = copyTree();
  edit(dir, PAGE, (s) => s.replace(/<!-- begin: how-to-fix -->[\s\S]*?<!-- end: how-to-fix -->/, '<!-- begin: how-to-fix -->\n<!-- end: how-to-fix -->'));
  assert.match(problems(dir), /sql-injection\.md: write the section\(s\) how-to-fix/);

  // A new page comes with TODO lines in every hand-written section.
  const [rule] = docRules(root).filter((r) => r.page === PAGE);
  const fresh = renderPage(rule, undefined);
  for (const { id } of SECTIONS) assert.equal(handWritten(fresh)[id], TODO);
});

test('reports an example without both code blocks, or in another language', () => {
  let dir = copyTree();
  edit(dir, PAGE, (s) => s.replace('**Compliant:**', 'Compliant:'));
  assert.match(problems(dir), /the example has no \*\*Compliant\*\* code block/);
  dir = copyTree();
  edit(dir, PAGE, (s) => s.replace('```python', '```ruby'));
  assert.match(problems(dir), /the noncompliant example is ```ruby/);
});

test('reports a stale index', () => {
  const dir = copyTree();
  edit(dir, 'docs/rules/README.md', (s) => s.replace('| Issue |', '| Bug |'));
  assert.match(problems(dir), /docs\/rules\/README\.md: out of date/);
  assert.match(renderIndex(docRules(root)), /\| \[`qualor:java\/sql-injection`\]\(java\/sql-injection\.md\) \|/);
});

test('extracts the two example blocks', () => {
  const text = [
    '<!-- begin: example -->',
    '**Noncompliant:** bad.',
    '',
    '```go',
    'package a',
    '```',
    '',
    '**Compliant:** good,',
    'in two lines.',
    '',
    '```go',
    'package b',
    '```',
    '<!-- end: example -->',
  ].join('\n');
  assert.deepEqual(examples(text), {
    noncompliant: { fence: 'go', code: 'package a\n' },
    compliant: { fence: 'go', code: 'package b\n' },
  });
  const cases = exampleCases(root);
  assert.equal(cases.length, 2 * docRules(root).length);
  assert.ok(cases.every((c) => existsSync(path.join(root, c.page))));
});

test("judges the examples from OpenGrep's JSON", () => {
  const dir = '/tmp/x';
  const cases = [
    { id: 'go.sql-injection', page: 'p.md', kind: 'noncompliant', file: 'go/sql-injection/noncompliant.go' },
    { id: 'go.sql-injection', page: 'p.md', kind: 'compliant', file: 'go/sql-injection/compliant.go' },
  ];
  const hit = (file, id, line) => ({ path: `${dir}/${file}`, check_id: id, start: { line } });
  assert.deepEqual(exampleProblems({ results: [hit(cases[0].file, 'go.sql-injection', 3)] }, cases, dir), []);
  assert.match(exampleProblems({ results: [] }, cases, dir).join('\n'), /the noncompliant example gets no go\.sql-injection finding/);
  // The compliant example must be clean for every rule.
  assert.match(
    exampleProblems({ results: [hit(cases[0].file, 'go.sql-injection', 3), hit(cases[1].file, 'go.xss', 7)] }, cases, dir).join('\n'),
    /the compliant example gets go\.xss findings on lines 7/,
  );
  assert.match(
    exampleProblems({ results: [hit(cases[0].file, 'go.sql-injection', 3)], errors: [{ type: 'Syntax error', path: `${dir}/${cases[1].file}` }] }, cases, dir).join('\n'),
    /compliant\.go: OpenGrep could not analyse it/,
  );
  assert.match(exampleProblems({ results: [] }, [], dir).join('\n'), /no example was tested/);
});
