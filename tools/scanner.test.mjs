import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { configs, probeArgs, reportLines, sq } from './scanner.mjs';

function tree() {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-scanner-'));
  mkdirSync(path.join(dir, 'rules/go/sql'), { recursive: true });
  writeFileSync(path.join(dir, 'rules/go/sql/sql-injection.yml'), 'rules: []\n');
  mkdirSync(path.join(dir, '.tmp/review'), { recursive: true });
  writeFileSync(path.join(dir, '.tmp/review/mutant.yml'), 'rules: []\n');
  writeFileSync(path.join(dir, '.tmp/review/fp.go'), 'package x\n');
  return dir;
}

test('takes rules under rules/ and scratch rule files under .tmp/, nothing else', () => {
  const dir = tree();
  const one = configs(['rules/go/sql/sql-injection.yml'], dir);
  assert.deepEqual(one.args, ['--config', '/src/rules/go/sql/sql-injection.yml']);
  assert.deepEqual([...one.langs], ['go']);
  assert.deepEqual([...configs(['rules'], dir).langs].sort(), ['go', 'java', 'js', 'python']);
  assert.deepEqual(configs(['.tmp/review/mutant.yml'], dir).args, ['--config', '/src/.tmp/review/mutant.yml']);
  for (const bad of ['.tmp', '.tmp/review', '.tmp/review/fp.go', 'tools', 'rules/go/sql/nothing.yml', '../x.yml']) {
    assert.throws(() => configs([bad], dir), /is not a rule file or directory/, bad);
  }
  assert.throws(() => configs([], dir), /name at least one rule/);
});

test('refuses unknown --only projects and keeps the rest of the arguments', () => {
  const projects = ['gin-realworld', 'gitea'];
  assert.deepEqual(probeArgs(['--recall', 'rules/go'], projects), { recall: true, only: undefined, list: ['rules/go'] });
  const p = probeArgs(['--only', 'gitea,qualor-cc', 'rules/go'], projects);
  assert.deepEqual([...p.only], ['gitea', 'qualor-cc']);
  assert.deepEqual(p.list, ['rules/go']);
  assert.throws(() => probeArgs(['--only', 'gitea,gittea', 'rules/go'], projects), /unknown project\(s\) gittea/);
  assert.throws(() => probeArgs(['--only'], projects), /none given/);
});

test('quotes for sh, single quotes included', () => {
  assert.equal(sq("a b'c"), "'a b'\\''c'");
});

test('prints findings and turns scan errors into warnings', () => {
  const res = {
    results: [{ check_id: 'go.sql-injection', path: 'a.go', start: { line: 3 }, extra: { lines: '  db.Query(q)\n' } }],
    errors: [{ type: 'Syntax error', path: 'b.ts' }],
    paths: { scanned: ['a.go', 'b.ts'] },
  };
  assert.deepEqual(reportLines(res, 'x'), [
    'x: 1 finding(s), 2 files scanned, 1 error(s)',
    '  go.sql-injection  a.go:3  db.Query(q)',
    '  warning: Syntax error b.ts (files OpenGrep could not analyse are not covered)',
  ]);
  assert.match(reportLines(undefined, 'x')[0], /no result/);
});
