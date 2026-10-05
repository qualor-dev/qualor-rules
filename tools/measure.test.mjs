import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkProblems, insertEntry } from './measure.mjs';
import { latestMeasurement, parseExpected, scoreBenchmark, targetVerdicts } from './score.mjs';

const CSV = [
  '# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1',
  'BenchmarkTest00001,sqli,true,89',
  'BenchmarkTest00002,sqli,true,89',
  'BenchmarkTest00003,sqli,false,89',
  'BenchmarkTest00004,sqli,false,89',
  'BenchmarkTest00005,pathtraver,true,22',
  'BenchmarkTest00006,xss,true,79',
].join('\r\n');
const at = (n) => `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest0000${n}.java`;

test('scores per category with the Benchmark method: TPR, FPR, score, and what no rule covers', () => {
  const cweByRule = new Map([
    ['java.sql-injection', ['CWE-89']],
    ['java.path-traversal', ['CWE-23']], // read as 22
  ]);
  const findings = [
    { check_id: 'java.sql-injection', path: at(1) },
    { check_id: 'java.sql-injection', path: at(1) },
    { check_id: 'java.sql-injection', path: at(3) },
    { check_id: 'java.path-traversal', path: at(5) },
    { check_id: 'java.sql-injection', path: at(6) }, // the wrong CWE for an xss case
    { check_id: 'java.sql-injection', path: 'src/Other.java' },
  ];
  const rows = scoreBenchmark(parseExpected(CSV), findings, cweByRule);
  const by = Object.fromEntries(rows.map((r) => [r.category, r]));
  assert.deepEqual([by.sqli.tp, by.sqli.fn, by.sqli.fp, by.sqli.tn], [1, 1, 1, 1]);
  assert.equal(by.sqli.tpr, 0.5);
  assert.equal(by.sqli.fpr, 0.5);
  assert.equal(by.sqli.score, 0);
  assert.equal(by.pathtraver.tp, 1);
  assert.equal(by.xss.covered, false);
  assert.equal(by.xss.tp, 0);
});

test('checks the §8.4 target only for covered injection categories', () => {
  const rows = [
    { category: 'sqli', covered: true, tpr: 0.7, fpr: 0.2 },
    { category: 'cmdi', covered: true, tpr: 0.5, fpr: 0.6 },
    { category: 'xss', covered: false, tpr: 0, fpr: 0 },
    { category: 'hash', covered: true, tpr: 1, fpr: 1 },
  ];
  const v = targetVerdicts(rows);
  assert.deepEqual(v.map((x) => [x.category, x.met]), [['sqli', true], ['cmdi', false]]);
  assert.match(v[1].why, /TPR 50\.0% < 60\.0%, FPR 60\.0% > 44\.4%/);
});

const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);

test('inserts a new entry above the newest one and reads it back', () => {
  const first = insertEntry('# Measurements\n\nIntro.\n', `## 2026-10-04 rules ${OLD} (js, python, java, go)\n\nold\n`);
  const second = insertEntry(first, `## 2026-10-05 rules ${SHA} (go)\n\nnew\n`);
  assert.ok(second.indexOf('2026-10-05') < second.indexOf('2026-10-04'));
  assert.ok(second.startsWith('# Measurements\n\nIntro.\n'));
  assert.deepEqual(latestMeasurement(second), { date: '2026-10-05', rules: SHA, langs: ['go'] });
});

test('a release needs the newest entry at the last rules commit, for all four languages', () => {
  const all = `# M\n\n## 2026-10-05 rules ${SHA} (js, python, java, go)\n`;
  assert.deepEqual(checkProblems(all, SHA), []);
  assert.match(checkProblems(all, OLD).join('\n'), /rules\/ last changed in bbbbbbbbbbbb/);
  assert.match(checkProblems(`# M\n\n## 2026-10-05 rules ${SHA} (go)\n`, SHA).join('\n'), /lacks js, python, java/);
  assert.match(checkProblems('# M\n', SHA).join('\n'), /no entry/);
});
