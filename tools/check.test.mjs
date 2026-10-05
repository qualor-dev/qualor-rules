import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkRepository } from './check.mjs';
import { forbiddenSource } from './rules.mjs';
import { testProblems } from './test-rules.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULE = 'rules/python/sql/sql-injection.yml';
const TEST = 'rules/python/sql/sql-injection.py';

/** checkRepository of a copy of the repository after `edit(dir)`. */
function withTree(edit) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-check-'));
  for (const f of ['package.json', 'schema', 'rules']) {
    cpSync(path.join(root, f), path.join(dir, f), { recursive: true });
  }
  edit(dir);
  return checkRepository(dir);
}

function withChange(file, change) {
  return withTree((dir) => {
    const full = path.join(dir, file);
    writeFileSync(full, change(readFileSync(full, 'utf8')));
  });
}

test('the repository passes its own check', () => {
  assert.deepEqual(checkRepository(root), []);
});

test('refuses metadata outside the schema', () => {
  assert.match(withChange(RULE, (s) => s.replace('kind: issue', 'kind: bug')).join('\n'), /metadata\/kind/);
  assert.match(withChange(RULE, (s) => s.replace("cwe: ['CWE-89']", "cwe: ['89']")).join('\n'), /metadata\/cwe/);
  assert.match(withChange(RULE, (s) => s.replace('      since: 2026.10.0\n', '')).join('\n'), /since/);
  // The bounds of Qualor's manifest schema: CWE ids of at most 7 digits, at most 16 CWEs and languages.
  assert.match(withChange(RULE, (s) => s.replace("cwe: ['CWE-89']", "cwe: ['CWE-12345678']")).join('\n'), /metadata\/cwe/);
  const cwes = Array.from({ length: 17 }, (_, i) => `'CWE-${i + 1}'`).join(', ');
  assert.match(withChange(RULE, (s) => s.replace("cwe: ['CWE-89']", `cwe: [${cwes}]`)).join('\n'), /metadata\/cwe/);
  const langs = Array.from({ length: 17 }, () => 'python').join(', ');
  assert.match(
    withChange(RULE, (s) => s.replace('languages: [python]', `languages: [${langs}]`)).join('\n'),
    /more than 16 languages/,
  );
});

test('refuses an id that does not match the path, and a rule without an ok line', () => {
  assert.match(
    withChange(RULE, (s) => s.replace('id: python.sql-injection', 'id: python.sqli')).join('\n'),
    /id must be python\.sql-injection/,
  );
  assert.match(
    withChange(TEST, (s) => s.replaceAll('# ok: python.sql-injection', '# fine')).join('\n'),
    /no "ok: python\.sql-injection" line/,
  );
  // Only comments are annotations: an `ok:` in code (a variable annotation here) is not one.
  assert.deepEqual(withChange(TEST, (s) => s.replace('    return "ok"', '    ok: bool = True\n    return ok')), []);
});

test('refuses a duplicate id, a test file without a ruleid line and a rule without a test file', () => {
  // The Qualor id is <lang>/<name>: the same name in another category is the same id.
  const duplicate = withTree((dir) => {
    mkdirSync(path.join(dir, 'rules/python/db'));
    for (const ext of ['.yml', '.py']) {
      cpSync(path.join(dir, `rules/python/sql/sql-injection${ext}`), path.join(dir, `rules/python/db/sql-injection${ext}`));
    }
  });
  assert.match(duplicate.join('\n'), /rules\/python\/sql\/sql-injection\.yml: id python\/sql-injection also in rules\/python\/db\/sql-injection\.yml/);
  assert.match(
    withChange(TEST, (s) => s.replaceAll('# ruleid: python.sql-injection', '# bad')).join('\n'),
    /no "ruleid: python\.sql-injection" line/,
  );
  assert.match(
    withTree((dir) => rmSync(path.join(dir, TEST))).join('\n'),
    /rules\/python\/sql\/sql-injection\.yml: no test file sql-injection\{\.py\}/,
  );
});

test("refuses sources from other vendors' rule sets (CLEAN-ROOM.md)", () => {
  for (const url of [
    'https://semgrep.dev/r/python.lang.security',
    'https://github.com/semgrep/semgrep-rules/blob/develop/x.yaml',
    'https://github.com/opengrep/opengrep-rules',
    'https://github.com/github/codeql/blob/main/x.ql',
    'https://rules.sonarsource.com/java/RSPEC-3649/',
    'https://github.com/SonarSource/sonar-java',
    'https://registry.semgrep.dev/rule/x',
    'https://SEMGREP.DEV/r/x',
    'https://sonarcloud.io/organizations/acme/rules?open=x',
    'https://sonarcloud.io/coding_rules?open=x',
    'https://next.sonarqube.com/sonarqube/coding_rules?open=x',
    'not a url',
  ]) {
    assert.equal(forbiddenSource(url), true, url);
  }
  for (const url of [
    'https://cwe.mitre.org/data/definitions/89.html',
    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'https://github.com/opengrep/opengrep',
    'https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text',
    'https://www.psycopg.org/docs/sql.html',
  ]) {
    assert.equal(forbiddenSource(url), false, url);
  }
  assert.match(
    withChange(RULE, (s) => s.replace('https://peps.python.org/pep-0249/', 'https://semgrep.dev/r/x')).join('\n'),
    /source not allowed/,
  );
});

test("reads failures from OpenGrep's JSON, whatever its exit code", () => {
  assert.deepEqual(testProblems({ results: { a: { checks: { x: { passed: true, matches: {}, errors: [] } } } } }), []);
  assert.equal(testProblems({ config_with_errors: [{ path: 'a.yml' }], results: {} }).length, 2);
  assert.match(testProblems({ config_missing_tests: ['a.yml'], results: { a: { checks: {} } } }).join(), /no test file/);
  assert.match(
    testProblems({
      results: { a: { checks: { x: { passed: false, matches: { f: { expected_lines: [3], reported_lines: [] } } } } } },
    }).join(),
    /expected lines \[3\], reported \[\]/,
  );
});

test('pins the same OpenGrep in package.json and tools/install-opengrep.sh', () => {
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const script = readFileSync(path.join(root, 'tools/install-opengrep.sh'), 'utf8');
  assert.equal(/^OPENGREP_VERSION=(\S+)$/m.exec(script)?.[1], pkg.opengrep);
  assert.match(script, /^OPENGREP_SHA256_X64=[0-9a-f]{64}$/m);
});
