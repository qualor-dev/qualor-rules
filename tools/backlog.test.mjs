import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { backlogProblems, parseTable, referenceProblems, BACKLOG_HEADER } from './backlog.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HEAD = '| id | lang | category | cwe | kind | frameworks and APIs | status | notes |\n|---|---|---|---|---|---|---|---|\n';
const DONE = [
  '| js.sql-injection | js | sql | CWE-89 | issue | express | done | |',
  '| python.sql-injection | python | sql | CWE-89 | issue | flask | done | |',
  '| java.sql-injection | java | sql | CWE-89 | issue | spring-mvc | done | |',
  '| go.sql-injection | go | sql | CWE-89 | issue | gin | done | |',
];

/**
 * backlogProblems of a copy of the four SQL rules (the DONE rows) with `rows` as the queue; the
 * other rules of rules/ have rows only in the real BACKLOG.md.
 */
function backlog(rows) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-backlog-'));
  for (const lang of ['js', 'python', 'java', 'go']) {
    cpSync(path.join(root, 'rules', lang, 'sql'), path.join(dir, 'rules', lang, 'sql'), { recursive: true });
  }
  writeFileSync(path.join(dir, 'BACKLOG.md'), `# Backlog\n\n${HEAD}${rows.join('\n')}\n\nAfter the table.\n`);
  return backlogProblems(dir).join('\n');
}

function reference(rows) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-reference-'));
  const head = '| lang | project | repository | commit | licence | frameworks | use |\n|---|---|---|---|---|---|---|\n';
  writeFileSync(path.join(dir, 'REFERENCE.md'), `${head}${rows.join('\n')}\n`);
  return referenceProblems(dir).join('\n');
}

test("the repository's BACKLOG.md and REFERENCE.md pass", () => {
  assert.deepEqual(backlogProblems(root), []);
  assert.deepEqual(referenceProblems(root), []);
});

test('reads a table by its header, with escaped pipes and the line of each row', () => {
  const rows = parseTable(`x\n\n${HEAD}| js.a | js | b | CWE-1 | issue | x \\| y | todo | n |\ntext\n`, BACKLOG_HEADER);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].line, 5);
  assert.equal(rows[0]['frameworks and apis'], 'x | y');
});

test('accepts todo rows without rules and maintenance items on existing rules', () => {
  assert.equal(
    backlog([
      ...DONE,
      '| js.command-injection | js | command | CWE-78 | issue | child_process | todo | |',
      '| go.sql-injection#echo-binder | go | sql | CWE-89 | issue | echo | todo | |',
      '| java.xxe | java | xxe | CWE-611, CWE-776 | issue | jaxp | blocked | Which parser? |',
    ]),
    '',
  );
});

test('refuses malformed rows', () => {
  const bad = (row) => backlog([...DONE, row]);
  assert.match(bad('| js.Command | js | command | CWE-78 | issue | x | todo | |'), /is not <lang>\.<name>/);
  assert.match(bad('| js.command-injection | python | command | CWE-78 | issue | x | todo | |'), /lang python does not match/);
  assert.match(bad('| js.command-injection | js | command | 78 | issue | x | todo | |'), /cwe must be/);
  assert.match(bad('| js.command-injection | js | command | CWE-78 | bug | x | todo | |'), /kind must be/);
  assert.match(bad('| js.command-injection | js | command | CWE-78 | issue | x | doing | |'), /status must be/);
  assert.match(bad('| js.command-injection | js | command | CWE-78 | issue | | todo | |'), /frameworks and APIs are empty/);
  assert.match(bad('| js.command-injection | js | command | CWE-78 | issue | x | blocked | no question |'), /needs the question/);
  assert.match(bad('| js.command-injection | js | command | CWE-78 | issue | x | todo |'), /7 cells, want 8/);
  assert.match(bad('| js.sql-injection | js | sql | CWE-89 | issue | x | todo | |'), /also on line/);
});

test('keeps rules/ and the queue in step', () => {
  assert.match(backlog(DONE.slice(1)), /rules\/js\/sql\/sql-injection\.yml: no BACKLOG\.md row js\.sql-injection/);
  assert.match(
    backlog([DONE[0].replace('| done |', '| todo |'), ...DONE.slice(1)]),
    /js\.sql-injection has a rule file but status todo/,
  );
  assert.match(backlog([DONE[0].replace('| sql |', '| db |'), ...DONE.slice(1)]), /category db, but the rule is in rules\/js\/sql/);
  assert.match(
    backlog([...DONE, '| js.command-injection | js | command | CWE-78 | issue | x | done | |']),
    /js\.command-injection is done but rules\/js\/command\/command-injection\.yml is missing/,
  );
  assert.match(
    backlog([...DONE, '| js.xss#nextjs | js | xss | CWE-79 | issue | x | todo | |']),
    /maintenance item js\.xss#nextjs names no existing rule js\.xss/,
  );
  assert.equal(backlog([DONE[0].replace('| done |', '| in-progress |'), ...DONE.slice(1)]), '');
  // The row and the rule agree on the kind and the CWEs.
  assert.match(backlog([DONE[0].replace('| issue |', '| hotspot |'), ...DONE.slice(1)]), /kind hotspot, but rules\/js\/sql\/sql-injection\.yml says issue/);
  assert.match(backlog([DONE[0].replace('| CWE-89 |', '| CWE-89, CWE-564 |'), ...DONE.slice(1)]), /cwe CWE-89, CWE-564, but rules\/js\/sql\/sql-injection\.yml says CWE-89/);
});

test('refuses reference projects without a full commit, a GitHub URL, a licence or a use', () => {
  const ok = '| go | gin-app | https://github.com/a/b | 0123456789abcdef0123456789abcdef01234567 | MIT | gin | noise |';
  assert.equal(reference([ok]), '');
  assert.match(reference([ok.replace('0123456789abcdef0123456789abcdef01234567', '0123456')]), /full 40-character SHA/);
  assert.match(reference([ok.replace('https://github.com/a/b', 'http://example.com/a')]), /repository must be/);
  assert.match(reference([ok.replace('| noise |', '| both |')]), /use must be noise or recall/);
  assert.match(reference([ok.replace('| go |', '| rust |')]), /lang must be one of/);
  assert.match(reference([ok, ok]), /project gin-app twice/);
  assert.match(reference([ok.replace('| MIT |', '| |')]), /licence is empty/);
  assert.match(reference([]), /no project/);
});
