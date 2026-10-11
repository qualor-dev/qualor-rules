import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { BLOCKS, POSITIONS, RULE, SCHEMA_REQUIREMENTS, SETTINGS, generate, regenerate, sequences } from './xxe-exclusions.mjs';

const P = Object.keys(POSITIONS).length;

test('the generated blocks of xxe.yml match their tables', () => {
  const text = readFileSync(RULE, 'utf8');
  assert.equal(regenerate(text), text, 'run node tools/xxe-exclusions.mjs');
});

test('a hand edit inside a block is detected', () => {
  const text = readFileSync(RULE, 'utf8');
  for (const [from, to] of [
    ['disallow-doctype-decl", true);', 'disallow-doctype-decl", false);'],
    ['property/accessExternalSchema", "");', 'property/accessExternalSchema", "all");'],
  ]) {
    const edited = text.replace(from, to);
    assert.notEqual(edited, text);
    assert.notEqual(regenerate(edited), edited);
  }
});

const count = (block) => (generate(block).match(/- pattern-not-inside:/g) ?? []).length;
const perPosition = (rows) => rows.reduce((n, r) => n + sequences(r, '$F').length, 0);

test('each setting of the parsers block appears once per position', () => {
  const block = BLOCKS.find((b) => b.settings === SETTINGS);
  const text = generate(block);
  assert.ok(text.startsWith(block.begin) && text.trimEnd().endsWith(block.end));
  const triple = SETTINGS.find((r) => r.together);
  assert.equal(sequences(triple, '$F').length, 3);
  const parser = SETTINGS.filter((r) => r.stmts[0].includes('$SET')).length;
  const reader = SETTINGS.filter((r) => !r.stax).reduce((n, r) => n + sequences(r, '$R').length, 0);
  // P positions × the sequences, 2 makes × 2 names of secure processing.
  assert.equal(count(block), P * perPosition(SETTINGS) + 2 * 2 + parser + reader);
});

test('the three entity features are checked one by one, each in its own branch', () => {
  const block = BLOCKS.find((b) => b.settings === SETTINGS);
  const text = generate(block);
  const together = SETTINGS.filter((r) => r.together);
  assert.equal(together.length, 1);
  const [row] = together;
  assert.equal(row.parts.length, row.stmts.length);
  const feature = (stmt) => stmt.match(/"[^"]+"/)[0];
  // Outside the pattern-either no entry names one of the features.
  const at = text.indexOf(`# Reported unless ${row.name}.`);
  assert.ok(at > 0);
  for (const stmt of row.stmts) assert.ok(!text.slice(0, at).includes(feature(stmt)));
  // One branch per feature: every exclusion in it holds that feature alone, once.
  // A last branch keeps transformer uses: $F is bound as the transformer's factory there.
  assert.match(text.slice(at), /# A transformer[^\n]*\n\s+- pattern-inside: \|\n\s+\$TR = \$F\.newTransformer\(\.\.\.\);/);
  const branches = text.slice(at).split(/\n\s+# Reported unless /).slice(1);
  assert.equal(branches.length, row.stmts.length);
  branches.forEach((branch, i) => {
    assert.ok(branch.startsWith(`${row.parts[i]}.`));
    assert.match(branch, /- pattern: \$F\.\$CALL\(\.\.\.\)/);
    const entries = branch.split('- pattern-not-inside: |').slice(1);
    assert.equal(entries.length, Object.keys(POSITIONS).length + 1);
    for (const entry of entries) {
      assert.equal((entry.match(/\.setFeature\(/g) ?? []).length, 1);
      assert.ok(entry.includes(feature(row.stmts[i])));
    }
  });
});

test('a SchemaFactory is safe only with both external DTD and schema access denied, each on its own', () => {
  const block = BLOCKS.find((b) => b.requirements === SCHEMA_REQUIREMENTS);
  const text = generate(block);
  assert.ok(text.startsWith(block.begin) && text.trimEnd().endsWith(block.end));
  assert.deepEqual(SCHEMA_REQUIREMENTS.map((r) => r.rows.map((row) => row.stmts.join(' ').match(/DTD|Schema|SCHEMA/)[0])), [['DTD', 'DTD'], ['SCHEMA', 'Schema']]);
  // Every exclusion is one statement: a setting under a condition cannot complete another one.
  for (const req of SCHEMA_REQUIREMENTS) for (const row of req.rows) assert.equal(row.stmts.length, 1);
  for (const entry of text.split('- pattern-not-inside: |').slice(1)) assert.equal((entry.match(/\.set(Property|Feature)\(/g) ?? []).length, 1);
  // One pattern-either branch per requirement, each keeping the use.
  assert.equal((text.match(/- pattern: \$F\.newSchema\(\.\.\.\)/g) ?? []).length, SCHEMA_REQUIREMENTS.length);
  // No row of the parsers' table (a refused DOCTYPE, the DTD property alone) reaches this block.
  assert.doesNotMatch(text, /disallow-doctype-decl|supportDTD|SUPPORT_DTD/);
  // 2 requirements × 2 names × P positions, 1 make × 2 names of secure processing.
  assert.equal(count(block), 2 * 2 * P + 2);
});

test('a Validator must deny external DTDs and schemas itself, each on its own', () => {
  const block = BLOCKS.find((b) => b.name === 'Validator');
  assert.equal(block.requirements, SCHEMA_REQUIREMENTS);
  const text = generate(block);
  assert.ok(text.startsWith(block.begin) && text.trimEnd().endsWith(block.end));
  // Each block's markers are its own.
  for (const other of BLOCKS.filter((b) => b !== block)) assert.ok(!other.begin.includes(block.begin) && !block.begin.includes(other.begin));
  assert.equal((text.match(/- pattern: \$F\.validate\(\.\.\.\)/g) ?? []).length, SCHEMA_REQUIREMENTS.length);
  // Secure processing is a factory setting: no newDefaultInstance exclusion on a Validator.
  assert.doesNotMatch(text, /newDefault|secure-processing|FEATURE_SECURE_PROCESSING/);
  assert.match(text, /# Set on the validator: before\./);
  // 2 requirements × 2 names × P positions.
  assert.equal(count(block), 2 * 2 * P);
});

test('a setting in a try block counts with catch clauses, a finally clause or both', () => {
  const s = ['$F.setFeature("x", true);'];
  const tries = Object.values(POSITIONS).map((p) => p(s)).filter((x) => x.startsWith('try {'));
  // OpenGrep matches a try statement with catch clauses and a finally clause by the template
  // without catch clauses, so two templates cover the three forms.
  assert.equal(tries.length, 2);
  assert.equal(tries.filter((x) => x.includes('} catch ($EX $E) {') && !x.includes('finally')).length, 1);
  assert.equal(tries.filter((x) => !x.includes('catch') && x.includes('} finally {')).length, 1);
  // A try-with-resources statement of one resource, with and without a finally clause.
  const resources = Object.values(POSITIONS).map((p) => p(s)).filter((x) => x.startsWith('try ($TT $TV = $TI) {'));
  assert.equal(resources.length, 2);
  assert.equal(resources.filter((x) => x.includes('} finally {')).length, 1);
});
