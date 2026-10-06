import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { BLOCKS, RULE, SCHEMA_REQUIREMENTS, SETTINGS, generate, regenerate, sequences } from './xxe-exclusions.mjs';

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

test('each setting of the parsers block appears once per position and order', () => {
  const block = BLOCKS.find((b) => b.settings === SETTINGS);
  const text = generate(block);
  assert.ok(text.startsWith(block.begin) && text.trimEnd().endsWith(block.end));
  const triple = SETTINGS.find((r) => r.anyOrder);
  assert.equal(sequences(triple, '$F').length, 6);
  const parser = SETTINGS.filter((r) => r.stmts[0].includes('$SET')).length;
  const reader = SETTINGS.filter((r) => !r.stax).reduce((n, r) => n + sequences(r, '$R').length, 0);
  // 5 positions × the sequences, 2 makes × 2 names × 2 positions of secure processing.
  assert.equal(count(block), 5 * perPosition(SETTINGS) + 8 + parser + reader);
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
  // 2 requirements × 2 names × 5 positions, 1 make × 2 names × 2 positions of secure processing.
  assert.equal(count(block), 2 * 2 * 5 + 4);
});
