import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { BEGIN, END, RULE, SETTINGS, generate, replaceBlock, sequences } from './xxe-exclusions.mjs';

test('the generated block of xxe.yml matches the SETTINGS table', () => {
  const text = readFileSync(RULE, 'utf8');
  assert.equal(replaceBlock(text, generate()), text, 'run node tools/xxe-exclusions.mjs');
});

test('a hand edit inside the block is detected', () => {
  const text = readFileSync(RULE, 'utf8');
  const edited = text.replace('disallow-doctype-decl", true);', 'disallow-doctype-decl", false);');
  assert.notEqual(edited, text);
  assert.notEqual(replaceBlock(edited, generate()), edited);
});

test('each setting appears once per position and order', () => {
  const block = generate();
  assert.ok(block.startsWith(BEGIN) && block.trimEnd().endsWith(END));
  const triple = SETTINGS.find((r) => r.anyOrder);
  assert.equal(sequences(triple, '$F').length, 6);
  // 5 positions × (settings, with the any-order row counted once per order).
  const perPosition = SETTINGS.reduce((n, r) => n + sequences(r, '$F').length, 0);
  const count = (block.match(/- pattern-not-inside:/g) ?? []).length;
  const parser = SETTINGS.filter((r) => r.stmts[0].includes('$SET')).length;
  const reader = SETTINGS.filter((r) => !r.stax).reduce((n, r) => n + sequences(r, '$R').length, 0);
  assert.equal(count, 5 * perPosition + 8 + parser + reader);
});
