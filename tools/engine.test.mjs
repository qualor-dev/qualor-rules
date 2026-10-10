import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { engine, intrafileOverride } from './engine.mjs';

function repo(pkg) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-engine-'));
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ opengrep: '1.30.0', ...pkg }));
  return dir;
}

test('takes the version and the mode from package.json', () => {
  assert.deepEqual(engine(repo({ taintIntrafile: true }), {}), { version: '1.30.0', taintIntrafile: true, args: ['--taint-intrafile'] });
  assert.deepEqual(engine(repo({ taintIntrafile: false }), {}), { version: '1.30.0', taintIntrafile: false, args: [] });
  assert.equal(engine(repo({}), {}).taintIntrafile, false);
});

test('QUALOR_TAINT_INTRAFILE overrides the mode, and only with 1 or 0', () => {
  assert.equal(engine(repo({ taintIntrafile: true }), { QUALOR_TAINT_INTRAFILE: '0' }).taintIntrafile, false);
  assert.deepEqual(engine(repo({ taintIntrafile: false }), { QUALOR_TAINT_INTRAFILE: '1' }).args, ['--taint-intrafile']);
  assert.equal(engine(repo({ taintIntrafile: true }), { QUALOR_TAINT_INTRAFILE: '' }).taintIntrafile, true);
  assert.equal(intrafileOverride('true'), true);
  assert.equal(intrafileOverride(undefined), undefined);
  assert.throws(() => intrafileOverride('yes'), /must be 1 or 0/);
});
