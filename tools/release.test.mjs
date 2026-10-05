import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { buildRelease, tarGz } from './release.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function copyRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-'));
  for (const f of ['package.json', 'LICENSE', 'NOTICE', 'schema', 'rules']) {
    cpSync(path.join(root, f), path.join(dir, f), { recursive: true });
  }
  return dir;
}

test('the same tree gives the same tarball, byte for byte', () => {
  const a = buildRelease(root);
  const b = buildRelease(copyRepo());
  assert.equal(a.sha256, b.sha256);
  assert.match(a.sha256, /^[0-9a-f]{64}$/);
  // gzip header: flags 0 (no file name), mtime 0, XFL 2 (level 9), OS 3 (Unix).
  assert.deepEqual([...a.tarball.subarray(3, 10)], [0, 0, 0, 0, 0, 2, 3]);
});

test('lists manifest.json, LICENSE, NOTICE and the rule YAML only, sorted, owner 0, mtime 0', () => {
  const { tarball, manifestText } = buildRelease(root);
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-tar-'));
  writeFileSync(path.join(dir, 'p.tar.gz'), tarball);
  const list = spawnSync('tar', ['-tvzf', 'p.tar.gz'], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, TZ: 'UTC' },
  });
  assert.equal(list.status, 0, list.stderr);
  const lines = list.stdout.trim().split('\n');
  const names = lines.map((l) => l.split(/\s+/).at(-1));
  assert.deepEqual(names, [...names].sort());
  assert.ok(names.includes('manifest.json') && names.includes('LICENSE') && names.includes('NOTICE'));
  assert.ok(names.filter((n) => n.startsWith('rules/')).every((n) => n.endsWith('.yml')));
  for (const l of lines) assert.match(l, /^-rw-r--r-- (root\/root|0\/0) .* 1970-01-01 00:00 /);
  const extracted = spawnSync('tar', ['-xzf', 'p.tar.gz', 'manifest.json'], { cwd: dir });
  assert.equal(extracted.status, 0);
  assert.equal(readFileSync(path.join(dir, 'manifest.json'), 'utf8'), manifestText.toString());
});

test('the manifest names every rule with its own SHA-256 and the pinned OpenGrep', () => {
  const { manifestText } = buildRelease(root);
  const manifest = JSON.parse(manifestText);
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.version, pkg.version);
  assert.equal(manifest.opengrep, pkg.opengrep);
  assert.ok(manifest.rules.length > 0);
  for (const r of manifest.rules) {
    assert.match(r.id, /^(js|python|java|go)\/[a-z0-9-]+$/);
    assert.match(r.path, /^rules\/(js|python|java|go)\/[a-z0-9-]+\/[a-z0-9-]+\.yml$/);
    assert.match(r.sha256, /^[0-9a-f]{64}$/);
    assert.ok(r.title.length > 0 && ['issue', 'hotspot'].includes(r.kind));
  }
});

test('refuses to release a tree that fails the check', () => {
  const dir = copyRepo();
  const file = path.join(dir, 'rules/python/sql/sql-injection.yml');
  writeFileSync(file, readFileSync(file, 'utf8').replace('kind: issue', 'kind: bug'));
  assert.throws(() => buildRelease(dir), /check failed/);
});

test('tarGz pads every file to 512 bytes and ends with two zero blocks', () => {
  const tar = gunzipSync(tarGz([['b', Buffer.from('x')], ['a', Buffer.alloc(512)]]));
  assert.equal(tar.length, 512 + 512 + 512 + 512 + 1024);
  assert.equal(tar.subarray(0, 1).toString(), 'a');
});
