import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { buildRelease, tarGz } from './release.mjs';
import { LANGS } from './rules.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** A copy of the repository with a fake engine publish (the real one needs the .NET SDK: npm run build:engine). */
function copyRepo({ engine = true } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-rules-'));
  for (const f of ['package.json', 'LICENSE', 'NOTICE', 'schema', 'rules', 'models/csharp', 'engine/dotnet/licenses']) {
    cpSync(path.join(root, f), path.join(dir, f), { recursive: true });
  }
  if (engine) {
    const publish = path.join(dir, 'engine/dotnet/publish');
    mkdirSync(publish, { recursive: true });
    writeFileSync(path.join(publish, 'Qualor.Taint.Cli.dll'), 'cli dll');
    writeFileSync(path.join(publish, 'Qualor.Taint.Cli.runtimeconfig.json'), '{}');
    writeFileSync(path.join(publish, 'YamlDotNet.dll'), 'yaml dll');
  }
  return dir;
}

const hex = (buf) => createHash('sha256').update(buf).digest('hex');

test('the same tree gives the same tarball, byte for byte', () => {
  const a = buildRelease(copyRepo());
  const b = buildRelease(copyRepo());
  assert.equal(a.sha256, b.sha256);
  assert.match(a.sha256, /^[0-9a-f]{64}$/);
  // gzip header: flags 0 (no file name), mtime 0, XFL 2 (level 9), OS 3 (Unix).
  assert.deepEqual([...a.tarball.subarray(3, 10)], [0, 0, 0, 0, 0, 2, 3]);
});

test('lists manifest.json, LICENSE, NOTICE and the rule YAML only, sorted, owner 0, mtime 0', () => {
  const { tarball, manifestText } = buildRelease(copyRepo());
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
  assert.ok(names.every((n) => ['manifest.json', 'LICENSE', 'NOTICE'].includes(n) || /^(rules|dotnet)\//.test(n)));
  for (const l of lines) assert.match(l, /^-rw-r--r-- (root\/root|0\/0) .* 1970-01-01 00:00 /);
  const extracted = spawnSync('tar', ['-xzf', 'p.tar.gz', 'manifest.json'], { cwd: dir });
  assert.equal(extracted.status, 0);
  assert.equal(readFileSync(path.join(dir, 'manifest.json'), 'utf8'), manifestText.toString());
});

test('the manifest names every rule with its own SHA-256, the pinned OpenGrep and its taint mode', () => {
  const { manifestText } = buildRelease(copyRepo());
  const manifest = JSON.parse(manifestText);
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.version, pkg.version);
  assert.equal(manifest.opengrep, pkg.opengrep);
  assert.equal(manifest.taintIntrafile, pkg.taintIntrafile);
  assert.deepEqual(Object.keys(manifest), ['version', 'opengrep', 'taintIntrafile', 'rules', 'dotnetEngine']);
  assert.ok(manifest.rules.length > 0);
  for (const r of manifest.rules) {
    const langs = Object.keys(LANGS).join('|');
    assert.match(r.id, new RegExp(`^(${langs})/[a-z0-9-]+$`));
    assert.match(r.path, new RegExp(`^rules/(${langs})/[a-z0-9-]+/[a-z0-9-]+\\.yml$`));
    assert.match(r.sha256, /^[0-9a-f]{64}$/);
    assert.ok(r.title.length > 0 && ['issue', 'hotspot'].includes(r.kind));
  }
});

test('the manifest takes the taint mode from package.json, not from QUALOR_TAINT_INTRAFILE', () => {
  const dir = copyRepo();
  const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ ...pkg, taintIntrafile: true }));
  const saved = process.env.QUALOR_TAINT_INTRAFILE;
  process.env.QUALOR_TAINT_INTRAFILE = '0';
  try {
    assert.equal(JSON.parse(buildRelease(dir).manifestText).taintIntrafile, true);
  } finally {
    if (saved === undefined) delete process.env.QUALOR_TAINT_INTRAFILE;
    else process.env.QUALOR_TAINT_INTRAFILE = saved;
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

test('the engine publish and the models go under dotnet/, each file with its SHA-256 in dotnetEngine', () => {
  const dir = copyRepo();
  const { manifestText, tarball } = buildRelease(dir);
  const manifest = JSON.parse(manifestText);
  const e = manifest.dotnetEngine;
  assert.equal(e.version, manifest.version);
  assert.equal(e.entry, 'dotnet/engine/Qualor.Taint.Cli.dll');
  assert.equal(e.models, 'dotnet/models');
  const paths = e.files.map((f) => f.path);
  assert.deepEqual(paths, [...paths].sort((a, b) => (a < b ? -1 : 1)));
  const models = readdirSync(path.join(dir, 'models/csharp')).filter((n) => n.endsWith('.yml'));
  assert.ok(models.length > 0);
  for (const m of models) assert.ok(paths.includes(`dotnet/models/csharp/${m}`), m);
  for (const n of ['Qualor.Taint.Cli.dll', 'Qualor.Taint.Cli.runtimeconfig.json', 'YamlDotNet.dll']) {
    assert.ok(paths.includes(`dotnet/engine/${n}`), n);
  }
  assert.ok(paths.includes('dotnet/engine/licenses/YamlDotNet.txt'));
  const cli = e.files.find((f) => f.path === 'dotnet/engine/Qualor.Taint.Cli.dll');
  assert.equal(cli.sha256, hex('cli dll'));
  // every listed file is in the tarball with those bytes
  const tar = gunzipSync(tarball);
  for (const f of e.files) assert.ok(tar.includes(Buffer.from(f.path)), f.path);
  for (const f of manifest.rules) assert.ok(!paths.includes(f.path));
});

test('the engine part of the manifest does not change the older fields', () => {
  const dir = copyRepo();
  const withEngine = JSON.parse(buildRelease(dir).manifestText);
  const { dotnetEngine, ...old } = withEngine;
  assert.ok(dotnetEngine);
  assert.deepEqual(Object.keys(old), ['version', 'opengrep', 'taintIntrafile', 'rules']);
});

test('without the publish directory the release asks for npm run build:engine', () => {
  assert.throws(() => buildRelease(copyRepo({ engine: false })), /run npm run build:engine first/);
});

test('a third-party DLL without a licence text, or a *.pdb, is refused', () => {
  const dir = copyRepo();
  writeFileSync(path.join(dir, 'engine/dotnet/publish/Npgsql.dll'), 'x');
  assert.throws(() => buildRelease(dir), /Npgsql\.dll: no licence text/);
  rmSync(path.join(dir, 'engine/dotnet/publish/Npgsql.dll'));
  writeFileSync(path.join(dir, 'engine/dotnet/publish/Qualor.Taint.Cli.pdb'), 'x');
  assert.throws(() => buildRelease(dir), /\*\.pdb/);
});

test('a licence text covers its own DLL only (an exact name, or a listed alias)', () => {
  const dir = copyRepo();
  const publish = path.join(dir, 'engine/dotnet/publish');
  // Microsoft.CodeAnalysis.txt names Roslyn's two packages: the CSharp DLL is its listed alias ...
  writeFileSync(path.join(publish, 'Microsoft.CodeAnalysis.dll'), 'x');
  writeFileSync(path.join(publish, 'Microsoft.CodeAnalysis.CSharp.dll'), 'x');
  buildRelease(dir);
  // ... but it does not cover another Microsoft.CodeAnalysis.* DLL, which needs its own text.
  writeFileSync(path.join(publish, 'Microsoft.CodeAnalysis.Razor.dll'), 'x');
  rmSync(path.join(dir, 'engine/dotnet/licenses/Microsoft.CodeAnalysis.Razor.txt'));
  assert.throws(() => buildRelease(dir), /Microsoft\.CodeAnalysis\.Razor\.dll: no licence text/);
});

test('a DLL whose package carries third-party notices ships them, byte for byte as pinned', () => {
  const dir = copyRepo();
  const publish = path.join(dir, 'engine/dotnet/publish');
  const licences = path.join(dir, 'engine/dotnet/licenses');
  writeFileSync(path.join(publish, 'Microsoft.AspNetCore.Razor.Language.dll'), 'x');
  writeFileSync(path.join(publish, 'System.Collections.Immutable.dll'), 'x');
  writeFileSync(path.join(publish, 'Microsoft.CodeAnalysis.dll'), 'x');
  const paths = JSON.parse(buildRelease(dir).manifestText).dotnetEngine.files.map((f) => f.path);
  for (const n of ['Microsoft.AspNetCore.Razor.THIRD-PARTY-NOTICES.TXT', 'dotnet-runtime.THIRD-PARTY-NOTICES.TXT', 'Microsoft.CodeAnalysis.ThirdPartyNotices.rtf']) {
    assert.ok(paths.includes(`dotnet/engine/licenses/${n}`), n);
  }
  const notices = path.join(licences, 'Microsoft.AspNetCore.Razor.THIRD-PARTY-NOTICES.TXT');
  const original = readFileSync(notices);
  writeFileSync(notices, Buffer.concat([original, Buffer.from('changed')]));
  assert.throws(() => buildRelease(dir), /Microsoft\.AspNetCore\.Razor\.THIRD-PARTY-NOTICES\.TXT: SHA-256/);
  rmSync(notices);
  assert.throws(() => buildRelease(dir), /Microsoft\.AspNetCore\.Razor\.Language\.dll: its third-party notices/);
});
