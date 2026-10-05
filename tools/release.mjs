// `npm run release`: dist/qualor-rules-<version>.tar.gz (README "Releases"), byte for byte the same
// from the same commit on any platform with the same Node.js major version (the gzip stream comes
// from Node's zlib): entries sorted, mtime 0, owner 0:0, modes 0644, a plain ustar archive written
// here and gzip with mtime 0 and the OS byte fixed to Unix. It holds
// manifest.json, LICENSE, NOTICE and rules/ (the rule YAML only, never the tests). Prints the
// tarball's SHA-256, which the scanner pins (QUALOR_RULES_SHA256 in qualor's install.sh).
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { checkRepository } from './check.mjs';
import { readRule, ruleFiles } from './rules.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function octal(value, width) {
  return `${value.toString(8).padStart(width - 1, '0')}\0`;
}

/** One ustar header for a regular file (mode 0644, owner 0:0, mtime 0). */
function header(name, size) {
  if (Buffer.byteLength(name) > 100) throw new Error(`${name}: name over 100 bytes`);
  const h = Buffer.alloc(512, 0);
  h.write(name, 0, 'utf8');
  h.write(octal(0o644, 8), 100, 'ascii');
  h.write(octal(0, 8), 108, 'ascii');
  h.write(octal(0, 8), 116, 'ascii');
  h.write(octal(size, 12), 124, 'ascii');
  h.write(octal(0, 12), 136, 'ascii');
  h.write('        ', 148, 'ascii');
  h.write('0', 156, 'ascii');
  h.write('ustar\0', 257, 'ascii');
  h.write('00', 263, 'ascii');
  h.write('root', 265, 'ascii');
  h.write('root', 297, 'ascii');
  let sum = 0;
  for (const byte of h) sum += byte;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return h;
}

/** A gzip-compressed ustar archive of `entries` ([name, Buffer]), sorted by name. */
export function tarGz(entries) {
  const sorted = [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const blocks = [];
  for (const [name, data] of sorted) {
    blocks.push(header(name, data.length), data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  const gz = gzipSync(Buffer.concat(blocks), { level: 9 });
  gz[9] = 3; // OS = Unix: zlib writes the build platform's code (10 on Windows); nothing else differs
  return gz;
}

/** The manifest and tarball of the repository at `root`; throws when `npm run check` would fail. */
export function buildRelease(root) {
  const problems = checkRepository(root);
  if (problems.length > 0) throw new Error(`check failed:\n${problems.join('\n')}`);
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const entries = [];
  const rules = [];
  for (const file of ruleFiles(root)) {
    const { rule, qualorId } = readRule(root, file);
    const data = readFileSync(path.join(root, file));
    entries.push([file, data]);
    rules.push({
      id: qualorId,
      path: file,
      sha256: sha256(data),
      languages: rule.languages,
      kind: rule.metadata.kind,
      severity: rule.metadata.severity,
      cwe: rule.metadata.cwe,
      title: rule.metadata.title,
    });
  }
  const manifest = { version: pkg.version, opengrep: pkg.opengrep, rules };
  const manifestText = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  entries.push(['manifest.json', manifestText]);
  entries.push(['LICENSE', readFileSync(path.join(root, 'LICENSE'))]);
  entries.push(['NOTICE', readFileSync(path.join(root, 'NOTICE'))]);
  const tarball = tarGz(entries);
  return { version: pkg.version, manifestText, tarball, sha256: sha256(tarball) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const r = buildRelease(root);
  const dist = path.join(root, 'dist');
  mkdirSync(dist, { recursive: true });
  const name = `qualor-rules-${r.version}.tar.gz`;
  writeFileSync(path.join(dist, name), r.tarball);
  writeFileSync(path.join(dist, 'manifest.json'), r.manifestText);
  writeFileSync(path.join(dist, `${name}.sha256`), `${r.sha256}  ${name}\n`);
  console.log(`${r.sha256}  dist/${name}`);
}
