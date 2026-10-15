// `npm run release`: dist/qualor-rules-<version>.tar.gz (README "Releases"), byte for byte the same
// from the same commit on any platform with the same Node.js major version (the gzip stream comes
// from Node's zlib): entries sorted, mtime 0, owner 0:0, modes 0644, a plain ustar archive written
// here and gzip with mtime 0 and the OS byte fixed to Unix. It holds
// manifest.json (with the pinned OpenGrep and the taint mode the rules are tested in), LICENSE,
// NOTICE, rules/ (the rule YAML only, never the tests) and the C# taint engine: dotnet/engine/ (the
// `npm run build:engine` publish output, framework-dependent, no *.pdb, with the licence text of every
// third-party DLL and its package's third-party notices in dotnet/engine/licenses/) and dotnet/models/csharp/*.yml, each file with its SHA-256 in the
// manifest's dotnetEngine. Prints the
// tarball's SHA-256, which the scanner pins (QUALOR_RULES_SHA256 in qualor's install.sh).
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
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

const ENGINE_ENTRY = 'Qualor.Taint.Cli.dll';

/**
 * A third-party DLL's licence text is engine/dotnet/licenses/<the DLL's name>.txt, exactly; these DLLs share
 * another's text (one text names both packages).
 */
const LICENCE_ALIASES = { 'Microsoft.CodeAnalysis.CSharp': 'Microsoft.CodeAnalysis' };

/**
 * The third-party notices files the engine's packages carry, shipped in engine/dotnet/licenses byte for byte as the
 * packages have them (SHA-256 pinned here; .gitattributes keeps their CRLF): a DLL listed here needs its file.
 */
const NOTICES = [
  {
    file: 'Microsoft.AspNetCore.Razor.THIRD-PARTY-NOTICES.TXT',
    sha256: '37c1884c8573813e817908b8249df022dce38ca4a680678e6cf724430a69e4e1', // THIRD-PARTY-NOTICES.TXT of the three 6.0.36 packages
    dlls: ['Microsoft.AspNetCore.Razor.Language', 'Microsoft.AspNetCore.Mvc.Razor.Extensions', 'Microsoft.CodeAnalysis.Razor'],
  },
  {
    file: 'dotnet-runtime.THIRD-PARTY-NOTICES.TXT',
    sha256: '6d15e10a101c6bfff2ab4429ed061bf76c456fc4b23ad6b03e0d0f8377148a21', // THIRD-PARTY-NOTICES.TXT of both 10.0.1 packages
    dlls: ['System.Collections.Immutable', 'System.Reflection.Metadata'],
  },
  {
    file: 'Microsoft.CodeAnalysis.ThirdPartyNotices.rtf',
    sha256: 'ef4678850e7e3aaf9297f07e5c4060d477854e545ccf8e2ef8452d65a7b2efaf', // ThirdPartyNotices.rtf of both 5.6.0 packages
    dlls: ['Microsoft.CodeAnalysis', 'Microsoft.CodeAnalysis.CSharp'],
  },
];

/** The regular files of `dir` (sorted names, no sub-directories), as [name, Buffer]. */
function filesOf(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .map((e) => {
      if (!e.isFile()) throw new Error(`${path.join(dir, e.name)}: only regular files are packed`);
      return [e.name, readFileSync(path.join(dir, e.name))];
    });
}

/**
 * The engine's tarball entries and the manifest's dotnetEngine: the publish output of Qualor.Taint.Cli
 * (engine/dotnet/publish), the models (models/csharp) and the licence texts (engine/dotnet/licenses).
 * Throws when the engine is not built, a *.pdb is among the files, or a third-party DLL has no licence text.
 */
function engineEntries(root, version) {
  const publish = path.join(root, 'engine/dotnet/publish');
  if (!existsSync(path.join(publish, ENGINE_ENTRY))) throw new Error('engine not built: run npm run build:engine first');
  const engine = filesOf(publish);
  if (engine.some(([n]) => n.endsWith('.pdb'))) throw new Error('engine/dotnet/publish holds a *.pdb: build with npm run build:engine');
  const licences = filesOf(path.join(root, 'engine/dotnet/licenses'));
  const licenceData = new Map(licences);
  for (const [n] of engine) {
    if (!n.endsWith('.dll') || n.startsWith('Qualor.')) continue;
    const base = n.slice(0, -4);
    const text = `${LICENCE_ALIASES[base] ?? base}.txt`;
    if (!licenceData.has(text)) throw new Error(`${n}: no licence text in engine/dotnet/licenses (${text})`);
    const notices = NOTICES.find((x) => x.dlls.includes(base));
    if (notices === undefined) continue;
    const data = licenceData.get(notices.file);
    if (data === undefined) throw new Error(`${n}: its third-party notices are missing (engine/dotnet/licenses/${notices.file})`);
    if (sha256(data) !== notices.sha256) {
      throw new Error(`${notices.file}: SHA-256 ${sha256(data)}, not the package's ${notices.sha256} (copy it unchanged)`);
    }
  }
  const models = filesOf(path.join(root, 'models/csharp'));
  const entries = [
    ...engine.map(([n, d]) => [`dotnet/engine/${n}`, d]),
    ...licences.map(([n, d]) => [`dotnet/engine/licenses/${n}`, d]),
    ...models.map(([n, d]) => [`dotnet/models/csharp/${n}`, d]),
  ];
  const dotnetEngine = {
    version,
    entry: `dotnet/engine/${ENGINE_ENTRY}`,
    models: 'dotnet/models',
    files: [...entries].sort(([a], [b]) => (a < b ? -1 : 1)).map(([n, d]) => ({ path: n, sha256: sha256(d) })),
  };
  return { entries, dotnetEngine };
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
  // package.json's mode, never QUALOR_TAINT_INTRAFILE (tools/engine.mjs): Qualor runs the pack so.
  const engine = engineEntries(root, pkg.version);
  entries.push(...engine.entries);
  const manifest = {
    version: pkg.version,
    opengrep: pkg.opengrep,
    taintIntrafile: pkg.taintIntrafile === true,
    rules,
    dotnetEngine: engine.dotnetEngine,
  };
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
