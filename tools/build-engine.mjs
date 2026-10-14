// `npm run build:engine`: publishes the C# taint engine (engine/dotnet/src/Qualor.Taint.Cli) to engine/dotnet/publish,
// which `npm run release` packs. Framework-dependent, no *.pdb, restore in locked mode (packages.lock.json), run from
// engine/dotnet so its global.json picks the SDK. No SourceRevisionId or other per-build value: the same commit gives
// the same bytes (CI builds with the exact SDK of global.json; a newer local SDK may differ).
import { spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'engine', 'dotnet');
rmSync(path.join(cwd, 'publish'), { recursive: true, force: true });
const r = spawnSync(
  'dotnet',
  [
    'publish', 'src/Qualor.Taint.Cli', '-c', 'Release', '-o', 'publish', '--nologo',
    '-p:ContinuousIntegrationBuild=true', '-p:RestoreLockedMode=true', '-p:DebugType=none', '-p:DebugSymbols=false',
  ],
  { cwd, stdio: 'inherit' },
);
process.exit(r.status ?? 1);
