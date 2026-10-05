// `npm run test:rules`: `opengrep scan --test` over rules/ with the OpenGrep version package.json
// pins ("opengrep"). OpenGrep exits 0 even when a rule file is invalid or has no test, so the
// verdict comes from its JSON, never from its exit code alone. OPENGREP names the binary
// (default: `opengrep` on PATH).
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** The problems of one `opengrep scan --test --json` result (its parsed JSON). */
export function testProblems(result) {
  const problems = [];
  for (const file of result.config_with_errors ?? []) problems.push(`invalid rule file: ${JSON.stringify(file)}`);
  for (const file of result.config_missing_tests ?? []) problems.push(`no test file: ${file}`);
  for (const [config, entry] of Object.entries(result.results ?? {})) {
    for (const [id, check] of Object.entries(entry.checks ?? {})) {
      if (check.errors?.length > 0) problems.push(`${id} (${config}): ${JSON.stringify(check.errors)}`);
      if (check.passed !== true) {
        for (const [file, m] of Object.entries(check.matches ?? {})) {
          problems.push(
            `${id}: ${file}: expected lines ${JSON.stringify(m.expected_lines)}, reported ${JSON.stringify(m.reported_lines)}`,
          );
        }
      }
    }
  }
  if (Object.keys(result.results ?? {}).length === 0) problems.push('no rule was tested');
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pinned = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).opengrep;
  const bin = process.env.OPENGREP || 'opengrep';
  const version = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (version.status !== 0 || version.stdout.trim() !== pinned) {
    console.error(`test-rules: ${bin} --version must print ${pinned}, got ${JSON.stringify(version.stdout?.trim())}`);
    process.exit(1);
  }
  const run = spawnSync(
    bin,
    ['scan', '--test', '--json', '--disable-version-check', '--no-rewrite-rule-ids', 'rules/'],
    { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  let result;
  try {
    result = JSON.parse(run.stdout);
  } catch {
    console.error(`test-rules: opengrep exited ${run.status} without JSON:\n${run.stderr}`);
    process.exit(1);
  }
  const problems = testProblems(result);
  for (const p of problems) console.error(p);
  console.log(problems.length === 0 ? `test-rules: ok (OpenGrep ${pinned})` : `test-rules: ${problems.length} problem(s)`);
  process.exit(problems.length === 0 && run.status === 0 ? 0 : 1);
}
