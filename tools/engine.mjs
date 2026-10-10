// How the rules are run: the OpenGrep version package.json pins ("opengrep") and the taint mode
// the rules are tested in ("taintIntrafile": `opengrep scan --taint-intrafile`, OpenGrep's
// inter-procedural taint analysis within one file). The one source of truth for every tool that
// runs OpenGrep (test-rules, test-examples, the probe, measure, scan) and for the pack's
// manifest.json (tools/release.mjs), so Qualor runs a pack the way it was tested.
//
// QUALOR_TAINT_INTRAFILE=1|0 runs the tools in the other mode for a comparison (a measurement
// records the mode it ran in); a release always takes package.json's value.
import { readFileSync } from 'node:fs';
import path from 'node:path';

const ON = new Set(['1', 'true']);
const OFF = new Set(['0', 'false']);

/** The mode an environment value asks for: true, false, or undefined when it is unset or empty. */
export function intrafileOverride(value) {
  if (value === undefined || value === '') return undefined;
  if (ON.has(value)) return true;
  if (OFF.has(value)) return false;
  throw new Error(`QUALOR_TAINT_INTRAFILE must be 1 or 0, got ${JSON.stringify(value)}`);
}

/**
 * The engine of the repository at `root`: `{ version, taintIntrafile, args }`, `args` being the
 * mode's `opengrep scan` arguments. `env` (default process.env) may override the mode.
 */
export function engine(root, env = process.env) {
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const taintIntrafile = intrafileOverride(env.QUALOR_TAINT_INTRAFILE) ?? pkg.taintIntrafile === true;
  return { version: pkg.opengrep, taintIntrafile, args: taintIntrafile ? ['--taint-intrafile'] : [] };
}

/** The mode as a measurement or a log line names it. */
export const modeName = (taintIntrafile) => (taintIntrafile ? 'taint-intrafile' : 'taint per function');
