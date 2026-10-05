// `npm run check`: the layout, the metadata schema, unique ids, test annotations and the
// clean-room source list of every rule (README "Checks"). Exit 1 with one line per problem.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { readRule, ruleFiles, VERSION } from './rules.mjs';

/** Bounds of Qualor's manifest schema that the metadata schema cannot express. */
const MAX_LANGUAGES = 16;
const MAX_RULES = 2000;

export function checkRepository(root) {
  const schema = JSON.parse(readFileSync(path.join(root, 'schema/rule-metadata.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const problems = [];
  if (!VERSION.test(pkg.version)) problems.push(`package.json: version ${pkg.version} is not YYYY.M.patch`);
  if (!/^\d+\.\d+\.\d+$/.test(pkg.opengrep ?? '')) problems.push('package.json: no "opengrep" version');
  const seen = new Map();
  let files;
  try {
    files = ruleFiles(root);
  } catch (err) {
    return [...problems, String(err.message)];
  }
  if (files.length === 0) problems.push('rules/: no rule');
  if (files.length > MAX_RULES) problems.push(`rules/: more than ${MAX_RULES} rules`);
  for (const file of files) {
    const r = readRule(root, file);
    problems.push(...r.problems);
    if (r.rule === undefined) continue;
    if (Array.isArray(r.rule.languages) && r.rule.languages.length > MAX_LANGUAGES) {
      problems.push(`${file}: more than ${MAX_LANGUAGES} languages`);
    }
    if (!validate(r.rule.metadata)) {
      for (const e of validate.errors ?? []) {
        problems.push(`${file}: metadata${e.instancePath} ${e.message}`);
      }
    }
    if (seen.has(r.qualorId)) problems.push(`${file}: id ${r.qualorId} also in ${seen.get(r.qualorId)}`);
    seen.set(r.qualorId, file);
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const problems = checkRepository(root);
  for (const p of problems) console.error(p);
  console.log(problems.length === 0 ? 'check: ok' : `check: ${problems.length} problem(s)`);
  process.exit(problems.length === 0 ? 0 : 1);
}
