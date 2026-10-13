// `npm run check`: the layout, the metadata schema, unique ids, test annotations and the
// clean-room source list of every rule, and that every engine model has its rule (README "Checks").
// Exit 1 with one line per problem.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { parseAllDocuments } from 'yaml';
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
  if (typeof pkg.taintIntrafile !== 'boolean') {
    problems.push('package.json: "taintIntrafile" must be true or false (the taint mode the rules are tested in)');
  }
  const seen = new Map();
  const ids = new Set();
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
    if (typeof r.rule.id === 'string') ids.add(r.rule.id);
  }
  problems.push(...checkModels(root, ids));
  return problems;
}

/** The engine's shared models (models/README.md): in models/csharp, but no rule's model. */
export const SHARED_MODELS = Object.freeze(['sources.yml', 'propagators.yml']);

/**
 * models/csharp, the Roslyn engine's models: every `<name>.yml` but the shared files is the model of
 * the rule `csharp.<name>`, which must exist (`ruleIds`: the OpenGrep ids of the rules) and which its
 * `rule:` key names. The engine's own loader checks the rest of the format (`npm run test:engine`).
 */
export function checkModels(root, ruleIds) {
  const problems = [];
  const dir = path.join(root, 'models');
  if (!existsSync(dir)) return problems;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isFile() && e.name === 'README.md') continue;
    if (!e.isDirectory() || e.isSymbolicLink() || e.name !== 'csharp') {
      problems.push(`models/${e.name}: the engine's models are models/csharp only (and models/README.md)`);
    }
  }
  const lang = path.join(dir, 'csharp');
  if (!existsSync(lang)) return problems;
  for (const shared of SHARED_MODELS) {
    if (!existsSync(path.join(lang, shared))) problems.push(`models/csharp/${shared}: missing (the engine's shared model)`);
  }
  for (const e of readdirSync(lang, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const file = `models/csharp/${e.name}`;
    if (!e.isFile() || e.isSymbolicLink() || !/^[a-z0-9]+(-[a-z0-9]+)*\.yml$/.test(e.name)) {
      problems.push(`${file}: only <name>.yml model files belong in models/csharp`);
      continue;
    }
    const text = readFileSync(path.join(root, file), 'utf8');
    if (text.includes('\r')) problems.push(`${file}: carriage return (the repository uses LF only)`);
    const docs = parseAllDocuments(text, { uniqueKeys: true });
    if (docs.length !== 1 || docs[0].errors.length > 0) {
      problems.push(`${file}: not one valid YAML document`);
      continue;
    }
    if (SHARED_MODELS.includes(e.name)) continue;
    const id = `csharp.${e.name.slice(0, -'.yml'.length)}`;
    if (!ruleIds.has(id)) problems.push(`${file}: no rule ${id} (a model needs its rule in rules/csharp/)`);
    if (docs[0].toJS()?.rule !== id) problems.push(`${file}: rule must be ${id} (the file's name)`);
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
