// Part of `npm run check`: BACKLOG.md (the queue of rules) and REFERENCE.md (the projects the rules
// are probed on) are well-formed and agree with rules/. Exit 1 with one line per problem.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LANGS, readRule, ruleFiles } from './rules.mjs';

const NAME = '[a-z0-9]+(?:-[a-z0-9]+)*';
/** `<lang>.<name>` for a rule, `<lang>.<name>#<topic>` for a maintenance item on that rule. */
const ID = new RegExp(`^(js|python|java|go)\\.(${NAME})(?:#(${NAME}))?$`);
export const STATUSES = Object.freeze(['todo', 'in-progress', 'done', 'blocked']);
export const BACKLOG_HEADER = Object.freeze(['id', 'lang', 'category', 'cwe', 'kind', 'frameworks and apis', 'status', 'notes']);
export const REFERENCE_HEADER = Object.freeze(['lang', 'project', 'repository', 'commit', 'licence', 'frameworks', 'use']);

/** The cells of a Markdown table row; `\|` is a literal pipe inside a cell. */
function cells(line) {
  const inner = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return inner.split(/(?<!\\)\|/).map((c) => c.trim().replaceAll('\\|', '|'));
}

/**
 * The rows of the first Markdown table in `text` whose header is `header` (lower case), as objects
 * keyed by the header, each with its 1-based `line`. Returns undefined when there is no such table.
 */
export function parseTable(text, header) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim().startsWith('|') && cells(l).map((c) => c.toLowerCase()).join('|') === header.join('|'));
  if (start < 0) return undefined;
  const rows = [];
  for (let i = start + 2; i < lines.length && lines[i].trim().startsWith('|'); i++) {
    const c = cells(lines[i]);
    rows.push({ line: i + 1, width: c.length, ...Object.fromEntries(header.map((h, j) => [h, c[j] ?? ''])) });
  }
  return rows;
}

/** The problems of BACKLOG.md against the rules in `root`. */
export function backlogProblems(root) {
  const file = path.join(root, 'BACKLOG.md');
  if (!existsSync(file)) return ['BACKLOG.md: missing'];
  const rows = parseTable(readFileSync(file, 'utf8'), BACKLOG_HEADER);
  if (rows === undefined) return [`BACKLOG.md: no table with the header | ${BACKLOG_HEADER.join(' | ')} |`];
  const problems = [];
  const byId = new Map();
  for (const r of rows) {
    const at = `BACKLOG.md:${r.line}`;
    if (r.width !== BACKLOG_HEADER.length) problems.push(`${at}: ${r.width} cells, want ${BACKLOG_HEADER.length}`);
    const m = ID.exec(r.id);
    if (m === null) {
      problems.push(`${at}: id ${JSON.stringify(r.id)} is not <lang>.<name> or <lang>.<name>#<topic>`);
      continue;
    }
    if (byId.has(r.id)) problems.push(`${at}: id ${r.id} also on line ${byId.get(r.id).line}`);
    byId.set(r.id, r);
    if (r.lang !== m[1]) problems.push(`${at}: lang ${r.lang} does not match the id`);
    if (!new RegExp(`^${NAME}$`).test(r.category)) problems.push(`${at}: category ${JSON.stringify(r.category)} is not lower-case words joined by -`);
    if (!/^CWE-[1-9]\d{0,6}(, CWE-[1-9]\d{0,6})*$/.test(r.cwe)) problems.push(`${at}: cwe must be "CWE-n" or "CWE-n, CWE-m"`);
    if (!['issue', 'hotspot'].includes(r.kind)) problems.push(`${at}: kind must be issue or hotspot`);
    if (!STATUSES.includes(r.status)) problems.push(`${at}: status must be one of ${STATUSES.join(', ')}`);
    if (r['frameworks and apis'] === '') problems.push(`${at}: frameworks and APIs are empty`);
    if (r.status === 'blocked' && !r.notes.includes('?')) problems.push(`${at}: a blocked row needs the question for the maintainer in its notes`);
  }
  // rules/ and the queue agree: a rule exists exactly while its row is in progress or done.
  const rules = new Map();
  for (const f of ruleFiles(root)) {
    const [, lang, category, base] = f.split('/');
    rules.set(`${lang}.${base.replace(/\.ya?ml$|\.json$/, '')}`, { file: f, category, metadata: readRule(root, f).rule?.metadata });
  }
  for (const [id, rule] of rules) {
    const r = byId.get(id);
    if (r === undefined) problems.push(`${rule.file}: no BACKLOG.md row ${id}`);
    else if (!['in-progress', 'done'].includes(r.status)) problems.push(`BACKLOG.md:${r.line}: ${id} has a rule file but status ${r.status}`);
    else if (r.category !== rule.category) problems.push(`BACKLOG.md:${r.line}: category ${r.category}, but the rule is in ${rule.file}`);
    else if (rule.metadata !== undefined) {
      // The row and the rule agree on what the rule is: its kind (ruling M1) and its CWEs.
      if (r.kind !== rule.metadata.kind) problems.push(`BACKLOG.md:${r.line}: kind ${r.kind}, but ${rule.file} says ${rule.metadata.kind}`);
      const cwes = [...(rule.metadata.cwe ?? [])].sort().join(', ');
      if (r.cwe.split(', ').sort().join(', ') !== cwes) problems.push(`BACKLOG.md:${r.line}: cwe ${r.cwe}, but ${rule.file} says ${cwes}`);
    }
  }
  for (const [id, r] of byId) {
    const [rule, topic] = id.split('#');
    if (topic === undefined) {
      if (r.status === 'done' && !rules.has(id)) problems.push(`BACKLOG.md:${r.line}: ${id} is done but rules/${r.lang}/${r.category}/${id.slice(r.lang.length + 1)}.yml is missing`);
    } else if (!rules.has(rule)) {
      problems.push(`BACKLOG.md:${r.line}: maintenance item ${id} names no existing rule ${rule}`);
    }
  }
  return problems;
}

/** The projects of REFERENCE.md ({ lang, project, repository, commit, frameworks, use }). */
export function referenceProjects(root) {
  const rows = parseTable(readFileSync(path.join(root, 'REFERENCE.md'), 'utf8'), REFERENCE_HEADER);
  if (rows === undefined) throw new Error(`REFERENCE.md: no table with the header | ${REFERENCE_HEADER.join(' | ')} |`);
  return rows;
}

/** The problems of REFERENCE.md. */
export function referenceProblems(root) {
  if (!existsSync(path.join(root, 'REFERENCE.md'))) return ['REFERENCE.md: missing'];
  let rows;
  try {
    rows = referenceProjects(root);
  } catch (err) {
    return [err.message];
  }
  const problems = [];
  const seen = new Set();
  for (const r of rows) {
    const at = `REFERENCE.md:${r.line}`;
    if (r.width !== REFERENCE_HEADER.length) problems.push(`${at}: ${r.width} cells, want ${REFERENCE_HEADER.length}`);
    if (!Object.hasOwn(LANGS, r.lang)) problems.push(`${at}: lang must be one of ${Object.keys(LANGS).join(', ')}`);
    if (!new RegExp(`^${NAME}$`).test(r.project)) problems.push(`${at}: project ${JSON.stringify(r.project)} is not lower-case words joined by -`);
    if (seen.has(r.project)) problems.push(`${at}: project ${r.project} twice`);
    seen.add(r.project);
    if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(r.repository)) problems.push(`${at}: repository must be https://github.com/<owner>/<repo>`);
    if (!/^[0-9a-f]{40}$/.test(r.commit)) problems.push(`${at}: commit must be a full 40-character SHA`);
    if (r.licence === '') problems.push(`${at}: licence is empty (write "none" when the project has no licence file)`);
    if (!['noise', 'recall'].includes(r.use)) problems.push(`${at}: use must be noise or recall`);
  }
  if (rows.length === 0) problems.push('REFERENCE.md: no project');
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const problems = [...backlogProblems(root), ...referenceProblems(root)];
  for (const p of problems) console.error(p);
  console.log(problems.length === 0 ? 'backlog: ok' : `backlog: ${problems.length} problem(s)`);
  process.exit(problems.length === 0 ? 0 : 1);
}
