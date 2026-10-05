// The rule files of this repository and what each must satisfy (README "Layout", CLEAN-ROOM.md).
// Shared by check.mjs (the CI gate) and release.mjs (the tarball): a rule that fails here never
// reaches a release.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parseAllDocuments } from 'yaml';

/** `<lang>` directory → the OpenGrep `languages` of its rules and the extensions of its tests. */
export const LANGS = Object.freeze({
  js: { languages: ['javascript', 'typescript'], tests: ['.js', '.ts', '.jsx', '.tsx'] },
  python: { languages: ['python'], tests: ['.py'] },
  java: { languages: ['java'], tests: ['.java'] },
  go: { languages: ['go'], tests: ['.go'] },
});

/** Calendar versions YYYY.M.patch, month without a leading zero (npm semver forbids one). */
export const VERSION = /^\d{4}\.([1-9]|1[0-2])\.(0|[1-9]\d*)$/;
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/**
 * A test annotation: `ruleid:`, `ok:`, `todoruleid:` or `todook:` after a comment marker (`//`,
 * `#` or `/*`), so an `ok:` in code (`{ ok: true }`, `ok: bool = True`) is not one.
 */
const ANNOTATION = /(?:\/\/|#|\/\*)\s*(ruleid|ok|todoruleid|todook):\s*([\w.-]+)/g;

/**
 * CLEAN-ROOM.md: sources a rule may never cite (other vendors' rule sets and rule descriptions).
 * Matched against `host + path` of each `metadata.sources` URL, lower case.
 */
export const FORBIDDEN_SOURCES = Object.freeze([
  /^([a-z0-9-]+\.)*semgrep\.dev\//,
  /^(www\.)?github\.com\/(semgrep|returntocorp)\//,
  /^(www\.)?github\.com\/opengrep\/opengrep-rules(\/|$)/,
  /^(www\.)?github\.com\/github\/codeql(\/|$)/,
  /^codeql\.github\.com\//,
  /^rules\.sonarsource\.com\//,
  /^(www\.)?github\.com\/sonarsource\//,
  /^([a-z0-9-]+\.)*sonarcloud\.io\/(.*\/)?(rules|coding_rules)(\/|$)/,
  /^[^/]+\/(.*\/)?coding_rules(\/|$)/, // the rule pages of any SonarQube server (next.sonarqube.com)
]);

export function forbiddenSource(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return true;
  }
  const where = `${u.host}${u.pathname}`.toLowerCase();
  return FORBIDDEN_SOURCES.some((re) => re.test(where));
}

/** Every `.yml`/`.yaml`/`.json` file below `root/rules`, sorted, as `/`-separated paths. */
export function ruleFiles(root) {
  const out = [];
  const walk = (rel) => {
    for (const e of readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const child = `${rel}/${e.name}`;
      if (e.isSymbolicLink()) throw new Error(`${child}: symbolic links are not allowed`);
      if (e.isDirectory()) walk(child);
      else if (/\.(ya?ml|json)$/.test(e.name)) out.push(child);
    }
  };
  walk('rules');
  return out.sort();
}

/**
 * One rule file: parsed and checked against the layout. Returns the rule (its YAML object), the
 * Qualor id (`java/sql-injection`) and the problems found; never throws for a bad rule.
 */
export function readRule(root, file) {
  const problems = [];
  const parts = file.split('/');
  const [, lang, category, base] = parts;
  if (parts.length !== 4 || !Object.hasOwn(LANGS, lang) || !NAME.test(category ?? '')) {
    return { problems: [`${file}: must be rules/<js|python|java|go>/<category>/<name>.yml`] };
  }
  const name = base.replace(/\.yml$/, '');
  if (!base.endsWith('.yml') || !NAME.test(name)) {
    problems.push(`${file}: the file name must be <name>.yml, lower-case words joined by -`);
  }
  if (file.length > 100) problems.push(`${file}: the path is over 100 characters (tar)`);
  const text = readFileSync(path.join(root, file), 'utf8');
  if (text.includes('\r')) problems.push(`${file}: carriage return (the repository uses LF only)`);
  const docs = parseAllDocuments(text, { uniqueKeys: true });
  if (docs.length !== 1 || docs[0].errors.length > 0) {
    return { problems: [...problems, `${file}: not one valid YAML document`] };
  }
  const rules = docs[0].toJS()?.rules;
  if (!Array.isArray(rules) || rules.length !== 1) {
    return { problems: [...problems, `${file}: must hold exactly one rule`] };
  }
  const rule = rules[0];
  const opengrepId = `${lang}.${name}`;
  if (rule.id !== opengrepId) problems.push(`${file}: id must be ${opengrepId}`);
  const want = LANGS[lang].languages;
  if (JSON.stringify(rule.languages) !== JSON.stringify(want)) {
    problems.push(`${file}: languages must be [${want.join(', ')}]`);
  }
  if (rule.mode === 'join' || Object.hasOwn(rule, 'join')) {
    problems.push(`${file}: join rules are not allowed (they can load rules from elsewhere)`);
  }
  const tests = LANGS[lang].tests
    .map((ext) => `rules/${lang}/${category}/${name}${ext}`)
    .filter((t) => existsSync(path.join(root, t)));
  if (tests.length === 0) problems.push(`${file}: no test file ${name}{${LANGS[lang].tests}}`);
  for (const t of tests) {
    const source = readFileSync(path.join(root, t), 'utf8');
    const ids = [...source.matchAll(ANNOTATION)];
    if (!ids.some((m) => m[1] === 'ruleid' && m[2] === opengrepId)) {
      problems.push(`${t}: no "ruleid: ${opengrepId}" line`);
    }
    if (!ids.some((m) => m[1] === 'ok' && m[2] === opengrepId)) {
      problems.push(`${t}: no "ok: ${opengrepId}" line`);
    }
    for (const m of ids) {
      if (m[2] !== opengrepId) problems.push(`${t}: annotation for another rule: ${m[2]}`);
    }
  }
  for (const url of rule.metadata?.sources ?? []) {
    if (forbiddenSource(url)) problems.push(`${file}: source not allowed (CLEAN-ROOM.md): ${url}`);
  }
  return { rule, lang, qualorId: `${lang}/${name}`, problems };
}
