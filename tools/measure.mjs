// `npm run measure -- [js|python|java|go]...`: the committed rules of those languages (default: all)
// on the REFERENCE.md recall sets of the same languages, in the qualor/scanner image. The OWASP
// Benchmark (Java) is scored per category (tools/score.mjs, design spec §8.4); the other sets get
// finding counts per rule. The result is printed and inserted as the newest entry of
// MEASUREMENTS.md, headed with the last commit that changed rules/.
//
// `npm run measure -- --check`: exit 1 unless the newest entry measured all four languages at the
// last commit that changed rules/ (what /release-pack requires before it pins a pack).
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { referenceProjects } from './backlog.mjs';
import { LANGS, readRule, ruleFiles } from './rules.mjs';
import { checkImage, configs, git, mainTree, outDir, readResult, referenceClone, root, scanTargets } from './scanner.mjs';
import { benchmarkTable, latestMeasurement, parseExpected, scoreBenchmark, targetVerdicts, TARGET } from './score.mjs';

const FILE = path.join(root, 'MEASUREMENTS.md');
const ALL = Object.keys(LANGS);

/** The last commit that changed rules/ (the state a measurement describes). */
const rulesCommit = () => git(['-C', root, 'log', '-1', '--format=%H', '--', 'rules']);

/** Inserts `entry` above the newest entry of MEASUREMENTS.md (after the file's introduction). */
export function insertEntry(text, entry) {
  const lines = text.split('\n');
  const at = lines.findIndex((l) => l.startsWith('## '));
  if (at < 0) return `${text.trimEnd()}\n\n${entry.trimEnd()}\n`;
  return [...lines.slice(0, at), ...entry.trimEnd().split('\n'), '', ...lines.slice(at)].join('\n');
}

/** Problems that make the newest entry of `text` unusable for a release at `commit`. */
export function checkProblems(text, commit) {
  const last = latestMeasurement(text);
  if (last === undefined) return ['MEASUREMENTS.md has no entry: run npm run measure'];
  const problems = [];
  if (last.rules !== commit) problems.push(`the newest entry measured rules at ${last.rules.slice(0, 12)}, but rules/ last changed in ${commit.slice(0, 12)}: run npm run measure`);
  const missing = ALL.filter((l) => !last.langs.includes(l));
  if (missing.length > 0) problems.push(`the newest entry lacks ${missing.join(', ')}: run npm run measure (all languages)`);
  return problems;
}

function measure(langs) {
  if (git(['-C', root, 'status', '--porcelain', '--', 'rules']) !== '') throw new Error('rules/ has uncommitted changes: measure committed rules only');
  const commit = rulesCommit();
  const dirs = langs.filter((l) => existsSync(path.join(root, 'rules', l))).map((l) => `rules/${l}`);
  const { args } = configs(dirs);
  checkImage();
  const cache = path.join(mainTree(), '.tmp');
  const sets = referenceProjects(root).filter((p) => p.use === 'recall' && langs.includes(p.lang));
  const targets = sets.map((p) => ({ name: p.project, lang: p.lang, dir: referenceClone(cache, p), commit: p.commit, excludes: [] }));
  const out = outDir();
  scanTargets(args, targets, cache, out);

  const cweByRule = new Map();
  for (const f of ruleFiles(root)) {
    const { rule } = readRule(root, f);
    if (rule?.id) cweByRule.set(rule.id, rule.metadata?.cwe ?? []);
  }
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const date = new Date().toISOString().slice(0, 10);
  const lines = [`## ${date} rules ${commit} (${langs.join(', ')})`, '', `OpenGrep ${pkg.opengrep}; ${dirs.length} rule directories; results in \`${path.relative(root, out).split(path.sep).join('/')}\`.`, ''];
  for (const t of targets) {
    const res = readResult(path.join(out, `${t.name}.json`));
    if (res === undefined) {
      lines.push(`### ${t.name}: no result (see its .err file)`, '');
      continue;
    }
    const findings = res.results ?? [];
    lines.push(`### ${t.name} (${t.lang}, ${t.commit.slice(0, 12)}): ${findings.length} finding(s), ${res.paths?.scanned?.length ?? 0} files, ${res.errors?.length ?? 0} error(s)`, '');
    if (t.name === 'owasp-benchmark') {
      const csv = path.join(t.dir, 'expectedresults-1.2.csv');
      const javaRules = new Map([...cweByRule].filter(([id]) => id.startsWith('java.')));
      const rows = scoreBenchmark(parseExpected(readFileSync(csv, 'utf8')), findings, javaRules);
      lines.push(...benchmarkTable(rows), '');
      const verdicts = targetVerdicts(rows);
      lines.push(
        `§8.4 target (TPR ≥ ${TARGET.minTpr * 100} %, FPR ≤ ${TARGET.maxFprShareOfFindSecBugs * 100} % of FindSecBugs' FPR) for the covered injection categories: ` +
          (verdicts.length === 0 ? 'none covered yet.' : verdicts.map((v) => `${v.category} ${v.met ? 'met' : `NOT met (${v.why})`}`).join('; ') + '.'),
        '',
      );
    }
    const byRule = new Map();
    for (const f of findings) byRule.set(f.check_id, (byRule.get(f.check_id) ?? 0) + 1);
    if (byRule.size > 0) lines.push(...[...byRule].sort().map(([id, n]) => `- ${id}: ${n}`), '');
  }
  const entry = lines.join('\n');
  console.log(entry);
  const text = existsSync(FILE) ? readFileSync(FILE, 'utf8') : '# Measurements\n';
  writeFileSync(FILE, insertEntry(text, entry));
  console.log(`added to ${path.relative(process.cwd(), FILE)}`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  try {
    if (argv.includes('--check')) {
      const problems = checkProblems(existsSync(FILE) ? readFileSync(FILE, 'utf8') : '', rulesCommit());
      for (const p of problems) console.error(`measure: ${p}`);
      if (problems.length === 0) console.log('measure: the newest entry covers the current rules');
      process.exit(problems.length === 0 ? 0 : 1);
    }
    const bad = argv.filter((l) => !ALL.includes(l));
    if (bad.length > 0) throw new Error(`unknown language(s) ${bad.join(', ')}; use ${ALL.join(', ')}`);
    process.exit(measure(argv.length > 0 ? ALL.filter((l) => argv.includes(l)) : ALL));
  } catch (err) {
    console.error(`measure: ${err.message}`);
    process.exit(1);
  }
}
