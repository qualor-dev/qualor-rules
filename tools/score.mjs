// Scoring of rule findings on the OWASP Benchmark (Java), for tools/measure.mjs. Our own code: the
// method of qualor-cc's docs/testing/owasp-benchmark/score.mjs (plan 6A), not the Benchmark's own
// scorecard tools (BenchmarkUtils, GPL), which are never used here.
//
// Per category: TPR = TP/(TP+FN), FPR = FP/(FP+TN), score = TPR - FPR. A test case counts as
// reported when a finding in its BenchmarkTestNNNNN.java comes from a rule whose metadata.cwe holds
// the category's CWE (CWE 23 and 36 read as 22, 326 as 327, as for SpotBugs in 6A).

export const CWE_ALIAS = new Map([[23, 22], [36, 22], [326, 327]]);

/** OWASP Benchmark categories that design spec §8.4 calls the Java injection categories. */
export const INJECTION = Object.freeze(['cmdi', 'ldapi', 'pathtraver', 'sqli', 'xpathi', 'xss']);

/**
 * FindSecBugs 1.14.0 on Benchmark 1.2 at 8b67a88 (qualor-cc plan 6A, Task 9: our own measurement):
 * the FPR per category that §8.4 compares against.
 */
export const FINDSECBUGS_FPR = Object.freeze({
  cmdi: 0.888, crypto: 0, hash: 0, ldapi: 0.844, pathtraver: 0.956, securecookie: 0,
  sqli: 0.905, trustbound: 0.814, weakrand: 0, xpathi: 0.95, xss: 0.522,
});

/**
 * §8.4: "FPR far below FindSecBugs' 85–96 %, at a TPR of about 60 % or more". Our reading of "far
 * below", until the maintainer sets another: at most half of FindSecBugs' FPR in that category.
 */
export const TARGET = Object.freeze({ minTpr: 0.6, maxFprShareOfFindSecBugs: 0.5 });

/** expectedresults-*.csv → Map test name → { category, real, cwe }. */
export function parseExpected(text) {
  const expected = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (line === '' || line.startsWith('#')) continue;
    const [name, category, real, cwe] = line.split(',');
    expected.set(name, { category, real: real === 'true', cwe: Number(cwe) });
  }
  return expected;
}

const cweNumber = (c) => {
  const n = Number(String(c).replace(/^CWE-/, ''));
  return CWE_ALIAS.get(n) ?? n;
};

/**
 * The category rows for OpenGrep `findings` ({ check_id, path }) given each rule's CWEs
 * (`cweByRule`: rule id → ['CWE-89', ...]). `covered` is true when some rule carries the category's
 * CWE at all, so an uncovered category is not mistaken for a recall failure.
 */
export function scoreBenchmark(expected, findings, cweByRule) {
  const hits = new Map();
  for (const f of findings) {
    const m = /(BenchmarkTest\d{5})\.java$/.exec(f.path ?? '');
    if (!m) continue;
    const set = hits.get(m[1]) ?? new Set();
    for (const c of cweByRule.get(f.check_id) ?? []) set.add(cweNumber(c));
    hits.set(m[1], set);
  }
  const coveredCwes = new Set([...cweByRule.values()].flat().map(cweNumber));
  const cats = new Map();
  for (const [name, e] of expected) {
    const c = cats.get(e.category) ?? { category: e.category, cwe: e.cwe, tp: 0, fn: 0, fp: 0, tn: 0 };
    const found = hits.get(name)?.has(e.cwe) === true;
    if (e.real) found ? c.tp++ : c.fn++;
    else found ? c.fp++ : c.tn++;
    cats.set(e.category, c);
  }
  return [...cats.values()]
    .sort((a, b) => (a.category < b.category ? -1 : 1))
    .map((c) => {
      const tpr = c.tp / (c.tp + c.fn || 1);
      const fpr = c.fp / (c.fp + c.tn || 1);
      return { ...c, tpr, fpr, score: tpr - fpr, covered: coveredCwes.has(c.cwe) };
    });
}

/** The §8.4 verdict of each covered injection category: { category, met, why }. */
export function targetVerdicts(rows) {
  return rows
    .filter((r) => r.covered && INJECTION.includes(r.category))
    .map((r) => {
      const maxFpr = FINDSECBUGS_FPR[r.category] * TARGET.maxFprShareOfFindSecBugs;
      const why = [];
      if (r.tpr < TARGET.minTpr) why.push(`TPR ${pct(r.tpr)} < ${pct(TARGET.minTpr)}`);
      if (r.fpr > maxFpr) why.push(`FPR ${pct(r.fpr)} > ${pct(maxFpr)}`);
      return { category: r.category, met: why.length === 0, why: why.join(', ') };
    });
}

export const pct = (x) => `${(100 * x).toFixed(1)}%`;

/** The Markdown table of `rows`. */
export function benchmarkTable(rows) {
  const out = ['| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |', '|---|---|---|---|---|---|---|---|---|---|'];
  for (const r of rows) {
    const vals = r.covered ? [r.tp, r.fn, r.fp, r.tn, pct(r.tpr), pct(r.fpr), pct(r.score)] : ['no rule', '', '', '', '', '', ''];
    out.push(`| ${r.category} | ${r.cwe} | ${vals.join(' | ')} | ${pct(FINDSECBUGS_FPR[r.category] ?? 0)} |`);
  }
  const cov = rows.filter((r) => r.covered);
  if (cov.length > 0) {
    const mean = (k) => cov.reduce((s, r) => s + r[k], 0) / cov.length;
    out.push(`| **mean of covered categories** | | | | | | ${pct(mean('tpr'))} | ${pct(mean('fpr'))} | ${pct(mean('score'))} | |`);
  }
  return out;
}

/** `## <date> rules <sha> (<langs>)`: the heading of one MEASUREMENTS.md entry. */
export const ENTRY = /^## (\d{4}-\d{2}-\d{2}) rules ([0-9a-f]{40}) \(([a-z, ]+)\)$/;

/** The newest entry of MEASUREMENTS.md: { date, rules, langs } or undefined. Entries are newest first. */
export function latestMeasurement(text) {
  for (const line of text.split(/\r?\n/)) {
    const m = ENTRY.exec(line);
    if (m) return { date: m[1], rules: m[2], langs: m[3].split(', ') };
  }
  return undefined;
}
