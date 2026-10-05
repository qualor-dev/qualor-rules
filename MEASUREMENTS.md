# Measurements

Recall of the rules on the deliberately vulnerable sets of `REFERENCE.md` (design spec §8.4),
**newest first**, written by `npm run measure -- [lang]...` (`tools/measure.mjs`). Each entry is
headed with the last commit that changed `rules/`, so it says exactly which rules were measured.
`/write-rules` measures the languages it touched at the end of a run; `/release-pack` pins a pack
only when `npm run measure -- --check` passes (the newest entry covers all four languages at the
current rules).

- **OWASP Benchmark (Java)** is scored per category with the Benchmark method (TPR = TP/(TP+FN),
  FPR = FP/(FP+TN), score = TPR − FPR), by our own code (`tools/score.mjs`, the method of
  qualor-cc's 6A scoring script; never the Benchmark's own scorecard tools). A test case counts as
  reported when a finding in its file comes from a rule whose `metadata.cwe` holds the category's
  CWE. Categories without such a rule show "no rule". The FindSecBugs column is our 6A measurement
  of FindSecBugs 1.14.0 on the same commit.
- **§8.4 target** for the covered Java injection categories (cmdi, ldapi, pathtraver, sqli, xpathi,
  xss): TPR at least 60 % and FPR "far below FindSecBugs' 85–96 %", read here as at most half of
  FindSecBugs' FPR in that category (`TARGET` in `tools/score.mjs`; the maintainer may set another
  reading). A miss is reported to the maintainer, not hidden.
- **Other sets** (Juice Shop, NodeGoat, PyGoat, GoVWA): finding counts per rule, a recorded
  baseline without a threshold (spec §8.4). Scoring them against their published vulnerability
  lists is a follow-up.
- Entries are data, not code: no line of a measured project is quoted here.

## 2026-10-04 rules 95f5696b1ee85db56719c6311c2f91b9832301a5 (js, python, java, go)

OpenGrep 1.30.0; 4 rule directories; results in `.tmp/probe/2026-10-04T10-25-58-540Z`.

### juice-shop (js, 1618a611b173): 6 finding(s), 652 files, 12 error(s)

- js.sql-injection: 6

### nodegoat (js, c5cb68a7084e): 0 finding(s), 51 files, 0 error(s)

### pygoat (python, 19d17cc88748): 0 finding(s), 85 files, 0 error(s)

### owasp-benchmark (java, 8b67a88d73b2): 212 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | no rule |  |  |  |  |  |  | 88.8% |
| crypto | 327 | no rule |  |  |  |  |  |  | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | no rule |  |  |  |  |  |  | 84.4% |
| pathtraver | 22 | no rule |  |  |  |  |  |  | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 134 | 138 | 78 | 154 | 49.3% | 33.6% | 15.6% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | no rule |  |  |  |  |  |  | 95.0% |
| xss | 79 | no rule |  |  |  |  |  |  | 52.2% |
| **mean of covered categories** | | | | | | 49.3% | 33.6% | 15.6% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: sqli NOT met (TPR 49.3% < 60.0%).

- java.sql-injection: 212

### govwa (go, 4058f79f31ee): 0 finding(s), 24 files, 0 error(s)
