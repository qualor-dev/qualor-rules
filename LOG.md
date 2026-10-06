# Run log

One section per `/write-rules` run, pack release or setup change, **newest first**. The next run
reads the newest three entries before it starts, so open questions and measurement notes belong
here, not only in a chat.

Entry format:

```markdown

## <yyyy-mm-dd>: <what> (`/write-rules 10 python`, `/release-pack`, setup)[ (in progress)]

- **Request:** what the maintainer asked for.
- **Plan** (runs): BASE = the "docs(backlog): start" commit of the run; batches `python-1` (<ids>),
  `python-2` (<ids>), … or "inline".
- **Progress** (runs, one line per event, committed as it happens): `- python-1 (<ids>): APPROVED; merged a16e65c..de368c8
  in round 2; merged <from>..<to>`.
- **Done:** `<id>` (<commit>), … — or none.
- **Blocked:** `<id>`: <the question for the maintainer> — or none.
- **Backlog:** rows added, reordered or reset (and why); `todo` left per language.
- **Measurement:** per rule, findings on the reference projects (`gin-realworld 2 (2 TP), gitea 0,
  qualor-cc 0`), the headline of the run's `MEASUREMENTS.md` entry, anything surprising.
- **Notes:** follow-ups, decisions taken without the maintainer (with the reason), worktrees or
  branches left behind.
```

## 2026-10-06: rules run (`/write-rules 52`) (in progress)

- **Request:** the maintainer asked to finish the rules backlog for the next release ("Давай к след. релизу доделаем беклог по правилам"): the 42 maintenance rows queued by the 2026-10-04 reviews, the open rows (java-4 of that run, js.insecure-cookie, python.tar-extraction, the three xss#sink-results rows) and python.command-injection, reopened. The four `*.sql-injection#dedupe-other-engines` rows are qualor-cc work (equivalences.json) and are done outside this run.
- **Plan:** BASE = the "docs(backlog): start" commit of this run; batches `js-1` (js.open-redirect#performance, js.xss#awaited-call-sanitizer, js.prototype-pollution#then-block-only, js.regex-injection#reassign-after-check), `js-2` (js.regex-injection#hand-written-escape, js.command-injection#powershell-params, js.command-injection#fallback-from-request, js.command-injection#cmd-powershell-tail), `js-3` (js.sql-injection#destructured-request, js.tls-verification-disabled#other-libraries, js.insecure-cookie, js.xss#sink-results), `python-1` (python.command-injection, python.sql-injection#allow-list-unify, python.sql-injection#slices, python.ssrf#origin-chain), `python-2` (python.open-redirect#middleware-path, python.open-redirect#django-guard, python.open-redirect#location-header-redirectview, python.path-traversal#shelve), `python-3` (python.xss#json-reassign-or, python.xxe#lxml-dtd-hotspot, python.tls-verification-disabled#ssl-wrap-socket, python.tls-verification-disabled#hostname-only), `python-4` (python.tls-verification-disabled#aiohttp, python.tls-verification-disabled#sdk-verify, python.tls-verification-disabled#httpx-transport, python.tar-extraction), `java-1` (java.sql-injection#source-block-align, java.sql-injection#source-block-trim, java.sql-injection#request-part, java.ssrf#backslash), `java-2` (java.xss#serialiser-string-var, java.xxe#schema-access, java.open-redirect#local-path-base, java.xpath-injection), `java-3` (java.regex-injection, java.tls-verification-disabled, java.weak-cipher, java.xss#sink-results), `go-1` (go.command-injection#encoded-command, go.path-traversal#test-support, go.sql-injection#bind-in-comparison, go.open-redirect#validator-guard), `go-2` (go.open-redirect#url-producers, go.ssrf#reverse-proxy, go.xss#text-template-buffer, go.weak-cipher#tls-cipher-suites), `go-3` (go.zip-slip#exit-calls, go.tls-verification-disabled#noop-callback-var, go.insecure-cookie#helper-cookies, go.xss#sink-results). New rules get `since: 2026.10.2`. Languages in parallel, each language's batches in turn; implementers and reviewers are opus subagents; the 2026-10-04 lessons (qualor-cc .superpowers/sdd/2026-10-04-rules-factory/lessons.md) apply, plus: every new rule gets its docs/rules page in the same commit; time a rule on a large minified file containing its literal (--timeout 0) when it adds alternatives.
- **Progress:**
- go-1 (go.command-injection#encoded-command, go.path-traversal#test-support, go.sql-injection#bind-in-comparison, go.open-redirect#validator-guard): APPROVED after 1 fix round (ruling G1: prefix checks without a backslash check stay reported); merged f64739c..4cc19dd
- java-1 (java.sql-injection#source-block-align, java.sql-injection#source-block-trim, java.sql-injection#request-part, java.ssrf#backslash): APPROVED after 2 fix rounds (Benchmark unchanged); merged efcec39..4391a36
- python-1 (python.command-injection, python.sql-injection#allow-list-unify, python.sql-injection#slices, python.ssrf#origin-chain): APPROVED after 1 fix round (python.command-injection shipped, F8 shapes quiet); merged f6e9ccb..05016d4
- js-1 (js.open-redirect#performance, js.xss#awaited-call-sanitizer, js.prototype-pollution#then-block-only, js.regex-injection#reassign-after-check): APPROVED after 3 fix rounds (open-redirect three.js ~300 s to ~15 s with identical findings; Location-header templates now match); merged ce241c2..11c8cbd
- go-2 (go.open-redirect#url-producers, go.ssrf#reverse-proxy, go.xss#text-template-buffer, go.weak-cipher#tls-cipher-suites): APPROVED after 2 fix rounds (rulings G2: weak-cipher follows crypto/tls InsecureCipherSuites; G3: oauth2/minio/s3 sanitizers bound to the real import); merged 21ab94c..14d5d89
- java-2 (java.xss#serialiser-string-var, java.xxe#schema-access, java.open-redirect#local-path-base, java.xpath-injection): APPROVED after 1 fix round (ruling J1: java.xpath-injection ships at Benchmark xpathi FPR 50.0 %, one case over the 47.5 % target, one-method precedent); merged 0b4f43a..8993b35

## 2026-10-06: release 2026.10.1 (`/release-pack`)

- **Request:** the maintainer asked to integrate the rules into the Qualor server and CLI (pin and publish the pack) and to release despite the §8.4 Java result ("Выпускать сейчас").
- **Done:** qualor-rules-2026.10.1.tar.gz, sha256 aa9ce2da7571a57d7191d23f3937ae58a6e6c4f1ca750b2e4c31430161402b32, OpenGrep 1.30.0; 49 rules (46 issues, 3 hotspots): the 4 seed rules (java.sql-injection changed) and the 45 rules of the 2026-10-04 run. Reproducible: host twice and Linux, identical.
- **Measurement:** MEASUREMENTS.md 2026-10-05 entry (rules fa2c6d7): noise projects and qualor-cc 0 findings; Benchmark TPR 86–89 %, FPR cmdi 45.6 %, ldapi 53.1 %, pathtraver 65.2 %, sqli 53.9 %, xss 47.8 %: §8.4 NOT met in all five (released on the maintainer's word; `--taint-intrafile` is the next task).
- **Notes:** the repository is public since 2026-10-06 (rulesets on main and v* tags, secret scanning, private vulnerability reporting, SECURITY.md).

## 2026-10-04: rules run (`/write-rules 56`)

- **Request:** the maintainer asked for 50 new rules now ("50 правил надо написать сейчас"); N = 56 so that 50 new rules are written after the 6 maintenance rows at the top of the queue.
- **Plan:** BASE = the "docs(backlog): start" commit of this run; batches `js-1` (js.sql-injection#res-name-filter, js.sql-injection#nextjs-fastify-sequelize-literal, js.nosql-injection, js.command-injection), `js-2` (js.path-traversal, js.ssrf, js.xss, js.react-dangerous-html), `js-3` (js.open-redirect, js.code-injection, js.template-injection, js.prototype-pollution), `js-4` (js.regex-injection, js.tls-verification-disabled), `python-1` (python.sql-injection#django, python.command-injection, python.path-traversal, python.ssrf), `python-2` (python.xss, python.unsafe-deserialization, python.open-redirect, python.code-injection), `python-3` (python.template-injection, python.xxe, python.xpath-injection, python.regex-injection), `python-4` (python.tls-verification-disabled), `java-1` (java.sql-injection#benchmark-recall, java.command-injection, java.path-traversal, java.ssrf), `java-2` (java.xss, java.xxe, java.unsafe-deserialization, java.open-redirect), `java-3` (java.ldap-injection, java.template-injection, java.expression-injection, java.zip-slip), `java-4` (java.xpath-injection, java.regex-injection, java.tls-verification-disabled, java.weak-cipher), `go-1` (go.sql-injection#echo-default-binder, go.sql-injection#numeric-fields, go.command-injection, go.path-traversal), `go-2` (go.ssrf, go.xss, go.open-redirect, go.template-injection), `go-3` (go.zip-slip, go.tls-verification-disabled, go.weak-cipher, go.weak-hash), `go-4` (go.insecure-cookie). Languages in parallel, each language's batches in turn; implementers and reviewers are opus subagents.
- **Progress:**
- js-1 (js.sql-injection#res-name-filter, js.sql-injection#nextjs-fastify-sequelize-literal, js.nosql-injection, js.command-injection): APPROVED in round 4 (3 fix rounds); merged bdbe8ef..0ee6065
- go-1 (go.sql-injection#echo-default-binder, go.sql-injection#numeric-fields, go.command-injection, go.path-traversal): APPROVED in round 3 (2 fix rounds; go.path-traversal unblocked by ruling F6); merged 69b5982..e0fae65
- python-1 (python.sql-injection#django, python.command-injection, python.path-traversal, python.ssrf): APPROVED after 3 fix rounds except python.command-injection, withdrawn (open Critical after round 3; ruling F8)
- java-1 (java.sql-injection#benchmark-recall, java.command-injection, java.path-traversal, java.ssrf): APPROVED after 3 fix rounds; merged 3a2509b..ec8a5ef
- go-2 (go.ssrf, go.xss, go.open-redirect, go.template-injection): APPROVED after 3 fix rounds (go.open-redirect shipped by ruling F9); merged af1e69e..5e9b8c9
- js-2 (js.path-traversal, js.ssrf, js.xss, js.react-dangerous-html): APPROVED after 3 fix rounds; merged 615a685..44c0445
- python-2 (python.xss, python.unsafe-deserialization, python.open-redirect, python.code-injection): APPROVED after 3 fix rounds; merged 1156a16..a83da95
- go-3 (go.zip-slip, go.tls-verification-disabled, go.weak-cipher, go.weak-hash): APPROVED after 1 fix round (go.tls-verification-disabled and go.weak-hash skip *_test.go by ruling F10); merged a002a2c..bd276e3
- python-3 (python.template-injection, python.xxe, python.xpath-injection, python.regex-injection): APPROVED after 1 fix round; merged 42623b5..82df4b5
- java-2 (java.xss, java.xxe, java.unsafe-deserialization, java.open-redirect): APPROVED after 2 fix rounds (java.xss Benchmark FPR 47.8 %, same one-method reason as java-1); merged 1fabe3c..1fb342f
- python-4 (python.tls-verification-disabled): APPROVED after 1 fix round (skips test files at rule level, as F10); merged 2811279..3217e0b
- js-3 (js.open-redirect, js.code-injection, js.template-injection, js.prototype-pollution): APPROVED after 1 fix round; merged 9cff086..94beb87
- go-4 (go.insecure-cookie): APPROVED after 2 fix rounds (skips *_test.go, as F10); merged bcf29ea..219353d
- js-4 (js.regex-injection, js.tls-verification-disabled): APPROVED after 1 fix round (tls skips test files, as F10); merged 77c584b..6023945
- java-3 (java.ldap-injection, java.template-injection, java.expression-injection, java.zip-slip): APPROVED after 1 fix round (ldapi Benchmark FPR 53.1 %, the one-method reason of java-1); merged d070808..4d48e57
- java-4 (java.xpath-injection, java.regex-injection, java.tls-verification-disabled, java.weak-cipher): not started — the maintainer stopped the run at the weekly usage limit; rows reset to `todo`
- **Done:** 51 rows: the 6 maintenance rows and 45 new rules (js 12, python 11, java 11, go 11); commits in the Progress merges above.
- **Blocked:** `python.command-injection`: withdrawn after 3 fix rounds (argv-table lookups reported, shell-string shapes missed): retry it alone with this run's lessons, or split it into subprocess and os.system rows?
- **Backlog:** statuses set (51 `done`, 1 `blocked`, the 4 java-4 rows back to `todo`). The reviewers' maintenance rows and candidates are NOT added yet (the run stopped at the usage limit); the list is below under Notes. `todo` left: java 4.
- **Measurement:** not run (usage limit). Per-batch numbers from the reviews: noise projects and qualor-cc 0 for every rule; Benchmark java.xss TPR 86.2 % FPR 47.8 %, ldapi TPR 88.9 % FPR 53.1 % (above the ≤ 42.2 % target; every FP is a same-file helper or switch; ldapi with `--taint-intrafile` 21.9 %). Run `npm run measure` first in the next session.
- **Notes:**
  - Rulings of the run: F6 go.path-traversal shipped with a test-support FP recorded; F8 python.command-injection withdrawn; F9 go.open-redirect shipped with recorded FPs; F10 rule-level `paths: exclude` of test files accepted for misuse/hotspot rules (go tls/weak-hash/insecure-cookie, python and js tls). COVERAGE.md still needs its "Test code" paragraph (Go `*_test.go`; Python `test_*.py`, `*_test.py`, `conftest.py`, `tests.py`, `tests/`, `test/`; JS `*.test.*`, `*.spec.*`, `__tests__/`, `test/`, `tests/`).
  - Performance: js.open-redirect times out on a large minified file (three.js, 154 s) — top maintenance row. OpenGrep 1.30 drops a rule's literal prefilter when it has many alternatives or a literal-less branch; time every new rule on a large minified file that contains the literal, with `--timeout 0` (add to rule-procedure.md).
  - Factory follow-ups: a per-alternative mutation tool (remove one pattern alternative at a time, the test must fail; java-3 wrote one) belongs in tools/; test-rules must check todo lines; enable `--taint-intrafile` after a speed measurement (maintainer's decision); fold the run's review lessons into rule-procedure.md and the COVERAGE source blocks; the first YAML anchor is in js.tls-verification-disabled.
  - Rows to add (maintenance): js.open-redirect#performance; js.xss#awaited-call-sanitizer; js.prototype-pollution#then-block-only; js.regex-injection#reassign-after-check, #hand-written-escape; js.command-injection#powershell-params, #fallback-from-request, #cmd-powershell-tail; js.sql-injection#destructured-request; js.tls-verification-disabled#other-libraries; python.*#allow-list-unify (r/b/u prefixes); python.ssrf#origin-chain; python.open-redirect#middleware-path, #django-guard, #location-header-redirectview; python.path-traversal#shelve; python.*#slices; python.xss#json-reassign-or; python.xxe#lxml-dtd-hotspot; python.tls-verification-disabled#ssl-wrap-socket, #hostname-only, #aiohttp, #sdk-verify, #httpx-transport; java.*#source-block-align, #source-block-trim (+ StringBuilder lines in template/expression fixtures); java.ssrf#backslash; java @RequestPart source; java.xss#serialiser-string-var; java.xxe#schema-access; java.open-redirect#local-path-base; go.command-injection#encoded-command; go.*#test-support, #bind-in-comparison; go.open-redirect#validator-guard, #url-producers; go.ssrf#reverse-proxy; go.xss#text-template-buffer; go.weak-cipher#tls-cipher-suites; go.zip-slip#exit-calls; go.tls-verification-disabled#noop-callback-var; go.insecure-cookie#helper-cookies.
  - Candidates (COVERAGE): template #mako, #compile-expression; python regex-module, Django `__regex`; java ldap #dn, template #spring-view-names, expression #jexl, zip-slip #zipfs; gorilla/sessions and Gin sessions options; client-side timers/DOM sources (js); a pinned Python reference project with TLS client code (REFERENCE.md).
  - Worktrees: none left.

## 2026-10-04: setup fix round 1 (review of the factory)

- **Request:** fix the six Important findings of the setup review and the cheap Minors.
- **Done:** no rules. Resume procedure for interrupted runs (Plan and Progress lines in the run's
  LOG entry, `Backlog: <id>` in every rule commit); batches of at most 4 rows per implementer and
  worktree (languages in parallel, a language's batches in turn); per-shape procedure and review
  checklist (taint from a request, taint from another source, misuse, hotspot); licences in
  REFERENCE.md and a hard rule against copying code from probed projects; `npm run measure`
  (`tools/measure.mjs`, `tools/score.mjs`: OWASP Benchmark per category, counts on the other
  recall sets) into the new `MEASUREMENTS.md`, run at the end of `/write-rules`, required by
  `/release-pack`; `/release-pack` now also brings the guide text, README lines and CHANGELOG up
  to date. `npm run check` also compares each rule's kind and CWEs with its backlog row; the
  scanner wrapper has tests, refuses unknown `--only` names, prints scan errors and prunes old
  qualor-cc clones.
- **Blocked:** none.
- **Backlog:** added `java.sql-injection#benchmark-recall` (from the first measurement); the
  notes of the Django and Next.js rows now say the implementer proposes the source blocks and the
  controller copies them into COVERAGE.md. `todo`: js 15, python 14, java 16, go 13.
- **Measurement:** `MEASUREMENTS.md` 2026-10-04 (rules 95f5696): Benchmark sqli TPR 49.3 %, FPR
  33.6 % (FindSecBugs 90.5 %); §8.4 target not met on TPR. Juice Shop 6, NodeGoat 0, PyGoat 0,
  GoVWA 0. New noise projects fastify-demo (47 files) and quarkus-quickstarts (654 files): 0
  findings; nestjs-realworld (NestJS is out of scope, no licence file) left the list.
- **Notes:** the first real run should be supervised: `/write-rules 2` with one taint row and one
  misuse row, then a run interrupted on purpose to try "Resume"; fold what goes wrong into the
  skill's red-flags table. Before qualor-rules is published, decide whether `.claude/`,
  BACKLOG.md, LOG.md and MEASUREMENTS.md (local paths, qualor-cc SHAs) go public.

## 2026-10-04: setup of the rules factory

- **Request:** build the system that lets the maintainer run `/write-rules [N] [language]` (and
  `/release-pack`) with all state in this repository; write no new rules.
- **Done:** no rules. Added `BACKLOG.md`, `COVERAGE.md`, `REFERENCE.md`, this log, the skills
  `.claude/skills/write-rules/` (with `rule-procedure.md` and `review-checklist.md`) and
  `.claude/skills/release-pack/`, `tools/backlog.mjs` (part of `npm run check`: the queue and the
  reference pins are well-formed and agree with `rules/`) and `tools/scanner.mjs`
  (`npm run test:docker`, `npm run probe`, `npm run scan`: OpenGrep 1.30.0 in `qualor/scanner:6b1`).
- **Blocked:** none.
- **Backlog:** 4 `done` (the 6B-1 SQL seed rules) and 57 `todo`: 5 maintenance rows first (the
  three R14 limits of 6B-1: the JS second-parameter name filter, Echo's DefaultBinder, Go numeric
  fields; plus Django sources for `python.sql-injection` and Next.js App Router / Fastify /
  `sequelize.literal()` for `js.sql-injection`, which design spec §7 names but the seed rules do
  not cover), then the 28 rules of spec §7's remaining categories, then 24 chosen by COVERAGE.md
  (template injection ×4, expression language, zip slip ×2, Python XXE, XPath ×2, prototype
  pollution, regex injection ×3, TLS verification off ×4, weak ciphers ×2, and four hotspots).
  `todo` by language: js 15, python 14, java 15, go 13.
- **Measurement (baseline, the four SQL rules at 58d453d):** 0 findings on all 12 noise projects
  (node-express-boilerplate, taxonomy, nestjs-realworld, djangoproject-com, microblog,
  full-stack-fastapi, spring-petclinic, spring-boot-realworld, jhipster-sample-app, gin-realworld,
  echo-realworld, gitea: 4,749 files) and 0 on qualor-cc main f681fba (1,210 files; one TypeScript
  parse error in `packages/shared/src/import/sonarqube/api.test.ts`). Recall sets: juice-shop 6,
  owasp-benchmark 212 (`java.sql-injection`, not yet scored against `expectedresults-*.csv`),
  nodegoat 0, pygoat 0 (Django: no Django sources yet, see `python.sql-injection#django`), govwa 0
  (not yet looked at why). A full noise probe of every rule takes about 7 minutes once the clones
  exist.
- **Notes:** the skills were checked by a dry read-through, not by pressure-testing subagents.
  `qualor/scanner:6b1` is a local image tag; if it is gone, set `QUALOR_SCANNER_IMAGE`.
