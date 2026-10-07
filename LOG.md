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

## 2026-10-07: prefilter cost (in progress)

- **Request:** qualor-cc CI failed on pack 2026.10.2 (a 20-file TypeScript dry run past 60 s on a 2-core runner); the maintainer chose to fix the rules before Qualor 0.7.0 ("Fix rules, then release").
- **Finding:** OpenGrep builds each rule's prefilter again per target. Full pack on a one-line file: 6 s (2026.10.1) → 13 s; 20 generated TypeScript files: 15 → 26 s; 200 files: 20 → 35 s (24 cores). Builds: js.tls-verification-disabled 2.0 s / 90 kB, js.nosql-injection 1.2 s / 33 kB, js.open-redirect 0.6 s / 27 kB, python.tls-verification-disabled 0.6 s / 208 B, go.ssrf 0.58 s / 67 kB, go.insecure-cookie 0.43 s / 6.5 MB, js.insecure-cookie 0.14 s / 215 kB; a plain rule ~0.1 s.
- **Plan:** the seven `#prefilter-cost` rows, one batch per language (js, python, go), then a prefilter budget check in `npm test` and pack 2026.10.3.
- **Progress:**
  - python.tls-verification-disabled#prefilter-cost (pf-python): done. The build cost was the product of the top-level branches' positive conditions (3^5 x 2^5), paid although the no-word branch drops them. The session branches of requests, aiohttp and boto3 now share one branch, those kept on self another, with the method names written out instead of a metavariable-regex (3 x 2^6): build 0.63 → 0.10 s, prefilter still the 208 B word regex; one-line scan 2.0 → 1.5 s, 150 kB Django module 3.6 → 2.7 s. Findings identical on the fixture, an exhaustive file of every session form and sink, and the probe; new matches only where one library's session meets another's sink: in practice code that cannot run, plus a name rebound from one library's session to another object (a Known limit, ruling P3b). Technique added to rule-procedure.md "Performance".
  - go.ssrf#prefilter-cost (pf-go): done. The three `*httputil.ProxyRequest` In/Out sources (a pattern and a metavariable-regex each: 2 CNF clauses each, ×8 in the product) became one source with the 26 names written out (1 clause); the shared request block is unchanged. Prefilter build 0.58 s → 0.17 s, 67 kB → 13.5 kB (go.sql-injection on the same host: 0.15 s, 7.7 kB). Fixture +23 `ruleid` lines, so each name is tested (the base rule gives the same 82 findings on the new fixture). Probe: gitea 1 (models/unittest/mock_http.go:86), the other Go projects and qualor-cc 0; identical findings before and after.
  - go.insecure-cookie#prefilter-cost (pf-go): done. Three top-level branches each carried the same 4-framework import binding (16 CNF clauses each: 16 × 16 × 16 × 2 = 8,192 clauses). The imports are now bound once, in a conjunct above the cookie forms that binds each call with `pattern-inside` (a positive `pattern` there added ranges of its own: fix round 1, after review found a safe call nested in a reported call reported too), and the forms name the same calls without the import; the Gin false-flag branch moved under that binding. Prefilter build 0.42 s → 0.08 s, 6.5 MB → 4.3 kB. Fixture findings identical (42, and 43 with the nested `ok:` line added in fix round 1). Probe: govwa 1 (util/cookie.go:38), the other Go projects and qualor-cc 0; identical findings before and after.
  - js.tls-verification-disabled#prefilter-cost (js batch, 7e96903): the calls an options object must sit in became exclusions ("not outside these calls"); prefilter build 2000 → 91 ms, 89.9 → 1.4 kB; one-line scan 2.0 → 0.0 s; findings identical on the fixture and the probe.
  - js.nosql-injection#prefilter-cost (js batch, 60b0280 + fix round 1): the OBJ sources keep the value as their only positive term; the Fastify OBJ source stays separate so its schema checks keep the route's metavariables (review: a route registered inside a schema route's handler was lost); build 1257 → 186 ms, 32.9 → 11.7 kB; one-line scan 1.3 → 0.05 s; findings identical.
  - js.open-redirect#prefilter-cost (js batch, ed3af36): wordless sink conditions became exclusions (template text, header method, Response receiver and header); build 646 → 143 ms, 27.2 → 11.1 kB; three.js with the words not slower (≈10 s); findings identical; four ok: lines added for the moved conditions.
  - js.insecure-cookie#prefilter-cost (js batch, 327fd12): the forms became exclusions of the cookie call; 215.6 → 1.3 kB, build 141 → 87 ms; findings identical.
  - python-taint (python.sql-injection#prefilter-restore, branch pf-python-taint: 30d1d97 and the eight commits after it): the 2026.10.2 slice sources (118206d) had made every Python taint rule's prefilter None; shared block restructured (776 source clauses), open-redirect word anchor and merged own sources, path-traversal names written out: Some for nine (all but python.command-injection and python.xss), 0.3–19.8 kB, 98–171 ms, identical findings (fixtures, probe, 162 kB Django module) except the documented shape changes of ruling P4; python.command-injection and python.xss stay None on their own sinks

## 2026-10-07: release 2026.10.2 (`/release-pack`)

- **Request:** the maintainer asked to release what the 2026-10-06 run produced ("Давай зарелизим что есть").
- **Done:** qualor-rules-2026.10.2.tar.gz, sha256 29a40881f01c7e7689a166b545830c8c818e51901b30b499d13250e3c7242c86, OpenGrep 1.30.0; 57 rules (51 issues, 6 hotspots). New since 2026.10.1: python.command-injection, java.xpath-injection, java.regex-injection, java.tls-verification-disabled, java.weak-cipher, js.insecure-cookie, python.xxe-dtd-options, python.tar-extraction; 45 maintenance changes (the Python Django match limit that blanked large Django files, js.open-redirect speed, TLS rules for more libraries, shared request blocks). Reproducible: host twice and Linux, identical.
- **Measurement:** MEASUREMENTS.md 2026-10-07 entry (rules 492d626): Benchmark mean of covered categories TPR 86.6 % / FPR 45.1 %; crypto 74.6 / 0.0, xpathi 93.3 / 50.0; §8.4 still not met for the Java injection categories (known one-method cause).

## 2026-10-06: rules run (`/write-rules 52`)

- **Request:** the maintainer asked to finish the rules backlog for the next release ("Давай к след. релизу доделаем беклог по правилам"): the 42 maintenance rows queued by the 2026-10-04 reviews, the open rows (java-4 of that run, js.insecure-cookie, python.tar-extraction, the three xss#sink-results rows) and python.command-injection, reopened. The four `*.sql-injection#dedupe-other-engines` rows are qualor-cc work (equivalences.json) and are done outside this run.
- **Plan:** BASE = the "docs(backlog): start" commit of this run; batches `js-1` (js.open-redirect#performance, js.xss#awaited-call-sanitizer, js.prototype-pollution#then-block-only, js.regex-injection#reassign-after-check), `js-2` (js.regex-injection#hand-written-escape, js.command-injection#powershell-params, js.command-injection#fallback-from-request, js.command-injection#cmd-powershell-tail), `js-3` (js.sql-injection#destructured-request, js.tls-verification-disabled#other-libraries, js.insecure-cookie, js.xss#sink-results), `python-1` (python.command-injection, python.sql-injection#allow-list-unify, python.sql-injection#slices, python.ssrf#origin-chain), `python-2` (python.open-redirect#middleware-path, python.open-redirect#django-guard, python.open-redirect#location-header-redirectview, python.path-traversal#shelve), `python-3` (python.xss#json-reassign-or, python.xxe#lxml-dtd-hotspot, python.tls-verification-disabled#ssl-wrap-socket, python.tls-verification-disabled#hostname-only), `python-4` (python.tls-verification-disabled#aiohttp, python.tls-verification-disabled#sdk-verify, python.tls-verification-disabled#httpx-transport, python.tar-extraction), `java-1` (java.sql-injection#source-block-align, java.sql-injection#source-block-trim, java.sql-injection#request-part, java.ssrf#backslash), `java-2` (java.xss#serialiser-string-var, java.xxe#schema-access, java.open-redirect#local-path-base, java.xpath-injection), `java-3` (java.regex-injection, java.tls-verification-disabled, java.weak-cipher, java.xss#sink-results), `go-1` (go.command-injection#encoded-command, go.path-traversal#test-support, go.sql-injection#bind-in-comparison, go.open-redirect#validator-guard), `go-2` (go.open-redirect#url-producers, go.ssrf#reverse-proxy, go.xss#text-template-buffer, go.weak-cipher#tls-cipher-suites), `go-3` (go.zip-slip#exit-calls, go.tls-verification-disabled#noop-callback-var, go.insecure-cookie#helper-cookies, go.xss#sink-results). New rules get `since: 2026.10.2`. Languages in parallel, each language's batches in turn; implementers and reviewers are opus subagents; the 2026-10-04 lessons (qualor-cc .superpowers/sdd/2026-10-04-rules-factory/lessons.md) apply, plus: every new rule gets its docs/rules page in the same commit; time a rule on a large minified file containing its literal (--timeout 0) when it adds alternatives.
- **Progress:**
- go-1 (go.command-injection#encoded-command, go.path-traversal#test-support, go.sql-injection#bind-in-comparison, go.open-redirect#validator-guard): APPROVED after 1 fix round (ruling G1: prefix checks without a backslash check stay reported); merged f64739c..4cc19dd
- java-1 (java.sql-injection#source-block-align, java.sql-injection#source-block-trim, java.sql-injection#request-part, java.ssrf#backslash): APPROVED after 2 fix rounds (Benchmark unchanged); merged efcec39..4391a36
- python-1 (python.command-injection, python.sql-injection#allow-list-unify, python.sql-injection#slices, python.ssrf#origin-chain): APPROVED after 1 fix round (python.command-injection shipped, F8 shapes quiet); merged f6e9ccb..05016d4
- js-1 (js.open-redirect#performance, js.xss#awaited-call-sanitizer, js.prototype-pollution#then-block-only, js.regex-injection#reassign-after-check): APPROVED after 3 fix rounds (open-redirect three.js ~300 s to ~15 s with identical findings; Location-header templates now match); merged ce241c2..11c8cbd
- go-2 (go.open-redirect#url-producers, go.ssrf#reverse-proxy, go.xss#text-template-buffer, go.weak-cipher#tls-cipher-suites): APPROVED after 2 fix rounds (rulings G2: weak-cipher follows crypto/tls InsecureCipherSuites; G3: oauth2/minio/s3 sanitizers bound to the real import); merged 21ab94c..14d5d89
- java-2 (java.xss#serialiser-string-var, java.xxe#schema-access, java.open-redirect#local-path-base, java.xpath-injection): APPROVED after 1 fix round (ruling J1: java.xpath-injection ships at Benchmark xpathi FPR 50.0 %, one case over the 47.5 % target, one-method precedent); merged 0b4f43a..8993b35
- go-3 (go.zip-slip#exit-calls, go.tls-verification-disabled#noop-callback-var, go.insecure-cookie#helper-cookies, go.xss#sink-results): APPROVED in round 1 (Minors recorded before merge; go.xss leaves command output to go.command-injection); merged fa5fde3..2de831e
- js-2 (js.regex-injection#hand-written-escape, js.command-injection#powershell-params, js.command-injection#fallback-from-request, js.command-injection#cmd-powershell-tail): APPROVED after 2 fix rounds (PowerShell modelled per about_pwsh / about_PowerShell_exe); merged 07d0832..d743983
- java-3 (java.regex-injection, java.tls-verification-disabled, java.weak-cipher, java.xss#sink-results): APPROVED after 2 fix rounds (Benchmark crypto TPR 74.6 % FPR 0 %; ruling J2: fetched bodies clean only from a fixed origin; J3: misuse rules skip test code); merged aca8545..b6137cf
- python-2 (python.open-redirect#middleware-path, python.open-redirect#django-guard, python.open-redirect#location-header-redirectview, python.path-traversal#shelve): APPROVED after 1 fix round (Location sink rebuilt: no match explosion; no findings lost vs base); merged 2cebfd2..8195036
- re-plan: added `python.sql-injection#django-import-match-limit` (found in python-2: large Django modules lose every finding to the match limit) at the head of python-3; python-3 is now (python.sql-injection#django-import-match-limit, python.xss#json-reassign-or, python.xxe#lxml-dtd-hotspot, python.tls-verification-disabled#ssl-wrap-socket), python-4 (python.tls-verification-disabled#hostname-only, #aiohttp, #sdk-verify, #httpx-transport), python-5 (python.tar-extraction)
- js-3 (js.sql-injection#destructured-request, js.tls-verification-disabled#other-libraries, js.insecure-cookie, js.xss#sink-results): APPROVED after 2 fix rounds (ruling JS1: TLS options of other libraries recognised by option keys; J2: a fetched response is request data only when its URL visibly starts with request data); merged f1e993c..6c089ae
- python-3 (python.sql-injection#django-import-match-limit, python.xss#json-reassign-or, python.xxe#lxml-dtd-hotspot as the new hotspot python.xxe-dtd-options, python.tls-verification-disabled#ssl-wrap-socket): APPROVED in round 1 (match limit: every Python rule lost all findings in large Django modules; 300-view file 0 → 300, large files 5–100x faster); merged cda278b..9aa6e7e
- python-4 (python.tls-verification-disabled#hostname-only, #aiohttp, #sdk-verify, #httpx-transport): APPROVED after 1 fix round (ruling P1: disabled host-name checks are issues in the same rule; P2: the rule's prefilter is a library-name word regex kept by a no-literal branch — without it OpenGrep built a 31–43 MB prefilter); merged 4eaafa8..7367a14
- python-5 (python.tar-extraction): APPROVED after 1 fix round (new hotspot; CPython 3.14 Lib + site-packages: 4 genuine unfiltered extractions); merged e32c37c..492d626
- **Done:** 54 rows: the 52 planned rows, `python.sql-injection#django-import-match-limit` (added in the re-plan) and the new rule `python.xxe-dtd-options` (the hotspot form of `python.xxe#lxml-dtd-hotspot`, one kind per rule). 8 new rules, `since: 2026.10.2`: python.command-injection, java.xpath-injection, java.regex-injection, java.tls-verification-disabled, java.weak-cipher, js.insecure-cookie, python.xxe-dtd-options, python.tar-extraction. 57 rules on `main` (js 14, python 15, java 16, go 12; 51 issues, 6 hotspots); commits in the Progress merges above.
- **Blocked:** none.
- **Backlog:** the 54 rows set to `done`; 53 maintenance rows added as `todo` from the implementers' and reviewers' proposals (prefilter None in js.ssrf, js.template-injection, python.xss, java.xss, java.command-injection, java.open-redirect, go.xss; the Go `#test-support` and `#bind-in-comparison` copies; Java shared-block `#builder-insert` and `#enum-valueof-nested`; xxe `#validator`, `#try-finally`, `#parser-conditional-features`; python `#large-file-performance`; and the FP and missed shapes the reviews found). `todo` left: 53 (js 7, python 11, java 14, go 21).
- **Measurement:** MEASUREMENTS.md 2026-10-07 entry (rules 492d626, idle host): recall juice-shop 21, nodegoat 5, pygoat 11, govwa 9 findings, 0 errors; OWASP Benchmark TPR / FPR — cmdi 87.3 / 45.6, crypto 74.6 / 0.0 (new java.weak-cipher), ldapi 88.9 / 53.1, pathtraver 87.2 / 65.2, sqli 89.0 / 53.9, xpathi 93.3 / 50.0 (new java.xpath-injection), xss 86.2 / 47.8; the §8.4 FPR target is still not met for the Java injection categories (one-method analysis; next task: --taint-intrafile after a speed measurement).
- **Notes:**
  - Rulings: G1 go.open-redirect validator guards: a prefix check without a backslash check, `IsAbs()` alone and `Host == ""` alone stay reported (lesson 18). G2 go.weak-cipher follows crypto/tls `InsecureCipherSuites()` (12 suites); title and message widened. G3 go.open-redirect takes the oauth2, minio and AWS S3 URL producers as sanitizers only, bound to the real import. J1 java.xpath-injection ships at Benchmark xpathi TPR 93.3 %, FPR 50.0 % (one case over the 47.5 % target; the one-method precedent). J2 a body fetched from a request-chosen URL stays request data in xss; it is clean only from a fixed origin. J3 misuse and hotspot rules skip test code (F10, now for Java too; COVERAGE.md "Test code"). JS1 TLS options of other JS libraries are recognised by their option keys (an import binding broke the prefilter, +1.7 s). P1 a disabled host-name check is an issue in python.tls-verification-disabled, no rule of its own. P2 python.tls-verification-disabled's prefilter is one library-name word regex, kept by a no-literal first branch (`$NOWORD is not ...`).
  - Match-limit incident (python-2 review): a 78 KB Django module gave 0 findings. The shared Django check `from $DJ import $NAME` counted every finding once per imported name toward OpenGrep's 10,000-match limit per file; past it the file reports nothing, in all 11 Python taint rules since 2026-10-04. Fixed in python-3 with a literal `import django` + `...` (300-view file 0 → 300; large files report a superset, 5–100x faster). In a combined run (all rules, as Qualor scans) one overflowing rule blanks the whole file for every rule: an 81 KB file went from 0 findings at main to 234. Other languages' module checks that bind a metavariable (Go import paths) were not checked yet.
  - Prefilter lesson: js.open-redirect had no prefilter (three.js 300 s → 14 s after js-1, identical findings), and seven rules still have none (the `#prefilter` rows). Size matters too: python.tls-verification-disabled grew from 283 kB to 11 MB and 43 MB during python-4 (CPython corpus 48 s → 552 s); P2 replaced it by one regex (corpus 82 s, about half of it the one-time CNF build per worker), 208 B after the review's word-regex fix. rule-procedure.md step 3 "Performance" now requires Some, a small size and a timing with `--timeout 0` on a large file containing the rule's words.
  - Tooling follow-ups (not backlog rows; also in COVERAGE.md "Growing the map"): a prefilter check in `npm test` (Some and a size budget per rule; nothing guards P2's no-word branch today); a per-alternative mutation sweep in tools/ (written again in `.tmp/` by java-1 and python-5: 124 of 290 mutants survived in the Java shared block before its trim row, 7 in python.tar-extraction); `--timeout 0` in `npm run probe` and `npm run measure` (the host load caused hundreds of default-timeout errors; `test:examples` got `--timeout 120` in 7db9fbc); generators for the JS, Java and Python shared source blocks. Still open from 2026-10-04: test-rules checking todo lines; `--taint-intrafile` after a speed measurement.
  - Proposals left out of the backlog because they need the maintainer's word: go.open-redirect#helper-guard (a name heuristic for validator helpers), java.ssrf#value-base-separator (open-redirect's stricter `@Value` base in ssrf), java.xss#serialiser-string-return and #data-access-results, python.tar-extraction#untyped-tar, js.regex-injection#hoisted-helper, CWE-59 beside CWE-22 for python.tar-extraction. go.xss keeps bodies fetched from request-chosen URLs reported (J2), so go.xss#ssrf-results is not queued.
  - Dedupe: the four `*.sql-injection#dedupe-other-engines` rows were done in qualor-cc 9a7d2aad (31 equivalence pairs, merged into qualor-cc's local main; rows closed in 5ca4739). Follow-up in qualor-cc: pair python.command-injection with ruff S602/S604/S605 in equivalences.json.
  - The procedure now carries both runs' lessons (rule-procedure.md, review-checklist.md); the merge step is gated on a green test, after a rebase the index is regenerated (the java-2 merge needed 348009b), and `origin` exists (public; pushed only on the maintainer's word).
  - Worktrees: none left; no `rules/*` branches.

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
