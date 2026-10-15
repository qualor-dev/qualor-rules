# Measurements

Recall of the rules on the deliberately vulnerable sets of `REFERENCE.md` (design spec §8.4),
**newest first**, written by `npm run measure -- [lang]...` (`tools/measure.mjs`). Each entry is
headed with the last commit that changed `rules/`, so it says exactly which rules were measured.
`/write-rules` measures the languages it touched at the end of a run; `/release-pack` pins a pack
only when `npm run measure -- --check` passes (the newest entry covers all five languages at the
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

## 2026-10-15 rules 6718e8e6a017ed9d1c2e91c1614737f4fd02abe2 (js, python, java, go, csharp)

OpenGrep 1.30.0 with --taint-intrafile; 5 rule directories; results in `.tmp/probe/2026-10-15T12-52-20-536Z`.

### juice-shop (js, 1618a611b173): 22 finding(s), 652 files, 17 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 9
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 12 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1154 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 115 | 11 | 30 | 95 | 91.3% | 24.0% | 67.3% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 7 | 25 | 88.9% | 21.9% | 67.0% | 84.4% |
| pathtraver | 22 | 118 | 15 | 44 | 91 | 88.7% | 32.6% | 56.1% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 255 | 17 | 60 | 172 | 93.8% | 25.9% | 67.9% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 3 | 17 | 93.3% | 15.0% | 78.3% | 95.0% |
| xss | 79 | 220 | 26 | 30 | 179 | 89.4% | 14.4% | 75.1% | 52.2% |
| **mean of covered categories** | | | | | | 88.6% | 19.1% | 69.5% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi met; ldapi met; pathtraver met; sqli met; xpathi met; xss met.

- java.command-injection: 169
- java.ldap-injection: 31
- java.path-traversal: 162
- java.sql-injection: 315
- java.tls-verification-disabled: 1
- java.weak-cipher: 97
- java.xpath-injection: 17
- java.xss: 361
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

### aspgoat (csharp, db3153f5dae0): 8 finding(s), 34 files, 0 error(s)

- csharp.open-redirect: 2
- csharp.path-traversal: 2
- csharp.sql-injection: 1
- csharp.ssrf: 1
- csharp.unsafe-deserialization: 1
- csharp.xxe: 1

### murayama-vulnerable-api (csharp, 465adefe3742): 1 finding(s), 57 files, 0 error(s)

- csharp.ssrf: 1

### vulnerablelightapp (csharp, 8998b55caab6): 7 finding(s), 7 files, 0 error(s)

- csharp.path-traversal: 2
- csharp.ssrf: 1
- csharp.unsafe-deserialization: 1
- csharp.xss: 1
- csharp.xxe: 2

### dvcsharp-api (csharp, 76c1de3c9d8d): 2 finding(s), 24 files, 0 error(s)

- csharp.sql-injection: 1
- csharp.ssrf: 1

### vulnerablecoreapp (csharp, 1ae87f8648c7): 0 finding(s), 23 files, 0 error(s)

## 2026-10-13 rules 498900edc76ff05b9586439d8706f4394ca8eb82 (js, python, java, go, csharp)

OpenGrep 1.30.0 with --taint-intrafile; 5 rule directories; results in `.tmp/probe/2026-10-13T18-12-30-117Z`.

### juice-shop (js, 1618a611b173): 22 finding(s), 652 files, 17 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 9
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 12 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1154 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 115 | 11 | 30 | 95 | 91.3% | 24.0% | 67.3% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 7 | 25 | 88.9% | 21.9% | 67.0% | 84.4% |
| pathtraver | 22 | 118 | 15 | 44 | 91 | 88.7% | 32.6% | 56.1% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 255 | 17 | 60 | 172 | 93.8% | 25.9% | 67.9% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 3 | 17 | 93.3% | 15.0% | 78.3% | 95.0% |
| xss | 79 | 220 | 26 | 30 | 179 | 89.4% | 14.4% | 75.1% | 52.2% |
| **mean of covered categories** | | | | | | 88.6% | 19.1% | 69.5% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi met; ldapi met; pathtraver met; sqli met; xpathi met; xss met.

- java.command-injection: 169
- java.ldap-injection: 31
- java.path-traversal: 162
- java.sql-injection: 315
- java.tls-verification-disabled: 1
- java.weak-cipher: 97
- java.xpath-injection: 17
- java.xss: 361
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

### aspgoat (csharp, db3153f5dae0): 8 finding(s), 34 files, 0 error(s)

- csharp.open-redirect: 2
- csharp.path-traversal: 2
- csharp.sql-injection: 1
- csharp.ssrf: 1
- csharp.unsafe-deserialization: 1
- csharp.xxe: 1

### murayama-vulnerable-api (csharp, 465adefe3742): 1 finding(s), 57 files, 0 error(s)

- csharp.ssrf: 1

### vulnerablelightapp (csharp, 8998b55caab6): 7 finding(s), 7 files, 0 error(s)

- csharp.path-traversal: 2
- csharp.ssrf: 1
- csharp.unsafe-deserialization: 1
- csharp.xss: 1
- csharp.xxe: 2

### dvcsharp-api (csharp, 76c1de3c9d8d): 2 finding(s), 24 files, 0 error(s)

- csharp.sql-injection: 1
- csharp.ssrf: 1

### vulnerablecoreapp (csharp, 1ae87f8648c7): 0 finding(s), 23 files, 0 error(s)

### C# noise review (by hand, 2026-10-13)

Probe of `rules/csharp` at 34d63fc (`npm run probe -- rules/csharp`, results in `.tmp/probe/2026-10-13T18-30-14-754Z`); every finding judged from its file and lines. Cells are findings per project; qualor-cc (0 files with C#) had none.

| rule | eshop | eshoponweb | orchardcore | jellyfin | nopcommerce | true | false |
|---|---|---|---|---|---|---|---|
| csharp.sql-injection | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.command-injection | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.path-traversal | 0 | 0 | 0 | 4 | 0 | 2 | 2 |
| csharp.ssrf | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.xss | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.open-redirect | 1 | 0 | 1 | 0 | 0 | 1 | 1 |
| csharp.ldap-injection | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.xpath-injection | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.regex-injection | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| csharp.unsafe-deserialization | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.xxe | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| csharp.tls-verification-disabled | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| **all** | 1 | 0 | 1 | 4 | 2 | 5 | 3 |

- True: orchardcore open-redirect (AdminController of the Tenants module, a redirect to a tenant host an administrator sets: a real flow, by design); jellyfin path-traversal at EnvironmentController 115 and 121 (the validate-path endpoint writes and deletes a probe file under the requested directory); nopcommerce tls-verification-disabled (the SMTP certificate validator accepts any certificate); nopcommerce regex-injection (SettingController 1275: an administrator-set username rule is run as a pattern; counted true as a flow).
- False, recorded (Known limit, `todook:` line and page text exist): eshop open-redirect (ConsentController 63: the URL comes back from a service of another class that validated the return URL); jellyfin path-traversal at ImageController 2069 (a path built by a service of another class) and PluginsController 242 (a path from the plugin manifest, checked by a StartsWith guard written in a form the rule does not recognise; new BACKLOG row `csharp.path-traversal#guard-is-false-or`).
- Noise findings per project match each rule's reviewed probe: no new finding.

### C# recall (by hand)

Planted vulnerabilities of the five recall sets in the 12 rules' categories, scored by file and line against each app's own list (table: the controller's ledger `recall-table.md`). Found / planted: path-traversal 4/4, ssrf 4/4, xxe 2/2, open-redirect 2/2 (aspgoat only), unsafe-deserialization 2/3 (missed: dvcsharp-api's import builds an XmlSerializer for a type named in the request body), sql-injection 2/3 (missed: vulnerablelightapp's login filter, cross-file because the request enters in Program.cs and the sink is in another file, and DataTable.Select is not a sink either), xss 1/6 (four are `Html.Raw` in Razor views, which OpenGrep does not parse; the fifth is aspgoat's DomXSS lab, client-side script in a .cshtml), command-injection 0/2 (aspgoat: the shell name is set in if/else branches; vulnerablelightapp: the input is written to the shell's standard input). 17 of 26 found; one miss is cross-file, eight are other. Recall not measured: ldap-injection, xpath-injection, regex-injection and tls-verification-disabled (no planted vulnerability in any set), and open-redirect beyond aspgoat.

### C# engine (Roslyn taint engine, by hand, 2026-10-14)

The engine (`engine/dotnet`, branch `csharp` at b19b4c6, with the models of `models/csharp`) on the same five recall sets and five noise projects, each built in `qualor/scanner-dotnet:dev-roslyn` with `qualor dotnet begin`, `dotnet build`, `qualor dotnet end` (eShop: `eShop.Web.slnf`, 19 of 25 projects; the Aspire ones need the Aspire CLI), the recorded compilations analysed with `Qualor.Taint.Cli analyze` and the default budgets. Every finding judged from its file and lines; details, per-site tables and the judged list in the controller's ledger `engine-measurement.md` (Phase 6B-C# R, Task 18). One engine fix came out of it: Razor's tag-helper attribute buffer (`WriteLiteral` between `BeginWriteTagHelperAttribute` and `EndWriteTagHelperAttribute`) is no raw output (b19b4c6; it removed 472 view findings).

- **Recall: 18 of 26** (OpenGrep 17; target 22). New: aspgoat's command injection (shell name assigned in branches). Missed: aspgoat ReflectedXSS (through `ViewData`, not followed) and StoredXSS (the view model is a list of strings passed to `View()`; models reach a view only through their properties), DomXSS (client-side); vulnerablelightapp login (`DataTable.Select` is no sink; the cross-file step itself is followed) and shell standard input; dvcsharp-api's XmlSerializer for a request-chosen type; vulnerablecoreapp's two Razor rows (ASP.NET Core 2.0 compiles views at run time: the build gives the engine no view code; retargeted to net8.0, one of the two is found).
- **Sink inventory** (the 6B-C# classification): firm core 1 of 7 flows (nopCommerce store HTTP client; misses: a Minimal API body object without `[FromBody]`, `HttpContext.Items`, two framework callbacks, `IFileInfo.PhysicalPath` and Fluid values without propagators); unconstrained (a) sites 4 of 5 (eShopOnWeb's Host-based health check: Host is no source); (b) sites 78 of 112 reported (34 of 56 unconstrained).
- **Noise: 559 findings, 47 true, 512 false** (OpenGrep: 8, 5 true, 3 false). False: data written in another request and read through the field-based heap 383 (cache keys, settings, configuration, entity and view-model properties); constrained flows the engine cannot see 82 (filename sanitizers, child-path and containment checks, `[RegularExpression]` parameters, hashes, lookups in another method); test code 14; fixed-host SSRF and own-URL redirects built in helpers 13; an encoder inside a LINQ lambda 7; a guard on a member (`Url.IsLocalUrl(model.ReturnUrl)`) 5; guards in project helpers 3; lookups 5. Per project: eShop 4 (0 true), eShopOnWeb 0, nopCommerce 187 (19), Jellyfin 227 (19), OrchardCore 141 (9).
- **Time and memory** (`/usr/bin/time -v`, analysis only): eShop 7.1 s / 317 MiB, eShopOnWeb 5.3 s / 283 MiB, nopCommerce 56.5 s / 2.59 GiB, Jellyfin 40.8 s / 1.23 GiB, OrchardCore 60.2 s / 2.40 GiB, recall sets under 2 s; budgets (nopCommerce 10 min / 4 GB, eShop 1 min) kept. Rebuild fidelity 345 of 346 projects with 0 errors (OrchardCore.Benchmarks: two entry points, `StartupObject` not recorded).
- **Acceptance: not met** (noise, recall, firm core). The field-based heap is the main cause and a design question for the maintainer, recorded in `models/README.md` "Known limits".

### C# engine, re-measured (Task 25, by hand, 2026-10-15)

The engine after Stages 6b and 6c (`csharp` at f9aacf1: request-scoped heap, member guards, ViewData and view models, DI-aware dispatch, allocation-site objects, confidence levels, backlog sources and sinks, engine-compiled views, model validation) on the same sets, this time through the real product path. A local image `qualor/scanner-dotnet:dev-roslyn-25` (qualor-cc `phase-6b-csharp` 0c6f0068 with this branch's pack) ran `qualor dotnet begin`, `dotnet build` and `qualor dotnet end --dry-run` on a copy of each clone; the hook recorded the views. The engine's SARIF and its time were taken from the `end` run itself. Every report carried the engine's findings with their confidence, and no run fell back to OpenGrep (on OrchardCore the OpenGrep part of the `qualor` analyzer timed out after 900 s, as in Task 18, and the report still carries all of the engine's findings). The finding sets equal Task 31's by rule, file, line and confidence on all 11 sets. Details, the per-finding analysis and the judged list are in the controller's ledger `engine-measurement-25.md` (Phase 6B-C# R, Task 25).

- **Recall: 23 of 26** (target 22, met; OpenGrep 17). Missed: aspgoat StoredXSS and vulnerablecoreapp DemoTypeI (stored in one request, shown in another: out of scope by the request-scoped heap), aspgoat DomXSS (client-side). Every recall-set finding is high confidence.
- **Sink inventory:** firm core 2 of 7 flows (nopCommerce store HTTP client, OrchardCore workflow form redirect). The misses are a Minimal API body object without `[FromBody]`, the tus upload id, a framework callback, `IFileInfo.PhysicalPath` and Fluid values. Unconstrained (a) sites 4 of 4 (eShop's consent redirect re-classed as constrained: the same IdentityServer check as its neighbours). (b) sites 63 of 112 (30 of 56 unconstrained), fewer than Task 18 because data stored in another request no longer counts.
- **Noise: 299 findings on the noise projects; high confidence 30 true and 75 false (target: at most 3 false), medium 22 true and 172 false (88.7 % false).** Seven findings judged false before are true on re-reading: a posted model written back raw in the same response, six of them self-only behind antiforgery. The high false positives by cause:
  - 33 view links that exist only through unresolved-view fallback edges. A confidence defect: a cycle of views and components closed by such an edge shares one "precise" reach, so these read high instead of medium. Recorded, not fixed.
  - 24 containment and single-segment checks inside project helpers (OrchardCore file store, Jellyfin child-path helper).
  - 5 redirects to the request's own URL.
  - 3 a project filename sanitizer.
  - 3 a registered-key lookup that throws on a miss.
  - 2 an extension taken from a span, 2 an allow-list set checked with a comparer, 2 a guard inside a project helper.
  - 1 view link not yet explained.
- With the defect fixed and the guard and model levers listed in the ledger (about six engine tasks), about 9 high false positives would remain. Eight of them rest on project invariants: the filename sanitizer and the own-URL redirects.
- **Time and memory** (the engine process inside `qualor dotnet end`, `/usr/bin/time -v`): nopCommerce 1:14.7 / 3.19 GiB (the whole `end` 7:10), OrchardCore 1:26.4 / 3.11 GiB, Jellyfin 55.0 s / 1.32 GiB, eShop 9.7 s / 0.32 GiB, eShopOnWeb 7.2 s / 0.29 GiB, recall sets under 3 s. Budgets kept (nopCommerce 10 min / 4 GB, eShop 1 min). Rebuild fidelity 352 of 352 projects with 0 errors (OrchardCore.Benchmarks included).
- **Acceptance: not met** (noise, firm core); fixtures and tests (733 of 733), fidelity, recall and budgets met.

### C# engine, re-measured after Stage 6d (Task 25b, by hand, 2026-10-15)

The engine at `csharp` b008874 (Stage 6d: precise reach without fallback cycles, guards in project code and membership guards, Minimal API bodies, file providers, Fluid, deserializers and caches) through the same real product path as Task 25. A local image `qualor/scanner-dotnet:dev-roslyn-25b` (qualor-cc `phase-6b-csharp` 0c6f0068 with this branch's pack) ran `qualor dotnet begin`, `dotnet build` and `qualor dotnet end --dry-run` on a fresh copy of each clone. Every report carried the engine's findings with their confidence, and no run fell back to OpenGrep. The results equal the Stage 6d tasks' own measurements by rule, file, line and confidence. Details and the per-finding analysis are in the controller's ledger `engine-measurement-25b.md` (Phase 6B-C# R, Task 25b).

- **Recall: 23 of 26** (target 22, met), unchanged; every recall-set finding is high confidence.
- **Sink inventory:** firm core 3 of 7 flows: the eShop webhook grant URL (a Minimal API body), the nopCommerce store HTTP client and the OrchardCore workflow form redirect. With the media cache folder counted as constrained (a file provider scopes it to its root), it is 3 of 6. Unconstrained (a) sites 4 of 4. (b) sites 59 of 112 (33 of 56 unconstrained).
- **Noise: 313 findings on the noise projects; high confidence 34 true and 15 false (target: at most 3 false), medium 21 true and 243 false (92.0 % false).** Since Task 25:
  - 33 high false positives went to medium (the fallback-cycle defect fixed);
  - 27 went away or to medium through guards in project helpers and membership guards;
  - 4 true findings became high (the eShop webhook grant URL, two Jellyfin tuner URLs fetched on validation, a Jellyfin channel cache file).
- **The 15 remaining high false positives:**
  - 5 redirects to the request's own URL and 4 paths through Jellyfin's filename sanitizer rest on project invariants the engine cannot see soundly;
  - 1 needs path conditions correlated across a call and a view;
  - 5 have a further lever, about 2.5 engine tasks: a guard carried to values derived before it, containment checked by a helper that normalises the path again, and a "no directory separator" check.
- **Time and memory** (the engine process inside `qualor dotnet end`): nopCommerce 1:23.1 / 3.42 GiB (the whole `end` 7:16), OrchardCore 1:37.4 / 3.40 GiB, Jellyfin 59.6 s / 1.34 GiB, eShop 12.4 s / 0.32 GiB, recall sets under 4 s. Budgets kept; nopCommerce memory is 0.33 GB under 4 GB. Tests 804 of 804; rebuild fidelity 352 of 352 projects with 0 errors.
- **Acceptance: not met** (noise; firm core 3 of 7). Recall, fidelity, tests and budgets met. The maintainer decides on the noise criterion.

## 2026-10-12 rules f8b01fae64a77dfcd6d4f3b52bb483f94e244460 (js, python, java, go)

OpenGrep 1.30.0 with --taint-intrafile; 4 rule directories; results in `.tmp/probe/2026-10-12T17-23-59-970Z`.

### juice-shop (js, 1618a611b173): 22 finding(s), 652 files, 17 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 9
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 12 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1154 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 115 | 11 | 30 | 95 | 91.3% | 24.0% | 67.3% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 7 | 25 | 88.9% | 21.9% | 67.0% | 84.4% |
| pathtraver | 22 | 118 | 15 | 44 | 91 | 88.7% | 32.6% | 56.1% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 255 | 17 | 60 | 172 | 93.8% | 25.9% | 67.9% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 3 | 17 | 93.3% | 15.0% | 78.3% | 95.0% |
| xss | 79 | 220 | 26 | 30 | 179 | 89.4% | 14.4% | 75.1% | 52.2% |
| **mean of covered categories** | | | | | | 88.6% | 19.1% | 69.5% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi met; ldapi met; pathtraver met; sqli met; xpathi met; xss met.

- java.command-injection: 169
- java.ldap-injection: 31
- java.path-traversal: 162
- java.sql-injection: 315
- java.tls-verification-disabled: 1
- java.weak-cipher: 97
- java.xpath-injection: 17
- java.xss: 361
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

## 2026-10-12 rules 4cfca7f08d8ac38a328b9bacfa4d1ab5593c5689 (js, python, java, go)

OpenGrep 1.30.0 with --taint-intrafile; 4 rule directories; results in `.tmp/probe/2026-10-12T11-07-33-250Z`.

### juice-shop (js, 1618a611b173): 22 finding(s), 652 files, 17 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 9
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 12 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1154 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 115 | 11 | 30 | 95 | 91.3% | 24.0% | 67.3% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 7 | 25 | 88.9% | 21.9% | 67.0% | 84.4% |
| pathtraver | 22 | 118 | 15 | 44 | 91 | 88.7% | 32.6% | 56.1% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 255 | 17 | 60 | 172 | 93.8% | 25.9% | 67.9% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 3 | 17 | 93.3% | 15.0% | 78.3% | 95.0% |
| xss | 79 | 220 | 26 | 30 | 179 | 89.4% | 14.4% | 75.1% | 52.2% |
| **mean of covered categories** | | | | | | 88.6% | 19.1% | 69.5% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi met; ldapi met; pathtraver met; sqli met; xpathi met; xss met.

- java.command-injection: 169
- java.ldap-injection: 31
- java.path-traversal: 162
- java.sql-injection: 315
- java.tls-verification-disabled: 1
- java.weak-cipher: 97
- java.xpath-injection: 17
- java.xss: 361
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

## 2026-10-11 rules 48b1fbd71731862823444c7ed2eda2ab28a22713 (js, python, java, go)

OpenGrep 1.30.0 with --taint-intrafile; 4 rule directories; results in `.tmp/probe/2026-10-10T23-59-30-005Z`.

### juice-shop (js, 1618a611b173): 22 finding(s), 652 files, 18 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 9
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 12 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1153 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 115 | 11 | 30 | 95 | 91.3% | 24.0% | 67.3% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 7 | 25 | 88.9% | 21.9% | 67.0% | 84.4% |
| pathtraver | 22 | 118 | 15 | 44 | 91 | 88.7% | 32.6% | 56.1% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 255 | 17 | 60 | 172 | 93.8% | 25.9% | 67.9% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 3 | 17 | 93.3% | 15.0% | 78.3% | 95.0% |
| xss | 79 | 220 | 26 | 30 | 179 | 89.4% | 14.4% | 75.1% | 52.2% |
| **mean of covered categories** | | | | | | 88.6% | 19.1% | 69.5% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi met; ldapi met; pathtraver met; sqli met; xpathi met; xss met.

- java.command-injection: 169
- java.ldap-injection: 31
- java.path-traversal: 162
- java.sql-injection: 315
- java.weak-cipher: 97
- java.xpath-injection: 17
- java.xss: 361
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

## 2026-10-07 rules 3fc89c9ec263ad9e4eee4ddb29412e7950c34dba (js, python, java, go)

OpenGrep 1.30.0; 4 rule directories; results in `.tmp/probe/2026-10-07T17-31-11-196Z`.

### juice-shop (js, 1618a611b173): 21 finding(s), 652 files, 18 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 8
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 11 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 1
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1373 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 110 | 16 | 57 | 68 | 87.3% | 45.6% | 41.7% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 17 | 15 | 88.9% | 53.1% | 35.8% | 84.4% |
| pathtraver | 22 | 116 | 17 | 88 | 47 | 87.2% | 65.2% | 22.0% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 242 | 30 | 125 | 107 | 89.0% | 53.9% | 35.1% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 10 | 10 | 93.3% | 50.0% | 43.3% | 95.0% |
| xss | 79 | 212 | 34 | 100 | 109 | 86.2% | 47.8% | 38.3% | 52.2% |
| **mean of covered categories** | | | | | | 86.6% | 45.1% | 41.6% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi NOT met (FPR 45.6% > 44.4%); ldapi NOT met (FPR 53.1% > 42.2%); pathtraver NOT met (FPR 65.2% > 47.8%); sqli NOT met (FPR 53.9% > 45.3%); xpathi NOT met (FPR 50.0% > 47.5%); xss NOT met (FPR 47.8% > 26.1%).

- java.command-injection: 196
- java.ldap-injection: 41
- java.path-traversal: 204
- java.sql-injection: 367
- java.weak-cipher: 97
- java.xpath-injection: 24
- java.xss: 443
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

## 2026-10-07 rules 492d6265dc9a11a592f50281c6d8877d6370d281 (js, python, java, go)

OpenGrep 1.30.0; 4 rule directories; results in `.tmp/probe/2026-10-07T12-56-37-888Z`.

### juice-shop (js, 1618a611b173): 21 finding(s), 652 files, 18 error(s)

- js.code-injection: 1
- js.insecure-cookie: 2
- js.nosql-injection: 2
- js.open-redirect: 1
- js.path-traversal: 8
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 5 finding(s), 51 files, 0 error(s)

- js.code-injection: 3
- js.insecure-cookie: 1
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 11 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.command-injection: 1
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1373 finding(s), 2772 files, 0 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 110 | 16 | 57 | 68 | 87.3% | 45.6% | 41.7% | 88.8% |
| crypto | 327 | 97 | 33 | 0 | 116 | 74.6% | 0.0% | 74.6% | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 17 | 15 | 88.9% | 53.1% | 35.8% | 84.4% |
| pathtraver | 22 | 116 | 17 | 88 | 47 | 87.2% | 65.2% | 22.0% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 242 | 30 | 125 | 107 | 89.0% | 53.9% | 35.1% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | 14 | 1 | 10 | 10 | 93.3% | 50.0% | 43.3% | 95.0% |
| xss | 79 | 212 | 34 | 100 | 109 | 86.2% | 47.8% | 38.3% | 52.2% |
| **mean of covered categories** | | | | | | 86.6% | 45.1% | 41.6% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi NOT met (FPR 45.6% > 44.4%); ldapi NOT met (FPR 53.1% > 42.2%); pathtraver NOT met (FPR 65.2% > 47.8%); sqli NOT met (FPR 53.9% > 45.3%); xpathi NOT met (FPR 50.0% > 47.5%); xss NOT met (FPR 47.8% > 26.1%).

- java.command-injection: 196
- java.ldap-injection: 41
- java.path-traversal: 204
- java.sql-injection: 367
- java.weak-cipher: 97
- java.xpath-injection: 24
- java.xss: 443
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 0 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

## 2026-10-05 rules fa2c6d7fc907a95f98d6400d1e72d895191e287e (js, python, java, go)

OpenGrep 1.30.0; 4 rule directories; results in `.tmp/probe/2026-10-05T21-12-23-028Z`.

### juice-shop (js, 1618a611b173): 15 finding(s), 652 files, 18 error(s)

- js.code-injection: 1
- js.nosql-injection: 2
- js.path-traversal: 5
- js.sql-injection: 6
- js.ssrf: 1

### nodegoat (js, c5cb68a7084e): 4 finding(s), 51 files, 2 error(s)

- js.code-injection: 3
- js.open-redirect: 1

### pygoat (python, 19d17cc88748): 10 finding(s), 85 files, 0 error(s)

- python.code-injection: 2
- python.path-traversal: 1
- python.sql-injection: 2
- python.ssrf: 1
- python.unsafe-deserialization: 3
- python.xxe: 1

### owasp-benchmark (java, 8b67a88d73b2): 1263 finding(s), 2772 files, 1 error(s)

| Category | CWE | TP | FN | FP | TN | TPR | FPR | Score | FindSecBugs FPR |
|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 110 | 16 | 57 | 68 | 87.3% | 45.6% | 41.7% | 88.8% |
| crypto | 327 | no rule |  |  |  |  |  |  | 0.0% |
| hash | 328 | no rule |  |  |  |  |  |  | 0.0% |
| ldapi | 90 | 24 | 3 | 17 | 15 | 88.9% | 53.1% | 35.8% | 84.4% |
| pathtraver | 22 | 116 | 17 | 88 | 47 | 87.2% | 65.2% | 22.0% | 95.6% |
| securecookie | 614 | no rule |  |  |  |  |  |  | 0.0% |
| sqli | 89 | 242 | 30 | 125 | 107 | 89.0% | 53.9% | 35.1% | 90.5% |
| trustbound | 501 | no rule |  |  |  |  |  |  | 81.4% |
| weakrand | 330 | no rule |  |  |  |  |  |  | 0.0% |
| xpathi | 643 | no rule |  |  |  |  |  |  | 95.0% |
| xss | 79 | 212 | 34 | 100 | 109 | 86.2% | 47.8% | 38.3% | 52.2% |
| **mean of covered categories** | | | | | | 87.7% | 53.1% | 34.6% | |

§8.4 target (TPR ≥ 60 %, FPR ≤ 50 % of FindSecBugs' FPR) for the covered injection categories: cmdi NOT met (FPR 45.6% > 44.4%); ldapi NOT met (FPR 53.1% > 42.2%); pathtraver NOT met (FPR 65.2% > 47.8%); sqli NOT met (FPR 53.9% > 45.3%); xss NOT met (FPR 47.8% > 26.1%).

- java.command-injection: 196
- java.ldap-injection: 41
- java.path-traversal: 204
- java.sql-injection: 367
- java.xss: 454
- java.xxe: 1

### govwa (go, 4058f79f31ee): 9 finding(s), 24 files, 1 error(s)

- go.insecure-cookie: 1
- go.weak-hash: 3
- go.xss: 5

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
