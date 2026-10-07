# Per-rule procedure

For one row of `BACKLOG.md`, in your working tree (a worktree, or the main tree when the
controller works inline). Run every command from the tree's root. The quality bar is design spec
§8 plus the lessons of the first review; each step exists because skipping it once shipped a
defect.

## Which shape is the rule?

Decide first; several steps differ by shape.

| shape | rows | mode | what it finds |
|---|---|---|---|
| **taint (request)** | `kind: issue`, data from an HTTP request reaches a sink (SQL, command, path, SSRF, XSS, redirect, template, …) | `mode: taint` | a flow |
| **taint (other source)** | `kind: issue`, the source is not a request: an archive entry name (zip slip), … | `mode: taint` | a flow |
| **misuse** | `kind: issue`, an unsafe configuration or API that is wrong whatever the data (TLS verification off, broken cipher, XXE-enabled parser) | search | a call or setting |
| **hotspot** | `kind: hotspot`, a usage a person should review (weak hash, cookie flags, CORS, raw HTML props, unfiltered archive extraction) | search | a call or setting |

## 0. Read

- The row: id, category, CWE, kind, frameworks and APIs, notes.
- `COVERAGE.md`: "Frameworks in scope", "Source blocks", "Kind and severity", "Allowed sources".
- Your language's SQL rule and its fixture (`rules/<lang>/sql/sql-injection.*`): the model for
  layout, comments and fixture style (and, for taint rules, the sources).
- **Maintenance row** (`<lang>.<name>#<topic>`): the base rule and its fixture. Steps 2–7 apply to
  the change only; no new file, `since` stays.

## 1. Docs first

Find and read the official documentation (allowed sources only, `CLEAN-ROOM.md`) for:

- **taint (request):** the request sources of every in-scope framework of the language (route and
  path parameters, query strings, form fields, headers, cookies, bodies bound through the
  framework's decoder or binder);
- **taint (other source):** where the untrusted value comes from (the archive API's entry name);
- the sinks or unsafe settings the row names, and what makes each one dangerous;
- the safe forms: parameterised or argument-vector APIs, sanitisers and escaping, safe settings
  and defaults, documented allow-list helpers;
- the CWE page and the OWASP cheat sheet of the category.

Search hygiene: fetch pages only from the allowed hosts (cwe.mitre.org, owasp.org and
cheatsheetseries.owasp.org, the project's own documentation site or repository docs, pkg.go.dev,
docs.oracle.com, docs.python.org, nodejs.org, developer.mozilla.org, docs.spring.io, jakarta.ee and
the like). When you search, restrict it with `site:` to such a host; never open a result on a
forbidden host (CLEAN-ROOM.md) or a blog post that reproduces rules.

Keep a list of every URL you used: it becomes `metadata.sources`. A sink or safe form you find no
docs for stays out of the rule. If the row's core API is undocumented, stop: the row is `BLOCKED`
("No official docs describe <API>; drop the row or name a source?").

## 2. Fixture first

`rules/<lang>/<category>/<name>.<ext>` (`js`: `.js`, plus `.ts` when typed handlers change the
shapes, `.jsx`/`.tsx` for React; `python`: `.py`; `java`: `.java`; `go`: `.go`). Every line is your
own, written from the docs' examples: **never paste code from a reference or recall project**,
whatever its licence. The annotation is a comment on the line before each line it is about:
`// ruleid: <id>`, `# ok: <id>`, `// todoruleid: <id>`, `// todook: <id>`.

**Taint (request)** — the fixture must contain:

- **`ruleid:`** the canonical vulnerable shapes, for **every in-scope framework** of the language:
  - route/path parameters (`req.params`, Flask/Django URL variables, `@PathVariable`,
    `c.Param`, `r.PathValue`, `chi.URLParam`, `mux.Vars`);
  - query strings, form fields, headers, cookies;
  - JSON bodies bound through the framework's decoder or binder (`req.body`, `request.get_json()`,
    a FastAPI model, `json.loads(request.body)`, `@RequestBody` DTO getters,
    `json.NewDecoder(r.Body).Decode(&x)`, Gin `ShouldBindJSON`, Echo `Bind`);
  - the value used in place, assigned to a variable first, and built into a string
    (concatenation, template literals or f-strings, format functions, builders).
- **`ok:`** the shapes that must stay quiet:
  - the parameterised or argument-vector form of the same call;
  - the framework's sanitiser or escaping function, and conversions to numbers;
  - an allow-list (a ternary or lookup that yields only constants), constants;
  - request data in a harmless position (template context, a bound value, the subject of a
    constant regex);
  - **look-alikes**: methods with the sink's name on other libraries (a GraphQL `execute`, a
    use-case `.execute()`, `Map.get`), functions with request-like parameter names that are not
    handlers, safe idiomatic ORM or query-builder code.

**Taint (other source)** — the same, with the category's own source instead of request shapes:
every documented way to obtain the value (zip: `File.Name`, `ZipEntry.getName()`; tar:
`Header.Name`, `TarArchiveEntry.getName()`), used in place and via variables, against `ok:` lines
for the documented checks and safe APIs (`filepath.IsLocal`, `os.Root`, `getFileName()`). No
request-shape lines are needed.

**Misuse and hotspot** — no request shapes. The fixture must contain:

- **`ruleid:`** the unsafe setting or call in every API form and position the docs show: a
  literal option, an option object built first, a builder or setter call, a lambda or anonymous
  class (Java trust managers), a constant passed in, each library the row names;
- **`ok:`** the safe setting of the same API (`InsecureSkipVerify: false`, `verify=True`, a
  strong algorithm name, `secure: true`), the documented safe alternative, a look-alike option or
  method of another library, and for hotspots the documented "explicitly reviewed" forms if any
  (`hashlib.md5(usedforsecurity=False)`).

**All shapes:** each shape you decide not to handle gets `todoruleid:` (a missed true finding) or
`todook:` (an accepted false finding), with a comment line above saying why, **and** a line in the
rule's Known limits and on its page: a limit that is only in a report is lost. OpenGrep 1.30
`--test` does not check `todoruleid:`/`todook:` lines: verify each with a separate scan and say so
in the report. Aim for at least ten `ruleid:` and ten `ok:` lines; taint rules need at least one
of each per framework.

**Shapes the reviews asked for in every run** (write them before you report):

- **Allow-lists are `ok:`** only for literal, untouched tables: a lookup by request data in a table
  of literal constants (JS object, array, `Map`, `Object.freeze`; Python upper-case dict, list or
  tuple of literals; Java `Map.of` of literals, static final maps, enums; Go map literals), in
  subscript and `.get()` forms, with comments and multi-line tables. A table built from or changed
  by request data anywhere in the file is `ruleid:`, and so is a lookup with a request-data
  fallback (`T.get(k, req…)`, `getOrDefault(k, req…)`, `T[k] || req…`, `T[k] ?? req…`).
- **Fixed origins** (SSRF, redirects, fetched bodies): a constant base is safe only when it holds a
  host and ends with a separator after it (`"https://api.example.com/"`, then request data; `/`
  not followed by `/` or `\`, or `?`/`#` after a host). A lone scheme (`'https:' + '//' + req`)
  or a base without the separator (`API + u`, where `@evil.example` sets the host) is `ruleid:`.
  Format-string and URI-builder forms with a separator are `ok:`; so are clients built with a
  fixed base URL given a relative path.
- **Commands:** a fixed program with an argument list is `ok:` in every container form (lists,
  tuples, `List.of`, `Arrays.asList`, arrays, concatenation, helpers); only a request-chosen
  program, or request data in shell code, is a sink. For POSIX shells only the element after `-c`
  is shell code; for `cmd /c` and `/k` and PowerShell `-Command`/`-c` every later element is (and
  PowerShell's `-File`, `-CommandWithArgs` follow about_pwsh). Whole-argument-vector sinks fire
  only on real request vectors (`getParameterValues`, a split of tainted text, an annotated
  collection parameter, a decoded JSON array), never by excluding a list of "safe" constructors.
- **Sources** are request objects of real handlers; framework coercion that guarantees a scalar
  (Fastify schema `type: string`, FastAPI `int`, typed Spring parameters) is no source for
  structure injection. Copy the source block's own limits (handler name filter, typed
  converters, helpers named `request`) into each new taint rule as todo lines.
- **Look-alikes are `ok:`:** same-name methods of other libraries (GraphQL `execute`, job queues,
  `headers.set`), and sanitizers bound to their real types (`getFileName()` on `Path`, `valueOf`
  on enums, `.extra()` on Django QuerySets), never by bare method name.
- **Test code:** misuse and hotspot rules skip it with their language's `paths: exclude` globs
  (COVERAGE.md "Test code"); taint rules do not.

**RED.** Write the rule file (step 3) with its main pattern replaced by a never-matching
`never_called_qualor_probe(...)` (the sinks of a taint rule, the pattern of a search rule), run
`npm run test:docker`, and keep the output: every `ruleid:` line must be listed as expected but
not reported. Then write the real pattern.

## 3. The rule

`rules/<lang>/<category>/<name>.yml`, one rule, id `<lang>.<name>`, `languages` as the README
says. Layout as the SQL rule: `message` (what is wrong and how to fix it), `metadata`, a
`# Known limits` comment block naming each `todo` line, then the patterns.

- **Taint (request): sources** start from a verbatim copy of the SQL rule's source block
  (COVERAGE.md "Source blocks") and add only what the category needs. Request objects of real
  handlers only: never "the first parameter of any function", never every parameter of every
  function. **Taint (other source):** the category's own source (the archive entry name), not
  the request block.
- **Taint sinks** bind their receiver: a type (`(java.sql.Statement $S)`, `($DB : *sql.DB)`), an
  object created in the same function or file, or literal evidence (a string that starts with an
  SQL keyword). Never a bare method name that other libraries share. `focus-metavariable` on the
  dangerous argument only. **Sanitizers:** number and boolean conversions, the documented escaping
  and sanitising functions, the safe wrappers the docs name.
- **Misuse and hotspot:** match the unsafe setting where it is set (the option key with its
  unsafe value, the call with the unsafe argument), bind the API by type or import, and exclude
  the safe forms with `pattern-not` / `pattern-not-inside` (a config that also sets
  `VerifyConnection`, a trust manager that delegates).
- **Shared blocks stay byte-identical.** A change to a language's source block (or its shared
  propagators and sanitizers) goes into every rule that carries it, identically; compare the
  copies with a script, and keep rule-specific items after the shared ones. A generated block
  (tools/xxe-exclusions.mjs) is changed in its generator, then regenerated.
- **OpenGrep 1.30.0 pitfalls** (all hit before):
  - a metavariable used in `metavariable-regex` must be bound in every branch of its
    `pattern-either`; a branch that binds it only sometimes matches anything in a
    `pattern-not-inside`. `metavariable-regex` is anchored at the start and does not interpolate
    other metavariables. Nested inside a `pattern-either` branch it silently breaks taint
    sanitizers, and `metavariable-pattern` on an outer metavariable fails there ("not in scope"):
    lift such branches to the top level;
  - in taint mode `metavariable-pattern` does not unify with metavariables bound outside it
    (write the shapes out); `metavariable-type` needs the type declared in the same file; `var` and
    `:=` declarations lose their type (bind from the constructor with a `pattern-inside`);
  - positive patterns in one `patterns` block match by inclusion, not equality (pin a callee
    with `metavariable-pattern`); `pattern-inside: if C: ...` also covers the else branch (use the
    body metavariable with `focus-metavariable`); a positive `pattern-regex` intersects by range,
    so a whole-file condition must span the file (`(?s)\A.*\bword\b.*\z`) next to a positive
    `pattern`;
  - **a sanitizer that matches a call also cleans every sink inside a function passed to that
    call.** Exclude function arguments (`pattern-not: 'await $F(..., <... function (...) { ... }
    ...>, ...)'` and the object-method form; it matches arrows too) and add an `exact: true` twin
    for the calls with function arguments: it cleans the call's value only;
  - `--test` ignores annotations in JSX children (`{/* ruleid */}`); OpenGrep's own file selection
    skips `tests/` (the probe passes `--x-ignore-semgrepignore-files`); Git Bash heredocs turn `\\`
    into `\`: write rules and scripts with backslashes through the editor and check them.
- **Performance** (every new rule, and every change that adds alternatives, sources or module
  conditions). Run `opengrep scan` once in the scanner container; `opengrep-core` is then at
  `/home/node/.cache/opengrep/v1.30.0/semgrep/bin/opengrep-core` (expand YAML anchors first: it
  does not read them).
  - **Prefilter:** `opengrep-core -prefilter_of_rules <rule>` must give `Some` **and a small
    size** (a few kB; 283 kB already cost 0.4 s per large file, 31 MB cost 20–110 s per module).
    OpenGrep multiplies the conditions of the top-level branches into a CNF and gives up past
    about 50,000 clauses, or when one branch alone grows too large: then the whole rule has no
    prefilter and every file is matched. Every positive conjunct in a branch (`pattern-inside`,
    `metavariable-regex`, `metavariable-pattern`) multiplies it; `pattern-not` and
    `pattern-not-inside` cost nothing. A branch without a literal drops the source words; string
    literals give no words, and words match as substrings ("set" in "offset"): the sink clause
    needs a rare word. The product is over clauses: an Or of single-pattern alternatives is one
    clause, a branch of `pattern-inside` + `pattern` (an import binding) or `pattern` +
    `metavariable-regex` is two. So bind a condition that every branch repeats (the imports)
    once in a conjunct above the `pattern-either`, with `pattern-inside` only (a positive
    `pattern` there adds ranges of its own, so a safe call nested in a reported one is reported
    too; go.insecure-cookie: 6.5 MB → 4 kB), and write out a handful of names rather than give
    several sources a `metavariable-regex` each (go.ssrf: 67 kB, 0.58 s → 13 kB, 0.17 s). A
    word-regex anchor beside a no-word branch (ruling P2) shrinks the result but not the build:
    the product is still multiplied (one experiment on go.insecure-cookie: 107 B but 350 ms;
    with the no-word branch first, None).
  - **Build time** (`time opengrep-core -prefilter_of_rules`, best of three, ~0.1 s for a plain
    rule): OpenGrep builds the prefilter again for every file, and before it drops anything, so
    a rule whose prefilter is tiny or dropped (a no-word branch) can still cost 0.5 s per file.
    The work grows with the product of the top-level branches' positive conditions (a
    `pattern-either` of plain patterns counts once). To cut it: write the names of a
    `metavariable-regex` out as `pattern-either` alternatives (`$S.get(..., verify=False, ...)`,
    `$S.post(...)` …: one condition instead of two), and join branches of the same shape (one
    `pattern-either` of the contexts, one of the sinks). Joined branches also match each
    context with the other branches' sinks: check those pairs occur in practice only in code that
    cannot run, and record what remains, such as a name rebound from the context to another
    object, as a Known limit with a `todook:` line. python.tls-verification-disabled: 3^5 x 2^5 →
    3 x 2^6, 0.63 → 0.1 s.
    `npm test` checks every rule (`npm run test:prefilter -- <rule> --table`: Some, at most
    20 kB, built within 400 ms, best of 3), looser than the budget below.
    The budget is ≤ 0.2 s and ≤ 20 kB. Exclusions cost nothing, so a branch (a source or sink of a
    taint rule too) can keep one or two positive terms exactly: write a context it must sit in as
    "not outside it" (a `pattern-not` of the same pattern with the context as a
    `pattern-not-inside`; metavariables shared with the context still have to agree), and a
    condition that gives no word as a `pattern-not` of the same shape with the condition
    reversed. Such an exclusion's own pattern must match few places (a template, a header name, a
    `new X(...)` with an object): one that matches every call costs its size squared on large
    files. Keep the term that holds the rare word positive. An exclusion left outside the new
    `pattern-not` (one at the branch level) no longer sees the metavariables the moved context
    bound: if it uses them (a Fastify schema check on the route's `$APP`, `$ROUTE`, `$PATH`),
    move it into the context's formula, or the rule changes. A group of forms that report the
    same call can also be one branch: a cheap pattern Q of that call with fresh metavariables and
    the forms' rare words, minus Q where it is not one of the forms (a `pattern-not` of Q over a
    `pattern-not` of the forms); exact only when every range a form reports is a range of Q.
    js.tls-verification-disabled: 2.0 s / 90 kB → 0.09 s / 1.4 kB, js.insecure-cookie: 215 kB →
    1.3 kB, identical findings.
  - **Taint rules** (python.*#prefilter-restore, 2026-10-07): the product runs over every source
    item and every sink item (each is a top-level branch) and over each nested `pattern-either`,
    before anything is dropped, and past roughly 250,000 literals in total (well under 50,000
    clauses) OpenGrep gives None too. Eleven source items of three to five conditions each
    (the Python slice sources) took every Python taint rule to None. Besides writing names out,
    join items that share a condition under it (one `import django` item with the Django shapes
    as its branches). A class with its method as one multi-line `pattern-inside` is one
    condition instead of two, but matches only a method written directly in the class body: one
    defined under an `if`, a nested function or a nested class's method of that name is not
    matched (two `pattern-inside`s match all three), so record the difference. A source item
    without words (a slice `$X[$A:$B]` checked by a regex) leaves the source side empty, so the
    prefilter is the sinks' alone: every sink item then needs a word, or the rule gets None (a
    word anchor `pattern-regex: (?s)\A.*\bword\b.*\z` on an item whose words are all string
    literals; with `(?si)` when the word may be written in another case, as an HTTP header name;
    the prefilter keeps the flag).
  - **Time** on a large real or minified file that **contains** the rule's words (three.js or a
    900 kB bundle for JS, gitea's largest files for Go, a 100–200 kB Django module for Python),
    with `--timeout 0` (OpenGrep's 5 s default times out on a loaded host and drops findings), and
    once on a large real module without them (pip's `pkg_resources/__init__.py`): a synthetic file
    holding every word hides the prefilter cost. For JS taint rules the file needs a source word
    and the sink's import, not only the sink name. A statement sequence that starts at any
    assignment (`$X = $INIT; ...`) or a `pattern-inside` that starts with `...` costs minutes:
    anchor it on the specific statement.
  - **Match limit:** OpenGrep stops at 10,000 matches per rule and file, and then the file
    reports nothing, and in a combined run (all rules on a file, as Qualor scans) one overflowing
    rule blanks the file **for every rule**. A condition that binds a metavariable once per import
    or per statement (`from $DJ import $NAME` + a regex, a header name `$X[$K]` with a regex)
    multiplies every finding. Anchor module checks with a literal `pattern-inside` that binds
    nothing (`import django` + `...`), and test a generated file with a few hundred findings.

Iterate until `npm run test:docker` is green.

## 4. Mutation check

Proves the test is not vacuous. Back up the rule (`cp <rule>.yml .tmp/<name>.yml.bak`), then
apply each change alone, run `npm run test:docker`, record what it reports, and restore:

| shape | mutation 1 | mutation 2 | mutation 3 |
|---|---|---|---|
| taint | break the main source (rename the request attribute) → missing `ruleid:` lines | break the main sink (rename the method) → missing lines | remove a sanitizer → extra findings on `ok:` lines |
| misuse, hotspot | break the main pattern (rename the option or call) → missing lines | break a second API form (another library or position) → missing lines | remove a `pattern-not` of a safe form → extra findings on `ok:` lines |

A mutation that leaves the test green means the fixture lacks a line for that part: add it and
repeat. Restore with `cp .tmp/<name>.yml.bak <rule>.yml` and check `git diff` shows only your work.

**Per-alternative sweep** (rules with more than a handful of alternatives, and every shared-block
change): generate one mutant per pattern item, removing each source, propagator, sanitizer and
each `pattern-either` alternative at any depth alone, and run `opengrep scan --test` on each in one
container. Every mutant must fail; a surviving one is an untested alternative (add a fixture line)
or a dead one (drop it). For a shared block, sweep every rule that carries it. Earlier runs found
7 to 124 surviving mutants this way where the three mutations above passed.

## 5. Probe

```sh
npm run probe -- rules/<lang>/<category>/<name>.yml
```

Review the findings as `REFERENCE.md` "How to review the findings" says (all up to 30 per
project, else a random 30, with the counts stated): TP or FP with a one-line reason; for hotspots
FP means the pattern matched the wrong thing, not that the usage is harmless. **qualor-cc must
show 0.** More than half FP on the noise projects: narrow the rule and probe again; still more
than half: the row is `BLOCKED` with the question.

Each FP shape you keep: describe it in one line, then write a **fresh, minimal** `todook:` line
from the docs (never the project's code) and a "Known limits" line. Open only the finding's file
and lines in a reference clone; never its tool configs, scripts or result directories.

`npm run probe -- --recall <rule>` once shows what the rule finds on the recall sets of its
language (the controller's `npm run measure` scores them at the end of the run); note the count.
To try a shape quickly, put it in a file under `.tmp/` and run
`npm run scan -- <rule>.yml -- .tmp/<file>`.

## 6. Metadata

- `title`: one line, like "SQL query built from HTTP request data (Go)".
- `cwe`, `owasp`, `kind`, `severity`, `confidence`: per COVERAGE.md "Kind and severity"; the
  OpenGrep `severity` matches; `kind` and `cwe` must equal the backlog row (`npm run check`
  compares them).
- `frameworks`: lower-case names of what the fixture covers.
- `sources`: every URL from step 1; `npm run check` refuses forbidden hosts.
- `since`: the version the controller gave you.

## 7. Page

`npm run docs` writes the rule's public page, `docs/rules/<lang>/<name>.md` (Qualor links each
finding to it), and the index. Replace its TODO sections, between the `begin`/`end` markers, with
plain English for users: what it finds, why it matters, an example (a minimal `**Noncompliant:**`
and `**Compliant:**` code block of your own, in the fixture's style), how to fix, and the known
limits in short (not the YAML comment's wording). The rest is generated from the metadata; rerun
`npm run docs` after changing the rule. `npm test` fails while a section is unwritten, a page is out
of date, or the example does not behave as it says (the noncompliant block must get a finding of
the rule, the compliant block no finding of any rule: `tools/test-examples.mjs`). Maintenance rows:
update the sections the change affects (usually Known limits).

## 8. Commit

```sh
npm run test:docker                      # green
git status --porcelain                   # only this rule's files, its page and docs/rules/README.md
git add rules/<lang>/<category>/<name>.yml rules/<lang>/<category>/<name>.<ext> docs/rules/<lang>/<name>.md docs/rules/README.md
git commit -s -m "feat(<lang>): <name> rule for <frameworks>" -m "Backlog: <id>" -m "<docs used, limits (todo lines), probe counts>"
```

One commit per rule, and its body always holds the line `Backlog: <id>` (the controller finds an
interrupted run's work by it). Maintenance rows: `fix(<lang>): ...` for behaviour,
`test(<lang>): record ...` for limits only, with `Backlog: <lang>.<name>#<topic>`.

- A new rule's page goes into the **same commit** as the rule; a maintenance change updates the
  page sections it affects in the same commit.
- After a rebase onto `main`, run `npm run docs`: `docs/rules/README.md` (the index) is generated
  and goes stale or conflicts when another batch added rules. Commit the regenerated index.
- End the body with a plain sentence, not `Key: value` lines: git takes a last paragraph of
  `Fixtures: …` / `Probe: …` lines as trailers and joins `Signed-off-by:` to it.

## Report

Your final message holds one block per row, in this shape and nothing else:

```text
### <id>: DONE | BLOCKED
- shape: taint (request) | taint (other source) | misuse | hotspot
- commit: <sha> <subject>
- fixture: <n> ruleid, <n> ok, <n> todoruleid, <n> todook (<files>)
- red: expected [<lines>], reported []
- mutations: <1> -> missing [<lines>]; <2> -> missing [<lines>]; <3> -> extra [<lines>]; sweep: <k> mutants, <s> survived
- perf: prefilter Some, <size>; <large file with the words> <s> s, <file without them> <s> s (--timeout 0)
- probe: <project> <n> (<tp> TP, <fp> FP: <reason>; "<k> of <n> reviewed" if sampled); ... ; qualor-cc 0
- recall: <set> <n> or not run
- limits: <one line per todo line>
- docs: <n> URLs in metadata.sources
- proposals: <maintenance rows, COVERAGE.md candidates, source-block changes, or none>
- question: <BLOCKED only: one line ending in ?>
```
