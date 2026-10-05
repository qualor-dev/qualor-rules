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
`todook:` (an accepted false finding), with a comment line above saying why. Aim for at least ten
`ruleid:` and ten `ok:` lines; taint rules need at least one of each per framework.

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
- **OpenGrep 1.30.0 pitfalls** (all hit before): a metavariable used in `metavariable-regex` must
  be bound in every branch of its `pattern-either` (split the branches otherwise); `var` and `:=`
  declarations lose their type (add a `pattern-inside` binding from the constructor or factory);
  `metavariable-regex` does not interpolate other metavariables; OpenGrep's own file selection
  skips `tests/` (the probe passes `--x-ignore-semgrepignore-files`).

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

## 7. Commit

```sh
npm run test:docker                      # green
git status --porcelain                   # only this rule's files
git add rules/<lang>/<category>/<name>.yml rules/<lang>/<category>/<name>.<ext>
git commit -s -m "feat(<lang>): <name> rule for <frameworks>" -m "Backlog: <id>" -m "<docs used, limits (todo lines), probe counts>"
```

One commit per rule, and its body always holds the line `Backlog: <id>` (the controller finds an
interrupted run's work by it). Maintenance rows: `fix(<lang>): ...` for behaviour,
`test(<lang>): record ...` for limits only, with `Backlog: <lang>.<name>#<topic>`.

## Report

Your final message holds one block per row, in this shape and nothing else:

```text
### <id>: DONE | BLOCKED
- shape: taint (request) | taint (other source) | misuse | hotspot
- commit: <sha> <subject>
- fixture: <n> ruleid, <n> ok, <n> todoruleid, <n> todook (<files>)
- red: expected [<lines>], reported []
- mutations: <1> -> missing [<lines>]; <2> -> missing [<lines>]; <3> -> extra [<lines>]
- probe: <project> <n> (<tp> TP, <fp> FP: <reason>; "<k> of <n> reviewed" if sampled); ... ; qualor-cc 0
- recall: <set> <n> or not run
- limits: <one line per todo line>
- docs: <n> URLs in metadata.sources
- proposals: <maintenance rows, COVERAGE.md candidates, source-block changes, or none>
- question: <BLOCKED only: one line ending in ?>
```
