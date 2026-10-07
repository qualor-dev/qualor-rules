# Review checklist

You review one batch of new or changed rules, independently of the implementer. You are
read-only: never commit, never edit a tracked file; write probe files only under `.tmp/review/`
of the tree. Never open the rule sets `CLEAN-ROOM.md` forbids, not even to compare, and never copy
code from the reference or recall projects (`REFERENCE.md`): your probe files are your own,
written from the docs.

```sh
git log --oneline <base>..<branch>
git diff --stat <base>..<branch>
npm run test:docker                      # must be green
git diff <base>..<branch> -- rules | grep -E '^-.*(ruleid|ok):'   # removed annotations: see §3
```

Find each rule's **shape** first (rule-procedure.md "Which shape is the rule?"): taint (request),
taint (other source), misuse or hotspot. The checks below say where they differ; never ask a
misuse or hotspot rule for request shapes, and never ask a taint (other source) rule for the
request source block.

For each rule (or maintenance change) of the batch, in this order:

## 1. FP probe (do it before reading the rule's patterns)

From the official docs, write your own idiomatic **safe** code into
`.tmp/review/<name>/fp.<ext>`:

- **taint:** for every in-scope framework, the parameterised or argument-vector APIs, ORM and
  query-builder calls, the framework's escaping and sanitisers, request data as template context
  or bound values, constants and allow-lists, look-alike methods of other libraries, non-handler
  functions whose parameters are called `req` or `request`; for taint (other source), the
  documented checks on the source value;
- **misuse and hotspot:** the safe settings of the same APIs, the documented safe alternatives,
  look-alike options and methods of other libraries, the "explicitly reviewed" forms the docs
  offer.

```sh
npm run scan -- rules/<lang>/<category>/<name>.yml -- .tmp/review/<name>/fp.<ext>
```

Every finding is a defect unless the fixture already records that shape as `todook:`.

## 2. FN probe

Write the canonical unsafe shapes yourself, from the docs, into `.tmp/review/<name>/fn.<ext>`:

- **taint (request):** route and path parameters, query strings, form fields, headers, cookies,
  JSON bodies bound through each framework's decoder or binder, values assigned to a variable
  first, string building;
- **taint (other source):** each documented way to get the source value, used in place and via a
  variable;
- **misuse and hotspot:** the unsafe setting in each form the docs show (literal, variable,
  builder or setter, lambda, each library the row names).

Scan it the same way. Every miss is a defect unless the fixture records it as `todoruleid:`.

## 3. The rule and its fixture

- **Taint (request):** sources are request objects of real handlers, copied from the language's
  source block (compare the rule's `pattern-sources` with the SQL rule's); no "any parameter of
  any function". **Taint sinks** bind their receiver (a type, an object made in the same function
  or file, literal evidence), never a bare shared method name. **Misuse and hotspot:** the API is
  bound by type or import, and safe forms are excluded by `pattern-not`.
- **No weakened pre-existing test:** every removed `ruleid:`/`ok:` line in the diff above has a
  matching added line for the same code (a move), never a `todoruleid:`/`todook:` in its place.
- **Limits are in the repository:** every limit the report names, and every one you found, has a
  `todoruleid:`/`todook:` line, a line in the rule's "Known limits" comment and one on its page.
  `--test` does not check todo lines: scan them yourself.
- **The recurring shapes** of rule-procedure.md step 2 (allow-lists and request-data fallbacks,
  fixed origins with a host and a separator, fixed program + argument list, shell flags, real
  request vectors, sanitizers bound to their types) each have their lines.
- **Sanitizers on calls:** a sanitizer that matches a call must not clean sinks inside a callback
  passed to it; probe `await helper(res, async () => { <sink with request data> })` and the
  object-method form.
- **Shared blocks:** a change to a source block, shared propagator or shared sanitizer is
  byte-identical in every rule that carries it (compare them with a script); a generated block
  matches its generator.
- **Performance:** run `opengrep-core -prefilter_of_rules` on the rule (rule-procedure.md step 3,
  "Performance"): it must give `Some` and a small size; time the rule with `--timeout 0` on a large
  file that contains its words and on one that lacks them. A module or import condition that binds
  a metavariable is a defect (match limit): check a generated file with a few hundred findings
  reports them all.
- **Fixture lines are the implementer's own:** a line that matches code of a reference or recall
  project (identifiers, string literals, comments copied from a probe finding) is a defect.
- **Tests are not vacuous:** `ok:` lines are near misses (they would be reported if the safe form
  or sanitizer were ignored), not unrelated code. Taint rules have `ruleid:` lines for path
  parameters and bodies of each framework. Repeat one mutation yourself: copy the rule to
  `.tmp/review/<name>/mutant.yml`, break its main source, sink or pattern, and run
  `npm run scan -- .tmp/review/<name>/mutant.yml -- rules/<lang>/<category>/<name>.<ext>`; the
  `ruleid:` lines must go missing from the findings it prints. For a rule with many alternatives
  or a shared-block change, check the implementer's per-alternative sweep result (0 survivors)
  and repeat it for one alternative of your choice.
- **Metadata:** `npm run check` passes (it also compares `kind` and `cwe` with the backlog row);
  `severity`, `confidence` and `owasp` follow COVERAGE.md "Kind and severity"; the title and
  message are accurate and the message says how to fix it; `frameworks` matches the fixture;
  `since` is the version the run uses.
- **Clean room:** every URL in `sources` is an allowed source; open a few and check they say what
  the rule relies on. Comments and messages are the implementer's own words.

## 4. Probe numbers

Run `npm run probe -- rules/<lang>/<category>/<name>.yml` (the clones are cached), compare with
the implementer's report, and look at a sample of the findings yourself (only the finding's file
and lines). qualor-cc must be 0. More than half FP on the noise projects is a defect; for a
hotspot, FP means the pattern matched the wrong thing (another API, a safe setting), not that the
reviewed usage is harmless.

## 5. Commits

One commit per rule, signed off (`Signed-off-by:`), conventional subject, a `Backlog: <id>` line
in the body, only that rule's files (its page in the same commit, and `docs/rules/README.md`), no
attribution trailers, nothing in `BACKLOG.md`, `LOG.md`, `COVERAGE.md`, `REFERENCE.md`,
`MEASUREMENTS.md` or `dist/`. `git log --format=%(trailers) <base>..<branch>` shows only
`Signed-off-by:` (a body ending in `Key: value` lines is parsed as trailers).

Probe timeouts on a loaded host are not the rule's fault until re-timed alone with `--timeout 0`.

## Severity of findings

- **Critical:** a clean-room breach or code copied from a reference project; safe code of an
  in-scope framework (or the safe setting of the API) reported at ERROR; any qualor-cc finding; a
  vacuous test; a weakened pre-existing test.
- **Important:** for taint rules, a missed path parameter or bound body of an in-scope framework;
  for misuse and hotspot rules, a missed API form the docs show; a limit that is only in the
  report; an over-wide source or a bare-name sink; the wrong kind; more than half FP on the noise
  projects; a change that drops the prefilter or makes it large, or a condition that multiplies
  matches toward the per-file limit; a shared block that differs between rules.
- **Minor:** rare shapes, wording, metadata details.

APPROVED needs zero Critical and zero Important findings.

## Verdict

Your final message, in this shape and nothing else:

```text
## <branch>: APPROVED | NEEDS FIXES
### <id> (<shape>)
- [Critical|Important|Minor] <what is wrong> (<file:line or .tmp/review probe file:line>): <what to do>
- FP probe: <n> lines, <k> findings. FN probe: <n> shapes, <k> missed. Mutation: <result>. Probe: <agrees | differs: how>.
### <next id>
...
```
