---
name: write-rules
description: Use when the maintainer runs /write-rules [N] [language] in the qualor-rules repository, or asks to write, continue, resume or extend Qualor's security rules from the backlog.
argument-hint: "[N] [js|python|java|go]"
---

# Write rules

One run takes the first N `todo` rows of `BACKLOG.md`, writes each rule to the quality bar, has it
reviewed, merges it into `main`, measures and logs the run. All state lives in the repository:
`BACKLOG.md` (the queue), `COVERAGE.md` (how to extend it), `REFERENCE.md` (where rules are
probed), `MEASUREMENTS.md` (recall scores), `LOG.md` (what runs did, including a run in progress).
You are the **controller**: you plan, dispatch, merge and keep those files; the per-rule work
follows `rule-procedure.md` and the review follows `review-checklist.md`, both next to this file.

**A rule ships only with evidence:** a fixture written first, a mutation check, reviewed probe
numbers, and every known limit written into the repository (a `todoruleid:`/`todook:` line and a
"Known limits" comment). A limit that exists only in a report is lost.

## Hard rules

- Never push, never tag, never add a remote. The repository has one remote, `origin`
  (github.com/qualor-dev/qualor-rules, public); pushing to it happens only on the maintainer's
  word, never as part of a run. Never run `npm run release` for a release, never touch `dist/` or
  the qualor-cc repository (that is `/release-pack`). The probe only reads a clone of qualor-cc.
- **Everything lands on `main`, linearly** (the maintainer's choice): no pull requests, no merge
  commits. Branches exist only for parallel implementers and are fast-forwarded (`--ff-only`).
- Never weaken a test that existed before this run: never delete or rewrite its `ruleid:`/`ok:`
  lines, never turn a `ruleid:` into a `todoruleid:` or an `ok:` into a `todook:` to get green. Fix
  the rule, or stop and ask.
- Clean room (`CLEAN-ROOM.md`): never open semgrep-rules, opengrep-rules, the semgrep.dev
  registry, CodeQL queries or SonarSource rule descriptions, not even "to compare".
- **Never copy code from a reference or recall project** (`REFERENCE.md`, whatever its licence)
  into this repository. Describe the shape, then write it anew from the docs.
- Commits: `git commit -s`, conventional message, stage by path (never `git add -A`, `-a` or `.`),
  no attribution trailers (no `Co-Authored-By`, no "Generated with").
- Only you edit `BACKLOG.md`, `LOG.md`, `COVERAGE.md`, `REFERENCE.md` and `MEASUREMENTS.md`, and
  only on `main`.
- Docker: your containers are named `qr-*` and run with `--rm`; never prune, never remove images,
  never touch other containers.
- Stop and ask before anything irreversible: deleting a branch with unmerged commits, rewriting
  `main`, removing a worktree you did not create, withdrawing a rule that an earlier run merged.
- **Shell blocks:** every Bash call starts a fresh shell. Set the variables at the top of each
  block (the blocks below do) or write the literal values; never rely on `$W` from an earlier call
  (an empty `$W` makes `git -C "$W"` act on the main tree).

## Arguments

`/write-rules [N] [language]`: N defaults to 10. The language is `js`, `python`, `java` or `go`
(`javascript`, `typescript`, `ts` → `js`; `py` → `python`; `golang` → `go`). No language: all four.

## 1. Start

Run in the main tree (`E:\Personal\qualor\qualor-rules`):

```sh
git status --porcelain            # must print nothing
git branch --show-current         # must print main
git remote -v                     # origin (qualor-dev/qualor-rules) only
git worktree list                 # the main tree only
git branch --list 'rules/*'       # nothing
grep -c '| in-progress |' BACKLOG.md   # 0
test -d node_modules || npm ci --ignore-scripts
npm run test:docker               # baseline: check, tool tests, opengrep --test (OpenGrep 1.30.0)
```

Read `AGENTS.md`, `CLEAN-ROOM.md`, `BACKLOG.md`, `REFERENCE.md` and the newest three entries of
`LOG.md` (their open questions and notes apply to this run).

- **Dirty tree, another branch, another remote:** stop and ask. Never stash, commit or reset what
  you did not write.
- **`in-progress` rows, `rules/*` branches, `qualor-rules-*` worktrees, or a LOG.md entry marked
  "(in progress)":** an earlier run was interrupted. Finish it first with "Resume" below, then
  start this request from step 1 again.
- **`npm run test:docker` cannot run:** `tools/scanner.mjs` uses `qualor/scanner:6b1`; set
  `QUALOR_SCANNER_IMAGE` to another local `qualor/scanner` tag whose `opengrep --version` prints
  `package.json`'s `"opengrep"` (`docker images qualor/scanner`). On Linux x86-64 without Docker:
  `sh tools/install-opengrep.sh` and `OPENGREP=.tmp/opengrep/opengrep npm test` (probes and
  measurements still need Docker). With neither: stop and ask the maintainer to build the image in
  qualor-cc (`docker build -f deploy/scanner/Dockerfile -t qualor/scanner:<tag> .`).
- **Baseline red:** stop and report the failure. Do not start rules on a red tree.

## 2. Top up the backlog

Count the `todo` rows (of the language, if given):

```sh
grep -c '| todo |' BACKLOG.md
grep '^| python\.' BACKLOG.md | grep -c '| todo |'      # one language
```

Fewer than N: extend `BACKLOG.md` by following COVERAGE.md "Extending the backlog" (doc gate,
priority rules), then `npm run check` and commit `docs(backlog): add <k> rows from COVERAGE.md`.
If the map runs dry, write the rules you have and put the question into the report.

## 3. Plan

1. Take the first N `todo` rows in table order (of the language, if given). Maintenance rows
   (`<lang>.<name>#<topic>`) count as rows.
2. Group them by language, keeping table order, and split each group into **batches of at most 4
   rows**: `<lang>-1`, `<lang>-2`, … (maintenance rows, being first in the table, land in the
   first batch). With N ≤ 5 there are no batches: you work inline.
3. `since` for new rules: the patch after `package.json`'s version
   (`node -p "require('./package.json').version"` gives 2026.10.0 → `since: 2026.10.1`);
   `/release-pack` renumbers it if the release gets another version. Maintenance rows keep `since`.
4. Set the rows to `in-progress`, and add the run's entry at the top of `LOG.md` (format in that
   file) with the heading ending in "(in progress)", the request, the Plan ("BASE = this commit"
   and the batches with their ids, or "inline"), and an empty **Progress** list. Then:

```sh
npm run check
git add BACKLOG.md LOG.md
git commit -s -m "docs(backlog): start <k> rules (run of <yyyy-mm-dd>)"
git rev-parse HEAD                # BASE: the start of the inline review range (Resume finds it again by the subject)
```

**Progress records.** After every review verdict that lets a batch merge, and after every merge,
append one line to the entry's Progress list and commit it on `main`
(`git commit -s -m "docs(log): <batch> <event>" -- LOG.md`), for example
`- python-1 (python.ssrf, python.xss): APPROVED in round 2; merged 1a2b3c4..5d6e7f8`. A later
agent resumes from these lines (see "Resume").

## 4. Write

**N ≤ 5: inline.** Work on `main` in the main tree. For each row in order, follow
`rule-procedure.md` yourself (one commit per rule). Then go to step 5 with `BASE..main`.

**N > 5: one implementer per batch, one worktree per batch.** Languages run in parallel; the
batches of one language run one after another (a later batch may need a source-block change of
an earlier one): batch `<lang>-<k+1>` starts only after `<lang>-<k>` is merged.

For each batch you start (fill in L, K and D; if the branch or the path already exists, use the
next unused K):

```sh
L=python; K=1; D=$(date +%Y%m%d)
W=E:/Personal/qualor/worktrees/qualor-rules-$L-$D-$K
git worktree add -b rules/$L-$D-$K "$W" main
npm --prefix "$W" ci --ignore-scripts
```

Worktrees live only under `E:\Personal\qualor\worktrees\`, one implementer per worktree. Dispatch
the first batch of every language in one message (parallel `Agent` calls, `general-purpose`,
background), each with this brief, filled in:

```text
You implement Qualor security rules in <W> (branch rules/<L>-<D>-<K>, based on main <sha>).
AGENTS.md and CLEAN-ROOM.md in that tree are binding. Work only in <W>; run every command from its
root.

Rows, in this order (from BACKLOG.md):
| id | lang | category | cwe | kind | frameworks and APIs | status | notes |
|---|---|---|---|---|---|---|---|
<the batch's rows, verbatim>

For each row, follow <W>/.claude/skills/write-rules/rule-procedure.md exactly, including its
report. New rules get `since: <since>`.

Do not edit BACKLOG.md, LOG.md, COVERAGE.md, REFERENCE.md or MEASUREMENTS.md: put proposals in
your report. Never copy code from the reference or recall projects. Never push, add a remote, tag,
run a release, or touch dist/ or qualor-cc. Commit with `git commit -s`, staged by path, no
attribution trailers. Docker containers: qr-*, --rm, never prune. If a row cannot meet the quality
bar, report it BLOCKED with a one-line question and go on with the next row.
```

Keep each implementer's agent id: fix rounds go back to the same agent. An implementer or reviewer
that ends without a report in the required shape gets one fresh agent with the same brief plus
"An earlier agent stopped; continue from the branch's state: rows with a commit carrying their
`Backlog: <id>` line are written." If that one fails too, the batch's rows without a commit become
`blocked` ("The implementer failed twice on <id>: retry it alone or split the row?").

## 5. Review and fix

One reviewer per batch (inline: one for `BASE..main`), in the background (`general-purpose`), with
this brief:

```text
You review Qualor security rules on branch <branch> in <W>, commits <base>..<branch>.
Rows: <the rows, verbatim>. The implementer's report: <paste it>.
Follow <W>/.claude/skills/write-rules/review-checklist.md exactly, including its verdict format.
Read-only: never commit; write probe files only under <W>/.tmp/review/. Never open the rule sets
CLEAN-ROOM.md forbids, and never copy code from the reference or recall projects.
```

- **APPROVED:** record it (step 3, "Progress records") and go to step 6.
- **NEEDS FIXES:** send every Critical and Important finding, and the Minors, to the same
  implementer (`SendMessage` with its agent id): "Fix these on your branch, following
  rule-procedure.md; Minors you do not fix become documented limits. Report in the same format."
  Then send the fix commits to the same reviewer for a re-review of those findings.
  **Inline:** you fix them yourself, following rule-procedure.md, then send the fix commits to the
  same reviewer.
- **At most 3 fix rounds per batch.** A row with an open Critical or Important after round 3 is
  withdrawn: the implementer (inline: you) removes its files in one commit
  (`revert(<lang>): withdraw <id> (blocked: <reason>)`, with `Backlog: <id>`) and the row becomes
  `blocked`. This needs no word from the maintainer: the rule never passed review.
- A `BLOCKED` row in an implementer's report needs no review; it becomes `blocked` with its
  question.

## 6. Merge (each batch, as soon as it is approved)

```sh
L=python; K=1; D=<yyyymmdd of the batch>; W=E:/Personal/qualor/worktrees/qualor-rules-$L-$D-$K
git merge --ff-only rules/$L-$D-$K
```

If `--ff-only` refuses (`main` moved: another batch merged, or a progress commit):
`git -C "$W" rebase main`, then `npm --prefix "$W" run check`; when it reports
`docs/rules/README.md` out of date (another batch added rules), run `npm --prefix "$W" run docs`
and commit the index on the branch (`git -C "$W" commit -s -m "docs(rules): regenerate the index"
-- docs/rules/README.md`). Then `npm --prefix "$W" run test:docker`, and merge again **only if it
is green**: a red rebased branch goes back to its implementer as a fix round (inline: you fix it)
and is never merged red.

Implementers never touch the shared files, so conflicts should not happen; if `BACKLOG.md` or
`LOG.md` conflicts anyway, keep both sides' rows and, for the same row, the later status
(`done`/`blocked` over `in-progress` over `todo`). `docs/rules/README.md`, the generated index of
the rule pages, does conflict when both sides added rules: rebuild it with
`npm --prefix "$W" run docs`, then `git -C "$W" add docs/rules/README.md` and
`git -C "$W" rebase --continue`. Then:

```sh
L=python; K=1; D=<yyyymmdd>; W=E:/Personal/qualor/worktrees/qualor-rules-$L-$D-$K
npm run test:docker               # must be green on main: if not, stop here (below)
git worktree remove "$W"
git branch -d rules/$L-$D-$K      # -d, never -D: an unmerged branch is a question for the maintainer
```

If `npm run test:docker` is red on `main` after a merge, do not record the merge, remove the
worktree or start another batch: fix `main` first (a commit of yours, with `Backlog: <id>` of the
row it fixes) or ask the maintainer. Otherwise record the merge (Progress line), then start that
language's next batch (step 4).

## 7. Finish

1. **Measure** the languages the run touched (rules committed, tree clean):
   `npm run measure -- <langs>`. It inserts an entry into `MEASUREMENTS.md`. A covered Java
   injection category that misses the §8.4 target goes into the report as a question.
2. **BACKLOG.md:** each planned row becomes `done` (on `main`) or `blocked` with notes ending in
   the one-line question. Add the implementers' and reviewers' proposals: a limit worth fixing
   later is a `todo` maintenance row `<id>#<topic>` above the first `todo` rule row; a new category
   or API goes into COVERAGE.md as a `candidate`; a new or changed source block goes into
   COVERAGE.md "Frameworks in scope" / "Source blocks". Tooling follow-ups (a check, a sweep,
   a generator) are not rows (`BACKLOG.md` ids are rule ids): they go into the LOG entry's Notes and
   COVERAGE.md "Growing the map". When a source block changed, add a
   `#<topic>` row for every other `done` taint rule of that language whose block does not match
   yet (COVERAGE.md "Source blocks").
3. **LOG.md:** complete the run's entry (drop "(in progress)", fill every field; keep Progress).
4. `npm run check`, then commit the files you changed:
   `git commit -s -m "docs: log the rules run of <yyyy-mm-dd>" -- BACKLOG.md LOG.md COVERAGE.md MEASUREMENTS.md`.
5. **Report to the maintainer**, in this shape:

```text
Rules run <yyyy-mm-dd> (/write-rules <args>): <d> done, <b> blocked.
Done: <ids>.
Blocked: <id>: <question> (one line each).
Questions: <other open questions, or none>.
Backlog: <t> todo (js <a>, python <b>, java <c>, go <d>).
Noise: <rules with findings on reference projects, "rule: n (tp TP)">; qualor-cc 0.
Recall: <MEASUREMENTS.md headline: Benchmark per covered category TPR/FPR, other sets' counts>.
Release: <suggestion>.
```

Suggest `/release-pack` when at least 10 rules have `since` above `package.json`'s version, or a
maintenance row fixed a false positive in a released rule; otherwise say how many new rules wait.

## Resume (an interrupted run)

Work from the repository's state only; dead agents cannot be asked.

```sh
BASE=$(git log -1 --format=%H --grep='^docs(backlog): start')
git log --oneline "$BASE"..main          # what reached main since the plan
git worktree list; git branch --list 'rules/*'
grep -n '| in-progress |' BACKLOG.md
```

Read the "(in progress)" LOG.md entry: its batches and Progress lines. Each rule commit carries
`Backlog: <id>` in its body (rule-procedure.md step 8). For each `in-progress` row:

1. **On `main` and its batch (or the inline range) is recorded as APPROVED:** written; it goes to
   step 7.
2. **On `main` without an APPROVED record** (`git log "$BASE"..main --grep 'Backlog: <id>'` finds
   it; typical for an inline run): run step 5 for those rows on `BASE..main` (you fix, inline
   style), record the verdict, then step 7.
3. **Only on a leftover branch** (`git log main..rules/<L>-<D>-<K> --grep 'Backlog: <id>'`): if
   the worktree is gone, recreate it with `git worktree add <W> rules/<L>-<D>-<K>`. Dispatch a new
   reviewer for the branch; fix rounds and the batch's unwritten rows go to a new implementer with
   the step-4 brief plus the "continue from the branch's state" line. Then steps 6 and 7.
4. **Nowhere:** set the row back to `todo` (no rule file exists, so `npm run check` passes).

The maintainer may say to discard a leftover batch instead (only then):

```sh
L=python; K=1; D=<yyyymmdd>; W=E:/Personal/qualor/worktrees/qualor-rules-$L-$D-$K
git worktree remove --force "$W"
git branch -D rules/$L-$D-$K
```

Its rows go back to `todo`. A rule already on `main` is never discarded silently: removing it is a
`revert(<lang>): withdraw <id>` commit on the maintainer's word, and the row becomes `todo` or
`blocked`. Record what you did in the LOG entry, then finish the run (step 7).

## Red flags: stop and correct course

| Thought | Reality |
|---|---|
| "The fixture is green, the probe can wait" | The fixture shows what you imagined. The probe on real projects is the quality bar; run it. |
| "Any parameter of a handler-ish function is a fine source" | Over-wide sources were the first review's main defect. Request objects of real handlers only (COVERAGE.md "Source blocks"). |
| "The ORM call looks like the sink, report it" | Idiomatic safe ORM and query-builder code flagged at ERROR is a Critical review finding. Write its `ok:` lines first. |
| "Path parameters and JSON bodies are edge cases" | They are the most common inputs. Every in-scope framework needs `ruleid:` lines for route parameters and decoded or bound bodies (taint rules). |
| "I'll paste the probe's FP line into the fixture" | That copies someone else's code (GPL in the Benchmark). Describe the shape, write a fresh minimal line from the docs. |
| "The rule is fast on its fixture" | Fixtures are tiny. Check the prefilter size and time a large real file with `--timeout 0` (rule-procedure.md step 3); one rule over the match limit blanks a whole file for every rule. |
| "I'll mention the limit in the report" | Reports are not shipped. `todoruleid:`/`todook:` line plus a "Known limits" comment, or it did not happen. |
| "Change the old `ok:` to `todook:` so it passes" | That weakens a test. Fix the rule, or stop and ask. |
| "The docs page is down, I know the API" | No docs, no row: the doc gate is the clean-room record. Block the row with the question. |
| "The qualor-cc finding is only in a test file" | Zero means zero. Rework the rule. |
| "Eight rows in one batch saves dispatches" | At most 4 per implementer: more does not fit one agent's context, and steps get skipped. |
| "The dead run's rows can just go back to todo" | Not if their rules are on `main` or a branch: follow "Resume". |
