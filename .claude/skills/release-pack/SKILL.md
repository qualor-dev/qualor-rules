---
name: release-pack
description: Use only when the maintainer explicitly asks to release the qualor-rules pack (/release-pack) or to pin a new pack version in qualor-cc's scanner image.
argument-hint: "[version]"
disable-model-invocation: true
---

# Release the rules pack

Builds a new `qualor-rules-<version>.tar.gz` here and pins it in qualor-cc on a new branch in its
own worktree, with the guide, the Docker Hub text and the changelog brought up to date, then
**stops for the maintainer's word** before anything is merged into qualor-cc's `main`. Nothing is
pushed, tagged or published: the tag `v<version>` is what publishes the pack
(`.github/workflows/ci.yml`), and only the maintainer creates it.

Background on the qualor-cc side (read when a step fails): qualor-cc
`.superpowers/sdd/2026-10-03-phase-6b-1-qualor-engine/task-5-report.md` (pins, drop directory,
images), `task-7-report.md` (fixture, real-tool tests) and `task-11-report.md` (full verification).

## Hard rules

- Run only when the maintainer asked for it in this conversation.
- Never push, never add a remote, never tag, never set `QUALOR_RULES_URL` (that publishes).
- Never merge into qualor-cc `main`, never switch the branch of qualor-cc's main tree (other
  sessions use it): work in the new worktree only.
- **No pin without a current measurement:** `npm run measure -- --check` must pass (the newest
  `MEASUREMENTS.md` entry covers all four languages at the last commit that changed `rules/`).
- `git commit -s`, conventional messages, stage by path, no attribution trailers, in both
  repositories.
- Docker: containers `qr-*` with `--rm`, volumes `qr-*` removed afterwards; never prune, never
  remove images you did not build.
- The tarball is never committed (`dist/` here, the drop directory there are git-ignored).
- **Shell blocks:** every Bash call starts a fresh shell; each block below sets its variables
  first. Fill in the values; never rely on a variable from an earlier call.

## 1. Preconditions (qualor-rules, main tree)

```sh
git status --porcelain && git branch --show-current && git remote -v   # clean, main, no remote
grep -c '| in-progress |' BACKLOG.md                                    # must be 0
npm run test:docker                                                     # green
npm run probe -- rules                                                  # qualor-cc 0; review new findings
npm run measure -- --check || npm run measure                           # then commit MEASUREMENTS.md if it changed
```

Any failure, an `in-progress` row, or a qualor-cc finding: stop and report. If `measure` ran,
commit its entry (`git commit -s -m "docs: measure the rules before the release" -- MEASUREMENTS.md`)
and read it: a covered Java injection category that misses the §8.4 target (the entry says
"NOT met") is a question for the maintainer before you go on ("release anyway, or fix first?").

## 2. Version and `since`

- The version is `YYYY.M.patch` from today's date: when `package.json`'s version has the same
  year and month, the next patch; otherwise `YYYY.M.0` (2026.10.0 → 2026.10.1 in October 2026,
  → 2026.11.0 in November). The maintainer's argument, if given, wins.
- `/write-rules` gave new rules `since: <package.json patch + 1>`. If the release version differs,
  renumber them, then check that no rule names a version above the release:

```sh
OLD=$(node -p "require('./package.json').version")
NEXT=<OLD with patch + 1>; V=<release version>
grep -rl "^      since: $NEXT\$" rules | xargs -r sed -i "s/^      since: $NEXT\$/      since: $V/"
grep -rh '^      since:' rules | sort | uniq -c
npm version "$V" --no-git-tag-version --ignore-scripts                  # package.json and package-lock.json
npm run check
git add package.json package-lock.json <renumbered rule files>
git commit -s -m "chore(release): qualor-rules $V"
```

Renumbering `since` changes `rules/`: run `npm run measure` again afterwards (the check of step 1
compares commits) and commit the entry, or renumber before measuring.

## 3. Build twice and record

```sh
V=<version>
npm run release && cp "dist/qualor-rules-$V.tar.gz" .tmp/first.tar.gz
npm run release && cmp .tmp/first.tar.gz "dist/qualor-rules-$V.tar.gz"  # no output = identical
cat "dist/qualor-rules-$V.tar.gz.sha256"
tar -tvzf "dist/qualor-rules-$V.tar.gz"                                  # LICENSE, NOTICE, manifest.json, rules/**.yml only
npm run measure -- --check                                              # still current
```

Also build once in Linux and compare the SHA-256 (it must be the same):

```sh
MSYS_NO_PATHCONV=1 docker run --rm --name qr-release -e HOME=/tmp -v "$(cygpath -w "$PWD")":/src:ro \
  --entrypoint sh qualor/scanner:6b1 -c 'mkdir /tmp/r && cd /src && tar --exclude=./node_modules --exclude=./.tmp --exclude=./.git --exclude=./dist -cf - . | tar -C /tmp/r -xf - && cd /tmp/r && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 && npm run release'
```

Add a release entry at the top of `LOG.md` (version, SHA-256, rule count by kind, the ids added
or changed since the previous release, the OpenGrep version, the `MEASUREMENTS.md` entry it was
measured in with its Benchmark headline), then `npm run check` and
`git commit -s -m "docs: log the qualor-rules $V release" -- LOG.md`.

## 4. Pin it in qualor-cc (new worktree)

```sh
V=<version>; CC=E:/Personal/qualor/qualor-cc; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
git -C "$CC" worktree add -b rules-pack-$V "$W" main
cp "dist/qualor-rules-$V.tar.gz" "$W/tools/analyzers/qualor-rules/"     # git-ignored drop directory
pnpm --dir "$W" install --frozen-lockfile
```

Collect what changed since the previous release, for the texts below:

```sh
PREV_COMMIT=<the previous release's commit>   # its "chore(release): qualor-rules <prev>" commit; for 2026.10.0, which has none, 95f5696
git log --format='%h %s%n  %b' "$PREV_COMMIT"..HEAD -- rules | grep -E '^[0-9a-f]{7}|Backlog:'
node -e "for (const r of require('./dist/manifest.json').rules) console.log(r.id, r.kind, r.severity, r.title)"
```

Edit, in the worktree:

- `tools/analyzers/install.sh`: `QUALOR_RULES_VERSION=<V>` and `QUALOR_RULES_SHA256=<sha256>`.
  Leave `QUALOR_RULES_URL=` empty.
- `tools/ci.test.ts`: add `'<V>': '<opengrep>'` to `PACK_OPENGREP` (keep the older entries; the
  test needs an entry for every pinned version). If the pack's `opengrep` differs from
  `install.sh`'s `OPENGREP_VERSION`, stop: an OpenGrep upgrade is a toolchain change in qualor-cc
  (new checksums for both architectures) and needs the maintainer's word.
- **Every text that describes the rules.** Find them first:
  `git -C "$W" grep -n "qualor-rules\|Qualor's .*security rules\|own security rules" -- docs/guide deploy README.md CHANGELOG.md`.
  Then make each one true for the new pack:
  - `docs/guide/languages-and-analyzers.md`, section "Security rules (Qualor)": the table gets one
    row per new rule and updated rows for changed rules (`qualor:<lang>/<name>` and what it finds,
    with the frameworks, in the style of the existing rows); the intro says what the rules find
    by kind once the pack has more than taint rules (taint rules follow request data to a
    dangerous call; misuse rules report unsafe settings such as disabled TLS verification;
    hotspots point at code to review); the bullet on the quality gate says that issues count in
    the gate and hotspots never do; the example version `1.30.0 + qualor-rules <V>`.
  - `docs/guide/README.md` and `README.md`: the one-line description of the rules, if the new
    categories make it untrue.
  - `deploy/dockerhub/scanner.md`: the qualor-rules version in the bullet on Qualor's security
    rules (`tools/deploy/dockerhub.test.ts` requires `QUALOR_RULES_VERSION` there); say
    "qualor-rules `<V>`", not "the first release".
  - `CHANGELOG.md`, `[Unreleased]`: the security-rules bullet lists the new rule categories per
    language and the changed rules (new frameworks, fixed false positives), and says which are
    hotspots.
  - Keep the licence wording exactly as it is (PolyForm Shield, source-available).
- Format and lint what you changed:
  `npx prettier --check <changed files>` (fix with `--write`) and `npx eslint tools/ci.test.ts`.

## 5. Images and tests

```sh
V=<version>; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V; cd "$W"
docker build -f deploy/scanner/Dockerfile --build-arg QUALOR_RULES_REQUIRED=1 -t qualor/scanner:rules-$V .
docker build -t qualor-analyzers:rules-$V tools/analyzers
docker build -f deploy/scanner-dotnet/Dockerfile --build-arg SCANNER_IMAGE=qualor/scanner:rules-$V -t qualor/scanner-dotnet:rules-$V .
npx vitest run --project unit tools/ci.test.ts tools/deploy cli/src/analyzers/qualor.test.ts
```

Each build log must say "installed the Qualor rules pack <V>". Then the real-tool tests and
fixtures in the toolbox, on a copy of the worktree in a volume:

```sh
V=<version>; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
docker volume create qr-cc-$V
MSYS_NO_PATHCONV=1 docker run --rm --name qr-cc-copy -v "$(cygpath -w "$W")":/src:ro -v qr-cc-$V:/w \
  --entrypoint sh qualor-analyzers:rules-$V -c 'tar -C /src --exclude=./node_modules --exclude="*/node_modules" --exclude=./.git -cf - . | tar -C /w -xf -'
MSYS_NO_PATHCONV=1 docker run --rm --name qr-cc-test -v qr-cc-$V:/w --entrypoint sh qualor-analyzers:rules-$V -c \
  'cd /w && pnpm install --frozen-lockfile >/dev/null && QUALOR_REQUIRE_ANALYZERS=1 npx vitest run --project unit cli/src/analyzers/qualor-real.test.ts cli/src/analyzers/qualor.test.ts tools/fixtures && QUALOR_REQUIRE_ANALYZERS=1 pnpm fixtures'
docker volume rm qr-cc-$V
```

(If you run `tools/ci.test.ts` or `tools/deploy/dockerhub.test.ts` in the volume, "never commits a
pack" and "placeholder image names" fail there because the copy has no `.git` and a pnpm store;
they must pass on the host.)

- **Expected values that change legitimately:** a new rule may report on a fixture
  (`fixtures/qualor-security` and the other `*-basic`/`*-security` fixtures) or change the finding
  keys `qualor-real.test.ts` expects. For each new `qualor` finding, open the line: a true finding
  in a fixture that is vulnerable on purpose goes into its `expected.json` (or the test's
  expectation); a false one is a rule defect: stop, go back to `/write-rules` (a maintenance row),
  and do not pin this pack.
- **Dogfood:** step 1's probe already showed 0 findings on qualor-cc main; nothing else to run.

## 6. Commit and stop

```sh
V=<version>; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
git -C "$W" status --porcelain                                          # only the files you changed
git -C "$W" add tools/analyzers/install.sh tools/ci.test.ts deploy/dockerhub/scanner.md docs/guide/languages-and-analyzers.md CHANGELOG.md <other changed texts, expected.json, tests>
git -C "$W" commit -s -m "build(scanner): pin qualor-rules $V" -m "<new and changed rules; guide, changelog and Docker Hub text>"
```

Report to the maintainer and wait:

```text
qualor-rules <V>: <n> rules (<i> issues, <h> hotspots; <k> new, <c> changed since <previous>), sha256 <sha>, OpenGrep <x>.
Reproducible: host twice + Linux, identical.
Measured: MEASUREMENTS.md <date> (rules <sha>): Benchmark <covered categories TPR/FPR>; §8.4 <met | not met: ...>.
qualor-cc: branch rules-pack-<V> in <W>, commit <sha>; images qualor/scanner:rules-<V>, qualor-analyzers:rules-<V>, qualor/scanner-dotnet:rules-<V>.
Texts: guide section, README lines, Docker Hub, CHANGELOG updated.
Tests: <host and toolbox results>; fixtures <changed expectations, or none>.
Waiting for your word to fast-forward qualor-cc main to <sha>. Publishing (tag v<V>, QUALOR_RULES_URL) stays with you.
```

On the maintainer's word only: `git -C E:/Personal/qualor/qualor-cc merge --ff-only rules-pack-<V>`
if the main tree is on `main` (otherwise hand them the command), then
`git -C E:/Personal/qualor/qualor-cc worktree remove E:/Personal/qualor/worktrees/qualor-cc-rules-<V>`
and `git -C E:/Personal/qualor/qualor-cc branch -d rules-pack-<V>`.
