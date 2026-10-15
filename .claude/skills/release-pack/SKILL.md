---
name: release-pack
description: Use only when the maintainer explicitly asks to release the qualor-rules pack (/release-pack) or to pin a new pack version in qualor-cc's scanner image.
argument-hint: "[version]"
disable-model-invocation: true
---

# Release the rules pack

Builds a new `qualor-rules-<version>.tar.gz` here and **stops for the maintainer's tag**: the tag
`v<version>` is what publishes the pack (`.github/workflows/ci.yml`, built twice with the pinned
.NET SDK), and only the maintainer creates it. Then it pins the published pack (its tarball and
sha256 from the GitHub release) in qualor-cc on a new branch in its own worktree, with the guide,
the Docker Hub text and the changelog brought up to date, and **stops again** before anything is
merged into qualor-cc's `main`. Nothing is pushed, tagged or published by the agent.

Background on the qualor-cc side (read when a step fails): qualor-cc
`.superpowers/sdd/2026-10-03-phase-6b-1-qualor-engine/task-5-report.md` (pins, drop directory,
images), `task-7-report.md` (fixture, real-tool tests) and `task-11-report.md` (full verification).

## Hard rules

- Run only when the maintainer asked for it in this conversation.
- Never push and never tag: the tag `v<version>` publishes the pack, and only the maintainer
  creates it (or tells you to). qualor-cc's `QUALOR_RULES_URL` stays as it is (set since 2026.10.1).
- Never merge into qualor-cc `main`, never switch the branch of qualor-cc's main tree (other
  sessions use it): work in the new worktree only.
- **No pin without a current measurement:** `npm run measure -- --check` must pass (the newest
  `MEASUREMENTS.md` entry covers all five languages at the last commit that changed `rules/`).
- `git commit -s`, conventional messages, stage by path, no attribution trailers, in both
  repositories.
- Docker: containers `qr-*` with `--rm`, volumes `qr-*` removed afterwards; never prune, never
  remove images you did not build.
- The tarball is never committed (`dist/` here, the drop directory there are git-ignored).
- **Shell blocks:** every Bash call starts a fresh shell; each block below sets its variables
  first. Fill in the values; never rely on a variable from an earlier call.

## 1. Preconditions (qualor-rules, main tree)

```sh
git status --porcelain && git branch --show-current && git remote -v   # clean, main, origin = qualor-dev/qualor-rules
grep -c '| in-progress |' BACKLOG.md                                    # must be 0
export QUALOR_SCANNER_IMAGE=qualor/scanner:rules-<previous V>           # a local scanner whose opengrep --version prints package.json's "opengrep"
npm run test:docker                                                     # green
npm run test:engine                                                     # green: the C# engine's tests are not part of npm test
npm run probe -- rules                                                  # qualor-cc 0; review new findings
npm run measure -- --check || npm run measure                           # then commit MEASUREMENTS.md if it changed
```

`QUALOR_SCANNER_IMAGE`: without it the tools use `tools/scanner.mjs`'s default, an old local dev
tag. Check the image first (`docker run --rm --entrypoint opengrep <image> --version`). Each
Bash call is a fresh shell: set the variable in every block that runs `test:docker`, `probe` or
`measure`. `npm run test:engine` needs the .NET SDK on the host; when Windows Application Control
blocks the freshly built test DLLs, run it in a local `qualor/scanner-dotnet` image.

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
tar -tvzf "dist/qualor-rules-$V.tar.gz"                                  # LICENSE, NOTICE, manifest.json, rules/**.yml, dotnet/engine/** (+ licenses/), dotnet/models/csharp/*.yml
npm run measure -- --check                                              # still current
```

`npm run release` builds the C# engine first (`npm run build:engine`, needs the .NET SDK): the tarball carries
`dotnet/engine/` and `dotnet/models/csharp/` and the manifest's `dotnetEngine` lists each file's SHA-256. Check that
the tarball holds a licence text for every third-party DLL (`dotnet/engine/licenses/`) and no `*.pdb`.

**Which SDK decides the bytes.** The engine's DLLs depend on the SDK that compiles them. `engine/dotnet/global.json`
pins 8.0.425 with `latestMajor`, so the host (SDK 10) builds too, but its Qualor DLLs differ from CI's, which installs
exactly 8.0.425. So the host double build above is only a smoke test (it proves host determinism, nothing more), and
the host sha256 is never the pin. The local reproducibility check builds twice with the pinned SDK on Linux, in the
`qualor/scanner-dotnet` image (it has 8.0.425 next to 10; the command makes the pin exact) and compares:

```sh
SDK=$(node -p "require('./engine/dotnet/global.json').sdk.version")   # the pinned SDK
MSYS_NO_PATHCONV=1 docker run --rm --name qr-release -e HOME=/tmp -e SDK="$SDK" -v "$(cygpath -w "$PWD")":/src:ro \
  --entrypoint sh qualor/scanner-dotnet:0.7.1 -c 'mkdir /tmp/r && cd /src \
    && tar --exclude=./node_modules --exclude=./.tmp --exclude=./.git --exclude=./dist --exclude=bin --exclude=obj --exclude=./engine/dotnet/publish -cf - . | tar -C /tmp/r -xf - \
    && cd /tmp/r && sed -i "s/latestMajor/disable/" engine/dotnet/global.json \
    && test "$(cd engine/dotnet && dotnet --version)" = "$SDK" \
    && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 \
    && npm run release && cp dist/qualor-rules-*.tar.gz /tmp/first.tgz \
    && npm run release && cmp /tmp/first.tgz dist/qualor-rules-*.tar.gz && sha256sum dist/qualor-rules-*.tar.gz && echo IDENTICAL'
```

The image must have that SDK (`qualor/scanner-dotnet:0.7.1` has 8.0.425 next to 10); when
`global.json` moves to another SDK, use an image that has it.

The sha256 to pin in qualor-cc is always the one of the tag's CI release build (the release job installs exactly the
pinned SDK, builds twice and compares), so the tag is published first (step 4) and the pin and the tarball are taken
from the GitHub release. The Linux sha256 above should equal it; the host's does not have to, and the host tarball is
never copied into qualor-cc.

Add a release entry at the top of `LOG.md` (version, SHA-256, rule count by kind, the ids added
or changed since the previous release, the OpenGrep version, the `MEASUREMENTS.md` entry it was
measured in with its Benchmark headline), then `npm run check` and
`git commit -s -m "docs: log the qualor-rules $V release" -- LOG.md`.

## 4. Publish (the maintainer), then fetch the release

Stop and report: the version, the host smoke sha256, the Linux pinned-SDK sha256 and the LOG
entry. The maintainer pushes `main` and creates the tag (`git push origin main`, `git tag v<V>`,
`git push origin v<V>`); CI's release job builds twice with the pinned SDK and publishes the
GitHub release. Once it is published, fetch its tarball and checksum (read-only):

```sh
V=<version>; D=.tmp/release-$V; mkdir -p "$D"
curl -fsSL -o "$D/qualor-rules-$V.tar.gz" "https://github.com/qualor-dev/qualor-rules/releases/download/v$V/qualor-rules-$V.tar.gz"
curl -fsSL -o "$D/qualor-rules-$V.tar.gz.sha256" "https://github.com/qualor-dev/qualor-rules/releases/download/v$V/qualor-rules-$V.tar.gz.sha256"
(cd "$D" && sha256sum -c "qualor-rules-$V.tar.gz.sha256")              # OK
cat "$D/qualor-rules-$V.tar.gz.sha256"                                  # the pin; it should equal step 3's Linux sha256
```

A difference from the Linux build is a reproducibility question for the maintainer, not a reason
to pin another sha256.

## 5. Pin it in qualor-cc (new worktree)

```sh
V=<version>; CC=E:/Personal/qualor/qualor-cc; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
git -C "$CC" worktree add -b rules-pack-$V "$W" main
rm -f "$W"/tools/analyzers/qualor-rules/*.tar.gz                        # no local build stays in the drop directory
cp ".tmp/release-$V/qualor-rules-$V.tar.gz" "$W/tools/analyzers/qualor-rules/"   # the published tarball (git-ignored drop directory)
pnpm --dir "$W" install --frozen-lockfile
```

Collect what changed since the previous release, for the texts below:

```sh
PREV_COMMIT=<the previous release's commit>   # its "chore(release): qualor-rules <prev>" commit; for 2026.10.0, which has none, 95f5696
git log --format='%h %s%n  %b' "$PREV_COMMIT"..HEAD -- rules | grep -E '^[0-9a-f]{7}|Backlog:'
node -e "for (const r of require('./dist/manifest.json').rules) console.log(r.id, r.kind, r.severity, r.title)"
```

Edit, in the worktree:

- `tools/analyzers/install.sh`: `QUALOR_RULES_VERSION=<V>` and `QUALOR_RULES_SHA256=<the GitHub
  release's sha256 from step 4>`. Leave `QUALOR_RULES_URL` as it is; CI downloads the pinned
  version from it.
- OpenGrep: nothing to add in `tools/ci.test.ts` (it reads the pins from install.sh, and the
  installer compares the manifest's `opengrep` with `OPENGREP_VERSION`). If the pack's `opengrep`
  differs from `install.sh`'s `OPENGREP_VERSION`, stop: an OpenGrep upgrade is a toolchain change
  in qualor-cc (new checksums for both architectures) and needs the maintainer's word.
- `tools/fixtures/known-pending.json`: remove an entry that waits for this pack (the first pack
  with the C# engine: `qualor-security-dotnet`; with none left the file is `{}`). `pnpm fixtures`
  fails on an entry whose fixture now passes.
- **Every text that describes the rules.** Find them first:
  `git -C "$W" grep -n "qualor-rules\|Qualor's .*security rules\|own security rules" -- docs/guide deploy README.md CHANGELOG.md`.
  Then make each one true for the new pack:
  - `docs/guide/languages-and-analyzers.md`, section "Security rules (Qualor)": the table gets one
    row per new rule and updated rows for changed rules (`qualor:<lang>/<name>` and what it finds,
    with the frameworks, in the style of the existing rows); the intro says what the rules find
    by kind once the pack has more than taint rules (taint rules follow request data to a
    dangerous call; misuse rules report unsafe settings such as disabled TLS verification;
    hotspots point at code to review); the bullet on the quality gate says that issues count in
    the gate and hotspots never do; the example versions `1.30.0 + qualor-rules <V>` and
    `qualor-taint <V> + qualor-rules <V>` (C# analysed by the Roslyn engine).
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
  `npx prettier --check <changed files>` (fix with `--write`) and `npx eslint <changed .ts files>`
  (usually none).

## 6. Images and tests

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

The C# engine end to end, in the dotnet image, on another copy (the engine's real test builds
`fixtures/csharp-basic` and `fixtures/qualor-security-dotnet`):

```sh
V=<version>; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
docker volume create qr-ccd-$V
MSYS_NO_PATHCONV=1 docker run --rm --name qr-ccd-copy -v "$(cygpath -w "$W")":/src:ro -v qr-ccd-$V:/w \
  --entrypoint sh qualor/scanner-dotnet:rules-$V -c 'tar -C /src --exclude=./node_modules --exclude="*/node_modules" --exclude=./.git -cf - . | tar -C /w -xf -'
MSYS_NO_PATHCONV=1 docker run --rm --name qr-ccd-test -v qr-ccd-$V:/w --entrypoint sh qualor/scanner-dotnet:rules-$V -c \
  'cd /w && pnpm install --frozen-lockfile >/dev/null && cd cli && QUALOR_REQUIRE_ANALYZERS=1 pnpm exec vitest run src/dotnet/real.test.ts'
docker volume rm qr-ccd-$V
```

Its engine tests must run, not skip (a skip names a pack without a valid `dotnetEngine`), and
`fixtures/csharp-basic` must still give exactly its one CA5351 finding (no C# rule matches it).

- **Expected values that change legitimately:** a new rule may report on a fixture
  (`fixtures/qualor-security` and the other `*-basic`/`*-security` fixtures) or change the finding
  keys `qualor-real.test.ts` expects. For each new `qualor` finding, open the line: a true finding
  in a fixture that is vulnerable on purpose goes into its `expected.json` (or the test's
  expectation); a false one is a rule defect: stop, go back to `/write-rules` (a maintenance row),
  and do not pin this pack.
- **Dogfood:** step 1's probe already showed 0 findings on qualor-cc main; nothing else to run.

## 7. Commit and stop

```sh
V=<version>; W=E:/Personal/qualor/worktrees/qualor-cc-rules-$V
git -C "$W" status --porcelain                                          # only the files you changed
git -C "$W" add tools/analyzers/install.sh deploy/dockerhub/scanner.md docs/guide/languages-and-analyzers.md CHANGELOG.md <tools/fixtures/known-pending.json, other changed texts, expected.json, tests>
git -C "$W" commit -s -m "build(scanner): pin qualor-rules $V" -m "<new and changed rules; guide, changelog and Docker Hub text>"
```

Report to the maintainer and wait:

```text
qualor-rules <V>: <n> rules (<i> issues, <h> hotspots; <k> new, <c> changed since <previous>), sha256 <sha>, OpenGrep <x>.
Reproducible: host twice (smoke) and the SDK of engine/dotnet/global.json on Linux twice, identical; pin = the GitHub release's sha256 (equal to the Linux build: yes | no).
Measured: MEASUREMENTS.md <date> (rules <sha>): Benchmark <covered categories TPR/FPR>; §8.4 <met | not met: ...>.
qualor-cc: branch rules-pack-<V> in <W>, commit <sha>; images qualor/scanner:rules-<V>, qualor-analyzers:rules-<V>, qualor/scanner-dotnet:rules-<V>.
Texts: guide section, README lines, Docker Hub, CHANGELOG updated.
Tests: <host, toolbox and dotnet-image results>; fixtures <changed expectations, removed known-pending entries, or none>.
Waiting for your word to fast-forward qualor-cc main to <sha>. The pack is published (tag v<V>), so qualor-cc's CI can download it.
```

On the maintainer's word only: `git -C E:/Personal/qualor/qualor-cc merge --ff-only rules-pack-<V>`
if the main tree is on `main` (otherwise hand them the command), then
`git -C E:/Personal/qualor/qualor-cc worktree remove E:/Personal/qualor/worktrees/qualor-cc-rules-<V>`
and `git -C E:/Personal/qualor/qualor-cc branch -d rules-pack-<V>`.
