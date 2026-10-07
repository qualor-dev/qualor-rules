# AGENTS.md: rules for AI agents working on qualor-rules

## Commands

- `npm ci --ignore-scripts`: install the two dev dependencies (ajv, yaml)
- `npm test`: `npm run check` (rules, `BACKLOG.md`, `REFERENCE.md`, the rule pages), the tools' own
  tests, `opengrep scan --test`, the pages' examples and the prefilter check (these three need the
  pinned OpenGrep)
- `npm run test:prefilter [-- <rule.yml|dir>...] [--table]`: every rule's OpenGrep prefilter
  (`tools/prefilter.mjs`, anchors expanded) must be Some, at most 20 kB and build within 400 ms
  (best of 3, scaled on a busy host); its `ALLOWED` list exempts a rule from one limit while its
  `BACKLOG.md` row is open and fails once the rule no longer needs it. `--table` prints the numbers
- `npm run docs`: the rule pages `docs/rules/<lang>/<name>.md` and their index, from the rules
  (hand-written sections are kept)
- `npm run test:docker`: the same inside the `qualor/scanner` image (`QUALOR_SCANNER_IMAGE`), for
  hosts without OpenGrep
- `npm run probe -- <rule>`: the rule on the `REFERENCE.md` projects and qualor-cc;
  `npm run scan -- <rule> -- <files>`: the rule on files of this tree
- `npm run measure -- [lang]...`: the rules on the recall sets (OWASP Benchmark scored per
  category) into `MEASUREMENTS.md`; `npm run measure -- --check` tells whether it is current
- `npm run release`: the release tarball in `dist/`, and its SHA-256

## How work is organised

- `BACKLOG.md`: the ordered queue of rules (`todo`, `in-progress`, `done`, `blocked`).
- `COVERAGE.md`: the map the queue is extended from (categories × languages × frameworks, priority
  rules, kind and severity, allowed sources).
- `REFERENCE.md`: the pinned projects every rule is probed on; qualor-cc must stay at zero findings.
- `MEASUREMENTS.md`: recall scores per run (design spec §8.4); a pack is pinned only with a current one.
- `LOG.md`: one entry per run, newest first, including a run in progress; read the newest three
  before starting.
- `/write-rules [N] [language]` (`.claude/skills/write-rules/`): takes the next N rows and writes,
  reviews, merges and logs them. `/release-pack` (`.claude/skills/release-pack/`): builds a pack
  release and pins it in qualor-cc, only when the maintainer asks.
- Tooling follow-ups (a check, a mutation sweep, a generator) are not `BACKLOG.md` rows, whose ids
  are rule ids: they are listed in COVERAGE.md "Growing the map" and in the LOG entries' Notes.
  Open ones: a per-alternative mutation sweep tool,
  `--timeout 0` in the probe and measure tools, generators for the JS, Java and Python source
  blocks.

## Rules

1. Clean room: read and follow `CLEAN-ROOM.md` before writing or changing any rule. Never open the
   rule sets it lists.
2. Test file first, then the rule. Every rule has at least one `ruleid:` and one `ok:` line.
3. One rule per file at `rules/<lang>/<category>/<name>.yml`, id `<lang>.<name>`; metadata must
   pass `schema/rule-metadata.json`; `sources` names what you read.
4. The licence is PolyForm Shield 1.0.0 (source-available). Never call the rules "open source".
   Never edit `LICENSE`.
5. Every rule has its public page, `docs/rules/<lang>/<name>.md`, written in the same commit as
   the rule (`npm run docs`, then the hand-written sections; rule-procedure.md step 7). Qualor links
   findings to these paths: never rename or move a page without its rule.
6. Commits: `git commit -s`, conventional messages, stage by path. No attribution trailers.
7. Never push, tag a release or publish anything without the maintainer's word. `origin` is the
   public GitHub repository qualor-dev/qualor-rules; add no other remote.
