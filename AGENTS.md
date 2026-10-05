# AGENTS.md: rules for AI agents working on qualor-rules

## Commands

- `npm ci --ignore-scripts`: install the two dev dependencies (ajv, yaml)
- `npm test`: `npm run check` (rules, `BACKLOG.md`, `REFERENCE.md`), the tools' own tests, and
  `opengrep scan --test` (needs the pinned OpenGrep)
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

## Rules

1. Clean room: read and follow `CLEAN-ROOM.md` before writing or changing any rule. Never open the
   rule sets it lists.
2. Test file first, then the rule. Every rule has at least one `ruleid:` and one `ok:` line.
3. One rule per file at `rules/<lang>/<category>/<name>.yml`, id `<lang>.<name>`; metadata must
   pass `schema/rule-metadata.json`; `sources` names what you read.
4. The licence is PolyForm Shield 1.0.0 (source-available). Never call the rules "open source".
   Never edit `LICENSE`.
5. Commits: `git commit -s`, conventional messages, stage by path. No attribution trailers.
6. Never push, tag a release or publish anything without the maintainer's word.
