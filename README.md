# Qualor security rules

The security rules of [Qualor](https://qualor.dev)'s `qualor` engine: [OpenGrep](https://github.com/opengrep/opengrep)
rules, mostly taint rules, that follow data from an HTTP request to a dangerous call in JavaScript
and TypeScript, Python, Java, Go and C#. The `qualor/scanner` image runs them on every scan; for C#
under `qualor dotnet end`, the pack's own Roslyn taint engine (`engine/dotnet`) runs the C# rules
across files and projects instead.

## Licence

**Source-available, not open source.** The rules, the C# engine's models and the C# engine's
source (`engine/dotnet`) are licensed under the PolyForm Shield License 1.0.0
([`LICENSE`](LICENSE)). This section summarises it in plain words; the licence text decides. The
pack's `dotnet/engine/` also holds third-party components under their own licences (MIT): see
[`NOTICE`](NOTICE).

- You may use, change and share the rules for any purpose, free of charge and in any Qualor
  edition, except providing a product that competes with Qualor or with the rules themselves.
- If you pass them on, pass on the licence terms too.

Required Notice: Copyright 2026 The Qualor project (https://qualor.dev)

## Rule documentation

Every rule has a page that says what it finds, why it matters and how to fix it, with an example
and the rule's known limits: see the [index of the rules](docs/rules/README.md). Qualor links each
finding to its rule's page, `docs/rules/<lang>/<name>.md`.

## Layout

- `rules/<lang>/<category>/<name>.yml`: one OpenGrep rule per file. `<lang>` is `js` (JavaScript
  and TypeScript, `languages: [javascript, typescript]`), `python`, `java`, `go` or `csharp` (C#, `languages: [csharp]`).
- The rule's `id` is `<lang>.<name>` (OpenGrep allows no `/` in an id). Qualor reports it as
  `qualor:<lang>/<name>`, for example `qualor:java/sql-injection`.
- Next to each rule, its test file `<name>.<ext>` with `ruleid: <id>` and `ok: <id>` comments on
  the line before each expected (or forbidden) finding, for `opengrep scan --test`.
- `metadata` (checked against [`schema/rule-metadata.json`](schema/rule-metadata.json)): `title`,
  `cwe`, `owasp`, `kind` (`issue` for taint and definite misuse, `hotspot` for "review this"),
  `severity`, `confidence`, `frameworks`, `sources` (the documents the rule was written from; see
  [`CLEAN-ROOM.md`](CLEAN-ROOM.md)) and `since` (the pack version that added it).
- `models/csharp/`: the models of the Roslyn taint engine (`engine/dotnet`) for the C# rules, one
  `<name>.yml` per rule `csharp.<name>` and the shared `sources.yml` and `propagators.yml`; the
  format is [`models/README.md`](models/README.md).
- `docs/rules/<lang>/<name>.md`: the rule's public page. `npm run docs` builds its header,
  frameworks, references and test links from the rule's metadata, and the index
  `docs/rules/README.md`; the sections between `<!-- begin: ... -->` and `<!-- end: ... -->` are
  written by hand and kept.

## Checks

```sh
npm ci --ignore-scripts
npm test          # check (layout, schema, ids, annotations, sources, pages), the tools' tests,
                  # opengrep --test, and the pages' examples
```

`npm run test:rules` and `npm run test:examples` need OpenGrep of exactly the version
`package.json` names (`"opengrep"`) on `PATH`, or its path in `OPENGREP`;
`tools/install-opengrep.sh` installs it (Linux x86-64).

`package.json`'s `"taintIntrafile"` is the taint mode the rules are tested in: when true, every
tool that runs OpenGrep (the tests, the pages' examples, the probe, `measure`, `scan`) passes
`--taint-intrafile` (taint followed through the functions of one file), and the release's
manifest says so, so Qualor runs the pack the same way. `QUALOR_TAINT_INTRAFILE=1` or `0` runs
the tools in the other mode for a comparison (`tools/engine.mjs`); there the fixture lines that
depend on the mode (same-file helpers and wrappers) are expected to fail.

## Releases

Versions are `YYYY.M.patch` (the first is `2026.10.0`). `npm run release` writes
`dist/qualor-rules-<version>.tar.gz`, its `.sha256` and `dist/manifest.json`, and prints the
SHA-256. The tarball holds `manifest.json`
(`{ version, opengrep, taintIntrafile, rules: [{ id, path, sha256, languages, kind, severity, cwe, title }] }`),
`LICENSE`, `NOTICE` and the rule YAML (no tests), and is byte for byte the same from the same
commit on any machine with the same Node.js major version (the gzip stream comes from Node's
zlib). Qualor's scanner pins that SHA-256.

The tarball also carries the C# taint engine: `dotnet/engine/` (the published, framework-dependent
`Qualor.Taint.Cli`, no `*.pdb`, with the licence text of every third-party DLL and the
third-party notices its package carries, unchanged and pinned by SHA-256, in
`dotnet/engine/licenses/`) and the models in `dotnet/models/csharp/`. The manifest's
`dotnetEngine` (`{ version, entry, models, files: [{ path, sha256 }] }`) lists each of those
files; the older fields are unchanged. `npm run release` first runs `npm run build:engine`
(`dotnet publish` in `engine/dotnet`, restore locked to the committed `packages.lock.json`), so it
needs the .NET SDK of `engine/dotnet/global.json` (8.0.425; locally any newer SDK is accepted,
CI installs exactly that one and builds twice and compares the tarballs). A newer local SDK compiles different
bytes than CI's, so the sha256 Qualor pins is always the tag's CI build (a local check builds twice with
exactly the pinned SDK, see the release-pack skill). `npm run test:engine`
runs the engine's tests; it is not part of `npm test` (the Docker gate has no .NET), CI runs it
as its own step. Adding or upgrading an engine dependency means updating the lock files
(`dotnet restore` in `engine/dotnet`) and the licence texts and `NOTICE`.

## Writing a rule

Read [`CLEAN-ROOM.md`](CLEAN-ROOM.md) first. It is binding.

The rules still to write are queued in [`BACKLOG.md`](BACKLOG.md); [`COVERAGE.md`](COVERAGE.md)
says how the queue grows, [`REFERENCE.md`](REFERENCE.md) lists the projects every rule is
measured on, [`MEASUREMENTS.md`](MEASUREMENTS.md) holds the recall scores, and [`LOG.md`](LOG.md)
records each run. [`AGENTS.md`](AGENTS.md) describes the workflow.
