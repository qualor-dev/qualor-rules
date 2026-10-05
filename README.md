# Qualor security rules

The security rules of [Qualor](https://qualor.dev)'s `qualor` engine: [OpenGrep](https://github.com/opengrep/opengrep)
rules, mostly taint rules, that follow data from an HTTP request to a dangerous call in JavaScript
and TypeScript, Python, Java and Go. Once the pack is published, the `qualor/scanner` image will
run them on every scan.

## Licence

**Source-available, not open source.** The rules are licensed under the PolyForm Shield License
1.0.0 ([`LICENSE`](LICENSE)). This section summarises it in plain words; the licence text
decides.

- You may use, change and share the rules for any purpose, free of charge and in any Qualor
  edition, except providing a product that competes with Qualor or with the rules themselves.
- If you pass them on, pass on the licence terms too.

Required Notice: Copyright 2026 The Qualor project (https://qualor.dev)

## Layout

- `rules/<lang>/<category>/<name>.yml`: one OpenGrep rule per file. `<lang>` is `js` (JavaScript
  and TypeScript, `languages: [javascript, typescript]`), `python`, `java` or `go`.
- The rule's `id` is `<lang>.<name>` (OpenGrep allows no `/` in an id). Qualor reports it as
  `qualor:<lang>/<name>`, for example `qualor:java/sql-injection`.
- Next to each rule, its test file `<name>.<ext>` with `ruleid: <id>` and `ok: <id>` comments on
  the line before each expected (or forbidden) finding, for `opengrep scan --test`.
- `metadata` (checked against [`schema/rule-metadata.json`](schema/rule-metadata.json)): `title`,
  `cwe`, `owasp`, `kind` (`issue` for taint and definite misuse, `hotspot` for "review this"),
  `severity`, `confidence`, `frameworks`, `sources` (the documents the rule was written from; see
  [`CLEAN-ROOM.md`](CLEAN-ROOM.md)) and `since` (the pack version that added it).

## Checks

```sh
npm ci --ignore-scripts
npm test          # check (layout, schema, ids, annotations, sources), the tools' tests, opengrep --test
```

`npm run test:rules` needs OpenGrep of exactly the version `package.json` names (`"opengrep"`) on
`PATH`, or its path in `OPENGREP`; `tools/install-opengrep.sh` installs it (Linux x86-64).

## Releases

Versions are `YYYY.M.patch` (the first is `2026.10.0`). `npm run release` writes
`dist/qualor-rules-<version>.tar.gz`, its `.sha256` and `dist/manifest.json`, and prints the
SHA-256. The tarball holds `manifest.json`
(`{ version, opengrep, rules: [{ id, path, sha256, languages, kind, severity, cwe, title }] }`),
`LICENSE`, `NOTICE` and the rule YAML (no tests), and is byte for byte the same from the same
commit on any machine with the same Node.js major version (the gzip stream comes from Node's
zlib). Qualor's scanner pins that SHA-256.

## Writing a rule

Read [`CLEAN-ROOM.md`](CLEAN-ROOM.md) first. It is binding.

The rules still to write are queued in [`BACKLOG.md`](BACKLOG.md); [`COVERAGE.md`](COVERAGE.md)
says how the queue grows, [`REFERENCE.md`](REFERENCE.md) lists the projects every rule is
measured on, [`MEASUREMENTS.md`](MEASUREMENTS.md) holds the recall scores, and [`LOG.md`](LOG.md)
records each run. [`AGENTS.md`](AGENTS.md) describes the workflow.
