# Security policy

## Reporting a vulnerability

Email **security@qualor.dev**, or use GitHub's private vulnerability reporting
(**Security → Report a vulnerability**). Please do not open a public issue or pull request for a
vulnerability.

Include what you found, the affected pack version or commit, how to reproduce it, and what an
attacker gains.

What to expect:

- an acknowledgement within **3 working days**;
- an assessment within **10 working days**;
- a fix and a coordinated disclosure within **90 days** of the report, sooner when the fix is
  ready, with credit to you unless you prefer otherwise.

## Scope

This repository's tooling and the published `qualor-rules-<version>.tar.gz` packs (for example a
pack that differs from its `manifest.json` checksum, or a rule that makes OpenGrep read or run
something outside the scanned code). A rule that misses a vulnerability or reports a false
positive is not a security issue: open an ordinary issue for it. Vulnerabilities in Qualor itself
go to [qualor-dev/qualor](https://github.com/qualor-dev/qualor/security/policy).
