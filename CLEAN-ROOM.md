# Clean-room process

Every rule here is our own work. This process is binding for people and for AI agents.

## Never open

- `semgrep-rules`, `opengrep-rules` and the semgrep.dev registry;
- CodeQL queries;
- SonarSource rule descriptions;
- any other vendor's or project's rule set.

Not to compare, not to check coverage, not "just the list". If you saw one by accident, say so in
the pull request and do not write a rule for that topic yourself.

## Allowed sources

- CWE (cwe.mitre.org);
- OWASP: the Top 10, the Cheat Sheet Series, ASVS;
- the official documentation of frameworks, drivers and standard libraries (which APIs read
  untrusted input, which are dangerous sinks, which make data safe);
- our own fixtures.

## Order of work

1. Write the test file first: vulnerable and safe code, taken from the framework's documentation,
   with `ruleid:` and `ok:` comments. Include the safe forms that apply: a parameterised call, a
   constant, the framework's sanitiser, an allow-list check.
2. Then write the rule until `opengrep scan --test` passes.
3. Put the URLs you used into `metadata.sources`. `npm run check` refuses URLs of the sets above.

## Residual risk

The rules may be written by AI agents whose training data may include public rule sets. This
process and the source records reduce that risk; only a third party could compare the rules with
those sets, since we may not open them.
