# Coverage map

What the rules should cover, and how to choose the next rows of `BACKLOG.md`. `/write-rules`
reads this file when fewer `todo` rows remain than it was asked to write.

## Extending the backlog

1. Collect the `candidate` cells of the matrix below (only the requested language's column, if
   the run names one).
2. Drop a candidate whose id is already in `BACKLOG.md`, whatever its status. A new framework or
   API for a category that already has a rule is a maintenance row `<lang>.<name>#<topic>` on that
   rule, never a second rule.
3. Apply the doc gate: open the official documentation (the allowed sources below) and confirm it
   describes the source (for taint rules), the dangerous API or setting, and the safe form. No
   such page: leave the cell `candidate`, add "(no docs found: <what is missing>)" to it, and go
   on. For a large extension (more than ten rows) you may give the doc gate of each language to
   one read-only subagent with this section and the language's candidate cells; it returns the
   rows it would add, with the doc URLs that passed the gate, and you write them.
4. Rank what is left with the priority rules, take as many as the run needs plus five, and append
   them below the last `todo` row in rank order. Maintenance rows go above the first `todo` rule
   row instead. A row takes the cell's id, `dir` (the category directory) and kind as they stand.
5. In the matrix, replace each `candidate` you used by the new id.
6. `npm run check`, then commit `BACKLOG.md` and `COVERAGE.md` alone:
   `git commit -s -m "docs(backlog): add <k> rows from COVERAGE.md"`.

When no candidate passes the gate, stop and ask the maintainer which category or framework to add
next ("Growing the map" below); do not invent rows outside the map.

## Priority rules

Apply them in this order; a later rule only breaks ties of the earlier ones.

1. **Known defects first.** Maintenance rows on shipped rules (a false-positive shape, a missed
   source of an in-scope framework, a limit to record) come before new rules.
2. **Taint before misuse before hotspots.** Taint `issue` rules, then definite-misuse `issue`
   rules, then `hotspot` rules.
3. **Weight of the weakness.** Prefer categories high in the current CWE Top 25
   (https://cwe.mitre.org/top25/) and in the current OWASP Top 10 (https://owasp.org/Top10/).
   Within taint rules: injection into an interpreter (code, command, SQL, NoSQL, template,
   expression language) before file and network access (path, archive, SSRF), before output
   (XSS, open redirect, headers), before the rest (XPath, LDAP, regex).
4. **Framework popularity.** Cover the in-scope frameworks of a language (below) in every rule
   before adding a framework. Within a language, the most used framework's shapes go into the
   fixture first.
5. **Balance the languages.** Among equals, take the language with the fewest `todo` + `done`
   rows.
6. **One rule per language, category and sink family**, named `<lang>.<category-ish-name>` like
   the rows already there (`js.path-traversal`, `java.zip-slip`). Never reuse an id.
7. **Docs or nothing.** A row exists only if official docs describe its sources, sinks and safe
   APIs (the doc gate above).

## The matrix

Cells hold the backlog id, `candidate: <id> — <API lead>` (the id the row would get), or `n/a` with
the reason. A cell with a rule id may also list maintenance candidates on that rule,
`candidate: <id>#<topic> — <lead>` (a framework or API to add; it becomes a maintenance row).
`dir` is the category directory under `rules/<lang>/`; `kind` applies to every cell of the row.
Hints in cells are leads for the doc gate, not facts.

| category | dir | CWE | kind | js | python | java | go |
|---|---|---|---|---|---|---|---|
| SQL injection | sql | CWE-89 | issue | js.sql-injection | python.sql-injection | java.sql-injection | go.sql-injection |
| NoSQL injection | nosql | CWE-943 | issue | js.nosql-injection | candidate: python.nosql-injection — pymongo filters and `$where` from request JSON | candidate: java.nosql-injection — Spring Data MongoDB `BasicQuery` from a JSON string | candidate: go.nosql-injection — mongo-go-driver filters decoded from request JSON |
| Command injection | command | CWE-78 | issue | js.command-injection | python.command-injection | java.command-injection | go.command-injection |
| Code injection | code | CWE-94, CWE-95 | issue | js.code-injection; candidate: js.code-injection#browser — setTimeout/setInterval with a string and DOM sources (`location`, `document.URL`) in browser code (browser code is out of scope: the maintainer's word first) | python.code-injection | candidate: java.code-injection — `javax.script` ScriptEngine.eval, GroovyShell.evaluate | n/a: no eval in the standard library |
| Template injection | template | CWE-1336, CWE-94 | issue | js.template-injection | python.template-injection; candidate: python.template-injection#mako — `mako.template.Template(x)`; candidate: python.template-injection#compile-expression — Jinja `Environment.compile_expression(x)` | java.template-injection; candidate: java.template-injection#spring-view-names — request data in a returned view name (Thymeleaf before 3.0.12; needs a view-resolver signal) | go.template-injection |
| Expression language injection | expression | CWE-917 | issue | n/a | n/a | java.expression-injection; candidate: java.expression-injection#jexl — Apache Commons JEXL `createExpression`/`createScript`, `JexlSandbox` as the safe form | n/a |
| Unsafe reflection | reflection | CWE-470 | issue | candidate: js.unsafe-require — `require(x)`, `import(x)` | candidate: python.unsafe-import — `importlib.import_module(x)`, `getattr(obj, x)` | candidate: java.unsafe-reflection — `Class.forName(x)` | n/a |
| Path traversal | path | CWE-22 | issue | js.path-traversal | python.path-traversal | java.path-traversal | go.path-traversal |
| Archive extraction (zip slip), taint from the entry name | archive | CWE-22 | issue | candidate: js.zip-slip — tar, adm-zip, unzipper entry paths (check each library's defaults) | n/a: zipfile sanitises names; tar is the hotspot row below | java.zip-slip; candidate: java.zip-slip#zipfs — paths of a zip `FileSystem` (`FileSystems.newFileSystem`, `Files.walk`) resolved under a destination | go.zip-slip |
| Archive extraction without a filter | archive | CWE-22 | hotspot | n/a | python.tar-extraction | n/a | n/a |
| SSRF | ssrf | CWE-918 | issue | js.ssrf | python.ssrf | java.ssrf | go.ssrf |
| XSS | xss | CWE-79 | issue | js.xss | python.xss | java.xss | go.xss |
| Raw HTML props (review) | xss | CWE-79 | hotspot | js.react-dangerous-html | n/a | n/a | n/a |
| Open redirect | redirect | CWE-601 | issue | js.open-redirect | python.open-redirect | java.open-redirect | go.open-redirect |
| Header injection, response splitting | header | CWE-113 | issue | candidate: js.header-injection — check whether Node's http rejects CR/LF in header values (n/a if so) | candidate: python.header-injection — check Werkzeug and Django (n/a if they reject newlines) | candidate: java.header-injection — servlet setHeader/addHeader, check the containers | candidate: go.header-injection — check net/http's header writing (n/a if it sanitises) |
| XXE (parser configuration) | xxe | CWE-611, CWE-776 | issue | candidate: js.xxe — libxmljs `parseXml(x, { noent: true })` | python.xxe | java.xxe | n/a: encoding/xml does not resolve external entities (confirm in the docs) |
| XXE: DTD loading or lifted parser limits (review) | xxe | CWE-611, CWE-776 | hotspot | n/a until js.xxe exists | python.xxe-dtd-options | n/a: java.xxe reports DTD-enabled parsers as an issue | n/a: encoding/xml has no DTD processing |
| XPath injection | xpath | CWE-643 | issue | candidate: js.xpath-injection — the xpath npm package | python.xpath-injection | java.xpath-injection; candidate: java.xpath-injection#dom4j-jdom — dom4j `selectNodes`/`selectSingleNode`/`valueOf`, `DocumentHelper.createXPath`; JDOM2 `XPathFactory.compile` (library scope: the maintainer's word) | n/a: no XPath in the standard library |
| LDAP injection | ldap | CWE-90 | issue | candidate: js.ldap-injection — ldapjs search filters | candidate: python.ldap-injection — ldap3 search filters, `escape_filter_chars` | java.ldap-injection; candidate: java.ldap-injection#dn — request data in a DN (search base, `lookup`, `bind`), `LdapNameBuilder` and DN encoding as sanitizers | candidate: go.ldap-injection — go-ldap search filters, `ldap.EscapeFilter` |
| Unsafe deserialization of request data | deserialization | CWE-502 | issue | candidate: js.unsafe-deserialization — check node-serialize-like libraries' docs | python.unsafe-deserialization | java.unsafe-deserialization | n/a: encoding/gob and encoding/json build data only (confirm) |
| Unsafe deserializer configuration | deserialization | CWE-502 | issue | candidate: js.unsafe-yaml-schema — js-yaml custom schemas with functions | candidate: python.unsafe-yaml-load — `yaml.load` with an unsafe Loader on any data | candidate: java.jackson-default-typing — Jackson `activateDefaultTyping`/`enableDefaultTyping`; SnakeYAML without SafeConstructor (version-dependent) | n/a |
| Prototype pollution | prototype | CWE-1321 | issue | js.prototype-pollution | n/a | n/a | n/a |
| Regex injection (ReDoS) | regex | CWE-1333, CWE-400 | issue | js.regex-injection | python.regex-injection; candidate: python.regex-injection#regex-module — the third-party `regex` module (re's API); candidate: python.regex-injection#django-lookups — Django ORM `__regex`/`__iregex` lookups with request data | java.regex-injection | n/a: the regexp package (RE2) runs in linear time |
| Log injection | log | CWE-117 | hotspot | candidate: js.log-injection — request data into `console.log` or a logger without encoding | candidate: python.log-injection — request data into `logging` calls | candidate: java.log-injection — request data into SLF4J/Log4j calls | candidate: go.log-injection — request data into `log`/`slog` calls |
| TLS verification disabled | tls | CWE-295 | issue | js.tls-verification-disabled | python.tls-verification-disabled | java.tls-verification-disabled | go.tls-verification-disabled |
| Weak cipher or mode | crypto | CWE-327 | issue | candidate: js.weak-cipher — `createCipheriv` with des, rc4 or ecb names | candidate: python.weak-cipher — cryptography's TripleDES/ECB, PyCryptodome DES/ARC4/MODE_ECB | java.weak-cipher; candidate: java.weak-cipher#bouncycastle — Bouncy Castle lightweight engines (`DESEngine`, `ECBBlockCipher`) | go.weak-cipher |
| Weak hash | crypto | CWE-328 | hotspot | candidate: js.weak-hash — `createHash('md5' / 'sha1')` | candidate: python.weak-hash — hashlib md5/sha1 without `usedforsecurity=False` | candidate: java.weak-hash — `MessageDigest.getInstance("MD5" / "SHA-1")` | go.weak-hash |
| Insecure randomness | random | CWE-330, CWE-338 | hotspot | candidate: js.insecure-random — `Math.random()` for tokens | candidate: python.insecure-random — `random` for tokens (docs point to `secrets`) | candidate: java.insecure-random — `java.util.Random` for tokens | candidate: go.insecure-random — `math/rand` for tokens |
| JWT signature not verified | jwt | CWE-347 | issue | candidate: js.jwt-unverified — jsonwebtoken `algorithms: ['none']`, `decode` for auth | candidate: python.jwt-unverified — PyJWT `options={"verify_signature": False}` | candidate: java.jwt-unverified — jjwt unsigned parsing | candidate: go.jwt-unverified — golang-jwt `ParseUnverified` |
| Insecure cookie flags | cookie | CWE-614, CWE-1004 | hotspot | js.insecure-cookie | candidate: python.insecure-cookie — `set_cookie` without secure/httponly, Django `SESSION_COOKIE_SECURE = False` | candidate: java.insecure-cookie — `new Cookie` without setSecure/setHttpOnly | go.insecure-cookie; candidate: go.insecure-cookie#gorilla-sessions — gorilla/sessions `Options{Secure, HttpOnly}`, `NewCookieStore` defaults; candidate: go.insecure-cookie#gin-sessions — gin-contrib/sessions `Options` |
| CORS: any origin with credentials | cors | CWE-942 | hotspot | candidate: js.cors-credentials — cors `origin: true` with `credentials: true` | candidate: python.cors-credentials — flask-cors, django-cors-headers allow-all with credentials | candidate: java.cors-credentials — Spring `allowedOriginPatterns("*")` with `allowCredentials(true)` | candidate: go.cors-credentials — rs/cors, gin-contrib/cors allow-all with credentials |
| CSRF protection disabled | csrf | CWE-352 | hotspot | n/a | candidate: python.csrf-disabled — Django `@csrf_exempt`, Flask-WTF CSRF off | candidate: java.csrf-disabled — Spring Security `csrf().disable()` | n/a |
| Debug mode on | debug | CWE-489, CWE-215 | hotspot | n/a | candidate: python.debug-enabled — Flask `app.run(debug=True)`, Django `DEBUG = True` | n/a | n/a |
| Hard-coded secrets | — | CWE-798 | — | n/a: Gitleaks covers it in Qualor | n/a: Gitleaks | n/a: Gitleaks | n/a: Gitleaks |

## Frameworks in scope (design spec §7)

| lang | frameworks | where the source block lives |
|---|---|---|
| js | Node `http`, Express 4 and 5, Next.js API routes (pages router `(req, res)` and App Router route handlers), Fastify | `rules/js/sql/sql-injection.yml`: Express-style handlers `(req, res, ...)`, Next.js App Router route handlers, Fastify routes, and handlers that destructure the request. |
| python | Django, Flask, FastAPI | `rules/python/sql/sql-injection.yml`: `flask.request.*`, the parameters of route-decorated views (which also matches FastAPI path operations), and Django views in a module that imports Django. |
| java | Servlet (javax and jakarta), Spring MVC, Jakarta REST (JAX-RS) | `rules/java/sql/sql-injection.yml`: servlet request getters, annotated controller parameters except scalar types (`@RequestPart` included), and `HttpEntity`/`RequestEntity` bodies. |
| go | `net/http`, Gin, Echo (also chi and gorilla/mux route variables) | `rules/go/sql/sql-injection.yml`: request fields and methods, Gin/Echo getters, binders (by side effect, also inside a condition) and the encoding/json propagators. The test-support skip lives in `rules/go/path/path-traversal.yml`. |

### Source blocks

OpenGrep has no includes, so every taint rule of a language carries its own copy of the
language's request sources.

- A new taint (request) rule starts from a verbatim copy of the `pattern-sources` (and the
  request propagators) of its language's SQL rule, then adds what the category needs. A taint rule
  with another source (zip slip: the archive entry name) does not copy the request block.
- Implementers propose source-block changes in their reports; only the controller edits this
  file. When a rule's source block gains a framework or a missed source (a maintenance row), the
  controller adds a maintenance row `<lang>.<rule>#<topic>` for every other `done` taint
  (request) rule of that language whose block does not match yet, so the copies stay the same.
- Sources are request objects of real handlers only: never "any parameter of any function".
  Path parameters, query strings, form fields, headers, cookies and JSON bodies bound through the
  framework's decoder or binder all belong in the block.
- Not in scope yet: Koa, NestJS (`@Param`/`@Query`/`@Body`), Hapi; aiohttp, Tornado, Starlette
  without FastAPI; Quarkus-specific APIs beyond the Jakarta REST annotations, Micronaut, Spring WebFlux; Fiber, Beego. Each is a framework to add.
- The shared items (sources, request propagators, shared sanitizers) must stay **byte-identical**
  in every rule that carries them. Compare them with a script after every change to the block,
  and run the per-alternative mutation sweep (rule-procedure.md step 4) on each rule. Items that
  belong to one rule only follow the shared ones (Python marks the end with the comment
  `# (End of the shared Python source block; the items below are this rule's own.)`).

What each language's block holds today (2026-10-06 run):

- **js** (11 rules: sql, nosql, command, path, ssrf, xss, open-redirect, code, template,
  prototype-pollution, regex). Express-style handlers, Next.js pages and App Router handlers,
  Fastify routes, and handlers that **destructure** the request, in the parameter list (shorthand,
  renamed, nested, typed; Fastify and Next.js forms too) or in a declaration
  (`const { query: { q } } = req`). The parameter forms are one branch whose handler and field
  tests are exclusions plus a whole-file field condition: keep it that way, a positive condition
  there costs the prefilter. Limit to copy into each new rule: a field with a default value in a
  destructured parameter (`todoruleid:`). **Awaited calls** (xss, open-redirect, regex): the value
  of an awaited method or of an awaited helper given the response object is stored data, not
  request data; when a function is passed to such a call, only the call's value is clean (an
  `exact: true` twin), so sinks written inside the callback are still checked.
- **python** (11 rules: sql, command, path, ssrf, xss, unsafe-deserialization, open-redirect,
  code, template, xpath, regex). Flask `request`, route-decorated views (FastAPI too), and Django
  views in a module that imports Django. **Slices** are sources themselves (OpenGrep carries no
  taint through a slice): of a request chain, of a variable assigned one, of a view parameter;
  a variable assigned again after the request value is not. **Allow-lists**: a lookup in a dict
  (or list or tuple) literal of literals, with r/b/u prefixes and comments, assigned to an
  upper-case name the module never changes, with no default or a literal default; or a ternary of
  constants. **The Django module check is `pattern-inside: import django` + `...`**, a literal that
  binds no metavariable and also matches `from django.x import y`. The old form
  (`from $DJ import $NAME` plus a regex) counted every finding once per imported name toward
  OpenGrep's 10,000-match limit per file; a large Django module went over it and reported nothing
  (python.sql-injection#django-import-match-limit). A Django import nested in `if TYPE_CHECKING:`
  or `try:` does not count.
- **java** (12 rules: sql, command, path, ssrf, xss, open-redirect, ldap, template, expression,
  unsafe-deserialization, xpath, regex). Three shared sources (servlet getters; annotated
  controller parameters except scalar types, `@RequestPart` included; `HttpEntity`/`RequestEntity`
  bodies), two propagators (`append` and an append chain), nine shared sanitizers (four number
  conversions, two `Map.of` allow-lists, `Enum.valueOf` twice, an enum declared in the file).
  java.ssrf and java.open-redirect add the **builder fixed-origin model**: a `StringBuilder` or
  `StringBuffer` created with a fixed origin or local path, or given it by its first append, is
  clean unless edited (`setLength`, `delete`, `replace`, `insert`, `setCharAt`) or assigned again.
  `insert` and `replace` carry no taint yet (java.sql-injection#builder-insert).
- **go** (7 rules: sql, command, path, ssrf, xss, open-redirect, template). Request fields and
  methods, Gin and Echo getters, binders by side effect, encoding/json propagators, and the
  number/boolean type sanitizer. **Bind in a condition** (`if c.ShouldBindJSON(&in) == nil`):
  the type sanitizer leaves out a boolean whose text holds a bind, `.Decode(` or `json.Unmarshal(`
  call (one `metavariable-regex` on `$E`), so the bound struct stays a source; in go.sql-injection
  so far. **Test support**: findings inside a function with a `*testing.T`, `B`, `F`, `M` or
  `testing.TB` parameter are skipped (ruling F6); in go.path-traversal so far. The `#test-support`
  and `#bind-in-comparison` rows carry both to the other rules.

### Test code

Misuse and hotspot rules skip test code at rule level with `paths: exclude` (rulings F10 and J3):
a test that turns TLS verification off or uses a weak cipher on purpose is not a finding. Taint
rules do not: request data in a test is still a flow (Go skips test-support functions instead,
see above). The globs in use, the same in every rule of a language:

- **go:** `*_test.go`.
- **python:** `test_*.py`, `*_test.py`, `conftest.py`, `tests.py`, `tests/`, `test/`.
- **js:** `*.test.*`, `*.spec.*`, `*-test.*`, `*_test.*`, `__tests__/`, `test/`, `tests/`.
- **java:** `src/test/`, `src/testFixtures/`, `src/integrationTest/`, `src/intTest/` (Maven and
  Gradle layouts), `*Test.java`, `*Tests.java`, `*TestCase.java`, `*IT.java`, `*ITCase.java`
  (Surefire and Failsafe defaults). Their `Test*.java` and `IT*.java` defaults are left out: they
  also hit production names (`TestimonialService`, `ITunesClient`).

A new misuse or hotspot rule copies its language's list; the page says that test code is skipped.
Rules that skip it today: the four TLS rules, java.weak-cipher, go.weak-hash, go.insecure-cookie,
js.insecure-cookie, python.xxe-dtd-options and python.tar-extraction. Not yet: go.weak-cipher
(row go.weak-cipher#test-code), java.xxe, python.xxe and js.react-dangerous-html (decide when the
rule is next changed).

## Growing the map

- **A framework.** Only with the maintainer's word (it widens what Qualor claims to cover): propose
  it in the run report with its docs. Once agreed: add it to "Frameworks in scope" with the URL of
  its request API docs, add a `REFERENCE.md` project that uses it, and add a maintenance row
  `<lang>.<rule>#<framework>` for each `done` taint rule of the language.
- **A category.** Add a matrix row with its `dir`, CWE, kind and one cell per language
  (`candidate: <id> — <API lead>`, or `n/a` with the reason) after the doc gate. One kind per row:
  a category with an issue form and a hotspot form gets two rows. A category outside the CWE Top
  25 and the OWASP Top 10 needs the maintainer's word.
- Commit map changes with the backlog rows they produce.
- **Tooling** is not a map or backlog item (`BACKLOG.md` ids are rule ids). Open follow-ups from
  the 2026-10-06 run, for a setup change: a prefilter check in `npm test` (every rule:
  `opengrep-core -prefilter_of_rules` is not None and below a size budget; it would have caught
  the 31 MB python.tls-verification-disabled prefilter and the rules that have none); a
  per-alternative mutation sweep in tools/ (remove one pattern item or alternative at a time,
  the rule's test must fail; implementers wrote it three times in `.tmp/`); `--timeout 0` in
  `npm run probe` and `npm run measure` (OpenGrep's 5 s default times out on a loaded host and
  drops findings); generators for the shared source blocks of JS, Java and Python, as
  tools/xxe-exclusions.mjs does for java.xxe, so the copies stay byte-identical.

## Kind and severity (ruling M1 of 6A)

Taint data flow and definite misuse are `issue` (they count in the quality gate); "review this
usage", where context decides, is `hotspot` (never counted).

| shape | kind | metadata severity | OpenGrep `severity` |
|---|---|---|---|
| Request data into code, commands, SQL, NoSQL, templates, expressions, deserialisation, files, URLs fetched by the server, HTML output, XML parsers, LDAP and XPath queries | issue | high | ERROR |
| Request data into redirects, headers, regular expressions | issue | medium | WARNING |
| Definite misuse: TLS verification off, broken ciphers or modes, XXE-enabled parser configuration | issue | high (TLS, XXE) or medium (ciphers) | ERROR or WARNING |
| Hotspots: weak hashes, cookie flags, CORS, randomness, debug mode, unfiltered archive extraction, raw-HTML React props | hotspot | medium or low | WARNING or INFO |

- "TLS verification off" includes a host-name check turned off (CWE-297 in substance; ruling P1):
  an issue in the language's TLS rule, CWE-295 as its row, not a rule of its own.
- `blocker` is not used for single rules. `info` only for rules that inform, not warn.
- `confidence: high` when sources are request objects of real handlers and sinks are typed or
  bound in the same function; `medium` when a sink is matched by method name only; a rule that
  would need `low` is not shipped: narrow it or block the row.
- `owasp`: the current Top 10 category and the 2021 one, as in the SQL rules (`['A05:2025',
  'A03:2021']`). Take both from the owasp.org category pages ("List of Mapped CWEs"); a CWE mapped
  in neither gets `owasp: []`.

## Allowed sources (clean room)

The binding text is `CLEAN-ROOM.md`. In short:

- **Allowed:** CWE (cwe.mitre.org); OWASP Top 10, Cheat Sheet Series, ASVS; the official
  documentation of the languages, frameworks, drivers and libraries (their own sites, API
  references, pkg.go.dev, javadocs, docs.python.org, nodejs.org, developer.mozilla.org); our own
  fixtures.
- **Never open:** semgrep-rules, opengrep-rules, the semgrep.dev registry, CodeQL queries,
  SonarSource rule descriptions, any other vendor's or project's rule set, blog posts that
  reproduce rules.
- Backlog and map entries name categories, CWEs and official doc pages only, never another
  vendor's rule id or text.
