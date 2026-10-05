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
the reason. `dir` is the category directory under `rules/<lang>/`; `kind` applies to every cell of
the row. Hints in cells are leads for the doc gate, not facts.

| category | dir | CWE | kind | js | python | java | go |
|---|---|---|---|---|---|---|---|
| SQL injection | sql | CWE-89 | issue | js.sql-injection | python.sql-injection | java.sql-injection | go.sql-injection |
| NoSQL injection | nosql | CWE-943 | issue | js.nosql-injection | candidate: python.nosql-injection — pymongo filters and `$where` from request JSON | candidate: java.nosql-injection — Spring Data MongoDB `BasicQuery` from a JSON string | candidate: go.nosql-injection — mongo-go-driver filters decoded from request JSON |
| Command injection | command | CWE-78 | issue | js.command-injection | python.command-injection | java.command-injection | go.command-injection |
| Code injection | code | CWE-94, CWE-95 | issue | js.code-injection | python.code-injection | candidate: java.code-injection — `javax.script` ScriptEngine.eval, GroovyShell.evaluate | n/a: no eval in the standard library |
| Template injection | template | CWE-1336, CWE-94 | issue | js.template-injection | python.template-injection | java.template-injection | go.template-injection |
| Expression language injection | expression | CWE-917 | issue | n/a | n/a | java.expression-injection | n/a |
| Unsafe reflection | reflection | CWE-470 | issue | candidate: js.unsafe-require — `require(x)`, `import(x)` | candidate: python.unsafe-import — `importlib.import_module(x)`, `getattr(obj, x)` | candidate: java.unsafe-reflection — `Class.forName(x)` | n/a |
| Path traversal | path | CWE-22 | issue | js.path-traversal | python.path-traversal | java.path-traversal | go.path-traversal |
| Archive extraction (zip slip), taint from the entry name | archive | CWE-22 | issue | candidate: js.zip-slip — tar, adm-zip, unzipper entry paths (check each library's defaults) | n/a: zipfile sanitises names; tar is the hotspot row below | java.zip-slip | go.zip-slip |
| Archive extraction without a filter | archive | CWE-22 | hotspot | n/a | python.tar-extraction | n/a | n/a |
| SSRF | ssrf | CWE-918 | issue | js.ssrf | python.ssrf | java.ssrf | go.ssrf |
| XSS | xss | CWE-79 | issue | js.xss | python.xss | java.xss | go.xss |
| Raw HTML props (review) | xss | CWE-79 | hotspot | js.react-dangerous-html | n/a | n/a | n/a |
| Open redirect | redirect | CWE-601 | issue | js.open-redirect | python.open-redirect | java.open-redirect | go.open-redirect |
| Header injection, response splitting | header | CWE-113 | issue | candidate: js.header-injection — check whether Node's http rejects CR/LF in header values (n/a if so) | candidate: python.header-injection — check Werkzeug and Django (n/a if they reject newlines) | candidate: java.header-injection — servlet setHeader/addHeader, check the containers | candidate: go.header-injection — check net/http's header writing (n/a if it sanitises) |
| XXE (parser configuration) | xxe | CWE-611, CWE-776 | issue | candidate: js.xxe — libxmljs `parseXml(x, { noent: true })` | python.xxe | java.xxe | n/a: encoding/xml does not resolve external entities (confirm in the docs) |
| XPath injection | xpath | CWE-643 | issue | candidate: js.xpath-injection — the xpath npm package | python.xpath-injection | java.xpath-injection | n/a: no XPath in the standard library |
| LDAP injection | ldap | CWE-90 | issue | candidate: js.ldap-injection — ldapjs search filters | candidate: python.ldap-injection — ldap3 search filters, `escape_filter_chars` | java.ldap-injection | candidate: go.ldap-injection — go-ldap search filters, `ldap.EscapeFilter` |
| Unsafe deserialization of request data | deserialization | CWE-502 | issue | candidate: js.unsafe-deserialization — check node-serialize-like libraries' docs | python.unsafe-deserialization | java.unsafe-deserialization | n/a: encoding/gob and encoding/json build data only (confirm) |
| Unsafe deserializer configuration | deserialization | CWE-502 | issue | candidate: js.unsafe-yaml-schema — js-yaml custom schemas with functions | candidate: python.unsafe-yaml-load — `yaml.load` with an unsafe Loader on any data | candidate: java.jackson-default-typing — Jackson `activateDefaultTyping`/`enableDefaultTyping`; SnakeYAML without SafeConstructor (version-dependent) | n/a |
| Prototype pollution | prototype | CWE-1321 | issue | js.prototype-pollution | n/a | n/a | n/a |
| Regex injection (ReDoS) | regex | CWE-1333, CWE-400 | issue | js.regex-injection | python.regex-injection | java.regex-injection | n/a: the regexp package (RE2) runs in linear time |
| Log injection | log | CWE-117 | hotspot | candidate: js.log-injection — request data into `console.log` or a logger without encoding | candidate: python.log-injection — request data into `logging` calls | candidate: java.log-injection — request data into SLF4J/Log4j calls | candidate: go.log-injection — request data into `log`/`slog` calls |
| TLS verification disabled | tls | CWE-295 | issue | js.tls-verification-disabled | python.tls-verification-disabled | java.tls-verification-disabled | go.tls-verification-disabled |
| Weak cipher or mode | crypto | CWE-327 | issue | candidate: js.weak-cipher — `createCipheriv` with des, rc4 or ecb names | candidate: python.weak-cipher — cryptography's TripleDES/ECB, PyCryptodome DES/ARC4/MODE_ECB | java.weak-cipher | go.weak-cipher |
| Weak hash | crypto | CWE-328 | hotspot | candidate: js.weak-hash — `createHash('md5' / 'sha1')` | candidate: python.weak-hash — hashlib md5/sha1 without `usedforsecurity=False` | candidate: java.weak-hash — `MessageDigest.getInstance("MD5" / "SHA-1")` | go.weak-hash |
| Insecure randomness | random | CWE-330, CWE-338 | hotspot | candidate: js.insecure-random — `Math.random()` for tokens | candidate: python.insecure-random — `random` for tokens (docs point to `secrets`) | candidate: java.insecure-random — `java.util.Random` for tokens | candidate: go.insecure-random — `math/rand` for tokens |
| JWT signature not verified | jwt | CWE-347 | issue | candidate: js.jwt-unverified — jsonwebtoken `algorithms: ['none']`, `decode` for auth | candidate: python.jwt-unverified — PyJWT `options={"verify_signature": False}` | candidate: java.jwt-unverified — jjwt unsigned parsing | candidate: go.jwt-unverified — golang-jwt `ParseUnverified` |
| Insecure cookie flags | cookie | CWE-614, CWE-1004 | hotspot | js.insecure-cookie | candidate: python.insecure-cookie — `set_cookie` without secure/httponly, Django `SESSION_COOKIE_SECURE = False` | candidate: java.insecure-cookie — `new Cookie` without setSecure/setHttpOnly | go.insecure-cookie |
| CORS: any origin with credentials | cors | CWE-942 | hotspot | candidate: js.cors-credentials — cors `origin: true` with `credentials: true` | candidate: python.cors-credentials — flask-cors, django-cors-headers allow-all with credentials | candidate: java.cors-credentials — Spring `allowedOriginPatterns("*")` with `allowCredentials(true)` | candidate: go.cors-credentials — rs/cors, gin-contrib/cors allow-all with credentials |
| CSRF protection disabled | csrf | CWE-352 | hotspot | n/a | candidate: python.csrf-disabled — Django `@csrf_exempt`, Flask-WTF CSRF off | candidate: java.csrf-disabled — Spring Security `csrf().disable()` | n/a |
| Debug mode on | debug | CWE-489, CWE-215 | hotspot | n/a | candidate: python.debug-enabled — Flask `app.run(debug=True)`, Django `DEBUG = True` | n/a | n/a |
| Hard-coded secrets | — | CWE-798 | — | n/a: Gitleaks covers it in Qualor | n/a: Gitleaks | n/a: Gitleaks | n/a: Gitleaks |

## Frameworks in scope (design spec §7)

| lang | frameworks | where the source block lives |
|---|---|---|
| js | Node `http`, Express 4 and 5, Next.js API routes (pages router `(req, res)` and App Router route handlers), Fastify | `rules/js/sql/sql-injection.yml`: Express-style handlers `(req, res, ...)`. Next.js App Router and Fastify: added by `js.sql-injection#nextjs-fastify-sequelize-literal` (its implementer proposes the block in the report; the controller copies it here). |
| python | Django, Flask, FastAPI | `rules/python/sql/sql-injection.yml`: `flask.request.*` and the parameters of route-decorated views (which also matches FastAPI path operations). Django: added by `python.sql-injection#django` (proposed by its implementer, copied here by the controller). |
| java | Servlet (javax and jakarta), Spring MVC, Jakarta REST (JAX-RS) | `rules/java/sql/sql-injection.yml`: servlet request getters and annotated controller parameters except scalar types. |
| go | `net/http`, Gin, Echo (also chi and gorilla/mux route variables) | `rules/go/sql/sql-injection.yml`: request fields and methods, Gin/Echo getters, binders (by side effect) and the encoding/json propagators. |

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

## Kind and severity (ruling M1 of 6A)

Taint data flow and definite misuse are `issue` (they count in the quality gate); "review this
usage", where context decides, is `hotspot` (never counted).

| shape | kind | metadata severity | OpenGrep `severity` |
|---|---|---|---|
| Request data into code, commands, SQL, NoSQL, templates, expressions, deserialisation, files, URLs fetched by the server, HTML output, XML parsers, LDAP and XPath queries | issue | high | ERROR |
| Request data into redirects, headers, regular expressions | issue | medium | WARNING |
| Definite misuse: TLS verification off, broken ciphers or modes, XXE-enabled parser configuration | issue | high (TLS, XXE) or medium (ciphers) | ERROR or WARNING |
| Hotspots: weak hashes, cookie flags, CORS, randomness, debug mode, unfiltered archive extraction, raw-HTML React props | hotspot | medium or low | WARNING or INFO |

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
