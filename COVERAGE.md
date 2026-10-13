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

| category | dir | CWE | kind | js | python | java | go | csharp |
|---|---|---|---|---|---|---|---|---|
| SQL injection | sql | CWE-89 | issue | js.sql-injection | python.sql-injection | java.sql-injection | go.sql-injection | csharp.sql-injection |
| NoSQL injection | nosql | CWE-943 | issue | js.nosql-injection | candidate: python.nosql-injection — pymongo filters and `$where` from request JSON | candidate: java.nosql-injection — Spring Data MongoDB `BasicQuery` from a JSON string | candidate: go.nosql-injection — mongo-go-driver filters decoded from request JSON | candidate: csharp.nosql-injection — MongoDB C# driver filters from request JSON (`BsonDocument.Parse`, `$where`) |
| Command injection | command | CWE-78 | issue | js.command-injection | python.command-injection | java.command-injection | go.command-injection | csharp.command-injection |
| Code injection | code | CWE-94, CWE-95 | issue | js.code-injection; candidate: js.code-injection#browser — setTimeout/setInterval with a string and DOM sources (`location`, `document.URL`) in browser code (browser code is out of scope: the maintainer's word first) | python.code-injection | candidate: java.code-injection — `javax.script` ScriptEngine.eval, GroovyShell.evaluate | n/a: no eval in the standard library | candidate: csharp.code-injection — Roslyn scripting `CSharpScript.EvaluateAsync`, System.Linq.Dynamic.Core expressions |
| Template injection | template | CWE-1336, CWE-94 | issue | js.template-injection | python.template-injection; candidate: python.template-injection#mako — `mako.template.Template(x)`; candidate: python.template-injection#compile-expression — Jinja `Environment.compile_expression(x)` | java.template-injection; candidate: java.template-injection#spring-view-names — request data in a returned view name (Thymeleaf before 3.0.12; needs a view-resolver signal) | go.template-injection | candidate: csharp.template-injection — RazorLight, Scriban or Fluid templates compiled from request strings |
| Expression language injection | expression | CWE-917 | issue | n/a | n/a | java.expression-injection; candidate: java.expression-injection#jexl — Apache Commons JEXL `createExpression`/`createScript`, `JexlSandbox` as the safe form | n/a | n/a: no expression language in ASP.NET Core |
| Unsafe reflection | reflection | CWE-470 | issue | candidate: js.unsafe-require — `require(x)`, `import(x)` | candidate: python.unsafe-import — `importlib.import_module(x)`, `getattr(obj, x)` | candidate: java.unsafe-reflection — `Class.forName(x)` | n/a | candidate: csharp.unsafe-reflection — `Type.GetType(x)`, `Activator.CreateInstance`, `Assembly.Load` |
| Path traversal | path | CWE-22 | issue | js.path-traversal | python.path-traversal | java.path-traversal | go.path-traversal | csharp.path-traversal |
| Archive extraction (zip slip), taint from the entry name | archive | CWE-22 | issue | candidate: js.zip-slip — tar, adm-zip, unzipper entry paths (check each library's defaults) | n/a: zipfile sanitises names; tar is the hotspot row below | java.zip-slip; candidate: java.zip-slip#zipfs — paths of a zip `FileSystem` (`FileSystems.newFileSystem`, `Files.walk`) resolved under a destination | go.zip-slip | candidate: csharp.zip-slip — `ZipArchiveEntry.FullName` combined under a destination, then `ExtractToFile` (check what `ExtractToDirectory` already refuses) |
| Archive extraction without a filter | archive | CWE-22 | hotspot | n/a | python.tar-extraction | n/a | n/a | n/a |
| SSRF | ssrf | CWE-918 | issue | js.ssrf | python.ssrf | java.ssrf | go.ssrf | csharp.ssrf |
| XSS | xss | CWE-79 | issue | js.xss | python.xss | java.xss | go.xss | csharp.xss |
| Raw HTML props (review) | xss | CWE-79 | hotspot | js.react-dangerous-html | n/a | n/a | n/a | candidate: csharp.razor-raw-html — `@Html.Raw(...)` in Razor views (.cshtml), generic mode (stage 0 matched it, 2026-10-13) |
| Open redirect | redirect | CWE-601 | issue | js.open-redirect | python.open-redirect | java.open-redirect | go.open-redirect | csharp.open-redirect |
| Header injection, response splitting | header | CWE-113 | issue | candidate: js.header-injection — check whether Node's http rejects CR/LF in header values (n/a if so) | candidate: python.header-injection — check Werkzeug and Django (n/a if they reject newlines) | candidate: java.header-injection — servlet setHeader/addHeader, check the containers | candidate: go.header-injection — check net/http's header writing (n/a if it sanitises) | candidate: csharp.header-injection — check whether Kestrel rejects CR/LF in header values (n/a if so) |
| XXE (parser configuration) | xxe | CWE-611, CWE-776 | issue | candidate: js.xxe — libxmljs `parseXml(x, { noent: true })` | python.xxe | java.xxe | n/a: encoding/xml does not resolve external entities (confirm in the docs) | csharp.xxe |
| XXE: DTD loading or lifted parser limits (review) | xxe | CWE-611, CWE-776 | hotspot | n/a until js.xxe exists | python.xxe-dtd-options | n/a: java.xxe reports DTD-enabled parsers as an issue | n/a: encoding/xml has no DTD processing | n/a: csharp.xxe reports DTD-enabled parsers as an issue |
| XPath injection | xpath | CWE-643 | issue | candidate: js.xpath-injection — the xpath npm package | python.xpath-injection | java.xpath-injection; candidate: java.xpath-injection#dom4j-jdom — dom4j `selectNodes`/`selectSingleNode`/`valueOf`, `DocumentHelper.createXPath`; JDOM2 `XPathFactory.compile` (library scope: the maintainer's word) | n/a: no XPath in the standard library | csharp.xpath-injection |
| LDAP injection | ldap | CWE-90 | issue | candidate: js.ldap-injection — ldapjs search filters | candidate: python.ldap-injection — ldap3 search filters, `escape_filter_chars` | java.ldap-injection; candidate: java.ldap-injection#dn — request data in a DN (search base, `lookup`, `bind`), `LdapNameBuilder` and DN encoding as sanitizers | candidate: go.ldap-injection — go-ldap search filters, `ldap.EscapeFilter` | csharp.ldap-injection |
| Unsafe deserialization of request data | deserialization | CWE-502 | issue | candidate: js.unsafe-deserialization — check node-serialize-like libraries' docs | python.unsafe-deserialization | java.unsafe-deserialization | n/a: encoding/gob and encoding/json build data only (confirm) | n/a: csharp.unsafe-deserialization reports the unsafe formatters on any data |
| Unsafe deserializer configuration | deserialization | CWE-502 | issue | candidate: js.unsafe-yaml-schema — js-yaml custom schemas with functions | candidate: python.unsafe-yaml-load — `yaml.load` with an unsafe Loader on any data | candidate: java.jackson-default-typing — Jackson `activateDefaultTyping`/`enableDefaultTyping`; SnakeYAML without SafeConstructor (version-dependent) | n/a | csharp.unsafe-deserialization |
| Prototype pollution | prototype | CWE-1321 | issue | js.prototype-pollution | n/a | n/a | n/a | n/a |
| Regex injection (ReDoS) | regex | CWE-1333, CWE-400 | issue | js.regex-injection | python.regex-injection; candidate: python.regex-injection#regex-module — the third-party `regex` module (re's API); candidate: python.regex-injection#django-lookups — Django ORM `__regex`/`__iregex` lookups with request data | java.regex-injection | n/a: the regexp package (RE2) runs in linear time | csharp.regex-injection |
| Log injection | log | CWE-117 | hotspot | candidate: js.log-injection — request data into `console.log` or a logger without encoding | candidate: python.log-injection — request data into `logging` calls | candidate: java.log-injection — request data into SLF4J/Log4j calls | candidate: go.log-injection — request data into `log`/`slog` calls | candidate: csharp.log-injection — request data in `ILogger` messages (check whether message templates make it n/a) |
| TLS verification disabled | tls | CWE-295 | issue | js.tls-verification-disabled | python.tls-verification-disabled | java.tls-verification-disabled | go.tls-verification-disabled | csharp.tls-verification-disabled |
| Weak cipher or mode | crypto | CWE-327 | issue | candidate: js.weak-cipher — `createCipheriv` with des, rc4 or ecb names | candidate: python.weak-cipher — cryptography's TripleDES/ECB, PyCryptodome DES/ARC4/MODE_ECB | java.weak-cipher; candidate: java.weak-cipher#bouncycastle — Bouncy Castle lightweight engines (`DESEngine`, `ECBBlockCipher`) | go.weak-cipher | candidate: csharp.weak-cipher — DES, TripleDES, RC2, `CipherMode.ECB` (CA5351 overlaps under dotnet end: check) |
| Weak hash | crypto | CWE-328 | hotspot | candidate: js.weak-hash — `createHash('md5' / 'sha1')` | candidate: python.weak-hash — hashlib md5/sha1 without `usedforsecurity=False` | candidate: java.weak-hash — `MessageDigest.getInstance("MD5" / "SHA-1")` | go.weak-hash | candidate: csharp.weak-hash — MD5, SHA1 (CA5350/CA5351 overlap under dotnet end: check) |
| Insecure randomness | random | CWE-330, CWE-338 | hotspot | candidate: js.insecure-random — `Math.random()` for tokens | candidate: python.insecure-random — `random` for tokens (docs point to `secrets`) | candidate: java.insecure-random — `java.util.Random` for tokens | candidate: go.insecure-random — `math/rand` for tokens | candidate: csharp.insecure-random — `System.Random` for tokens (`RandomNumberGenerator` is the safe form) |
| JWT signature not verified | jwt | CWE-347 | issue | candidate: js.jwt-unverified — jsonwebtoken `algorithms: ['none']`, `decode` for auth | candidate: python.jwt-unverified — PyJWT `options={"verify_signature": False}` | candidate: java.jwt-unverified — jjwt unsigned parsing | candidate: go.jwt-unverified — golang-jwt `ParseUnverified` | candidate: csharp.jwt-unverified — `TokenValidationParameters` with `ValidateIssuerSigningKey = false` or `RequireSignedTokens = false` |
| Insecure cookie flags | cookie | CWE-614, CWE-1004 | hotspot | js.insecure-cookie | candidate: python.insecure-cookie — `set_cookie` without secure/httponly, Django `SESSION_COOKIE_SECURE = False` | candidate: java.insecure-cookie — `new Cookie` without setSecure/setHttpOnly | go.insecure-cookie; candidate: go.insecure-cookie#gorilla-sessions — gorilla/sessions `Options{Secure, HttpOnly}`, `NewCookieStore` defaults; candidate: go.insecure-cookie#gin-sessions — gin-contrib/sessions `Options` | candidate: csharp.insecure-cookie — `CookieOptions` with `Secure`/`HttpOnly` false, `CookiePolicyOptions` |
| CORS: any origin with credentials | cors | CWE-942 | hotspot | candidate: js.cors-credentials — cors `origin: true` with `credentials: true` | candidate: python.cors-credentials — flask-cors, django-cors-headers allow-all with credentials | candidate: java.cors-credentials — Spring `allowedOriginPatterns("*")` with `allowCredentials(true)` | candidate: go.cors-credentials — rs/cors, gin-contrib/cors allow-all with credentials | candidate: csharp.cors-credentials — `AllowAnyOrigin` or `SetIsOriginAllowed(_ => true)` with `AllowCredentials()` |
| CSRF protection disabled | csrf | CWE-352 | hotspot | n/a | candidate: python.csrf-disabled — Django `@csrf_exempt`, Flask-WTF CSRF off | candidate: java.csrf-disabled — Spring Security `csrf().disable()` | n/a | candidate: csharp.csrf-disabled — `[IgnoreAntiforgeryToken]`, `DisableAntiforgery()` |
| Debug mode on | debug | CWE-489, CWE-215 | hotspot | n/a | candidate: python.debug-enabled — Flask `app.run(debug=True)`, Django `DEBUG = True` | n/a | n/a | candidate: csharp.debug-enabled — `UseDeveloperExceptionPage()` outside an `IsDevelopment()` check |
| Hard-coded secrets | — | CWE-798 | — | n/a: Gitleaks covers it in Qualor | n/a: Gitleaks | n/a: Gitleaks | n/a: Gitleaks | n/a: Gitleaks |

## Frameworks in scope (design spec §7)

| lang | frameworks | where the source block lives |
|---|---|---|
| js | Node `http`, Express 4 and 5, Next.js API routes (pages router `(req, res)` and App Router route handlers), Fastify | `rules/js/sql/sql-injection.yml`: Express-style handlers `(req, res, ...)`, Next.js App Router route handlers, Fastify routes, and handlers that destructure the request. |
| python | Django, Flask, FastAPI | `rules/python/sql/sql-injection.yml`: `flask.request.*`, the parameters of route-decorated views (which also matches FastAPI path operations), and Django views in a module that imports Django. |
| java | Servlet (javax and jakarta), Spring MVC, Jakarta REST (JAX-RS) | `rules/java/sql/sql-injection.yml`: servlet request getters, annotated controller parameters except scalar types (`@RequestPart` included), and `HttpEntity`/`RequestEntity` bodies. |
| go | `net/http`, Gin, Echo (also chi and gorilla/mux route variables) | `rules/go/sql/sql-injection.yml`: request fields and methods, Gin/Echo getters, binders (by side effect, also inside a condition) and the encoding/json propagators. The test-support skip lives in `rules/go/path/path-traversal.yml`. |
| csharp | ASP.NET Core: MVC and Web API controllers, Minimal APIs, Razor Pages | `rules/csharp/sql/sql-injection.yml`: controller action parameters (scalar types excluded), `[From*]` parameters, Minimal API handler parameters, Razor Pages `[BindProperty]` properties and handler parameters, `Request` members. |

### Source blocks

OpenGrep has no includes, so every taint rule of a language carries its own copy of the
language's request sources.

The rules are tested and run with OpenGrep's `--taint-intrafile` (package.json `taintIntrafile`,
written into the pack's manifest), so a helper or wrapper in the same file is followed and only
other files are not. That mode models `get`-like calls as container reads: the Python shared block
therefore carries two `dict.get` propagators (key and default into the dict), identical in the 11
Python taint rules, and a rule whose sink argument comes from such a call (`Paths.get`, an HTTP
client's `get`) needs a propagator of its own.

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
  without FastAPI; Quarkus-specific APIs beyond the Jakarta REST annotations, Micronaut, Spring WebFlux; Fiber, Beego; classic ASP.NET (System.Web, MVC 5, Web API 2), Blazor, Razor markup (`.cshtml`, `.razor`). Each is a framework to add.
- The shared items (sources, request propagators, shared sanitizers) must stay **byte-identical**
  in every rule that carries them. Compare them with a script after every change to the block,
  and run the per-alternative mutation sweep (rule-procedure.md step 4) on each rule. Items that
  belong to one rule only follow the shared ones (Python marks the end with the comment
  `# (End of the shared Python source block; the items below are this rule's own.)`).

What each language's block holds today (2026-10-11 run):

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
  a variable assigned again after the request value is not. **Middleware** (python-1): in a
  Starlette `BaseHTTPMiddleware.dispatch()` or an `@app.middleware("http")` function, the request's
  URL (not its scheme, port or `is_secure`), query and path params, headers, cookies, `json()`,
  `body()`, `form()` and `stream()`, the middleware context written as an exclusion (one
  prefilter condition); python.open-redirect takes the request's own URL there for this site's URL
  and its path and query as its own sources. **Containers** (intrafile, python-4): `dict.get`
  key and default, an item write `$D[$K] = $X`, and `pop()`/`setdefault()` key and default carry
  request data into the receiver (receiver form only: a `to:` on the call costs 2–3×).
  **Allow-lists**: a lookup in a dict
  (or list or tuple) literal of literals, with r/b/u prefixes and comments, assigned to an
  upper-case name the module never changes (the "assigned again" exclusions start at a
  `$ALLOWED = {...}` assignment), with no default or a literal default; or a ternary of
  constants. **The Django module check is `pattern-inside: import django` + `...`**, a literal that
  binds no metavariable and also matches `from django.x import y`. The old form
  (`from $DJ import $NAME` plus a regex) counted every finding once per imported name toward
  OpenGrep's 10,000-match limit per file; a large Django module went over it and reported nothing
  (python.sql-injection#django-import-match-limit). A Django import nested in `if TYPE_CHECKING:`
  or `try:` does not count.
- **java** (12 rules: sql, command, path, ssrf, xss, open-redirect, ldap, template, expression,
  unsafe-deserialization, xpath, regex). Three shared sources (servlet getters; annotated
  controller parameters except scalar types, `@RequestPart` included; `HttpEntity`/`RequestEntity`
  bodies), three propagators (`append`, an append chain, and `insert`/`replace` on a typed
  `StringBuilder`/`StringBuffer`), shared sanitizers (four number conversions, two `Map.of`
  allow-lists, `Enum.valueOf` twice, and an enum declared in the file: before or after a class, or
  nested in a class or interface and named by it from any class of the file, one-argument
  `valueOf` only). In intrafile mode a two-argument `insert` on a class without a body in the file
  (a MyBatis `SqlSession`) counts as a container write (a Known limit in all 12 rules).
  java.ssrf and java.open-redirect add the **builder fixed-origin model**: a `StringBuilder` or
  `StringBuffer` created with a fixed origin or local path, or given it by its first append, is
  clean unless edited (`setLength`, `delete`, `replace`, `insert`, `setCharAt`) or assigned again.
  `insert` and `replace` carry taint since java.sql-injection#builder-insert (2026-10-11).
- **go** (7 rules: sql, command, path, ssrf, xss, open-redirect, template). Request fields and
  methods, Gin and Echo getters, binders by side effect, encoding/json propagators, and the
  number/boolean type sanitizer, which is `exact: true` (go.sql-injection#sink-in-comparison,
  2026-10-11): only the number's or boolean's own value is clean, so a sink called inside a
  comparison, nested in a compared call or inside a callback of one is still checked, and the
  struct a bind fills inside a condition stays a source (the earlier bind-call `metavariable-regex`
  is gone). **Test support**: findings inside a function with a `*testing.T`, `B`, `F`, `M` or
  `testing.TB` parameter are skipped (ruling F6), in all 7 rules. Both items are byte-identical in
  the 7 rules. go.xss carries a verbatim copy of go.command-injection's sinks as sanitizers;
  python.xss carries one of python.command-injection's sinks (python-3): a sink change there must
  be copied in the same commit.
- **csharp** (1 of 12 planned rules: csharp.sql-injection, the seed, 2026-10-13; spec 2026-10-13
  §5.1). **Three shared regions**, each copied byte for byte and each ended by its own comment:
  `pattern-sources` up to `# (End of the shared C# source block; the items below are this rule's
  own.)`, `pattern-propagators` up to `# (End of the shared C# propagators; the items below are
  this rule's own.)`, and `pattern-sanitizers` up to `# (End of the shared C# sanitizers; the
  items below are this rule's own.)`; a rule's own items follow each marker. Sources:
  (1) **controller actions**: the parameters of public methods of a class whose (first) base
  class's name ends in `Controller` or `ControllerBase` (generic bases too: `CrudController<T>`), of a class without a base list whose own
  name ends in `Controller`, or of a class marked `[ApiController]`/`[Controller]` (the documented
  controller conditions; `[NonController]` excepted; a `*Controller` class with another base, such
  as a game engine's script, is not one), except `[FromServices]`/`[FromKeyedServices]`
  parameters and `[NonAction]` methods; (2) **Razor Pages handlers**: parameters of
  `On<Verb>...` methods of a class whose base class's name ends in `PageModel`, `[FromServices]`
  excepted; (3) **`[BindProperty]` properties** (with or without arguments or an initializer) in
  any class, and every public property of a `[BindProperties]` class, used as `P` or `this.P` (no
  PageModel base is required: the attribute is MVC's own and binds in controllers too);
  (4) **Minimal API handlers** given to `MapGet/Post/Put/Delete/Patch/Methods`: a lambda with an
  expression or a block body (`async` is transparent), or a method group that is a local function
  of the top-level program mapped before it, or a method of the class whose extension method
  (`MapXxx(this IEndpointRouteBuilder b)`) maps it; only the types `string`, `string?`,
  `string[]`, `StringValues`, `IFormFile`, `IFormFileCollection`, `IFormCollection`, `Stream`,
  `PipeReader` count (a DTO bound implicitly from the body cannot be told from a DI service: Known
  limit); (5) **attribute-bound parameters** (`[FromQuery]`, `[FromRoute]`, `[FromForm]`,
  `[FromHeader]`, `[FromBody]`, `[AsParameters]`, also qualified or with `Attribute`) of any method
  or lambda; (6) **the request**: `Request.X`, `ctx.Request.X`, `(HttpRequest r).X`, and `r.X`
  after `var r = ctx.Request;` or `var r = Request;`, for X in `Query`, `Form`, `Headers`,
  `Cookies`, `RouteValues`, `Path`, `PathBase`, `QueryString`, `Body`, `BodyReader`,
  `ReadFormAsync`, `ReadFromJsonAsync(<T>)` (a field-access pattern on the method name also taints
  the call's value). **Scalar types** (not sources in (1), (2), (3), (5)): `byte`, `sbyte`,
  `short`, `ushort`, `int`, `uint`, `long`, `ulong`, `decimal`, `double`, `float`, `bool`, `char`,
  `Guid`, `DateTime`, `DateTimeOffset`, `DateOnly`, `TimeOnly`, `TimeSpan` and the
  `System.Int32`-style names, nullable, as arrays, and as
  `List`/`IList`/`IEnumerable`/`ICollection`/`IReadOnlyList`/`IReadOnlyCollection`/`HashSet`/`ISet`
  of them; also `CancellationToken` and interfaces (DI services), except the `IForm*` types and
  the collection interfaces; and in (1), (2), (5) an enum declared earlier in the file
  (`pattern-not-inside: enum $T { ... }` + `...`). **Propagators**: `StringBuilder` `Append` (also
  later in an `Append` chain), `AppendLine`, `AppendFormat`, and the out value of `TryGetValue` on
  a request collection (`Insert(i, x)` needs none: intrafile mode takes it for a container write).
  **Sanitizers**: `int`/`long`/`Guid`/`DateTime.Parse`, `Convert.ToInt32/64`,
  `Enum.Parse<T>`/`Enum.Parse`, and **allow-lists**: a `static readonly` `Dictionary`, `HashSet`,
  list or array of string/number literals (target-typed or not, a `StringComparer` argument
  allowed) that no method after it in the class changes (indexer write, `Add`, `TryAdd`,
  `AddRange`, `Insert`, `InsertRange`, `UnionWith`, `SymmetricExceptWith`); clean are its indexer
  lookups, `GetValueOrDefault(k, <literal>)`, `T.Contains(x) ? x : <literal>` (`ContainsKey` too),
  and `x` after `if (!T.Contains(x))` whose body always leaves the method: a single `return`/`throw`,
  or one ending in it after at most two other top-level statements (`{ ... return ...; }` would
  also take a conditional return, one in a loop or in a lambda). `TryParse` out values, ternaries and switch expressions of constants need
  none. (C# has no `const` collections, so spec §5.1's "or a const" has no form.) **OpenGrep
  facts** (2026-10-13): a method-name metavariable binds the generic arguments too
  (`Query<User>`), so name regexes end in `(<.*>)?`, and a literal method name does not match a
  generic call; `[$A(...)]` matches an attribute with or without arguments; `=> $BODY` matches
  expression bodies only and `=> { ... }` block bodies; `class $C { ... }` also matches a class
  with a base list (add `pattern-not-inside: class $C : $B { ... }` for base-less classes); a `var`
  local needs its own `var $R = ...; ...` form; **no taint leaves an expression-bodied method
  (`=> expr`, also a pass-through `F(q) => "..." + q`) or any property getter (block body too)**,
  while block-bodied methods work; a one-argument `GetValueOrDefault(key)` is a container read that
  drops the key's taint. **Prefilter**: the source block gives no words, so a C# taint rule's
  prefilter is its sinks' alone and every sink item needs a word (seed: Some, 1.5 kB). **Cost**:
  the class-wide method-group form and the allow-list exclusions dominate; both are anchored (an
  extension method; the table's field first); 0.11 s on the largest real reference files with sink
  words. **Limits to copy into each new rule as todo lines**: a Minimal API DTO bound from the
  body without `[FromBody]`, a method-group handler of another class, a `*Controller` class whose
  base class is named otherwise, a helper written as an expression-bodied method, a pass-through
  expression-bodied helper, a property getter (expression and block body) that reads the request,
  a value assigned again after an allow-list guard (`todoruleid:`); an enum declared after its
  use, an equality guard, a static `Enumerable.Contains` check (`todook:`); and as comments
  without lines: other files (intrafile), `$$"""` raw strings, body-less types (`class X : Y;`)
  and some multi-line collection expressions, which OpenGrep 1.30 parses only partly (a finding
  there comes from error recovery, never counted).

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
- **csharp:** `test/`, `tests/`, `*.Tests/`, `*.UnitTests/`, `*.IntegrationTests/`, `*.Test/`, `*.Specs/`, `*Tests.cs`, `*Test.cs`.

A new misuse or hotspot rule copies its language's list; the page says that test code is skipped.
Rules that skip it today: the four TLS rules, java.weak-cipher, go.weak-cipher, go.weak-hash,
go.insecure-cookie, js.insecure-cookie, python.xxe-dtd-options and python.tar-extraction. Not
yet: java.xxe, python.xxe and js.react-dangerous-html (decide when the
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
  the 2026-10-06 run, for a setup change (the prefilter check is `npm run test:prefilter` since
  2026-10-07): a per-alternative mutation sweep in tools/ (remove one pattern item or
  alternative at a time, the rule's test must fail; implementers wrote it three times in
  `.tmp/`); `--timeout 0` in `npm run probe` and `npm run measure` (OpenGrep's 5 s default times
  out on a loaded host and drops findings); generators for the shared source blocks of JS, Java
  and Python, as tools/xxe-exclusions.mjs does for java.xxe, so the copies stay byte-identical.
  Added by the 2026-10-11 run: a check that go.xss's and python.xss's copied command sinks equal
  their command-injection rules' sinks; `.mjs` and `.cjs` in the js test-file extensions of
  tools/rules.mjs (check and the pages' Tests links skip them today); a generated 400–800-view
  Python module and a large minified JS file in `npm run measure`; the sweep with conjunct
  removal (written again in `.tmp/sweep.mjs` by go-1, java-1, java-2 and python-1).

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
