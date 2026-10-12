# Reference projects

Every new or changed rule is run on these projects before it is committed, and every finding is
reviewed by hand (design spec §8.3). The **noise** projects are well-known applications built on
the in-scope frameworks; their findings should be few and mostly true. The **recall** sets are
deliberately vulnerable applications: `npm run measure` scores the OWASP Benchmark per category
and counts findings on the others (design spec §8.4, `MEASUREMENTS.md`).

Each project is pinned to a full commit SHA (checked with `git ls-remote` on 2026-10-04; the csharp rows on 2026-10-13) and its
licence is the one its licence file states ("none": no licence file, so all rights are reserved).

**Never copy code from these projects into this repository**, whatever their licence: not into a
fixture, a rule, a comment or a commit message. A shape you saw in a probe is described in words
and written anew, minimal, from the framework's documentation (`CLEAN-ROOM.md` "Order of work").
Read only the file and lines of a finding; never open a project's tool configurations, scripts or
result directories (owasp-benchmark ships other tools' runner scripts and score cards).
Exception (6B-C# ruling C6): the C# sink inventory may read a finding's call chain in other files of a noise project, to class the flow as in-file, cross-file or none. Nothing read that way is quoted anywhere, in the repository or outside it.

| lang | project | repository | commit | licence | frameworks | use |
|---|---|---|---|---|---|---|
| js | node-express-boilerplate | https://github.com/hagopj13/node-express-boilerplate | 179ae84efec61b14206d0305d941daed6c6d07f9 | MIT | express 4, mongoose 5, joi | noise |
| js | taxonomy | https://github.com/shadcn-ui/taxonomy | 298a8857c7128a0d121e7f699dfd729f23b3966d | MIT | next.js 13 (app router, route handlers), prisma, next-auth | noise |
| js | fastify-demo | https://github.com/fastify/demo | 5cd560125b3c2f0d42192bc7f493e8e3b9e75e52 | MIT | fastify 5, knex, mysql2 (typescript) | noise |
| python | djangoproject-com | https://github.com/django/djangoproject.com | 911575b3d8a6e3fb48d116ce6f42cdbcd7dae4bc | BSD-3-Clause | django 6.1 | noise |
| python | microblog | https://github.com/miguelgrinberg/microblog | a975ef64864354867c88e0ed3a17ba7d17dca752 | MIT | flask 3, flask-sqlalchemy | noise |
| python | full-stack-fastapi | https://github.com/fastapi/full-stack-fastapi-template | 1762adac607a1b29cfc4da129557780beea71616 | MIT | fastapi, sqlmodel (backend/) | noise |
| java | spring-petclinic | https://github.com/spring-projects/spring-petclinic | 500158f732419217507c7656904b8e6aa1bcc0d6 | Apache-2.0 | spring boot, spring mvc, spring data jpa, thymeleaf | noise |
| java | spring-boot-realworld | https://github.com/gothinkster/spring-boot-realworld-example-app | ee17e31aafe733d98c4853c8b9a74d7f2f6c924a | MIT | spring boot, spring mvc, mybatis, graphql (dgs) | noise |
| java | jhipster-sample-app | https://github.com/jhipster/jhipster-sample-app | 6b000b5d23a36c45e01472471b84a44fa2464044 | Apache-2.0 | spring boot, spring mvc, spring data jpa, spring security | noise |
| java | quarkus-quickstarts | https://github.com/quarkusio/quarkus-quickstarts | e289a82f369c3e7e2f1f38b2e7e15ee5e7a233fe | Apache-2.0 | jakarta rest (quarkus rest), hibernate orm/panache (many small apps) | noise |
| go | gin-realworld | https://github.com/gothinkster/golang-gin-realworld-example-app | 626c372d259472148d93303f74aa9b9a1cdcef24 | MIT | gin 1.10, gorm 1.25 | noise |
| go | echo-realworld | https://github.com/xesina/golang-echo-realworld-example-app | e578590b51e93440c5bdfdb5a98578679c0ee383 | MIT | echo v4, jinzhu/gorm v1 | noise |
| go | gitea | https://github.com/go-gitea/gitea | a9ac8c0afdb82068f7f242826bbe28c8e921df99 | MIT | net/http, chi v5, xorm (large) | noise |
| csharp | eshop | https://github.com/dotnet/eShop | dc7ea499cd356924fb6689b3702964a5869dbae9 | MIT | asp.net core minimal apis, ef core, .net 10 | noise |
| csharp | eshop-on-web | https://github.com/dotnet-architecture/eShopOnWeb | 4da8212117e87d808d4bbc7da6286fd2147ce606 | MIT | asp.net core 8 mvc, razor pages, web api, ef core (archived, last commit 2025-01-13) | noise |
| csharp | orchardcore | https://github.com/OrchardCMS/OrchardCore | 8970bfce61bee5b3b07efdac26ae8a039d05dc26 | BSD-3-Clause | asp.net core mvc, razor pages, minimal apis (large) | noise |
| csharp | jellyfin | https://github.com/jellyfin/jellyfin | 61f9a9df23a46175de2b8bac0a6da47f807cafd0 | GPL-2.0 | asp.net core web api controllers, ef core, .net 10 | noise |
| csharp | nopcommerce | https://github.com/nopSolutions/nopCommerce | b82cabdcd1f57ea1d97592b639150ecafbecb46f | nopCommerce Public License 4.0 | asp.net core mvc, razor views, linq2db (large) | noise |
| js | juice-shop | https://github.com/juice-shop/juice-shop | 1618a611b173b4bf114028e6e02549950606e29d | MIT | express, sequelize, angular (deliberately vulnerable) | recall |
| js | nodegoat | https://github.com/OWASP/NodeGoat | c5cb68a7084e4ae7dcc60e6a98768720a81841e8 | Apache-2.0 | express, mongodb (deliberately vulnerable) | recall |
| python | pygoat | https://github.com/adeyosemanputra/pygoat | 19d17cc8874861142b330636d068bbde54e86b85 | MIT | django (deliberately vulnerable) | recall |
| java | owasp-benchmark | https://github.com/OWASP-Benchmark/BenchmarkJava | 8b67a88d73b2594570fc21150705283de884620b | GPL-2.0 | servlet; scored with expectedresults-1.2.csv | recall |
| go | govwa | https://github.com/0c34/govwa | 4058f79f31eeb4a36d8f1e64bba1f0c899646e6f | none | net/http, database/sql (deliberately vulnerable) | recall |
| csharp | aspgoat | https://github.com/Soham7-dev/AspGoat | db3153f5dae036a9d67e12be22548299855c6b40 | MIT | asp.net core mvc (deliberately vulnerable) | recall |
| csharp | murayama-vulnerable-api | https://github.com/AlexandreMurayama/Murayama.VulnerableApi | 465adefe3742d8806368d30a3e7ad1ab42deaa9d | MIT | asp.net core web api, ef core, postgresql (deliberately vulnerable, OWASP API Top 10; vulnerable and fixed variants) | recall |
| csharp | vulnerablelightapp | https://github.com/Aif4thah/VulnerableLightApp | 8998b55caab6a4a5bb2d725ad054c797c7d101f4 | GPL-3.0 | asp.net core rest api (.net), deliberately vulnerable (CWE table in the README) | recall |
| csharp | dvcsharp-api | https://github.com/appsecco/dvcsharp-api | 76c1de3c9d8d9c2e8ec0b50abe3b198a4330d7fc | MIT | asp.net core 2.x rest api, ef core (deliberately vulnerable; runtime out of support, source read only) | recall |
| csharp | vulnerablecoreapp | https://github.com/zsusac/VulnerableCoreApp | 1ae87f8648c71ae2dcf0eee3bd6cf3c7114e9e15 | none | asp.net core 2.0 mvc (deliberately vulnerable; runtime out of support, source read only) | recall |

**qualor-cc** (`E:\Personal\qualor\qualor-cc`, TypeScript, also JS/Python/Java/Go test data) is
probed on every run too, at its local `main`, without the paths its own `qualor.yml` excludes from
scans (`fixtures/**` and recorded test data). **Zero findings are required there.**

Deviation from design spec §8.4 (sets cloned "outside the repositories", results under qualor-cc
`docs/testing/`): the clones live in this repository's git-ignored `.tmp/ref/`, and the numbers go
into `MEASUREMENTS.md` here, next to the rules they describe. Nothing of the sets is committed.

## How to probe

```sh
npm run probe -- rules/<lang>/<category>/<name>.yml            # noise projects of that language + qualor-cc
npm run probe -- --recall rules/<lang>/<category>/<name>.yml   # also the recall sets
npm run probe -- --only microblog,qualor-cc rules/python       # named projects only
npm run probe -- rules                                          # every rule on every noise project
npm run measure -- java                                         # recall scores (MEASUREMENTS.md)
```

`tools/scanner.mjs` runs OpenGrep of `package.json`'s version in the `qualor/scanner` image
(`QUALOR_SCANNER_IMAGE`, default `qualor/scanner:6b1`), the way the `qualor` engine runs it: test
files included, files up to 1 MiB. It prints every finding as `rule  path:line  code` and each file
OpenGrep could not parse as a warning, keeps the JSON in `.tmp/probe/<run>/`, and exits 1 when
qualor-cc has a finding. The first run clones the projects (gitea is the largest); later runs reuse
the clones.

## How to review the findings

Open the file at the line of each finding (only there) and decide. Review all findings of a project
up to 30; above 30, review a random sample of 30 and state the counts as "n of N reviewed, x FP".

**Taint and definite-misuse rules (`issue`):**

- **TP**: request data really reaches the sink unsanitised, or the misuse is real.
- **FP**: it cannot: a constant, a conversion, an allow-list, a sanitiser, data not from a request,
  or a look-alike method of another library. Note why in one line.
- **Unsure**: the flow leaves the file or depends on configuration you cannot see; count it as FP.

**Hotspot rules:** a hotspot asks a person to look, so a finding is

- **TP** when it is the usage the rule is about (an MD5 checksum is a TP of a weak-hash hotspot,
  even though it is harmless: that is for the reviewer of the hotspot to decide);
- **FP** only when the pattern matched something else: another API, a look-alike, a safe setting
  the rule should have recognised.

A rule whose findings on the noise projects are **more than half FP** is reworked (narrow the
source or sink, add the sanitiser or the safe form) and probed again; if it stays above half, mark
the backlog row `blocked` with the question. An FP shape you keep is described in one line and
written as a fresh, minimal `todook:` line from the docs (never pasted from the project), with a
line in the rule's "Known limits" comment. Record the counts per project in the run's LOG.md entry
(`gin-realworld 2 (2 TP), gitea 0, qualor-cc 0`). Zero findings on the noise projects is a normal
result for taint rules on well-written code.

## How to change this list

Add a project when a new framework comes into scope (COVERAGE.md) and no project here uses it.
Pick a well-known application (not a library or a framework's own repository) on the framework's
current major version, with a licence file; take the default branch's head with
`git ls-remote https://github.com/<owner>/<repo>.git HEAD`; read its licence file and add a row;
`npm run check` checks the table. Move a pin only on purpose (a new framework version), in its own
commit, and say in LOG.md that the numbers before and after are not comparable.
