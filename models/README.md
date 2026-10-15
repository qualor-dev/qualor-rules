# The engine's models (format v1)

`models/csharp/` holds the models of Qualor's Roslyn taint engine (`engine/dotnet`) as data: which
members are sources, sinks, sanitizers, guards and propagators. Their semantics follow the OpenGrep
C# rules of the same ids (`rules/csharp/`); where the engine, knowing the types, deliberately does
otherwise, a YAML comment next to the item says so and why.

- `sources.yml`: the ASP.NET Core request sources, shared by every taint model.
- `propagators.yml`: how taint passes through code the engine does not analyse, shared.
- `<name>.yml`: the model of the rule `csharp.<name>`. `npm run check` refuses a model without
  its rule in `rules/csharp/`; the engine's loader (`ModelLoader`, `npm run test:engine`) refuses
  an unknown or missing key, a wrong value and a malformed name, with the file and the line.

Clean room ([`CLEAN-ROOM.md`](../CLEAN-ROOM.md)): the models come from the OpenGrep rules here,
learn.microsoft.com and the libraries' own documentation, never from another tool's taint
configuration.

## Names

- A **type** is written by its metadata name: namespace and name, generic arity after a backtick,
  nested types after `+` (`System.Collections.Generic.IDictionary`2`,
  `System.Collections.Generic.Dictionary`2+KeyCollection`). Where a list of types says so, an
  array is `<type>[]` (`System.String[]`).
- A **member** is `<type>.<name>`; a constructor is `<type>..ctor`. `*` may end a member name:
  `Dapper.SqlMapper.Query*` names every method whose name starts with `Query`
  (`QueryFirstOrDefault` too), `System.Linq.Enumerable.*` every method of the type. Without `*` the
  name is exact (`QueryFirst` is not `QueryFirstOrDefault`). Generic methods have no arity in their
  name (`Query` is `Query<T>`). An indexer is written by its metadata name `Item` (or its
  `[IndexerName]`): `property-get: Microsoft.AspNetCore.Http.IQueryCollection.Item`.
- Each entry names its member under one key: `method:` (also `..ctor`), `property-get:` (a read)
  or `property-set:` (a write; an object initializer's too).

## Matching

- `T..ctor` matches the constructors of `T` only (constructors are not inherited).
- Any other `T.M` matches a member `M` of the right kind declared on `T` or on a class derived from
  `T` (an override, or a member hiding `T`'s with `new`), and every implementation of the member
  `M` of an interface `T` (implicit or explicit, also through a base class's implementation that a
  derived class overrides). `System.Data.Common.DbCommand.CommandText` thus matches
  `SqlCommand.CommandText`; `System.Data.Common.DbDataSource.CreateCommand` matches
  `NpgsqlDataSource.CreateCommand`.
- A pattern on a derived type does not match a call through its base type
  (`Microsoft.Data.SqlClient.SqlCommand.CommandText` does not match `DbCommand.CommandText`).
- Generic types and methods match by their definitions; an extension method matches whether it is
  called as one or in its static form.
- **Parameter ordinals** count the parameters of the declaration; an extension method's `this`
  parameter is 0.

## `<name>.yml`

```yaml
rule: csharp.sql-injection       # must be csharp.<file name>
kind: taint                      # taint | misuse
sinks:                           # a taint rule needs at least one
  - method: Microsoft.Data.SqlClient.SqlCommand..ctor
    args: [0]                    # the arguments that are the sink (parameter ordinals)
  - method: Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlCommand
    args: [1]
    param-types: [System.String, Microsoft.EntityFrameworkCore.RawSqlString]
                                 # optional: only overloads whose parameter has one of these types
  - method: System.Text.RegularExpressions.Regex.Replace
    args: [1]
    param-names: [pattern]       # optional (method sinks): only parameters of one of these names
  - property-set: System.Data.Common.DbCommand.CommandText   # the assigned value; no args
                                 # optional on any sink: `when:` (conditional sinks, below)
  - method: System.Data.DataTable.Select
    args: [0]
    message: "request data reaches a DataTable or DataView filter expression ..."
                                 # optional on any sink: the finding's message (below)
sources:                         # optional: the rule's own sources (below)
  - property-get: Microsoft.AspNetCore.Http.HttpRequest.Host
sanitizers:                      # optional: the member's result is clean
  - method: System.Int32.Parse
guards:                          # optional: the checked argument is clean on the branch where the
  - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl   # call's result equals clean-when
    arg: 0
    clean-when: true
```

A rule of `kind: misuse` has `misuse:` (below) and no `guards`. It may also have a taint form (Task 29): `sinks:` (with
`sanitizers:` and `sources:` of its own), whose findings carry the misuse rule's id (`csharp.unsafe-deserialization`
reports a serializer built for a type the request names). Like the taint rules, the taint form skips no test code.

- `sources:` (Task 29, decision R-10): the rule's own sources, `property-get:` or `method:` entries as in
  `sources.yml`'s `members`. What they read is request data for this rule only: clean for every other rule, so it is
  reported only where it reaches this rule's sinks (joined with other request data, that data still counts for every
  rule). With `receiver: T.P`, only a read whose receiver is a read of property P of T in place
  (`Request.PathBase.Value`, not a PathString held in a variable first). A rule's own sources do not make a body an
  implicit entry point (EntryPoints reads `sources.yml` only).
- `message:` on a sink: the finding's SARIF message, `<rule id>: <message>`, instead of the rule's generic one, where the
  generic one would mislead (a DataTable filter is reported under csharp.sql-injection, a request-chosen type under a
  misuse rule).

`sanitizers` take `method:` or `property-get:` (the member's result is clean), or one of the kinds below. A `method:`
sanitizer may add `receiver-type: T`: the result is clean only when the receiver (its static type) is T or derives
from T (`System.Text.Encodings.Web.TextEncoder.Encode` with `receiver-type: System.Text.Encodings.Web.UrlEncoder` is
UrlEncoder.Encode, not HtmlEncoder.Encode). A `method:` sanitizer may instead add `keep-members: [names]` (ruling R-E37
refined, fix round 2): the result keeps what the call was given as a whole value; where the engine knows its properties
exactly (in place, through a local), the named ones hold that value and every other one the cleaned value
(PhysicalFileProvider.GetFileInfo: the PhysicalPath stays under the root, a not-found file's Name is the path as given).
A read that lost the exact members reads the whole value: an over-report, never a miss.
A user-defined conversion operator named as a sanitizer (`op_Implicit`) cleans a conversion to `System.String` only
(PathString's text); its conversions to other types keep the value.

```yaml
sanitizers:
  - string-prefix: '^https?://[^/?#\s]+[/?#]'   # a value placed into a string after text that matches is clean
    type: Microsoft.AspNetCore.Http.PathString  # optional: only a value of this type (before an implicit conversion)
  - lookup: '^(Get|Find|Load)\w*Async$'         # what a body-less method so named returns is clean
```

- `string-prefix: R` (with `type: T`): a value built into a string in place (a string `+`, an interpolated string,
  `string.Format` with a known format: its `arg0` to `arg2` and the elements of its params array) is clean when the text
  before it in that string, from the string's start, matches R; an earlier value in that text reads as U+FFFC (write
  `\uFFFC` in R) unless its text is known. A text is known for a constant, a static readonly field or get-only static
  property initialised with a literal (in a type without a static constructor, which could assign it), and a call or read of a project member whose every return starts with the same
  text (its summary's returned text: the common start of what each `return` gives, a constant, a literal-initialised
  static, another such member, a `+` or interpolation of them; joined over the dispatch targets): `Api.Base + "/" + id`
  with `static string Base => "https://api.example/v1"` reads as written in place (Task 23). A string held in a variable
  keeps the value it was built with; its text is not followed.
  An external static string the models know (`known-text:` of `propagators.yml`: `Uri.SchemeDelimiter`,
  `Uri.UriSchemeHttps`, ...) is known too (Task 29, ruling R-E22), and a value chosen between known texts (`c ? a : b`)
  reads as their common start and a hole (`secure ? Uri.UriSchemeHttps : Uri.UriSchemeHttp` is "http" + U+FFFC).
- `property-get: T.Item` with `key: R` or `key-is: T.F` (Task 29): the read of the indexer whose key (argument 0) is a
  constant matching R, or reads the field or property T.F, is clean (`Request.Headers["Host"]`,
  `Request.Headers[HeaderNames.Host]`: the request's own origin for open-redirect and xss, ruling R-E22). A key held in a
  variable is not read. `method: T.M` with `key:` or `key-is:` and `receiver-type: D` (required): a call of M (argument 0
  the key) on a receiver whose static type is D, derives from it or implements it leaves its `out` values clean
  (`Request.Headers.TryGetValue("Host", out var h)` with `IDictionary`2.TryGetValue` and `IHeaderDictionary`).
- `lookup: R`: the result of a call to a method whose name matches R is clean when the engine has no body to analyse
  for it (an external method, an abstract or interface method without an implementation in the solution): a record
  found by an id is stored data. A method with a body is analysed instead. With `awaited: true`, only the awaited
  result of such a call is clean (`await store.GetAsync(id)`, also through `.ConfigureAwait(...)`); the call's value
  without an await keeps the request data.

```yaml
sanitizers:
  - by-name: Encoder.LdapFilterEncode   # a method LdapFilterEncode of a type named Encoder, in any namespace
  - allow-list: literal-tables          # the shared allow-lists (below)
```

- `by-name: T.M`: the result of a call of a method named M on a type whose simple name is T (any namespace, any
  body: the name wins over what the method's body does) is clean. For an API the OpenGrep rule binds by name only.
- `allow-list: literal-tables`: the shared allow-lists apply to this rule (section "Allow-lists").

### Guards

```yaml
guards:
  - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl
    arg: 0                       # the checked value: a parameter ordinal, or `this` (the receiver)
    clean-when: true             # true or false: the call's result on the branch where the value is clean
  - method: System.String.StartsWith
    arg: this
    clean-when: true
    when:                        # optional: every condition must hold at the call
      - assigned-from: System.IO.Path.GetFullPath   # the checked value is a local every assignment of which in
                                                     # the body is a call of this method
      - arg: 0                   # argument 0 carries no request data and its text matches the expression
        text: '[\\/]$'
  - method: Duende.IdentityServer.Services.IIdentityServerInteractionService.GetAuthorizationContextAsync
    arg: 0
    clean-when: not-null         # the (awaited) result, held in a local, is not null
```

`guards` take `method:` with `arg` and `clean-when`, all required, and `when:` (optional, a non-empty list).

The engine reads guards on the control-flow graph of each body: a block that ends in a condition gives each of its
two successors the state as the condition leaves it on that branch.

- A guard's call in the condition (alone, negated, either side of `&&` or `||`, a ternary's condition; the graph splits
  `&&` and `||` into blocks) makes the checked value clean for the guard's rule on the branch where the call returns
  `clean-when`. The value is a local or a parameter (or a flow capture that holds one), or a member read on one
  (section "Guards on members"); a call's result is not refined.
- The value is clean only on that branch: inside the failing branch it is the value that failed; where a failing
  branch that does not leave the method (no return or throw on every path) rejoins, the join is the unchecked value
  again; a value assigned anew after the check is whatever it is assigned.
- `when:` conditions: `assigned-from: T.M` holds when the checked value is a local whose every assignment in the body
  (its initializer too) is a call of T.M (through `await` and `ConfigureAwait`), and the local is written no other way
  (`ref`, `out`, `+=`, deconstruction); since Task 33 also when the checked value is a call of T.M written in place, or
  an assignment is a conditional (`c ? a : b`) each arm of which is a call of T.M, a string constant or a read-only field
  that holds no request data there. `arg: N, text: R` holds when argument N carries no request data and every text it may
  have matches R: the text built from constants, both sides of a string `+`, the text and holes of an interpolated
  string, `Path.DirectorySeparatorChar` and `Path.AltDirectorySeparatorChar` as `/`, any other value as U+FFFC; since
  Task 33 a local is each value it is assigned and a conditional each of its arms (at most 8 texts), and an arm `v` taken
  where `Path.EndsInDirectorySeparator(v)` (or `v.EndsWith('/')`, `'\\'`, the separator fields) holds reads as a folder
  and a separator (`EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar`). The parameters
  argument N carries (a helper given its root) stay in the checked value for the guard's rule: it is clean there as far
  as the caller's root is (section "Guards in project code").
- `clean-when: not-null`: where a null check (`x != null`, `x == null`, `x is null`, `x is not null`) says that a local
  x is not null, and x is assigned once in the body, from the (awaited) result of a call of the guard's member, that
  call's argument `arg` is clean for the rule, when it is a local or a parameter assigned nowhere after the call, or a
  member (below) that no write or call changed between the call and the null check.

The engine's own guard, for every rule: where a value is equal to a constant (`x == c`, `x != c` on its false branch,
`x.Equals(c)`, `string.Equals(x, c, ...)`, `x is c`, `x is c1 or c2`; `c` a literal, a `const` or `null`), the local or
parameter x is that constant: clean for every rule (`if (dir != "ASC" && dir != "DESC") return;` leaves dir clean).
Only for a string, char, number, bool or enum (or Nullable of one), with the built-in `==` (or System.String's) and
System.String's or a primitive's `Equals`: a user-defined `==` or an overridden `Equals` may compare anything and is no
guard (ruling R-E13).

### Guards on members

Every guard above (a model guard, the not-null guard, the equality guard, an allow-list's membership) also holds for a
member read on a local, a parameter or `this`: an access path `x.M`, `x.M.N` (up to four members; fields,
auto-properties, and properties of referenced assemblies that are not indexers; `x?.M` too; a static member's path
`T.M` as well). A property of the project with a getter body (computed, `Full => Base + Tail`, or backed by a field)
is no member guard: a write of what it reads would not end the fact; nor is a virtual, abstract or interface property
one of whose overrides or implementations has a getter body. On the branch where the check
holds, a read of that path is clean for the guard's rule (for every rule after an equality); the other members of x
keep their taint. `if (Url.IsLocalUrl(model.ReturnUrl)) return Redirect(model.ReturnUrl);`,
`if (!Sorts.Contains(dto.Sort)) return BadRequest();` and `if (req.Kind == "a" || req.Kind == "b")` are guards.

The engine keeps these as must-hold facts in its state: where branches meet, a path stays clean only if it is clean on
every one of them (a loop's head included: a write later in the loop's body reaches it through the back edge). A fact
ends at:

- an assignment of x (a local or parameter; a `foreach` taking the next element is one), x given as a `ref` or `out`
  argument, an increment of it;
- a write of any member on the path (`x.M = ...`, `x.M.N = ...`, `x.M++`, `ref x.F`, a collection write into it), on
  whatever object it is written: `alias.M = ...` ends the fact of `x.M` (an alias of x is not tracked, its member is);
- a call (or a setter that is not an auto-property's) that may change an object along the path. The choice, by type:
  the call's receiver or an argument (string, scalars, enums and delegates aside; a struct or tuple passed by value
  too) may reach an object of the type of the root or of a member on the path, of a type derived from it or one it
  derives from, of an interface it implements, or `object` or a type parameter. What a value reaches: its own type,
  an array's elements, a generic type's type arguments (`List<Form>`, `Dictionary<string, Form>`, `(Form, int)`), and
  the instance fields of the project's types (`new Holder(form)` then `holder.Reset()`). The walk goes at most three
  steps and 32 types; a value whose walk is cut off at either bound with types left may reach anything, so only past
  the bound does a call end every fact. A field typed `object`, `dynamic` or a type parameter is not followed, and a
  field typed an interface or a base class reaches only that type (not below). A struct of the project called in place
  is written. Every call
  ends the facts of static paths. A call given other objects (`_audit.NoteAsync(form.User,
  form.Remember)`, `_mail.SendAsync(new Notice(...))`, a `CancellationToken`, a `List<string>`) keeps them.
- a write through a `ref` local or a `ref`/`out` parameter, a dynamic call (`Reset(d)` with `d` dynamic, a dynamic
  member assignment), a call through a function pointer: every fact ends;
- an `await` of anything but a call made right there and given no task (`await pending`, `await Task.WhenAll(tasks)`):
  every fact ends, since work started earlier and given the object may change it while the method waits.
- A path gets no fact when a lambda or local function of the method writes its root or one of its members, calls a
  method on its root (or on an object read from it), or gives the root to a call or a constructor
  (`xs.ForEach(x => form.Reset())`, `Task.Run(() => Reset(form))`), or when a method-group delegate of the method is
  bound to it (`Action a = form.Reset;`): the delegate may run at any call.

The not-null guard on a member: its call records the path as given to it; the null check of the call's held result
makes the path clean only if that record survived every write and call in between.

Not covered (by design): a guarded path read through another variable (`var copy = x;` then `copy.M`: still request
data); a computed property of a referenced assembly whose inputs change (`UriBuilder.Uri` after a write of `Path`), or
whose getter computes a different value each time; work started before the check and not awaited (fire-and-forget,
`_ = ResetAsync(form);`) that changes the object while the method awaits something else later (concurrency is not
modelled); an object held in a field typed `object`, `dynamic` or a type parameter, or by an implementation or subclass
behind a field typed an interface or a base class (`new Outer(new FormHolder(form))` with `Outer.Holder` an
`IHolder`), changed by a call given the holder: the guard is kept (FN; following the project's implementations of such
a field through the call graph's dispatch is a follow-up). Follow-up: a callee that changes the guarded object through the heap
without being given it or an object whose type reaches it (the object kept in a static, or in a field typed `object`,
then changed there) is not seen (FN); the member writes the callee summaries already record (the heap writes of each
body, closed over its calls) could end the facts of the members a call may write.

### Guards in project code (Task 33)

Guards written the way projects write them, read by the engine for every rule (none needs a model entry):

- **Equality with a value.** Where `x == y` (or `x.Equals(y)`, `string.Equals(x, y, ...)`, the spans' `Equals`) holds,
  x's text is y's: x is clean for the rules y is clean for; where y carries no request data at all (a field holding
  server data, a value of the caller's), x holds what y holds (in a helper: what the caller gives for y; for a value
  that holds only what callers give, only when y holds the elements of a collection parameter, the shape of membership
  written as a loop: `foreach (var item in items) if (value.Equals(item, comparison)) return true;`, or the object's own
  state, `this` or a member read through it: `full.Equals(_root)` in a store's helper). A summary applied at a call site
  (below) changes an argument only for the rules where what it gives is no more than what the argument holds (request
  data for a rule only where the argument has some; no caller's value the argument does not hold, the object's own state
  aside): a server value compared with a collection the request fills stays the server's. The comparison
  given to `Equals` is not read (a culture-sensitive comparison may ignore characters no rule treats as special).
- **Stored data never vouches** (ruling R-E41). Equality with a value and every membership (below) read nothing a
  request may have stored: when the other side reads a field or auto-property of the project (directly, through a local
  assigned from one, or as the argument a guard summary compares with) to which some request wrote request data in any
  request, the comparison cleans nothing. Data written only at startup or from configuration (no request data) still
  guards. Within one request the heap is request-scoped (decision R-6), so without this a value another request stored
  (`Seen.Add(tag)`, `_last = v`) would look clean and vouch for the same text sent again. A containment check is no
  allow-list (ruling R-E41 refined): `x.StartsWith(root + separator)` and, joined to it by `||`, its "is the root itself"
  arm `x.Equals(root)` keep Task 11's rule for the root: a root the current request chose (request data where the check
  runs) never guards, a root stored earlier guards as configuration does (startup, tenant setup, admin settings). Cost:
  a containment root an attacker could have stored in an earlier request (an admin-level write) is trusted.
- **Fixed point.** `x == S(x)` with S a sanitizer of the models (`name == Path.GetFileName(name)`,
  `string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal)`) makes x as clean as S's result: a single
  segment, as the GetFileName sanitizer (`..` is such a segment too, as there: `Path.Combine(root, "..")` names the
  root's parent, so a recursive directory sink such as `Directory.Delete(Combine(root, name), true)` given `..` acts on
  the parent; the sanitizer has the same reach, a known limit, review M1 of Task 33).
- **Conditions as written.** `a || b` true and `a && b` false hold what both of their ways hold (the left side, and the
  right side after the left one had the other outcome; the join of the two). A bool local assigned once
  (`var allowed = full.Equals(root) || full.StartsWith(prefix); if (!allowed) throw ...;`) is read as its condition,
  for the locals and parameters that no code assigns after the assignment (nor a lambda), when the check comes after it
  and the condition writes nothing (no assignment, `out`, `ref` or await); a member's fact is not kept that way.
- **Containment.** Besides the extended `when:` conditions above, the path a checked full path was made of (the
  argument of `GetFullPath` written in place, or of every assignment of the checked local when they all take the same
  local or parameter, unchanged after each) is clean too: `var full = Path.GetFullPath(p); if (!full.StartsWith(root +
  "/")) return; File.ReadAllText(p);` reads the same file. Only the one-argument `GetFullPath(path)`:
  `GetFullPath(path, basePath)` resolves against another base than a sink given the path (the working directory).
- **Membership** (section "Allow-lists"): in a collection the server built and the request never wrote, and the
  searches of .NET's collections whose predicate compares the value with an element: `First`, `Single`, `Last` that
  returned (they throw on a miss), `Any`, `Array.Exists`, `List.Exists` true, `FirstOrDefault`, `SingleOrDefault`,
  `LastOrDefault`, `Array.Find`, `List.Find` not null (an element of a reference type; the result checked in place or held
  in a local assigned once), with a lambda `e => e.Key == key` (`==`, string's and the spans' `Equals`, either side of
  `&&`): the compared value is clean for the allow-list rules where the element side carries no request data (the element
  itself of a server-built collection, or fields and auto-properties of the project that no request wrote in any request:
  registered keys), and the collection searched carries nothing at the check (no request data and no value a caller
  gives; a field of the object's own state only as that field) and is read from nothing a request wrote in any request:
  a posted list searched for a posted code proves nothing (review C1).
- **Guard summaries.** A project method returning bool records, for each parameter it never assigns (passed by value,
  not a scalar), what the parameter holds where it returns true and where it returns false (a returned condition read as
  written): `bool IsInside(string root, string p)` returning `GetFullPath(p).StartsWith(root + "/")` says p is clean for
  path traversal where it returns true, as far as root is; a wrapper of a guard (`CheckIsLocalUrl(url) => url != "" &&
  RedirectHttpResult.IsLocalUrl(url)`) is that guard. A call's branch of that outcome gives each argument (a local, a
  parameter or a member path) what the summary says, with the caller's arguments in place of the callee's parameters.
- **Exit summaries.** Every project method records what such a parameter holds at its normal exits: a method that
  throws unless its check holds (`EnsureInside(p)`, a lookup whose `First` throws on a miss) cleans its argument after the
  call; one that returns early on a failing check does not. An iterator records none (it runs nothing when called); an
  async method's exit is where its task completes, so it applies only to a call awaited right there (`await
  EnsureAsync(p)`, also through `ConfigureAwait`), not to `_ = EnsureAsync(p);` or a task awaited later.
- Both summaries apply only when every target of the call (Dispatch) is such a body outside the caller's component of the
  call graph (a recursive helper's summary is not final while its component runs): a wrapper behind an interface one of
  whose implementations does not check is no guard.
- **Provenance** (Task 35). A check that makes a local or parameter x of a type compared as text (a string, a char, a
  number, a bool, an enum; not a Uri, whose Equals ignores the user info and the fragment) one of the server's values (equal to a constant
  or to a value that carries nothing, a member of an allow-list or a server-built collection, a key a search found
  among the registered ones) also holds for a local computed from x alone before the check: `var file = FileOf(key);`,
  then `key` looked up and the lookup's miss thrown, then `file` read. The local is assigned once (nothing else writes
  it, no lambda; a `ref` local or ref assignment that takes x or the local counts as a write), before the check; what
  it is assigned reads x (or a local so computed before it), unchanged since, and every other part of it is provably
  free of request data, so that all of its request data comes through x (review C1 of Task 35; the request data being
  "from x's sources" is only a second check, since another part of the same request value enters at the same source):
  - constants, `this`; locals and parameters unchanged since that hold no request data and none of x's labels;
  - fields and auto-properties of the project no request wrote request data to in any request, of a type the heap
    tracks: a string, a scalar, an enum, or a project type. A builder, an AsyncLocal, a collection, an array or any
    other type of .NET can be filled by a request with no write of the member (Append, a Value set, an alias of the
    request store), so a read of one, whether as a receiver or as a value given on, ends the derivation (re-review 2);
  - a project property with a getter body (also an interface's, an abstract one, an indexer), as a call of its getter;
  - members of .NET, properties, indexers and methods: static ones, properties giving a scalar, and instance ones
    read or called on x (or such a local) or a constant. Any other receiver may hold another part of the request and
    is no part of a derivation: `this`, a field, the request's members (`HttpContext.Items[...]`, ViewData), and a
    static field or property, since what a request puts into the object it holds (a builder's Append, an AsyncLocal's
    Value, an alias of the request's item store) is no write of the field (re-review I1);
  - calls of project bodies (each target outside the caller's component) whose summary returns no request data of
    their own and which read, themselves and through the calls and getters they make (four levels), no heap member
    some request wrote request data to (nor one of a type the heap does not track), no member of .NET but static ones and those on their own parameters, locals or
    constants, and make no delegate, dynamic or project constructor call (what each body reads is collected once per
    run; the heap's request writes are asked at each use);
  - no lambda, await, assignment, object creation or dynamic call.
  - no project value handed to .NET code that may run its overrides (re-review 3): a project-typed value converted to
    `object` or a .NET interface (`string.Concat(obj)`, `"x" + obj`, a boxing argument), an interpolation hole of a
    project type, or a .NET method argument whose type mentions one (`string.Join<T>`): .NET may call a ToString
    or Equals override the walk does not follow.

  It is cleaned as x is, in x's part only: its request data and x's labels (what a caller gives for another parameter
  stays, so a helper given a request folder still reports). A containment or a sanitizer's guard gives nothing to derived values: a
  path below the root with `..` added is not below it.
- **The root itself, answered apart** (Task 35). In a body that checks `x.StartsWith(prefix)` with the prefix built from
  a root (a field, local or parameter, also as `GetFullPath(root)` written in place), where x is a full path (the
  containment guard's `assigned-from`), `x == root` (any equality form) holds x as the root itself, whether it is joined
  to the check by `||` or answered by an early `if (full.Equals(top)) return true;`: x, and the path its one-argument
  GetFullPath was given, are clean for path traversal as far as the root is (Task 11's rule, ruling R-E41 refined): a
  root holding this request's data cleans nothing, what a caller gives for the root stays for path traversal (a guard
  summary's call site decides), a root stored earlier guards. A caller's full path given to such a helper is normalised
  again there, which names the same file. An equality with a value no containment check of x uses is equality with a
  value (above, R-E41 applies).
- **No directory separator** (Task 35). Where a search for directory separators found none, the local or parameter
  searched is one path segment, as Path.GetFileName leaves it: clean for path traversal (the rules GetFileName is a
  sanitizer of). The searches: `IndexOf` and `IndexOfAny` of System.String, and MemoryExtensions' on a span (`AsSpan()`
  of the value too), compared with a constant so that the branch admits no index of a match (`>= 0` false, `< 0`,
  `== -1`); `Contains` and `ContainsAny` false. `IndexOf` and `Contains` look for one character (a char or a
  one-character string constant: a longer string is a substring); a search from a start index or of a count checks part
  of the value only and is no guard. A comparison given (`StringComparison`) must be `Ordinal` or `OrdinalIgnoreCase`
  (review I1 of Task 35): a culture's comparison takes a separator followed by a combining mark as one text element and
  does not find it (`"../\u0301x".IndexOf("/")` is -1 on ICU, and the path names the parent), so `IndexOf(string)`
  without a comparison (the current culture) and any culture or invariant comparison are no guard; `Contains(string)`,
  `Contains(char)`, `IndexOf(char)`, `IndexOfAny` and the span searches without a comparison are ordinal. The
  separators: the constants '/' and '\', a string constant's
  characters, Path.DirectorySeparatorChar and AltDirectorySeparatorChar, Path.GetInvalidFileNameChars() (it holds the
  platform's separators; GetInvalidPathChars does not), given in place (an argument, an array or collection expression).
  Both separators of a platform that has two must be absent on the branch (Windows: '\' and '/'): one search may find
  both, or two searches one each (`if (x.Contains('/') || x.Contains('\\')) throw ...;`), the value unchanged between
  them (each records a must-hold fact on the variable; an assignment ends it, a join keeps it only where every
  predecessor has it). A check of DirectorySeparatorChar alone is no guard (on Windows `/` separates folders too). Like
  GetFileName's result, `..` is such a segment; on Windows a check of the two separators alone also admits a
  drive-relative `C:name` (BACKLOG.md `csharp.path-traversal#no-separator-segment`). Nothing is cleaned in a value
  computed from x before the check.
- **Element reads and stored data** (Task 35). The stored-data check (R-E41) reads an element read's collection, not its
  index: `names[n]` in a loop `for (int n = 0; ...; n++)` is the collection's data, whatever the counter (written by
  `n++`) selects, so membership written as a counting loop over a server collection is a guard summary as the `foreach`
  form is.

Not covered (FN, by design): a separator search given a collection held in a variable or a field
(`IndexOfAny(_invalid)`), `SearchValues`, or a search through a call (`x.ToLowerInvariant().Contains('/')`); a value
derived before a separator or containment check; a lambda given to an external member whose delegate binding is not
known (below, "Delegate parameters") gets the call's receiver and every argument in each of its parameters, so a guard
inside it may see a caller's value in the collection it searches; a helper's result that is not a bool (a found object checked for null by the caller; a
`Task<bool>` or `ValueTask<bool>` awaited, `if (await IsSafeAsync(p))`; a `bool?`); a
comparison through a project comparer or `string.Compare(...) == 0`; a bool local assigned more than once or written in a
lambda; a predicate that is a method group or compares through a call; a member path's fact through a bool local;
membership in a collection a caller gives (a parameter), unless the helper compares element by element (above); a
dictionary whose keys a caller's helper writes or that is copied from another dictionary (keys are not request data in a
dictionary's value, ruling R-E21; the Keys location covers the keys written into a field's dictionary directly).
Over-approximations (FP) are unchanged: a guard is never assumed where these conditions fail.

### Model validation

Task 31, decision R-12, rulings R-E33 and R-E34: a value model binding validated is clean for the rules its validation
attributes leave no character for, where validation is known to hold. From Microsoft's documentation only
(learn.microsoft.com: System.ComponentModel.DataAnnotations, ASP.NET Core "Model validation" and "Create web APIs");
`sources.yml` (7) names the types, each taint rule's `validation:` its characters.

```yaml
validation:                      # optional, a taint rule
  metacharacters: '[/\\:\p{Cc}]' # one .NET character class: the characters a value needs to inject into the sinks
validation: never                # or: no validation attribute cleans the rule ([Range] and enums neither)
```

What an attribute on a bound member of type string cleans (several attributes on one member all hold; their rules are
united). Members of enum and number types are clean already (`scalars`).

| attribute | cleans | why (documentation) |
|---|---|---|
| `[Range]` with a numeric operand (`int`, `double`, or `typeof` a number type) | every rule but `validation: never` | "Specifies the numeric range constraints"; a string value is converted to the operand type first. The accepted text is a number's in a loose sense: surrounding whitespace, a sign, group separators, an exponent, a trailing line break or NUL, hex forms with a `typeof` operand (" 5", "-5", "1,000", "1E+2", "0x10"); no quote, no letter run. A range over another type (a date) cleans nothing. |
| `[EnumDataType(typeof(E))]` | every rule but `validation: never` | the value names the enum's values: names, numbers, spaces and commas ("Top, Middle", "3"). |
| `[RegularExpression]` | the rules whose metacharacters its alphabet does not hold | "The regular expression searches for an exact match, not using `^` before and `$` at the end of the pattern produces the same results as using it" (ruling R-E33): the whole value is matched, anchored or not, so its characters are the ones the pattern's consuming parts admit (below). |
| `[EmailAddress]`, `[Url]`, `[Phone]` | nothing | the documentation says only that the value "has an email format" (a URL, a telephone number format) and names no alphabet. |
| `[StringLength]`, `[MaxLength]`, `[MinLength]`, `[Required]` | nothing | length and presence only. |

A pattern's alphabet (RegexAlphabet): the union of what its consuming parts match (literal characters, escapes naming
one, character classes and class escapes, `.` as any character), read with .NET's Regex on each UTF-16 code unit, both
case-sensitively and case-insensitively (the union: a negated class keeps what its case-insensitive reading drops, a
named letter brings its case partners; the tr/az dotted and dotless i are not read, and no set holds them). Anchors,
quantifiers, alternation and the contents of lookarounds consume nothing (a lookaround's parts count when the pattern
holds a backreference: `\1`, `\k<name>`, or the legacy `\<name>` and `\'name'`). A class subtraction needs an unescaped
`-` before its `[`. A pattern in the free-spacing mode (`(?x)`), a conditional, a pattern that does not parse, or one
with a part that matches no single character (a misread) cleans nothing. Only the attribute classes themselves count (a
derived attribute may validate otherwise).

The metacharacters, per rule (each model file says why):

- sql-injection: quotes and backquote with the Unicode apostrophe look-alikes a best-fit code page conversion may map to
  a quote, backslash, comment and statement markers, whitespace and control characters, parentheses, operators, commas,
  brackets, braces, `@ ? : $`;
- command-injection: `validation: never` (ruling R-E34): a token of letters can name the program to run, and the text
  [Range] and [EnumDataType] accept carries signs, separators and spaces (an option or another argument);
- path-traversal: `/ \ :` and control characters (a value without them is one segment, as Path.GetFileName leaves it,
  `..` included);
- ssrf: everything but an ASCII digit (letters can name an internal host);
- open-redirect: `/ \ : . @ % ? #`, whitespace and control characters and the Unicode dots and slashes browsers map to
  them;
- xss: angle brackets, quotes and the backquote, `& = ( ) [ ] { } : ; \`, whitespace, control characters, U+2028/U+2029;
- ldap-injection: the specials of RFC 4515 and RFC 4514, `/`, control characters;
- xpath-injection: quotes, brackets, parentheses, `/ | = < > @ * : , . ! $`, whitespace and control characters;
- regex-injection: the pattern metacharacters, `#`, whitespace and control characters.

A rule without `validation:` (the misuse rules' taint forms) is cleaned by `[Range]` and enums only.

Which values are validated: in a controller action or a Razor Pages handler, its source parameters (their own
attributes: "Model-bound top-level nodes are validated"), the member paths below them ("ValidationVisitor traverses the
object graph": public properties of the project's classes and structs, recursively, up to four members and 32 paths;
not into collections, whose elements the documentation does not say are validated member by member), and the bound
properties of the controller or page model and the paths below them; at most 32 paths per action (half the member facts
a state holds, so the body's own guards keep room). `[ValidateNever]` on a parameter, a property (or one it overrides)
or a type (or a base class: the attribute is inherited) leaves it out.

Where validation holds:

- On the branch where `ModelState.IsValid` (ModelState read on `this`) or `TryValidateModel(...)` ("true if the
  ModelState is valid") is true: through `!`, `&&`, `||` and `== true`/`!= false`; not through a local holding the result
  (`var ok = ModelState.IsValid;`). The validated paths get member facts (Guards on members) at the entry, pending until
  the check: a write of the member, an assignment of its root, or a call that may change the object between the entry
  and the check ends the fact, so the check does not clean it. A validated parameter is cleaned only if the body assigns
  it nowhere. TryValidateModel's model (a parameter, a local built in the action, a property of `this`) gets the facts of
  its own paths at the check.
- Only while ModelState is as validation left it (a validity fact from the entry, review C2): the check cleans nothing
  after the action's ModelStateDictionary (`ModelState`, `ViewData.ModelState`, ...) is used otherwise than by a member
  of `keeps-validity` (reads, AddModelError, which can only make it invalid): `Remove`, `Clear`,
  `ClearValidationState`, `MarkFieldValid`, `MarkFieldSkipped`, `SetModelValue`, an entry taken through the indexer or
  `TryGetValue`, the dictionary given to a call or held in a variable. A project method called on `this` (or given it, or
  given an object that holds ModelState: an ActionContext such as ControllerContext, ViewContext or PageContext, a
  ViewDataDictionary) and `TryUpdateModel(Async)` end it too, and a lambda or local function of the action that does any of this keeps it
  from the start. `await` of earlier work ends it as it ends every member fact.
- Throughout an action of an `[ApiController]` controller (on the class, a base class, or `[assembly: ApiController]`):
  "model validation errors automatically trigger an HTTP 400 response", so the action runs only with a valid model. Its
  validated parameters are clean at the entry and its validated paths start with cleaning facts. Not for a Razor Pages
  handler (the attribute is a controller behaviour; a page model carrying it too), and not when the source anywhere
  assigns `SuppressModelStateInvalidFilter` (other than `= false`, "To disable the automatic 400 behavior") or
  `InvalidModelStateResponseFactory` (the factory decides the response), or binds `Configure<ApiBehaviorOptions>(...)`
  from anything but a lambda (configuration may set the option): then only the IsValid check counts.

Only the framework's call is validated (review C1): an action or handler that project code calls, or takes a method
group of (the call graph's edges, dispatch included: `return Details(id)`, `Save(new Basket { Code = raw })`, a public
controller helper), gets no validation at all, since such a caller passes values binding never saw and its ModelState
is the caller's request's (Task 27 gives a bound parameter its own object, so a caller's object members could not be
told apart from the binding's). Besides, validation cleans a value's request data only (TaintValue.RequestCleanedFor;
a member fact's `Validated` rules), never its labels, what a caller would pass. TryValidateModel's own model facts are
whole guards: that call validates the object in every run.

After validation the facts follow the rules of Guards on members: a write of the member (or of its root), a ref or out
use, or a call that may change the object ends them.

Not covered (the values stay request data, the safe side): IValidatableObject, custom ValidationAttributes,
FluentValidation and other validation libraries; [ModelMetadataType] buddy classes; Minimal API handlers (no automatic
validation in ASP.NET Core 8); a validated member read in a callee given the model (the facts are the action's own: the
model object passed on is whole-object request data); elements of collection members; the check held in a local.

Not covered (FN side): the automatic 400 turned off another way: the option set in a referenced binary or through
another configuration API than `Configure<ApiBehaviorOptions>`, the invalid-model filter removed by hand, or a filter
that rewrites the action's arguments after it; a project method that changes ModelState without being called on
`this` or given it, nor given an object that holds ModelState (a static helper reaching the controller through the
heap, a helper keeping the controller from its constructor, a service reading the request's ActionContext through
IActionContextAccessor).

Known cost: a value of one token (letters, digits, `_`) placed into a statement without quotes may still name another
column, keyword or node (`//user[id=id]`; ruling R-E33); digits clean ssrf and open-redirect as an int parameter does,
though a host can be written as one decimal number (`http://2130706433/` is 127.0.0.1) and digits can choose a port
(ruling R-E34); the alphabet does not see sequences (`^-?\d+$` holds `-`, so it does not clean sql-injection, whose
`--` needs two).

### Allow-lists

`allow-list: literal-tables` (the shared C# allow-lists of the OpenGrep rules) makes these clean for the rule:

- a **table** is a `static readonly` field declared in source that no other assembly can reach (it, or a type that
  holds it, is private or internal), of .NET's own collection type (an array, or a type of System.Collections.Generic,
  System.Collections.Frozen or System.Collections.Immutable: not a project's subclass, whose Contains may mean
  something else; not a concurrent collection), whose initializer is a collection of constants written in place: an
  array (`{ "eu", "us" }`, `new[] { ... }`), a collection expression, or a `new` of such a type whose constructor
  arguments are constants or .NET's own comparers (`StringComparer.OrdinalIgnoreCase`) and whose initializer holds
  constants (`{ "ASC", "DESC" }`, `{ ["name"] = "name" }`, `{ { "a", "b" } }`); its elements may be literals or
  `const`s, verbatim or not.
- and **every use** of the field in its class's files (a private field) or its project's files is a known read: the
  receiver of a member of .NET's collections that only reads (Contains, ContainsKey, ContainsValue, TryGetValue,
  GetValueOrDefault, IndexOf, BinarySearch, Exists, Find*, TrueForAll, GetEnumerator, ToArray, ToList, the set
  comparisons, Count, Length, Keys, Values, an indexer or element read that is not written or taken by `ref`),
  argument 0 of System.Linq.Enumerable's methods, of Array.IndexOf/LastIndexOf/BinarySearch/Exists/Find*/TrueForAll,
  of CollectionExtensions.GetValueOrDefault, an argument of string.Join or Concat, a `foreach` collection, `nameof`.
  Any other use (assigned to a variable or a field, passed to another method, cast, `AsSpan()`, written, `ref` or
  `out`) may change it, and the field is no table (ruling of the Task 11 review, I2). A field of another project is no
  table.
- **lookups**: an element read by the table's indexer; `GetValueOrDefault(key)` and `GetValueOrDefault(key, d)` (the
  value of `d` itself still counts); the `out` value of `TryGetValue`.
- **membership**: where `T.Contains(x)`, `T.ContainsKey(x)` or `T.TryGetValue(x, out ...)` holds (the extension
  method, also called as a static `Enumerable.Contains(T, x)`, and on the table's `Keys` or `Values`; a comparer given to
  it must be one of .NET's own), x is clean, as a guard (above): the branch of an `if`, the code after `if
  (!T.Contains(x)) return/throw ...;`, a ternary `T.Contains(x) ? x : "fallback"`.
- **server-built collections** (Task 33; ruling R-E41): membership also cleans x in a collection the server built that
  no request wrote: a field declared in source of .NET's own collection type (not `static` or `readonly` necessarily) that no other
  assembly can reach, every use of which is a known read (above), a removal (`Remove`, `Clear`, ...), an assignment of the
  whole collection from a known build, or, in a constructor of its type, a write into it (`Add`, an indexer set); and no
  request data was ever written to it (the heap, in any request: data another request stored there would defeat the
  check), nor, searched by key, to a dictionary's keys (recorded apart, KeysLocation, since a dictionary's value does not
  carry its keys: ruling R-E21). A local qualifies when every use of it in its method is such a read, removal or
  assignment, or (no dictionary) a write into it, its value holds nothing at the check and what it was built from reads
  nothing a request wrote in any request (`var copy = Seen.ToList()` with `Seen` written by another request is none;
  ruling R-E41). A known build: an array or a
  collection expression; a `new` of .NET's collection type whose comparers are .NET's own (for a dictionary: given no
  other collection, an initializer of constant keys); .NET's `ToArray`, `ToList`, `ToHashSet`, `ToDictionary`,
  `ToFrozenSet`, `ToFrozenDictionary`, `ToImmutable*`, `Create*` with .NET's comparers (a dictionary only from a key
  selector given there), `Array.Empty`, an `Empty` member. So `_formats = new HashSet<string>(naming.Extensions,
  StringComparer.OrdinalIgnoreCase)` in a constructor and `_stores = factories.SelectMany(f => f.Stores()).ToArray()`
  are allow-lists while nothing writes request data into them.
- **.NET's own comparers** (review I4 of Task 33): only those that tell every character apart, so that a value "in" the
  collection is one of its texts (case aside): `StringComparer.Ordinal`, `OrdinalIgnoreCase`, `InvariantCulture(IgnoreCase)`,
  `CurrentCulture(IgnoreCase)`, `StringComparer.FromComparison(...)`, `StringComparer.Create(culture, ignoreCase)`,
  `StringComparer.Create` and `CompareInfo.GetStringComparer` with constant options `None` or `IgnoreCase`,
  `EqualityComparer<T>.Default`, `Comparer<T>.Default`. A comparer that ignores symbols (`CompareOptions.IgnoreSymbols`
  calls `../etc/passwd` equal to `etcpasswd`), or any other, is no guard.

### Conditional sinks (`when:`)

A sink with `when:` applies only where every condition of its list holds (each item names one kind):

```yaml
  - method: System.Diagnostics.Process.Start
    args: [1]
    param-types: [System.String]
    when:
      - arg: 0                       # argument 0 may be a constant matching the expression:
        matches: '(?i)^(.*[\\/])?(sh|bash|cmd)(\.exe)?$'   # a literal, a const, a local assigned constants, ?: or ??
      - literal-text: '(^|\s)-c(\s|$)' # the argument's literal text matches, or it has none
  - property-set: System.Diagnostics.ProcessStartInfo.Arguments
    when:
      - property: FileName           # the object written to has FileName set to a matching constant
        matches: '(?i)^(.*[\\/])?(sh|bash|cmd)(\.exe)?$'
  - method: System.Collections.ObjectModel.Collection`1.Add
    args: [0]
    when:
      - receiver: System.Diagnostics.ProcessStartInfo.ArgumentList   # called on this property: the object is its owner
      - property: FileName
        matches: '(?i)^(.*[\\/])?(sh|bash)$'
      - after: '^-c$'                # an element after one matching the expression
        next: true                   # right after it (without: anywhere after it)
```

| condition | holds when |
|---|---|
| `arg: N`, `matches: R` | argument N (parameter ordinal) may be a constant that matches R: a literal or a const, a local assigned constants in the body, both branches of `?:` and `??`. A value that is no constant (a parameter, a call) matches nothing. On a property-set sink that is an indexer, N is the indexer's argument (`headers["Location"] = x`). |
| `arg: N`, `is: T.F` | argument N reads the field or property T.F (`HeaderNames.Location`, a `static readonly` field whose value the engine cannot read). |
| `property: P`, `matches: R` (`of: N`) | the object the sink acts on has its property P set to a constant that matches R anywhere in the body, before or after the sink: an assignment `x.P = c`, an object initializer `{ P = c }`, or a constructor parameter named P (ignoring case: `new ProcessStartInfo("sh")` sets FileName). P may be a path (`StartInfo.FileName`: FileName of the object's StartInfo, Task 29); a local assigned `Process.Start(info)` or `Process.Start(fileName, ...)` once in the body has that info as its StartInfo, or that FileName (and arguments); a member assigned a local that holds one object creation (`p.StartInfo = psi`, `new Process { StartInfo = psi }`) is that object. A `receiver:` held in a local assigned once in the body (`using (var input = p.StandardInput)`) is the property it was assigned. With `unless: R` instead of `matches`: no constant P is set to matches R (also when P is never set; a value that is no constant matches nothing). The object of a property-set sink is the object written to; of a method sink its receiver (an extension method's `this`), the created object for a constructor; `of: N` takes argument N instead. Objects are told apart by access path (`psi`, `p.StartInfo`, `this.Response`, `context.Response`); a variable assigned exactly one object creation in the body is that object (one reused for a second object is neither). |
| `literal-text: R` | the sink argument is no collection written in place, and its literal text matches R or it has none (a variable or a call's result, whose text the engine does not follow). The literal text is the strings the argument is built from in place: constants, both sides of a string `+`, the text and holes of an interpolated string, both branches of `?:` and `??`, the arguments of `string.Format`, `Concat` and `Join`; each string is matched by itself. |
| `after: R` (`next: true`) | for a sink argument written in place as a collection (an array or a collection initializer, `new[] { "-c", x }`, `new List<string> { ... }`, a collection expression): the sink is each element after one that may be a constant matching R (with `next`: the element right after it), reported where that element is; the sink does not apply when no element qualifies. For an `Add` call: the earlier Adds to the same collection (an access path, also the Adds of a collection initializer `ArgumentList = { "-c", x }`), in source order, must hold such an element. Otherwise the condition does not hold. |
| `receiver: T.P` | the call's receiver (for a property-set sink: the object written to) is property P of T (also through a nested collection initializer); the object of `property:` conditions is then the object that holds P. |
| `outside: T.M`, `until: T.N` | the sink's statement is not in a region a call of M opened and no call of N has closed yet: the nearest of the two calls among the statements before it in its block (then before each enclosing statement in its block, up to the body; a lambda or local function is a body of its own) is not M. The calls are statements of their own (`M();`, `x = N();`). |

The conditions read the body's code flow-insensitively (a constant set after the sink counts too), so a property set
to a shell in one branch and to another program in the other (`if (a) { psi.FileName = "bash"; ... } else {
psi.FileName = "git"; psi.Arguments = q; }`) counts as a shell in both (a known false positive). The expressions
are .NET regular expressions; write `(?i)` for case-insensitive matching.

## Misuse rules (`kind: misuse`)

A misuse rule reports a dangerous call, setting or callback wherever it is, whatever the data (no sources, no taint):

```yaml
rule: csharp.xxe
kind: misuse
misuse:
  test-code: ['test/', 'tests/', '*.Tests/', '*Tests.cs']   # required: the files the rule skips
  calls:                         # optional: a call of the method (a read of the property) is a finding
    - method: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize*
    - property-get: System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
  enum-values:                   # optional: a constant of the enum written to a field or property
    - type: Newtonsoft.Json.TypeNameHandling
      safe: [None]               # the enum members that are no finding
  values:                        # optional: what the value given to a member must be to be a finding
    - property-set: System.Xml.XmlReaderSettings.XmlResolver   # the assigned value
      created: [System.Xml.XmlUrlResolver]   # a creation of one of these types
      with: { property: DtdProcessing, values: [Parse] }       # optional: the object also has this set
      at: object                 # optional: report an initializer's assignment at the object's creation
    - property-set: System.Xml.XmlTextReader.XmlResolver
      created: [System.Xml.XmlUrlResolver]
      without: { property: DtdProcessing, values: [Prohibit, Ignore] }   # optional: ... never has this set
    - method: System.Net.Security.SslStream..ctor
      args: [2]                  # a method's or constructor's arguments (parameter ordinals)
      accepts-all: true          # a callback that accepts all (below)
  accepts-all-methods: System.Net.Security.SslPolicyErrors   # optional (below)
```

- `test-code`: the rule's OpenGrep `paths: exclude`, copied (a test checks the two lists are equal; COVERAGE.md
  "Test code"). A file is skipped when its path, relative to the scanned directory, matches one: a glob ending in `/`
  names a directory at any depth, any other glob a file or directory name at any depth; `*` is any characters, case
  matters. The scanned directory is the engine's source root (`TaintEngineOptions.SourceRoot`); without one, the
  nearest directory above the file that holds `.git`.
- `calls`: `method:` (a constructor too: `T..ctor`) or `property-get:` entries, matched as in "Matching" (by the
  receiver's type, wherever the object comes from). Reported at the member's name (`.Deserialize`), a constructor at
  its `new`.
- `enum-values`: a constant of the enum type (its value: a member, a `const`, a cast number) that is none of the
  `safe` members, written to a field or property of that type (or Nullable of it): an assignment, an object
  initializer, an attribute's named argument (`[JsonProperty(TypeNameHandling = ...)]`), a field or property
  initializer. A `const` declaration is no setting; where the const is written is. A value in a variable or a
  parameter is not known. Reported at the assignment (the named argument, the initializer's value).
- `values`: the value given to the member: a `property-set:`'s assigned value (`=`, `+=`, `??=`, an object
  initializer's, a nested one's: `SslOptions = { RemoteCertificateValidationCallback = ... }`), or the `args` of a
  `method:` (also a constructor; `D..ctor` of a delegate type D is `new D(x)`, x at 0). Exactly one of:
  - `created: [T, ...]`: the value may be a creation of one of these types (exactly the type: any constructor, with
    or without an object initializer and parentheses);
  - `accepts-all: true`: the value may be a lambda or anonymous method that accepts all (below). A method group is
    not (its declaration is, under `accepts-all-methods`).

  The value "may be" what it is directly, through conversions, both branches of `?:` and `??`, a delegate creation's
  target, and a local's values: its initializer and the values assigned to it anywhere in the body (flow-insensitive),
  unless it is also written another way (`ref`, `out`, a compound assignment, `++`, a deconstruction). A parameter, a
  field or a call's result is not followed.

  For a `property-set:` only: `with: { property: P, values: [...] }` holds when the object written to has its
  property P set, anywhere in the same body (flow-insensitive), to a value that may be one of these enum members
  (a constant or a local holding one); `without:` holds when it never is. The object is told apart by access path, as
  for the conditional sinks' `property:` (a variable assigned exactly one object creation is that object; an object
  initializer's object is the created one). `at: object`: an assignment in an object initializer is reported at the
  object's `new`; otherwise a value is reported at the assignment (or the argument).
- `accepts-all-methods: T`: a method or local function with a parameter of type T that returns bool and accepts all,
  reported at its name (where it is declared, whether or not it is wired in).

A callback **accepts all** when every `return` of its own body (not those of nested lambdas and local functions)
returns an always-true value, there is at least one, and the body has no `throw` (a statement or an expression): a
constant `true`, `a || b` with either side, `a && b` and `c ? a : b` with both sides always true. A log line or an
`if` that only logs does not hide it; a callback that returns `errors == SslPolicyErrors.None` or `false` on errors,
or throws, accepts nothing.

## `sources.yml`

Every key is required, except `validation`.

| key | what is a source |
|---|---|
| `controllers` | The parameters of a controller's actions. A class is a controller when it derives from one of `bases`, when one of its base classes has a name ending in one of `base-name-suffixes`, when it derives from `System.Object` only and its own name ends in one of `name-suffixes`, or when it or a base class carries one of `class-attributes`; never with one of `not-class-attributes`. Actions: its methods (`public-methods-only`: the public ones) without one of `not-method-attributes`. |
| `razor-pages` | The parameters of a page model's handlers: methods (`public-methods-only`) whose names start with one of `handler-prefixes`, in a class derived from one of `bases`. |
| `bound-properties` | A property with one of `property-attributes`; every public property of a class with one of `class-attributes`. |
| `minimal-api` | The parameters of one of `source-types` (or `Nullable` of one) of a handler (lambda, local function or method group) given to one of `map-methods` (method names, no `*` needed). Optional `body` (Task 34): the complex-type parameters bound from the request body, below. |
| `binding-attributes` | A parameter with one of these attributes, in any method, local function or lambda. |
| `not-source-attributes` | A parameter with one of these attributes is never a source (a DI service). |
| `parameter-types` | The types that are never sources in `controllers`, `razor-pages`, `bound-properties` and `binding-attributes`: `scalars` (and `Nullable` of them), arrays and `scalar-collections` of them unless the element is one of `not-scalar-elements`, enums when `enums-are-scalar`, `not-source-types`, and interfaces (DI services) when `interfaces-are-services`, except `source-interfaces`. |
| `members` | Reads that are sources: `property-get:` and `method:` entries (the call's value). |
| `validation` | Optional (Task 31): model validation as a sanitizer, section "Model validation": `model-state` and `is-valid` (the action's `ModelState.IsValid`), `try-validate`, `api-controller-attributes`, `suppress-option`, `not-validated-attributes`, and the attributes `range`, `regular-expression` and `enum-data-type`. |

### Minimal API body binding (`minimal-api: body:`, Task 34)

A Minimal API handler's parameter without a binding attribute is bound by the precedence of
learn.microsoft.com aspnet/core/fundamentals/minimal-apis/parameter-binding ("Binding Precedence"): an explicit attribute,
the special types (`special-types`), a type with a static `BindAsync` (or `IBindableFromHttpContext<T>`), string or a type
with a static `TryParse` (or `IParsable<T>`: route or query), a service the container provides, and last the body. The
engine takes the parameter for the body (request data, a bound object like a controller action's model) when:

- the handler is given to one of `map-methods` (MapPost, MapPut, MapPatch), or to `verbs-method` (MapMethods) with an
  HTTP method outside `no-body-verbs` ("GET, HEAD, OPTIONS, and DELETE don't implicitly bind from body"; a verb named by
  a constant or a static field of `verb-fields`, HttpMethods.Options; a list that is not written in place counts as one
  that may bind it);
- its type is not a special type, not a never-source type (`parameter-types`: scalars, enums, interfaces, ...), has no
  static `BindAsync` or `TryParse`, and is not a service;
- its type is declared in the solution (a class, record or struct, not abstract or static), an array or one of the
  `parameter-types` collections whose element is text or such a type, or one of `library-body-types` (or derived from
  one). Any other library type (a SqlConnection, LinkGenerator, an HttpClient) is taken for a service the framework
  registers.

A service is a type derived from one of `service-bases` (EF Core's DbContext) or a type a registration in the solution
names: a type argument or a `typeof` argument of a call whose receiver, or an extension method's `this`, is one of
`registrars` (IServiceCollection, IHostApplicationBuilder: `AddScoped<T>()`, `AddDbContext<T>()`, a provider's
`builder.AddXxxDbContext<T>(...)`, a project's own `AddStore<T>(this IServiceCollection)`), of a member of
`registration-types` (ServiceDescriptor), or a `typeof` given to a ServiceDescriptor constructor. The service and the
implementation type count alike (the safe side for noise). The scan binds only the calls whose type arguments or
`typeof` arguments name a body candidate by its simple name, after every project's handlers are known. OpenGrep takes no
such parameter for request data (it cannot tell it from a DI service without types).

## `propagators.yml`

```yaml
propagators:
  - method: System.String.Concat           # defaults: from [this, args] to [return]
  - method: System.Text.StringBuilder.Append*
    from: [args]
    to: [this, return]
  - method: System.Collections.Generic.IDictionary`2.TryGetValue
    from: [this]
    key: [0]
    to: [out]
unmodelled-external: string-or-collection-return
```

- `from`: `this`, `args` (every argument but `out` ones) or parameter ordinals; `to`: `return`,
  `this`, `out` (the `out` and `ref` arguments) or parameter ordinals. Defaults: a method from
  `[this, args]`, a constructor from `[args]`, a property read from `[this]`; to `[return]`.
- `key`: parameter ordinals of a lookup key (not in `from`, which then has no `args`): the key reaches a `return` or
  `out` value only when that value's type can carry an injection by itself (ruling R-E18): a string-like type, a scalar
  of `sources.yml` (a number, bool, char), a JSON value (`JToken`, `JsonNode`, `JsonElement`), an array or
  `IEnumerable<T>` of those (`StringValues`, `List<string>`, `string[]`), also a Task's result; `dynamic` and a type
  parameter count (it may be one), unless a constraint rules every carrier out: a class other than `string`, `object`,
  `ValueType` and `Enum` (`where T : Entity`), or an interface declared outside the System namespaces (`where T :
  IPlugin`; `IComparable`, `IEquatable<T>`, `IConvertible` do not, string implements them). An object
  found by a request key (a settings or tenant record, an entity, a content item, `object`) is not request data, nor are
  its members. A key that reaches a value typed by a type parameter is marked (ruling R-E23): a call of a value-factory
  shaped method drops it from its result (below), any other call keeps it.
- Entries take `method:` or `property-get:`, or `property-set:` (ruling R-E40, alone: the value assigned to the property
  is written into the receiver; `ICacheEntry.Value`).
- `entry: true` (ruling R-E40, a method propagator): the call gives an entry of its receiver (`IMemoryCache.CreateEntry`);
  a write into that entry (into a local the call initialises, or into the call itself) is a write into the receiver.
- `only-for: [rule ids]` (Task 29): what the propagator returns stays request data for these rules only (clean for the
  others). `System.Type.GetType` and `Assembly.GetType` pass a type name on to the Type for
  `csharp.unsafe-deserialization` only: a real type's name holds no quote, `<` or path separator, so it is no free text
  for the other rules.
- `param-types: [types]` (Task 29, a method propagator whose `from` names parameter ordinals only): it applies only to
  the overloads whose parameters at those ordinals have one of these types (`XmlDocument.Load` of a Stream, TextReader or
  XmlReader holds the data it reads; `Load(string fileName)` does not).
- `drop-key-only: true` (ruling R-E39, a method propagator): what reached its inputs only as the key of a lookup (R-E18's
  string found by a request key, R-E23's type-parameter element) does not pass to its outputs; the rest does. The JSON
  deserializers carry it: text found in a cache or table by a request key makes no request-data object, text that is
  request data otherwise (the body, a parameter, a key lookup joined with them) does. The mark (TaintValue.KeyDerived,
  Label.KeyDerived) is set by every key lookup, kept through summaries, and lost in a join with any other request data.
- `known-text:` (Task 29, a list of `{ member: T.M, text: "..." }`): the text of an external static string field or
  property, which the `string-prefix:` sanitizers read as written in place (learn.microsoft.com gives each value:
  `Uri.SchemeDelimiter` is "://", `Uri.UriSchemeHttps` "https").
- Element reads of a collection are propagators of its indexer (`property-get: <type>.Item`, from
  `[this]`): `propagators.yml` names those of the dictionary and list interfaces and of the request
  collections. An array element read is no member call; it is the engine's own.
- `unmodelled-external`: what an external member no propagator names does.
  `string-or-collection-return`: its arguments and receiver reach its result when the result is
  string-like or a collection; `none`: nothing passes.

## Sources and sinks beyond the OpenGrep rules (Task 29, decision R-10, ruling R-E22)

The engine closes five BACKLOG rows the OpenGrep rules keep open (each row says "Closed by the engine (Task 29)"), and
treats the request's own origin apart. Compared with the OpenGrep shared C# source block (rules/csharp/sql/
sql-injection.yml up to "End of the shared C# source block") and the rules' own items, the differences are:

| item | engine | OpenGrep |
|---|---|---|
| `HttpContext?.Request.Query` (null-conditional) | a source: request members are matched by type (`sources.yml` (6)), whatever the receiver | not a source: the block matches `$CTX.Request.$PART` written without `?.` |
| `Request.Host` | csharp.ssrf's own source (`ssrf.yml` `sources:`); no source of any other rule | no source of any rule |
| the Host header (`Headers.Host`, `Headers["Host"]` in any case, `Headers[HeaderNames.Host]`, `RequestHeaders.Host`, `Headers.TryGetValue("Host", out v)`) | request data (it is a header), except for csharp.open-redirect and csharp.xss, where keyed sanitizers make it the request's own origin (R-E22) | request data for every rule (`Headers` is a source as a whole) |
| `Request.PathBase` | a shared source; for csharp.open-redirect a sanitizer (as OpenGrep), for csharp.xss a sanitizer except its unescaped `Value` read on it in place (xss.yml `sources:` with `receiver:`; OpenGrep's xss.cs:193) | a shared source; open-redirect cleans the read; xss cleans the read except `PathBase.Value` in place |
| `Request.Scheme` | no source | no source |
| `Uri.SchemeDelimiter`, `Uri.UriScheme*` | known text for the string-prefix fact (`known-text:`) | a fixed origin must be a literal written in place |
| DataTable filter (`DataTable.Select`, `DataView.RowFilter` and its constructor, `DataTable.Compute`'s filter) | a csharp.sql-injection sink with its own message | no sink |
| a shell's standard input (`p.StandardInput.WriteLine(x)`) | a csharp.command-injection sink when the process's StartInfo is cmd, pwsh/powershell, sh or bash started so that it reads its standard input as commands (per shell, from cmd's reference, about_pwsh, the POSIX sh utility and bash's Invoking Bash: no `/c`; `-Command -`/`-File -` or no command or script; no `-c` and no command file, or `-s`), option values (a double-quoted value with spaces included) not taken for a script; PowerShell parameter names in any case, shortened to an unambiguous prefix or written with `/`; `sh.exe`/`bash.exe` in any case | no sink |
| a serializer built for a request-chosen type (`new XmlSerializer(Type.GetType(name))`, its `extraTypes`, DataContractSerializer and DataContractJsonSerializer with their `knownTypes`, XmlSerializerFactory.CreateSerializer, XmlSerializer.FromTypes) | the taint form of csharp.unsafe-deserialization, with its own message and the shared allow-lists | a fixed-type serializer is safe; the type is not followed |

A rule's own source is request data like any other for the request scope (TaintValue.Scope is one per value, not per
rule): joined with heap data from other requests and written to the heap, it widens that data's scope to its own
request, for every rule (Jellyfin: the request Host joined with a stored media path in one call; FP, measured 2 on
Jellyfin, a case of the heap's precision limits below).

R-E22's cost: an application that forwards an attacker-set `X-Forwarded-Host` or `X-Forwarded-Prefix` into the Host or
PathBase (the forwarded-headers middleware behind a proxy that passes them on) is not followed for open-redirect and xss.

Shell standard input, not followed (FN): bytes written to `StandardInput.BaseStream`; a shell started through a launcher
(`env bash`, `busybox sh`); shells the cited documents do not cover (dash, zsh, ksh, fish, csh, ...); arguments given
through `ArgumentList` (not read: the shell counts as reading its input). The conditions read the body flow-insensitively,
so a process variable whose program or arguments differ by branch takes every constant of them together.

A framework or library callback whose parameter the library fills from the request (OrchardCore's tus store,
`ITusStore.*(string fileId, ...)` called by tusdotnet with the upload id from the request URL) is no source: neither
learn.microsoft.com nor tusdotnet's documentation (its wiki's "Custom data store" and "Custom file id provider" pages)
says where the store's `fileId` comes from or whether it is validated before the store is called (a file id provider has
a `ValidateId`), and the models are written from documentation only (Task 29; a recall loss, see Known limits).

## Confidence (Task 28, decision R-9, ruling R-E29)

Each engine finding is `high` or `medium` confidence, by the steps of the path it reports. Value passing within the
request is high: local flows, calls resolved to the implementations the solution creates or registers (or with one
candidate), the view-model edge (`View(model)` to the view's `Model`), and keyed request store entries under a constant
key (`ViewData["k"]`, `ViewBag.K`, `HttpContext.Items["k"]`). A path is medium when a step of it is:

| step kind (SARIF `threadFlowLocations[].properties.kind`) | what |
|---|---|
| `heap-read` | a field or auto-property read from the heap (written elsewhere in the request): at its field location or at an object's (R-8); a member a callee reads that its caller wrote into a known object; a member a callee's exit or returned object gives the caller; a member read through another object (a field's object, an alias, a parameter, a view's model). A member exact within one method stays plain (ruling R-E35): the body's own or static member written in it, or a member of an object the method allocates, written and read there (also nested, `n.Inner.Text`); so does a bound parameter's member (what the binder put there) |
| `any-key-entry` | a keyed store entry written or read with a key that is not a constant, or a view model of type object |
| `key-lookup` | an element found by a request key (R-E9/R-E18: a dictionary or JSON lookup, `GetValueOrDefault`, a `key:` propagator) |
| `view-fallback` | a keyed entry or view model a view shares with its writer only through an unresolved view name (every view of the project) |
| `dispatch-fallback` | a call of more than one candidate resolved by the class-hierarchy fallback (no implementation created or registered), or a target of it only types opened by scanning or reflection run (R-7, Task 26), also beside registered ones (R-E32 as revised); a body's call steps, and an auto-property's or external member's result; and a keyed entry or view model a view shares with its writer only through such a call (Task 32) |

What a keyed read shares with its writer "through resolved edges" is the precise reach (Task 32): the entry points that
reach the reading body over the call graph without the fallback edges of unresolved view names and of fallback dispatch,
computed over the strongly connected components of that graph. A cycle that only a fallback edge closes (a view component
whose view renders a view by a name chosen at run time, invoked from one of the views that name reaches) therefore gives
its members no shared precise reach: a view an action never renders reads that action's model as `view-fallback` even
when it invokes the same component. The writer side is checked the same way (Task 32 fix round 1): request data a body
writes to a keyed entry under a constant key or to a view model is high only for the entry points that reach the writing
body over resolved edges; for the others (a helper only a fallback dispatch call reaches, a partial only a run-time view
name reaches) the write is a `dispatch-fallback` or `view-fallback` step, so the action's own view reads it medium. Code
around every action writes for every entry point on both sides (R-E17). The request scope of data and of the heap still
uses the whole call graph, fallback edges included, so the precise reach changes confidence only, never a finding.

(`keyed-entry` and `view-model` steps are named too; they are high.) Of the paths to one sink the engine reports a high
one when it finds one (R-E32 as revised). A join keeps the witnesses of both sides, each with its scope and its
cleanliness (the rules it is cleaned for), best first (high, then shorter), at most four plus those that keep a
witness, and a high one, for every rule some witness had one for; a finding reports the best witness that reaches its
sink and is not cleaned for its rule (an encoded value is no witness of an xss finding, but is one of a SQL finding; a
rule's own source of another rule is none; Task 35, witness defect W1: a sink inside a callee chooses its witness after the callee's steps are added to every witness, so a high witness cleaned for the rule that sorts first no longer stands in for a medium one that is not). A label (a parameter's path inside a summary) keeps its paths of different
cleanliness the same way, bounded alike: a sink inside a callee records, per rule, the best path not cleaned for that
rule, a call site substitutes the argument through each path with its own cleanliness, and a parameter passed on to
a callee keeps one call edge per path's cleanliness. The rules a
value has a high witness for are part of the analysis's order: a value, a summary's sink or call edge, a heap location
or a finding whose path becomes high counts as changed. A value's confidence can fall again only with a strict shrink
of its cleanliness (a dirtier part joins) or a medium step taken anew, so the order, lexicographic on (cleanliness,
then the rules with a high witness), is well-founded and the fixed point ends. A misuse finding is high. SARIF: `result.properties.confidence` is `"high"` or `"medium"`; a medium
result's `level` is `warning`, a high one keeps the rule's `error`; `analysisStats` counts `highFindings` and
`mediumFindings`. Qualor shows a medium finding as "possible".

R-E29's cost: a constant-key `ViewData` flow whose writer is code around every action (a filter) counts high. A
member written and read through one known object (`o.Name = q; Save(o)` reading `o.Name`) is a heap read, so medium.

## Known limits (measured 2026-10-14, MEASUREMENTS.md "C# engine")

What the engine does by design or does not model, as measured on the reference projects; each one is a source of
false positives (FP) or misses (FN) there.

- Heap (spec §5 as amended, decision R-6; since Task 20): request-scoped. A field or auto-property written with request
  data is request data only where code reachable from the same entry point reads it: controller actions, Razor Pages
  handlers, Minimal API handlers, and request code the framework invokes (a view or view component no action names, a
  tag helper or hub; and code around every action — filters, middleware, constructors DI builds, bodies that read the
  request themselves — whose request data and writes count in every request); an action reaches the view it renders
  (`View()`, `PartialView()`, `Page()`, resolved as MVC's conventional lookup does, areas included; a name chosen at run
  time reaches every view of the project and of the projects referencing it) and a view its partials, view components
  and tag helpers. Keyed request stores are heap locations scoped the same way (since Task 22): each `ViewData` entry
  (`ViewData["k"]`, `Add`, `TryGetValue`; `ViewBag.K` is the entry "K"; keys compared without case), each
  `HttpContext.Items` entry (also through a local initialised with it and never assigned again), and the view model
  (what `View(model)`, `PartialView(model)`, a view component's `View(model)`, `Html.Partial*(name, model)`,
  `<partial model>` or `ViewData.Model = m` (m statically typed) give, read as the view's `Model`, a list iterated in the view included). A
  key that is not a constant writes the store's "any key" entry, which every read joins, and a read with such a key joins
  every entry; a static property returning a string literal or a static readonly field initialised with one counts as
  its constant. The view model is keyed by type: a model is written under its static type (generic arguments included),
  its base classes, its interfaces and its exact type, and a view reads its own model type and the exact entries of its
  model type's base classes declared in the project and of its generic collection interfaces (`IEnumerable<T>`,
  `ICollection<T>`, `IList<T>`, `IReadOnlyCollection<T>`, `IReadOnlyList<T>`; ruling R-E24), so a model reaches the views
  of its own static type and of its supertypes, and a view of a subtype only when the model is typed by a project base
  class or a generic collection interface (a model typed by an interface that other view models share is not read by
  their views); an `object`/`dynamic` model is read by every
  view, an `object`/`dynamic` view reads only such models (FN: a typed model in a `dynamic` view, covariant
  `IEnumerable<Base>`). A generic helper's model whose type holds a type parameter (`T`, `List<T>`, `T[]`) is written at
  each call under the argument's type; a change of it analyses the helper's callers again (recursive helpers included).
  A call or constructor bound at run time (`Html.Raw(ViewBag.K)`, `new HtmlString(ViewBag.K)`) reports the
  unconditional sinks of its candidate members (named arguments are not matched). `TempData` crosses requests and is not
  followed. Data saved in one request and read in another
  (settings, entities, stored XSS) is not followed (FN, as the OpenGrep rules). Within one request the heap is per
  abstract object where the objects are known (Objects, below), and the call graph is context-insensitive: an interface
  every action reaches joins most code into one request (FP).
- Dispatch (since Task 26, decision R-7, ruling R-E25): a virtual or interface call runs the implementations whose type
  the solution creates: `new` (target-typed too), a DI registration (`Add{Scoped,Transient,Singleton}`, keyed, `TryAdd*`,
  `TryAddEnumerable`, `ServiceDescriptor`, `AddHostedService`, `AddDbContext`, `AddHttpClient`, Scrutor `Decorate`,
  Autofac `RegisterType`/`RegisterGeneric`; type arguments, `typeof` pairs and open generics, through a project's own
  generic registration helper too), a framework-built type (controllers, views, pages, page models, view components, tag
  helpers, filters and attributes, middleware, hubs, hosted services, Blazor components, EF migrations), an entry
  point's parameter type, a type argument of a library method given explicitly (`Activator.CreateInstance<T>()`,
  `Deserialize<T>()`, `Get<T>()`) or inferred for a creation or deserialization call (`Deserialize(s, JsonTypeInfo<T>)`),
  with the element and argument types inside it (`List<T>`, `T[]`, a dictionary's values; a bound `List<T>` parameter
  too). Every subtype of a type named by `typeof` (outside registrations, service lookups and assembly designators,
  attribute arguments and generic attribute type arguments included, also on a lambda's parameters in a body), cast to
  from an object built by reflection, a `DbSet<T>` entity or an entity its navigation properties reach counts too. So does
  every type of a project scanned without a filter: Scrutor `Scan`, Autofac `RegisterAssemblyTypes`, and a
  `GetTypes()`/`GetExportedTypes()` enumeration when a body registers or builds by a `Type` value without a filter. Only a
  `typeof` that can bound a scan filters it (an interface, an abstract or overridable base, a library base, a type
  parameter; not an attribute marker, a namespace or name check, a log line, nor an exclusion such as
  `!typeof(Attribute).IsAssignableFrom(t)`), as do an assignability test that is not negated and the type
  the objects are cast to. The enumerating body and the registering one may differ when the enumerated assembly is named
  (`typeof(T).Assembly`, the executing assembly); a body that enumerates unknown assemblies (`AppDomain.GetAssemblies()`,
  a variable) and registers by a run-time type itself opens every project. A project that no project with a registration
  is or references is open as well (registration code not in source; a library whose only registrations are in a sample
  or test project counts as hosted, so implementations meant for consumers' own registrations are dropped). The class
  hierarchy stays when no implementation is known. FN: an implementation built only by code these forms miss:
  - a class type parameter's `new T()` or registration (`class Registrar<TImpl>` registering `TImpl`), a factory in a
    library;
  - model binding of a nested or polymorphic member type, a configuration-bound nested options member
    (`Configure<Options>` builds `Options.Inner`);
  - an object made by reflection and cast in another body (a helper returning `object`), or registered uncast; a type
    loaded by name and never cast;
  - a scan split over bodies when the enumerated assemblies are unknown (a module loader's assembly list);
  - a library assembly scan (MediatR `RegisterServicesFromAssembly*`, FluentValidation `AddValidatorsFromAssembly*`/
    `AddValidatorsFromAssemblyContaining<T>`, AutoMapper `AddAutoMapper(assemblies or types)`, MassTransit `AddConsumers`,
    FluentMigrator `ScanIn`, in an `IServiceCollection` extension or a lambda given to one) opens a project only when its
    assembly is named: `typeof(X).Assembly`, a `*Containing<T>` form or marker type, `Get{Executing,Calling,Entry}Assembly`,
    `Assembly.Load` of a literal name (ruling R-E27). An unknown assembly list (nopCommerce's validators and migrations,
    Jellyfin's plugin assemblies) is ignored, as split scans over unknown assemblies are. Their own interfaces are
    external, so only a source base or interface that their scanned classes share and that is also built elsewhere is
    affected.
- Objects (decision R-8, since Task 27; rulings R-E30, R-E31): an object made by `new` (a class or struct, an
  anonymous object, an array, a collection expression) is its allocation site; a record's `with` copy is a new site whose
  members start as the source's (its known members, and reads through the source's objects too, since the heap is
  flow-insensitive: a write through the copy reaches the source's members as well, FP) and then take the initializer's
  writes; the model the binder makes for an action parameter is one object per action, and `TryUpdateModelAsync(model)`
  of a controller or page model makes every member of the model request data. A value knows at most 8 objects. A member
  written or read through known objects is that member of those objects (a read also joins what was written through
  unknown objects); through unknown objects it is the member's field location, as before Task 27, which every read joins
  (FP: a write through an unknown object reaches that member of every object). Unknown: more than 8 objects, a value
  read from a member, an element of a collection, what an external method returns, objects DI or the framework make,
  `this` of a method the framework calls (one object per type would split a controller between its base class and
  itself). A method other project code calls, where no entry point starts and that is no method group and overrides or
  implements no external member, reads the members of its parameters' and `this`'s objects as what each call's argument
  holds there, and writes into them at each call into the call's objects; a constructor's `this` is the object its `new`
  makes. Collections stay element-insensitive per object.
  Strong updates: a member path assigned through a variable (`x.M = v`, `x.M.N = v`, `this.M = v`, an object
  initializer) is exactly v where every path assigned it, until the variable is assigned, a member on the path is
  written through any object, a lambda or local function of the method touches it, or a call may change it. A value held
  so keeps its objects but not what it knew of its own members, so `x.M` known exactly says nothing of `x.M.N`, which a
  write through an alias of `x.M` may change (exactness is one level deep). Calls:
  - a project method (symbolic, outside the caller's component of the call graph) ends it when its summary writes the
    member into a parameter's object, its component writes the member through unknown objects, or the parameter's object
    (or something read from it) escapes to code the engine does not see; a caller's exact member is given to such a
    method only when the method does none of these, else joined with what it writes;
  - .NET's core libraries end nothing: external methods of the namespaces System, System.Collections(.Generic,
    .Concurrent, .Immutable, .ObjectModel), System.Linq, System.Text, System.Threading(.Tasks), System.Globalization and
    Microsoft.Extensions.Logging set no member of a project's object. Not exempt: System.Type (`InvokeMember`),
    System.Delegate and MulticastDelegate (`DynamicInvoke`), and any call given a delegate that is no lambda or local
    function of the calling method (a method group, a delegate parameter or variable: `ForEach(Rename)`,
    `Parallel.ForEach`, `Task.Run`, LINQ with a method group); reflection, serializers, binders, mappers and ASP.NET Core
    are outside these namespaces;
  - any other call ends it by type, as guards.
  What a callee assigns on every path to the members of a reference-type parameter it never assigns (a constructor: of
  its object; an async method: only when the call is awaited where it is made) holds after the call; what a body returns
  carries the members it is known to hold. A view reads a member of its model as what every model it may render in the
  reader's requests knew of it when given to the view, joined with what was written into that member of the model's
  objects (after `View(model)`, in a filter, in the view). So a posted model whose member a factory replaces before
  `View(model)` reads that member clean while its other members stay request data. Not followed: a member assigned only
  under a condition the caller decides (nopCommerce's factories fill an order model inside `if (order != null)`: FP);
  a write through a `ref` return or a `ref` local (FN); the objects of the variables a lambda captures (unknown); a
  callee that changes the object through a field holding it, or a delegate it was handed earlier that does (FN, as
  guards).
- Guards hold for locals, parameters and members read on them (since Task 21, "Guards on members"); a call given the
  guarded object (or one of a related type, or something that holds one) between the check and the sink, an await of
  earlier work, or a nested body touching the object ends the guard (FP); a member read through a project property
  with a getter body is no guard (FP). A callee that changes the guarded object through the heap without being given
  it or something holding it keeps the guard (FN; follow-up: the member writes recorded in summaries), and so does one
  that reaches it only through a field typed `object`, an interface or a base class, or fire-and-forget work started
  before the check. A guard inside
  a project's own helper (`CheckIsLocalUrl(x)` that calls `IsLocalUrl`) is no guard (FP).
- Validation in another method or by an attribute is not seen: a filename sanitizer, a child-path or containment check,
  `[RegularExpression]` on a bound parameter, a hash used as a file name, an allow-list lookup (FP).
- The fixed-origin prefix (ssrf, open-redirect) is read where the URL is built in place and through the text project
  members return (since Task 23), not through a variable that holds the text, an external member, or a member whose text
  depends on its arguments (FP). Since Task 29 (ruling R-E22) the Host header is no source of open-redirect and xss, and
  `Uri.SchemeDelimiter` and the `Uri.UriScheme*` fields have known text, so `$"{scheme}{Uri.SchemeDelimiter}{host}{path}"`
  built in one place is quiet; a redirect to the request's own URL whose origin part goes through a local assigned
  several times, `TrimEnd`, or a helper that may also return `""` or a stored URL is still reported (FP): nopCommerce's
  `GetThisPageUrl` (`GetStoreLocation(...).TrimEnd('/')` + Request.Path; 5 findings).
- LINQ (since Task 23): `Select`, `SelectMany` and the element selectors of `ToDictionary`/`ToLookup` give what their
  selector returns when it is a lambda or a method group given there, so an encoder in the selector cleans the result;
  `SelectMany`'s result selector also gets the collection selector's elements (two `from` clauses); the other operators
  (`Where`, `OrderBy`, `Take`, `Distinct`, ...) pass the source on. A selector that is a delegate parameter, a field or
  a local (ruling R-E23: `Map(xs, n => Encode(n))` through a helper's `Select(f)` is reported), `Queryable`'s operators,
  and the result selectors of `GroupBy`, `Join`, `Zip` and `Aggregate` keep the source sequence (FP). A lambda's
  parameters are seeded alike: the outer element of a two-`from` query takes the inner elements' data too (FP).
- Delegate parameters (Task 35): a lambda given to a member of .NET gets in each parameter what the member's documented
  signature passes there (learn.microsoft.com, the API reference of each type), no longer the join of the call's
  receiver and every argument:
  - `ConcurrentDictionary`: GetOrAdd's `valueFactory` and AddOrUpdate's `addValueFactory` get the key (and the
    `factoryArgument`: `GetOrAdd(key, static (k, owner) => ..., this)` gives `owner` the object, not the key);
    `updateValueFactory` the key, the stored value (the dictionary's taint) and the `factoryArgument`;
  - `List<T>` callbacks (ForEach, Find, FindAll, FindIndex, FindLast, FindLastIndex, Exists, TrueForAll, RemoveAll,
    ConvertAll, Sort) and the `Array` ones given the array: an element (the list's or array's taint);
  - `Enumerable`: a `predicate`, `selector`, `keySelector`, `elementSelector` or `collectionSelector` of a method with a
    `source`: an element of the source (an index: nothing); Zip's result selector an element of `first` and one of
    `second`; Join's and GroupJoin's key selectors an element of `outer` or `inner`, their result selector one of each;
  - `TaskFactory.StartNew` given a `state`: the state; `Task.ContinueWith`: the task and its `state` (`Task.Run`'s
    delegates take no parameter).
  Every other member, a method group, and a parameter the list leaves open (Aggregate's accumulator, the result selectors
  of GroupBy and SelectMany) keep the join, as before.
- Lookups by a request key (ruling R-E18, narrowing R-E9; since Task 23): the key's taint reaches what a lookup finds
  only when it can carry an injection by itself (a string, a number, a sequence of them: `key:` in `propagators.yml`).
  Cost: a record found by a request key (a settings or tenant object, an entity, a content item) whose string field
  later reaches a sink is missed (FN), e.g. a request-keyed table of records whose name goes into SQL; a lookup through
  an external member no propagator names still follows the `unmodelled-external` default. A dictionary's key is not
  written into it by `Add`, `TryAdd`, `GetOrAdd` or `AddOrUpdate` (as by `d[k] = v`), so its keys enumerated later are
  not request data (FN). Caches with a value factory give the factory's result, not the key: IMemoryCache's
  `GetOrCreate*`, `ConcurrentDictionary.GetOrAdd`/`AddOrUpdate`, and a project method shaped like `T Get(key, Func<T>
  acquire)` (it returns a type parameter or a Task of one, takes a delegate returning it and another parameter that is
  not of that type; by shape, whatever its name): its own return is kept, without what reached it only as the key of a
  lookup whose element is typed by a type parameter (ruling R-E23), so `Parse<T>(raw, fallback)` still returns `raw`.
  A GetOrCreate factory's `ICacheEntry.Key` is the key. A generic lookup without a factory (`Cache<T>.Find(key)`) keeps
  the key's taint unless T is constrained to a type that cannot carry (FP for `Cache<Tenant>`; follow-up: a label
  conditional on the type argument, resolved at the call). A literal allow-list table still cleans.
- Not followed (FN): `TempData` entries (another request); a model that is not a collection, statically typed as an
  interface or a library base class and given to a view of a narrower type, whose members are never written in code
  (members written in code still reach the view through the field heap); `ViewData.Model = m` with an `object`/`dynamic` m (a view
  engine's own plumbing, which every view goes through); `HttpContext.Items` held in a local that is assigned again or
  in a field; a layout reads none of an action's heap data (it is an entry
  point of its own); a view model given as a model expression (`<partial for>`, editor and display templates); callbacks a framework or library makes into the project
  (static-file providers, tus stores: no documentation says the store's file id is unvalidated request data, Task 29); externals whose result is neither string-like nor a collection and that no
  propagator names; a value given to a Fluid template through a context property set (`context.Model = x`), a custom
  value converter or member access strategy (Task 34); a Minimal API body parameter whose type a registration the engine
  cannot see names as a service is still reported (an Autofac-only registration, a scan: FP), and one whose type a
  registration names only as an implementation (`AddSingleton<IClock, Clock>` and a `Clock` parameter) is not (FN).
- Through a PhysicalFileProvider (Task 34, ruling R-E37 refined): the PhysicalPath of the file it finds and the entries of
  the directory it enumerates for a request path are clean for csharp.path-traversal (its documentation: the provider
  "scopes all paths to a directory and its children"; a path it cannot serve gives a file that does not exist and has no
  PhysicalPath). The result's `Name` keeps the request data (`keep-members: [Name]`): a file that is not found is a
  NotFoundFileInfo whose Name is the path as given (`../x`). The provider follows a symbolic link under its root that
  points out of it; the engine counts what the link reaches as the root's own content. The PhysicalPath is clean only
  where the engine knows the result's members exactly (in place, through a local): a result passed to a project method or
  kept in a field and read elsewhere is read as a whole, so its PhysicalPath is reported (FP, fix round 2 RR-I2). Costs
  (FN): a provider whose root itself is chosen by the request (`new PhysicalFileProvider(root)` with a request-built
  root: its results are clean although the root is not). A provider known only as an `IFileProvider` keeps the path in
  every member.
- A Fluid template's rendered text holds the values it was given for every rule, also when rendered with an HtmlEncoder
  (the template may write a value `raw`; templates are not read): FP for csharp.xss where the template encodes every
  value. Not followed (FN, fix round 1 of Task 34, M4): the context a fluent `SetValue` returns (`template.Render(new
  TemplateContext(o).SetValue("n", v))` loses `v`), a template parsed from request text (`FluidParser.Parse(source)`: the
  source never reaches the rendered text), a value given through a context property set (`Model = x`), a custom value
  converter or member access strategy.
- A key-value pair (Task 34, R-E38): `new KeyValuePair<K, V>(k, v)` and `KeyValuePair.Create` give the pair one taint, the
  join of key and value, so the pair's `Key` carries the value's data too (FP; nopCommerce's localized resources: 15 medium
  findings, +0.13 GiB in Task 34's measurement).
- JSON deserialization (Task 34, ruling R-E38): `JsonSerializer.Deserialize*`, `JsonConvert.DeserializeObject*` and
  `JToken.ToObject` pass the JSON's taint to the object they make, whatever its static type (a DTO, a dictionary, a bare
  `T` in a project's generic wrapper such as `Read<T>(text) => JsonSerializer.Deserialize<T>(text)`), so its members
  read from the result are request data, unless the JSON is request data only through a lookup key (R-E39,
  `drop-key-only`): a cache entry found by a request key deserializes into stored data. The other parsers carry the same
  rule (fix round 1, M3): `JsonDocument.Parse*` (with `RootElement`, `JsonElement.GetProperty`/`TryGetProperty`),
  `JsonNode.Parse` (with its indexer), `JObject.Parse`, `JToken.Parse`, `JArray.Parse`,
  `JsonConvert.DeserializeAnonymousType` and `XmlSerializer.Deserialize` (with `StringReader`). A converter, a
  `JsonSerializerContext` or `PopulateObject` is not followed.
  - Caches (ruling R-E40): a value put into an IMemoryCache (`CacheExtensions.Set`, `CreateEntry` and the entry's `Value`,
    `CacheEntryExtensions.SetValue`) or an IDistributedCache (`Set`, `SetAsync`, `SetString`, `SetStringAsync`) is written
    into the cache object (`to:` the receiver; the entry of `CreateEntry` is its cache, `entry: true`), so the same
    request reads it back as request data, deserialized too. What another request put into the cache is not this
    request's data (decision R-6). The cache object is one location for every key (fix round 2, RR-M1): in a request
    that puts request data into a cache, every read of that cache returns it, whatever its key (a read with another
    constant key too: FP). A per-key cache store would avoid it only for constant keys; the measured caches compute their
    keys.
  - R-E39's remaining cost (FN; review I2 of Task 34): JSON that another request put into an IMemoryCache, an
    IDistributedCache or a dictionary, read back by a key and deserialized, is missed (it was found at R-E38 only through
    the key); so is JSON a request puts into a cache through an API not named above (a project's own cache, an entry
    written after a `using` block's local is reassigned, a third-party cache). A text stored in a field and deserialized
    in another method keeps the key's taint (FP, the mark does not cross the heap).
- Not followed (FN), Task 34:
  - A Minimal API parameter of a type with a static `BindAsync` (or `IBindableFromHttpContext<T>`) or `TryParse` (or
    `IParsable<T>`), other than string: by the binding precedence it is bound from the request (the context, the route or
    the query), not from the body, and the engine takes it for no source (fix round 1, M1).
  - A text parsed into a syntax tree by a third-party library and generated back (OrchardCore's SQL queries go through
    the Cyqwel SQL parser and generator: the tree is neither string-like nor a collection, and no documentation the
    models could cite describes its API; firm core 25.30 is missed there).
  - The result of an interface with no implementation in the solution is not known to come from anywhere else: it
    carries its arguments' taint through the `unmodelled-external` default (Jellyfin's lyric providers: the request's
    lyric id reaches the downloaded lyric's format, and so a save path; FP). This is what keeps Jellyfin's
    `LyricManager` save sites reported, not the Path sanitizers: their `ReadOnlySpan<char>` overloads clean as the string
    ones do (Task 34, G5).
- Witness paths (Task 34): when two callers pass values into one project helper that returns its parameter (a span
  helper such as `Skip(this ReadOnlySpan<char>, int)`), the witness of a finding found through one caller can start in
  the other and leave out that caller's sanitizer step (the helper's label path is shared by its call sites). The finding
  is right; its witness can name a caller whose value was cleaned. (Task 35 fixed a separate cause of wrong witnesses, W1: a callee's sink took the first witness of the joined value rather than the one chosen for its rule, and with it that witness's confidence.)
- Views no build compiles (ASP.NET Core 2.x compiles views at run time, plugins copy theirs as Content; since Task 30,
  decision R-11): the hook records the project's `.cshtml` files (`razor-view=`) and the engine compiles those that have
  no generated class with the Razor 6.0 language API and MVC's extensions, `_ViewImports.cshtml` and the project's tag
  helpers included. The code is MVC 3.0+'s whatever the project's ASP.NET Core; an attribute of it whose type the
  references lack (ASP.NET Core 2.0 has no `Microsoft.AspNetCore.Razor.Hosting`) is left out. A view whose code has Razor
  or compiler errors is counted (`engineViewErrors`) and analysed as far as its code binds, and so is a project whose tag
  helpers could not be discovered (its views render them as markup). Views outside the project's directory (linked items)
  are not compiled (counted unless the build compiled them). A view the build compiled into a separate assembly
  (`*.Views.dll`, ASP.NET Core 2.1 to 5.0; .NET 6's source generator compiles views into the application assembly) is
  compiled here too.
- The taint models have no `test-code:` (as the OpenGrep taint rules): findings in test projects are reported. The
  engine measurements count them apart, by the misuse rules' `test-code:` globs, not as false positives (Task 23).
- Witness paths are not stable from run to run (seen in Task 31's measurement, from before it: the same code gave
  OrchardCore 30 and Jellyfin 10 results whose codeFlows differ, by alternative but equivalent paths). The finding set
  is stable: compare measurements by rule, file and line, not by the reported path.
