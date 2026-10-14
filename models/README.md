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
UrlEncoder.Encode, not HtmlEncoder.Encode). A user-defined conversion operator named as a sanitizer (`op_Implicit`)
cleans a conversion to `System.String` only (PathString's text); its conversions to other types keep the value.

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
  (`ref`, `out`, `+=`, deconstruction); `arg: N, text: R` holds when argument N carries no request data and the text it
  is built from in place matches R: constants, both sides of a string `+`, the text and holes of an interpolated
  string, `Path.DirectorySeparatorChar` and `Path.AltDirectorySeparatorChar` as `/`, any other value as U+FFFC.
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
- **membership**: where `T.Contains(x)` or `T.ContainsKey(x)` holds (the extension method, also called as a static
  `Enumerable.Contains(T, x)`, and on the table's `Keys` or `Values`; a comparer given to it must be one of .NET's
  own), x is clean, as a guard (above): the branch of an `if`, the code after `if (!T.Contains(x)) return/throw ...;`,
  a ternary `T.Contains(x) ? x : "fallback"`.

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

Every key is required.

| key | what is a source |
|---|---|
| `controllers` | The parameters of a controller's actions. A class is a controller when it derives from one of `bases`, when one of its base classes has a name ending in one of `base-name-suffixes`, when it derives from `System.Object` only and its own name ends in one of `name-suffixes`, or when it or a base class carries one of `class-attributes`; never with one of `not-class-attributes`. Actions: its methods (`public-methods-only`: the public ones) without one of `not-method-attributes`. |
| `razor-pages` | The parameters of a page model's handlers: methods (`public-methods-only`) whose names start with one of `handler-prefixes`, in a class derived from one of `bases`. |
| `bound-properties` | A property with one of `property-attributes`; every public property of a class with one of `class-attributes`. |
| `minimal-api` | The parameters of one of `source-types` (or `Nullable` of one) of a handler (lambda, local function or method group) given to one of `map-methods` (method names, no `*` needed). |
| `binding-attributes` | A parameter with one of these attributes, in any method, local function or lambda. |
| `not-source-attributes` | A parameter with one of these attributes is never a source (a DI service). |
| `parameter-types` | The types that are never sources in `controllers`, `razor-pages`, `bound-properties` and `binding-attributes`: `scalars` (and `Nullable` of them), arrays and `scalar-collections` of them unless the element is one of `not-scalar-elements`, enums when `enums-are-scalar`, `not-source-types`, and interfaces (DI services) when `interfaces-are-services`, except `source-interfaces`. |
| `members` | Reads that are sources: `property-get:` and `method:` entries (the call's value). |

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
- Entries take `method:` or `property-get:`.
- `only-for: [rule ids]` (Task 29): what the propagator returns stays request data for these rules only (clean for the
  others). `System.Type.GetType` and `Assembly.GetType` pass a type name on to the Type for
  `csharp.unsafe-deserialization` only: a real type's name holds no quote, `<` or path separator, so it is no free text
  for the other rules.
- `param-types: [types]` (Task 29, a method propagator whose `from` names parameter ordinals only): it applies only to
  the overloads whose parameters at those ordinals have one of these types (`XmlDocument.Load` of a Stream, TextReader or
  XmlReader holds the data it reads; `Load(string fileName)` does not).
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
| `heap-read` | a field or auto-property read from the heap (written elsewhere in the request) |
| `any-key-entry` | a keyed store entry written or read with a key that is not a constant, or a view model of type object |
| `key-lookup` | an element found by a request key (R-E9/R-E18: a dictionary or JSON lookup, `GetValueOrDefault`, a `key:` propagator) |
| `view-fallback` | a keyed entry or view model a view shares with its writer only through an unresolved view name (every view of the project) |
| `dispatch-fallback` | a call of more than one candidate resolved by the class-hierarchy fallback (no implementation created or registered), or a target of it only types opened by scanning or reflection run (R-7, Task 26), also beside registered ones (R-E32 as revised); a body's call steps, and an auto-property's or external member's result |

(`keyed-entry` and `view-model` steps are named too; they are high.) Of the paths to one sink the engine reports a high
one when it finds one (R-E32 as revised). A join keeps the witnesses of both sides, each with its scope and its
cleanliness (the rules it is cleaned for), best first (high, then shorter), at most four plus those that keep a
witness, and a high one, for every rule some witness had one for; a finding reports the best witness that reaches its
sink and is not cleaned for its rule (an encoded value is no witness of an xss finding, but is one of a SQL finding; a
rule's own source of another rule is none). A label (a parameter's path inside a summary) has one path: the one of the
side that is request data for more rules, else the high one, else the shorter; so is a summary's call edge. The rules a
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
  propagator names (`IFileProvider.GetFileInfo` → `IFileInfo.PhysicalPath`, Fluid values); a Minimal API body object
  bound without `[FromBody]`.
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
