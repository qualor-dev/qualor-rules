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
sanitizers:                      # optional: the member's result is clean
  - method: System.Int32.Parse
guards:                          # optional: the checked argument is clean on the branch where the
  - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl   # call's result equals clean-when
    arg: 0
    clean-when: true
```

A rule of `kind: misuse` has `misuse:` (below) and no `sinks`, `sanitizers` or `guards`.

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
  `string.Format` with a constant format: its `arg0` to `arg2`) is clean when the text before it in that string,
  from the string's start, matches R; an earlier value in that text reads as U+FFFC (write `\uFFFC` in R). A string held
  in a variable keeps the value it was built with.
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
  `clean-when`. The value is a local or a parameter (or a flow capture that holds one); a field, a property or a
  call's result is not refined.
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
  call's argument `arg` is clean for the rule, when it is a local or a parameter assigned nowhere after the call.

The engine's own guard, for every rule: where a value is equal to a constant (`x == c`, `x != c` on its false branch,
`x.Equals(c)`, `string.Equals(x, c, ...)`, `x is c`, `x is c1 or c2`; `c` a literal, a `const` or `null`), the local or
parameter x is that constant: clean for every rule (`if (dir != "ASC" && dir != "DESC") return;` leaves dir clean).
Only for a string, char, number, bool or enum (or Nullable of one), with the built-in `==` (or System.String's) and
System.String's or a primitive's `Equals`: a user-defined `==` or an overridden `Equals` may compare anything and is no
guard (ruling R-E13).

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
| `property: P`, `matches: R` (`of: N`) | the object the sink acts on has its property P set to a constant that matches R anywhere in the body, before or after the sink: an assignment `x.P = c`, an object initializer `{ P = c }`, or a constructor parameter named P (ignoring case: `new ProcessStartInfo("sh")` sets FileName). The object of a property-set sink is the object written to; of a method sink its receiver (an extension method's `this`), the created object for a constructor; `of: N` takes argument N instead. Objects are told apart by access path (`psi`, `p.StartInfo`, `this.Response`, `context.Response`); a variable assigned exactly one object creation in the body is that object (one reused for a second object is neither). |
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
    to: [out]
unmodelled-external: string-or-collection-return
```

- `from`: `this`, `args` (every argument but `out` ones) or parameter ordinals; `to`: `return`,
  `this`, `out` (the `out` and `ref` arguments) or parameter ordinals. Defaults: a method from
  `[this, args]`, a constructor from `[args]`, a property read from `[this]`; to `[return]`.
- Entries take `method:` or `property-get:`.
- Element reads of a collection are propagators of its indexer (`property-get: <type>.Item`, from
  `[this]`): `propagators.yml` names those of the dictionary and list interfaces and of the request
  collections. An array element read is no member call; it is the engine's own.
- `unmodelled-external`: what an external member no propagator names does.
  `string-or-collection-return`: its arguments and receiver reach its result when the result is
  string-like or a collection; `none`: nothing passes.

## Known limits (measured 2026-10-14, MEASUREMENTS.md "C# engine")

What the engine does by design or does not model, as measured on the reference projects; each one is a source of
false positives (FP) or misses (FN) there.

- Heap (spec §5): a field or auto-property is tainted for the whole run, whatever the request that wrote it. Data an
  administrator or a customer saved in one request (settings, configuration, entities, cache keys, a view model bound
  in another action) is request data for every reader in every other request (FP, the largest share), and stored XSS is
  found the same way (FN otherwise).
- Guards clean a local or a parameter only: `Url.IsLocalUrl(model.ReturnUrl)` (or a not-null check of the IdentityServer
  context looked up for it) leaves `model.ReturnUrl` tainted (FP). A guard inside a project's own helper
  (`CheckIsLocalUrl(x)` that calls `IsLocalUrl`) is no guard (FP).
- Validation in another method or by an attribute is not seen: a filename sanitizer, a child-path or containment check,
  `[RegularExpression]` on a bound parameter, a hash used as a file name, an allow-list lookup (FP).
- The fixed-origin prefix (ssrf, open-redirect) is read only where the URL is built in place, not through a helper that
  builds it; a redirect to the request's own URL (scheme, host, path) is reported (FP).
- `Enumerable.*` passes its source sequence to the result as well as a lambda's return: an encoder inside
  `Select(x => ...)` does not clean the result (FP).
- Not followed (FN): `ViewData`, `ViewBag`, `TempData` and `HttpContext.Items` entries; a model passed to `View()` as the
  view's `Model` (only its properties, through the heap); callbacks a framework or library makes into the project
  (static-file providers, tus stores); externals whose result is neither string-like nor a collection and that no
  propagator names (`IFileProvider.GetFileInfo` → `IFileInfo.PhysicalPath`, Fluid values); a Minimal API body object
  bound without `[FromBody]`; views that the build does not compile (ASP.NET Core 2.x runtime compilation).
- The taint models have no `test-code:` (as the OpenGrep taint rules): findings in test projects are reported.
