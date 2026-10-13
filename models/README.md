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
  - property-set: System.Data.Common.DbCommand.CommandText   # the assigned value; no args
sanitizers:                      # optional: the member's result is clean
  - method: System.Int32.Parse
guards:                          # optional: the checked argument is clean on the branch where the
  - method: Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl   # call's result equals clean-when
    arg: 0
    clean-when: true
misuse: {}                       # kind misuse only: the misuse rule's settings (a mapping)
```

`sanitizers` take `method:` or `property-get:`; `guards` take `method:` with `arg` and
`clean-when`, all required.

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
