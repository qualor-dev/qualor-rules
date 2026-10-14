namespace Qualor.Taint;

// The engine's models (models/csharp, format v1; models/README.md), as ModelLoader reads them. Types are named by their
// metadata name (`System.Collections.Generic.IDictionary`2`, nested types with `+`), arrays with a `[]` suffix.

public enum RuleKind { Taint, Misuse }

public enum MemberKind { Method, Constructor, PropertyGet, PropertySet }

/// A member of a type: `TypeName.MemberName`, or every member whose name starts with MemberName when Prefix
/// (`Query*`; `*` alone: every member of that kind). Constructors have MemberName `.ctor`.
public sealed record MemberPattern(string TypeName, string MemberName, bool Prefix, MemberKind Kind)
{
    public override string ToString() => $"{TypeName}.{MemberName}{(Prefix ? "*" : "")}";
}

/// A sink: the arguments at Args (parameter ordinals; an extension method's `this` is 0) of a method or constructor,
/// or the assigned value of a property set (Args empty). ParamTypes, when not empty, limits the sink to arguments
/// whose parameter has one of these types (one overload of several).
public sealed record SinkModel(MemberPattern Member, IReadOnlyList<int> Args)
{
    public IReadOnlyList<string> ParamTypes { get; init; } = Array.Empty<string>();

    /// When not empty, limits the sink to arguments whose parameter (in the member's definition) has one of these names.
    public IReadOnlyList<string> ParamNames { get; init; } = Array.Empty<string>();

    /// A conditional sink (`when:`): the sink applies only where every condition holds at the call or assignment.
    public IReadOnlyList<SinkCondition> When { get; init; } = Array.Empty<SinkCondition>();

    /// What the sink is, for the finding's message (`message:`, Task 29), when the rule's generic text would mislead (a
    /// DataTable filter under csharp.sql-injection); null: the generic text.
    public string? Message { get; init; }
}

/// The kinds of a conditional sink's conditions (models/README.md, `when:`).
public enum SinkConditionKind
{
    /// `arg: N, matches: R`: argument N is a constant (a literal, a const, a local or a ternary of them) one of whose
    /// values matches R; `arg: N, is: T.F`: argument N reads the field or property T.F. On a property-set sink (an
    /// indexer) N is the indexer's argument.
    Argument,

    /// `property: P [of: N], matches: R`: the object the sink acts on (or argument N) has its property P set in the
    /// body (an assignment, an initializer, a constructor parameter named P) to a constant one of whose values matches R.
    /// P may be a path (`StartInfo.FileName`: property FileName of the object's StartInfo). With `unless: R` instead
    /// (Negated): no constant P is set to matches R (also when P is never set).
    Property,

    /// `literal-text: R`: the sink argument is no collection written in place, and its literal text (the strings it
    /// is built from in place) matches R or it has none.
    LiteralText,

    /// `after: R [next: true]`: the sink is an element after one that is a constant matching R (right after it with
    /// `next`): an element of the sink argument written in place as a collection, or the argument of an Add after the
    /// earlier Adds to the same collection.
    After,

    /// `receiver: T.P`: the call's receiver is property P of T; the object of `property:` conditions is then its owner.
    Receiver,

    /// `outside: T.M, until: T.N`: the sink's statement is not in a region that a call of M opened and no call of N has
    /// closed yet (the statements before it in its block and the enclosing blocks of the same body).
    Outside,
}

/// One condition of a conditional sink. Arg: Argument's ordinal, or Property's `of` (−1: the sink's own object);
/// Pattern: the `matches`, `literal-text` or `after` regular expression; Member: Receiver's property, or Argument's
/// `is` member (then Pattern is null), or Outside's opening method; Until: Outside's closing method.
public sealed record SinkCondition(SinkConditionKind Kind)
{
    public MemberPattern? Until { get; init; }

    public int Arg { get; init; } = -1;

    public string? Property { get; init; }

    public System.Text.RegularExpressions.Regex? Pattern { get; init; }

    public bool Next { get; init; }

    public MemberPattern? Member { get; init; }

    /// A Property condition written `unless: R`: it holds when none of the property's constants matches.
    public bool Negated { get; init; }
}

/// What a guard's call tells (`clean-when:`): its boolean result (true or false), or whether its awaited result, held in a
/// variable, is null (`not-null`).
public enum GuardKind { Result, NotNull }

/// A guard (models/README.md, `guards:`): a call whose boolean result says the argument at Arg (−1: the receiver) is
/// clean on the branch where it equals CleanWhen; with Kind NotNull, a call whose (awaited) result is held in a variable
/// whose null check says the argument is clean where the variable is not null. When: the guard's conditions.
public sealed record GuardModel(MemberPattern Member, int Arg, bool CleanWhen)
{
    public GuardKind Kind { get; init; } = GuardKind.Result;

    public IReadOnlyList<GuardCondition> When { get; init; } = Array.Empty<GuardCondition>();
}

/// The kinds of a guard's conditions (models/README.md, guards' `when:`).
public enum GuardConditionKind
{
    /// `assigned-from: T.M`: the checked value is a local every assignment of which in the body is a call of T.M.
    AssignedFrom,

    /// `arg: N, text: R`: argument N carries no request data, and the text it is built from in place (constants, the
    /// platform's directory separators as '/', other values as U+FFFC) matches R.
    ArgumentText,
}

/// One condition of a guard: Member for AssignedFrom; Arg and Pattern for ArgumentText.
public sealed record GuardCondition(GuardConditionKind Kind)
{
    public MemberPattern? Member { get; init; }

    public int Arg { get; init; } = -1;

    public System.Text.RegularExpressions.Regex? Pattern { get; init; }
}

/// A misuse rule's checks (models/README.md, `misuse:`). TestCode: the globs of the files the rule skips (its OpenGrep
/// rule's `paths: exclude`). Calls: members whose call (a method or constructor) or read (property-get) is a finding.
/// EnumValues: enum constants that are findings where written to a field or property. Values: what a value given to a
/// member must be to be a finding. AcceptsAllMethods: the parameter type of the callbacks whose declaration is a finding
/// when every return is `true`.
public sealed record MisuseModel(IReadOnlyList<string> TestCode)
{
    public IReadOnlyList<MemberPattern> Calls { get; init; } = Array.Empty<MemberPattern>();

    public IReadOnlyList<EnumValueCheck> EnumValues { get; init; } = Array.Empty<EnumValueCheck>();

    public IReadOnlyList<ValueCheck> Values { get; init; } = Array.Empty<ValueCheck>();

    public string? AcceptsAllMethods { get; init; }
}

/// `enum-values:` a constant of the enum Type, other than its members named in Safe, written to a field or property.
public sealed record EnumValueCheck(string Type, IReadOnlyList<string> Safe);

/// `values:` the value given to Member (a property set: the assigned value; a method or constructor: the arguments at
/// Args) is a finding when it is a creation of one of Created, or (AcceptsAll) a callback whose every return is `true`;
/// With / Without: the object written to has (never has) the property set to one of the values in the same body.
/// AtObject: an assignment in an object initializer is reported at the object's creation.
public sealed record ValueCheck(MemberPattern Member, IReadOnlyList<int> Args)
{
    public IReadOnlyList<string> Created { get; init; } = Array.Empty<string>();

    public bool AcceptsAll { get; init; }

    public PropertyValues? With { get; init; }

    public PropertyValues? Without { get; init; }

    public bool AtObject { get; init; }
}

/// A property of the object a value check writes to, and the names of the enum members it is compared with.
public sealed record PropertyValues(string Property, IReadOnlyList<string> Values);

/// One rule's model (`models/csharp/<name>.yml`, rule id `csharp.<name>`). Misuse holds the checks of a misuse rule;
/// null for a taint rule.
public sealed record RuleModel(
    string RuleId, RuleKind Kind, IReadOnlyList<SinkModel> Sinks, IReadOnlyList<MemberPattern> Sanitizers,
    IReadOnlyList<GuardModel> Guards, MisuseModel? Misuse)
{
    /// Sanitizers by position in a string (`string-prefix:`): a value placed into a string after text that matches.
    public IReadOnlyList<StringSanitizer> StringSanitizers { get; init; } = Array.Empty<StringSanitizer>();

    /// Sanitizers by name (`lookup:`): the result of a call, whose body the engine cannot see, to a method so named.
    public IReadOnlyList<System.Text.RegularExpressions.Regex> LookupSanitizers { get; init; } = Array.Empty<System.Text.RegularExpressions.Regex>();

    /// `lookup:` sanitizers with `awaited: true`: only the awaited result of such a call (also through ConfigureAwait).
    public IReadOnlyList<System.Text.RegularExpressions.Regex> AwaitedLookupSanitizers { get; init; } = Array.Empty<System.Text.RegularExpressions.Regex>();

    /// Sanitizers with `receiver-type:`: the member's result is clean only when the call's receiver is of that type (or
    /// derives from it).
    public IReadOnlyList<(MemberPattern Member, string ReceiverType)> ReceiverSanitizers { get; init; } = Array.Empty<(MemberPattern, string)>();

    /// Sanitizers by simple names (`by-name: Type.Method`): a method of that name on a type of that simple name, in any
    /// namespace.
    public IReadOnlyList<(string Type, string Method)> NamedSanitizers { get; init; } = Array.Empty<(string, string)>();

    /// `allow-list: literal-tables`: the shared allow-lists (models/README.md, "Allow-lists") apply to this rule.
    public bool AllowLists { get; init; }

    /// Sanitizers of a keyed read (`property-get:` with `key:` or `key-is:`, Task 29): the read of an indexer whose key
    /// is a constant matching the expression, or reads the named field or property (`Headers["Host"]`,
    /// `Headers[HeaderNames.Host]`), is clean.
    public IReadOnlyList<KeySanitizer> KeySanitizers { get; init; } = Array.Empty<KeySanitizer>();

    /// The rule's own sources (`sources:`, Task 29): request data for this rule only (clean for every other rule).
    public IReadOnlyList<RuleSource> Sources { get; init; } = Array.Empty<RuleSource>();

    /// `validation: metacharacters:` (Task 31, decision R-12): a .NET regular expression character class of the
    /// characters a value needs to inject into this rule's sinks; a validated value whose [RegularExpression] admits none
    /// of them is clean for the rule. Null: no pattern cleans the rule.
    public System.Text.RegularExpressions.Regex? ValidationMetacharacters { get; init; }

    /// `validation: never` (ruling R-E34): no validation attribute cleans the rule, [Range] and [EnumDataType] neither.
    public bool ValidationNever { get; init; }
}

/// A keyed-read sanitizer: the read of Member (an indexer), or the `out` values of a call of Member (a method such as
/// TryGetValue), whose argument 0 is a constant matching Matches or reads the field or property Is.
public sealed record KeySanitizer(MemberPattern Member, System.Text.RegularExpressions.Regex? Matches, MemberPattern? Is)
{
    /// A method's keyed sanitizer only (`TryGetValue` with `receiver-type:`): the call's receiver is of this type or
    /// derives from it or implements it; the call's `out` values are clean.
    public string? ReceiverType { get; init; }
}

/// A rule's own source: a read of the property (or the value of the method) Member, and with Receiver only where the
/// read's receiver is a read of that property in place (`HttpRequest.PathBase` for `PathString.Value`).
public sealed record RuleSource(MemberPattern Member)
{
    public MemberPattern? Receiver { get; init; }
}

/// A `string-prefix:` sanitizer: a value built into a string (concatenation, interpolation, string.Format with a
/// constant format) is clean when the text before it in that string (from its start; an earlier value reads as
/// U+FFFC) matches Prefix, and, with Type, when the value's own type (before an implicit conversion) is Type.
public sealed record StringSanitizer(System.Text.RegularExpressions.Regex Prefix, string? Type);

/// MVC controllers: the parameters of their actions are sources.
public sealed record ControllerSources(
    IReadOnlyList<string> Bases, IReadOnlyList<string> BaseNameSuffixes, IReadOnlyList<string> NameSuffixes,
    IReadOnlyList<string> ClassAttributes, IReadOnlyList<string> NotClassAttributes, IReadOnlyList<string> NotMethodAttributes,
    bool PublicMethodsOnly);

/// Razor Pages: the parameters of the handlers of a page model are sources.
public sealed record RazorPageSources(IReadOnlyList<string> Bases, IReadOnlyList<string> HandlerPrefixes, bool PublicMethodsOnly);

/// Properties model binding sets: a property with one of PropertyAttributes, every public property of a class with one
/// of ClassAttributes.
public sealed record BoundPropertySources(IReadOnlyList<string> PropertyAttributes, IReadOnlyList<string> ClassAttributes);

/// Minimal APIs: the parameters of SourceTypes (also Nullable of them) of a handler given to one of MapMethods.
public sealed record MinimalApiSources(IReadOnlyList<MemberPattern> MapMethods, IReadOnlyList<string> SourceTypes);

/// The parameter and property types that are never sources (in controllers, Razor Pages handlers, bound properties and
/// attribute-bound parameters): Scalars (also Nullable), arrays and ScalarCollections of them unless the element is
/// one of NotScalarElements, enums when EnumsAreScalar, NotSourceTypes, and interfaces (DI services) when
/// InterfacesAreServices, except SourceInterfaces.
public sealed record ParameterTypes(
    IReadOnlyList<string> Scalars, IReadOnlyList<string> ScalarCollections, IReadOnlyList<string> NotScalarElements,
    bool EnumsAreScalar, IReadOnlyList<string> NotSourceTypes, bool InterfacesAreServices, IReadOnlyList<string> SourceInterfaces);

/// sources.yml: the ASP.NET Core request sources shared by every taint rule.
public sealed record SourceModel(
    ControllerSources Controllers, RazorPageSources RazorPages, BoundPropertySources BoundProperties, MinimalApiSources MinimalApi,
    IReadOnlyList<string> BindingAttributes, IReadOnlyList<string> NotSourceAttributes, ParameterTypes ParameterTypes,
    IReadOnlyList<MemberPattern> Members)
{
    /// sources.yml (7) `validation:` (Task 31, decision R-12): where model validation holds and which attributes clean;
    /// null: validation cleans nothing.
    public ValidationSources? Validation { get; init; }
}

/// Model validation (sources.yml (7), models/README.md "Model validation"): ModelState (the action's
/// ModelStateDictionary properties) and its IsValid property, the TryValidateModel methods, the [ApiController]
/// attributes, what turns the automatic 400 off (the suppress option and the response factory, property names; the
/// options type, a simple name), the attributes that leave a member out of validation, and the three attributes that
/// clean. KeepsValidity: the ModelStateDictionary members whose use leaves what IsValid says about binding's values
/// (reads, AddModelError); any other use of the dictionary ends it. ModelStateHolders: the types that hold the dictionary
/// (and it itself); a project method given one may change it.
public sealed record ValidationSources(
    IReadOnlyList<MemberPattern> ModelState, MemberPattern IsValid, IReadOnlyList<MemberPattern> TryValidate,
    IReadOnlyList<string> ApiControllerAttributes, string SuppressOption, string ResponseFactory, string OptionsType,
    IReadOnlyList<string> KeepsValidity, IReadOnlyList<string> ModelStateHolders, IReadOnlyList<string> NotValidatedAttributes,
    string Range, string RegularExpression, string EnumDataType);

/// How taint passes through a member the engine does not analyse: From (`this`, `args`, or a parameter ordinal) to
/// To (`return`, `this`, `out`: the out and ref arguments, or a parameter ordinal). Keys: the parameter ordinals of a
/// lookup key (`key:`), which reach a To position only when the value there can carry an injection by itself (a
/// string, a number, a sequence of them: ruling R-E18), never an object found by the key.
public sealed record PropagatorModel(MemberPattern Member, IReadOnlyList<string> From, IReadOnlyList<string> To)
{
    public IReadOnlyList<int> Keys { get; init; } = Array.Empty<int>();

    /// `only-for:` (Task 29): the request data the propagator passes stays request data for these rules only (a type
    /// found by a request-chosen name is no free text for the other rules); empty: for every rule.
    public IReadOnlyList<string> OnlyFor { get; init; } = Array.Empty<string>();

    /// `param-types:` (Task 29): the propagator applies only to the overloads whose parameters at its `from` ordinals
    /// have one of these types (XmlDocument.Load of a Stream holds its data; Load of a file name does not).
    public IReadOnlyList<string> ParamTypes { get; init; } = Array.Empty<string>();
}

/// Every model of models/csharp. UnmodelledExternal is the policy for external members no propagator names.
public sealed record ModelSet(SourceModel Sources, IReadOnlyList<PropagatorModel> Propagators, string UnmodelledExternal, IReadOnlyList<RuleModel> Rules)
{
    /// The text of external static string fields and properties (`known-text:` of propagators.yml, Task 29), by
    /// `Type.Member`: the string-prefix fact reads them as written in place (`Uri.SchemeDelimiter` is "://").
    public IReadOnlyDictionary<string, string> KnownTexts { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);
}

/// An invalid model file: Message is `<file>:<line>: <message>` (line 1-based).
public sealed class ModelException : Exception
{
    public ModelException(string file, int line, string message, Exception? inner = null)
        : base($"{file}:{line}: {message}", inner)
    {
        File = file;
        Line = line;
    }

    public string File { get; }

    public int Line { get; }
}
