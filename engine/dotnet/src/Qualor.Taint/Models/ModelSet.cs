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

    /// A conditional sink (`when:`): the sink applies only where every condition holds at the call or assignment.
    public IReadOnlyList<SinkCondition> When { get; init; } = Array.Empty<SinkCondition>();
}

/// The kinds of a conditional sink's conditions (models/README.md, `when:`).
public enum SinkConditionKind
{
    /// `arg: N, matches: R`: argument N is a constant (a literal, a const, a local or a ternary of them) one of whose
    /// values matches R.
    Argument,

    /// `property: P [of: N], matches: R`: the object the sink acts on (or argument N) has its property P set in the
    /// body (an assignment, an initializer, a constructor parameter named P) to a constant one of whose values matches R.
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
}

/// One condition of a conditional sink. Arg: Argument's ordinal, or Property's `of` (−1: the sink's own object);
/// Pattern: the `matches`, `literal-text` or `after` regular expression; Member: Receiver's property.
public sealed record SinkCondition(SinkConditionKind Kind)
{
    public int Arg { get; init; } = -1;

    public string? Property { get; init; }

    public System.Text.RegularExpressions.Regex? Pattern { get; init; }

    public bool Next { get; init; }

    public MemberPattern? Member { get; init; }
}

/// A guard: a call whose boolean result says the argument at Arg is clean on the branch where it equals CleanWhen.
public sealed record GuardModel(MemberPattern Member, int Arg, bool CleanWhen);

/// One rule's model (`models/csharp/<name>.yml`, rule id `csharp.<name>`). Misuse holds the `misuse:` mapping of a
/// misuse rule as plain values (string, list, dictionary); empty for a taint rule.
public sealed record RuleModel(
    string RuleId, RuleKind Kind, IReadOnlyList<SinkModel> Sinks, IReadOnlyList<MemberPattern> Sanitizers,
    IReadOnlyList<GuardModel> Guards, IReadOnlyDictionary<string, object?> Misuse)
{
    /// Sanitizers by position in a string (`string-prefix:`): a value placed into a string after text that matches.
    public IReadOnlyList<StringSanitizer> StringSanitizers { get; init; } = Array.Empty<StringSanitizer>();

    /// Sanitizers by name (`lookup:`): the result of a call, whose body the engine cannot see, to a method so named.
    public IReadOnlyList<System.Text.RegularExpressions.Regex> LookupSanitizers { get; init; } = Array.Empty<System.Text.RegularExpressions.Regex>();
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
    IReadOnlyList<MemberPattern> Members);

/// How taint passes through a member the engine does not analyse: From (`this`, `args`, or a parameter ordinal) to
/// To (`return`, `this`, `out`: the out and ref arguments, or a parameter ordinal).
public sealed record PropagatorModel(MemberPattern Member, IReadOnlyList<string> From, IReadOnlyList<string> To);

/// Every model of models/csharp. UnmodelledExternal is the policy for external members no propagator names.
public sealed record ModelSet(SourceModel Sources, IReadOnlyList<PropagatorModel> Propagators, string UnmodelledExternal, IReadOnlyList<RuleModel> Rules);

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
