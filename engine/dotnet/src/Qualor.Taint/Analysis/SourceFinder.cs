using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// Which parameters and properties are request data (sources.yml, models/README.md "sources.yml"), and the type facts
/// the transfer functions need: scalars carry no taint, string-like and collection results take the
/// `unmodelled-external` default. Results are cached by symbol.
internal sealed class SourceFinder
{
    private readonly SourceModel _model;
    private readonly HashSet<string> _scalars, _scalarCollections, _notScalarElements, _notSourceTypes, _sourceInterfaces;
    private readonly HashSet<string> _bindingAttributes, _notSourceAttributes, _minimalSourceTypes, _controllerBases, _pageBases;
    private readonly HashSet<string> _controllerAttributes, _notControllerAttributes, _notActionAttributes;
    private readonly HashSet<string> _propertyAttributes, _boundClassAttributes;
    private readonly HashSet<string> _mapMethodNames;
    private readonly HashSet<(SyntaxTree Tree, TextSpan Span)> _handlers = new();
    private readonly MemberTable<MemberPattern> _members = new();
    private readonly Dictionary<ISymbol, bool> _parameterCache = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ISymbol, bool> _propertyCache = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ISymbol, bool> _controllerCache = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ITypeSymbol, bool> _scalarCache = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ITypeSymbol, bool> _stringOrCollectionCache = new(SymbolEqualityComparer.Default);

    private readonly MemberTable<(string Rule, RuleSource Source)> _ruleSources = new();

    public SourceFinder(SourceModel model, IEnumerable<RuleModel> rules)
    {
        foreach (var rule in rules)
            foreach (var s in rule.Sources) _ruleSources.Add(s.Member, (rule.RuleId, s));
        _model = model;
        static HashSet<string> Set(IEnumerable<string> items) => new(items, StringComparer.Ordinal);
        var types = model.ParameterTypes;
        _scalars = Set(types.Scalars);
        _scalarCollections = Set(types.ScalarCollections);
        _notScalarElements = Set(types.NotScalarElements);
        _notSourceTypes = Set(types.NotSourceTypes);
        _sourceInterfaces = Set(types.SourceInterfaces);
        _bindingAttributes = Set(model.BindingAttributes);
        _notSourceAttributes = Set(model.NotSourceAttributes);
        _minimalSourceTypes = Set(model.MinimalApi.SourceTypes);
        _controllerBases = Set(model.Controllers.Bases);
        _pageBases = Set(model.RazorPages.Bases);
        _controllerAttributes = Set(model.Controllers.ClassAttributes);
        _notControllerAttributes = Set(model.Controllers.NotClassAttributes);
        _notActionAttributes = Set(model.Controllers.NotMethodAttributes);
        _propertyAttributes = Set(model.BoundProperties.PropertyAttributes);
        _boundClassAttributes = Set(model.BoundProperties.ClassAttributes);
        _mapMethodNames = Set(model.MinimalApi.MapMethods.Select(m => m.MemberName));
        foreach (var member in model.Members) _members.Add(member, member);
    }

    /// The source member (sources.yml (6) `members`) a call or a property read is, or null.
    public MemberPattern? SourceMember(ISymbol member, Access access)
    {
        var hits = _members.Match(member, access);
        return hits.Length == 0 ? null : hits[0];
    }

    /// The rules whose own source (a rule's `sources:`, Task 29) a call or property read is: the member matches and, with a
    /// `receiver:`, the read's receiver is a read of that property in place. Rule-own sources do not make a body an entry
    /// point (EntryPoints reads the shared ones only).
    public IReadOnlyCollection<string> RuleSourceOf(ISymbol member, Access access, IOperation? instance)
    {
        if (_ruleSources.IsEmpty) return Array.Empty<string>();
        var hits = _ruleSources.Match(member, access);
        if (hits.Length == 0) return Array.Empty<string>();
        while (instance is IConversionOperation c) instance = c.Operand;
        List<string>? rules = null;
        foreach (var (rule, source) in hits)
        {
            if (source.Receiver != null && !(instance is IPropertyReferenceOperation r && SymbolMatch.Matches(source.Receiver, r.Property))) continue;
            (rules ??= new List<string>()).Add(rule);
        }
        return (IReadOnlyCollection<string>?)rules ?? Array.Empty<string>();
    }

    // ---- Minimal API handlers ----

    /// Records the handlers given to a map method in this compilation: lambdas, local functions and method groups (the
    /// method wherever it is declared), by their declaring syntax.
    public void RegisterHandlers(Compilation compilation, CancellationToken ct)
    {
        foreach (var tree in compilation.SyntaxTrees)
        {
            ct.ThrowIfCancellationRequested();
            SemanticModel? model = null;
            foreach (var call in tree.GetRoot(ct).DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                var name = call.Expression switch
                {
                    MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
                    SimpleNameSyntax s => s.Identifier.ValueText,
                    _ => null,
                };
                if (name == null || !_mapMethodNames.Contains(name)) continue;
                model ??= compilation.GetSemanticModel(tree);
                if (model.GetOperation(call, ct) is not IInvocationOperation invocation) continue;
                if (!_model.MinimalApi.MapMethods.Any(p => SymbolMatch.Matches(p, invocation.TargetMethod))) continue;
                foreach (var argument in invocation.Arguments)
                {
                    var handler = HandlerOf(argument.Value);
                    if (handler == null) continue;
                    foreach (var r in handler.DeclaringSyntaxReferences) _handlers.Add((r.SyntaxTree, r.Span));
                }
            }
        }
    }

    private static IMethodSymbol? HandlerOf(IOperation value)
    {
        while (true)
        {
            switch (value)
            {
                case IConversionOperation c: value = c.Operand; continue;
                case IDelegateCreationOperation d: value = d.Target; continue;
                case IAnonymousFunctionOperation f: return f.Symbol;
                case IMethodReferenceOperation m: return m.Method.OriginalDefinition;
                default: return null;
            }
        }
    }

    private bool IsHandler(IMethodSymbol method) =>
        _handlers.Count > 0 && method.OriginalDefinition.DeclaringSyntaxReferences.Any(r => _handlers.Contains((r.SyntaxTree, r.Span)));

    /// Whether this syntax (a lambda, a local function, a method declaration) is a handler given to a map method.
    public bool IsHandlerSyntax(SyntaxNode node) => _handlers.Count > 0 && _handlers.Contains((node.SyntaxTree, node.Span));

    // ---- Entry points (spec §5 "Heap", decision R-6) ----

    /// Whether a method is a request entry point: a controller action (1), a Razor Pages handler (2), a Minimal API
    /// handler given as a method group (4), or a method with a parameter bound from the request by an attribute (5) —
    /// the methods whose parameters this model makes request data, whether or not they have parameters.
    public bool IsEntry(IMethodSymbol method)
    {
        method = method.OriginalDefinition;
        return IsAction(method) || IsPageHandler(method) || IsHandler(method) || method.Parameters.Any(IsSourceParameter);
    }

    /// A controller action (sources.yml (1)): a public (by the model) instance method of a controller, not marked as no
    /// action.
    public bool IsAction(IMethodSymbol method)
    {
        if (method.MethodKind != MethodKind.Ordinary || method.IsStatic || method.ContainingType is not { } type) return false;
        return (!_model.Controllers.PublicMethodsOnly || method.DeclaredAccessibility == Accessibility.Public) && IsController(type)
            && !NotAction(method);
    }

    /// A Razor Pages handler (sources.yml (2)): a public (by the model) instance method of a page model whose name starts
    /// with a handler prefix.
    public bool IsPageHandler(IMethodSymbol method)
    {
        if (method.MethodKind != MethodKind.Ordinary || method.IsStatic || method.ContainingType is not { } type) return false;
        var p = _model.RazorPages;
        return (!p.PublicMethodsOnly || method.DeclaredAccessibility == Accessibility.Public)
            && p.HandlerPrefixes.Any(h => method.Name.StartsWith(h, StringComparison.Ordinal))
            && IsPageModel(type);
    }

    /// A class derived from a Razor Pages base (sources.yml (2) `bases`).
    public bool IsPageModel(INamedTypeSymbol type) => BaseTypes(type).Any(b => _pageBases.Contains(SymbolMatch.MetadataName(b)));

    // ---- Parameters ----

    /// Whether a parameter is bound from the request: a binding attribute (5), a Minimal API handler's parameter of a
    /// source type (4), a controller action's (1) or a Razor Pages handler's (2) parameter; never with a DI attribute.
    public bool IsSourceParameter(IParameterSymbol parameter)
    {
        parameter = parameter.OriginalDefinition;
        if (_parameterCache.TryGetValue(parameter, out var cached)) return cached;
        var result = Compute(parameter);
        _parameterCache[parameter] = result;
        return result;
    }

    private bool Compute(IParameterSymbol parameter)
    {
        if (parameter.RefKind == RefKind.Out || parameter.ContainingSymbol is not IMethodSymbol method) return false;
        if (HasAttribute(parameter.GetAttributes(), _notSourceAttributes)) return false;
        if (HasAttribute(parameter.GetAttributes(), _bindingAttributes) && !IsNeverSourceType(parameter.Type)) return true;
        if (IsHandler(method) && _minimalSourceTypes.Contains(SymbolMatch.MetadataName(UnwrapNullable(parameter.Type)))) return true;
        if (method.MethodKind != MethodKind.Ordinary || method.IsStatic || method.ContainingType == null) return false;
        if (IsNeverSourceType(parameter.Type)) return false;

        return IsAction(method) || IsPageHandler(method);
    }

    /// A method with a not-action attribute, on itself or on a method it overrides (`[NonAction]` is inherited:
    /// Controller.OnActionExecuting overridden in a controller is no action).
    private bool NotAction(IMethodSymbol method)
    {
        for (var m = method; m != null; m = m.OverriddenMethod)
            if (HasAttribute(m.GetAttributes(), _notActionAttributes)) return true;
        return false;
    }

    /// A controller (sources.yml (1)): by a base class, a base class's name, its own name over System.Object, or an
    /// attribute; never with a not-controller attribute.
    public bool IsController(INamedTypeSymbol type)
    {
        type = type.OriginalDefinition;
        if (_controllerCache.TryGetValue(type, out var cached)) return cached;
        var result = false;
        if (type.TypeKind == TypeKind.Class && !SelfAndBases(type).Any(t => HasAttribute(t.GetAttributes(), _notControllerAttributes)))
        {
            var c = _model.Controllers;
            result = SelfAndBases(type).Any(t => HasAttribute(t.GetAttributes(), _controllerAttributes))
                || BaseTypes(type).Any(b => _controllerBases.Contains(SymbolMatch.MetadataName(b))
                    || c.BaseNameSuffixes.Any(s => b.Name.EndsWith(s, StringComparison.Ordinal)))
                || (type.BaseType?.SpecialType == SpecialType.System_Object
                    && c.NameSuffixes.Any(s => type.Name.EndsWith(s, StringComparison.Ordinal)));
        }
        _controllerCache[type] = result;
        return result;
    }

    // ---- Properties ----

    /// A property model binding sets (sources.yml (3)): with a property attribute, or public in a class with a class
    /// attribute; not of a never-source type.
    public bool IsBoundProperty(IPropertySymbol property)
    {
        property = property.OriginalDefinition;
        if (_propertyCache.TryGetValue(property, out var cached)) return cached;
        var result = !property.IsStatic && !property.IsIndexer
            && (HasAttribute(property.GetAttributes(), _propertyAttributes)
                || (property.DeclaredAccessibility == Accessibility.Public
                    && SelfAndBases(property.ContainingType).Any(t => HasAttribute(t.GetAttributes(), _boundClassAttributes))))
            && !IsNeverSourceType(property.Type);
        _propertyCache[property] = result;
        return result;
    }

    // ---- Types ----

    /// The parameter types that are never sources (sources.yml `parameter-types`).
    public bool IsNeverSourceType(ITypeSymbol type)
    {
        type = UnwrapNullable(type);
        var t = _model.ParameterTypes;
        if (IsScalar(type)) return true;
        var name = SymbolMatch.MetadataName(type);
        if (_notSourceTypes.Contains(name)) return true;
        if (type is IArrayTypeSymbol array) return IsScalarElement(UnwrapNullable(array.ElementType));
        if (type is INamedTypeSymbol { TypeArguments.Length: 1 } named && _scalarCollections.Contains(name))
            return IsScalarElement(UnwrapNullable(named.TypeArguments[0]));
        return type.TypeKind == TypeKind.Interface && t.InterfacesAreServices && !_sourceInterfaces.Contains(name);
    }

    private bool IsScalarElement(ITypeSymbol type) =>
        !_notScalarElements.Contains(SymbolMatch.MetadataName(type)) && IsScalar(type);

    /// A value of this type never carries request data: a scalar of the model (also Nullable of one), an enum when
    /// `enums-are-scalar`, and void.
    public bool IsScalar(ITypeSymbol type)
    {
        if (_scalarCache.TryGetValue(type, out var cached)) return cached;
        var t = UnwrapNullable(type);
        var result = t.SpecialType == SpecialType.System_Void
            || (t.TypeKind == TypeKind.Enum && _model.ParameterTypes.EnumsAreScalar)
            || (t is INamedTypeSymbol && _scalars.Contains(SymbolMatch.MetadataName(t)));
        _scalarCache[type] = result;
        return result;
    }

    /// The results the `string-or-collection-return` default passes taint to: string-like types (string, StringBuilder,
    /// FormattableString, StringValues, spans and memories of char), arrays, enumerables and enumerators (IEnumerable,
    /// IEnumerator and their async forms), also as a Task's or ValueTask's result.
    public bool IsStringOrCollection(ITypeSymbol type)
    {
        if (_stringOrCollectionCache.TryGetValue(type, out var cached)) return cached;
        var result = ComputeStringOrCollection(UnwrapNullable(type));
        _stringOrCollectionCache[type] = result;
        return result;
    }

    private static readonly HashSet<string> StringLike = new(StringComparer.Ordinal)
    {
        "System.String", "System.Text.StringBuilder", "System.FormattableString", "Microsoft.Extensions.Primitives.StringValues",
        "Microsoft.Extensions.Primitives.StringSegment",
    };

    private static readonly HashSet<string> CharContainers = new(StringComparer.Ordinal)
    {
        "System.Span`1", "System.ReadOnlySpan`1", "System.Memory`1", "System.ReadOnlyMemory`1",
    };

    private static readonly HashSet<string> Enumerables = new(StringComparer.Ordinal)
    {
        "System.Collections.IEnumerable", "System.Collections.IEnumerator",
        "System.Collections.Generic.IAsyncEnumerable`1", "System.Collections.Generic.IAsyncEnumerator`1",
    };

    private static bool ComputeStringOrCollection(ITypeSymbol type)
    {
        if (type is IArrayTypeSymbol) return true;
        var name = SymbolMatch.MetadataName(type);
        if (StringLike.Contains(name)) return true;
        if (type is INamedTypeSymbol named)
        {
            if (CharContainers.Contains(name)) return named.TypeArguments[0].SpecialType == SpecialType.System_Char;
            if ((name == "System.Threading.Tasks.Task`1" || name == "System.Threading.Tasks.ValueTask`1"))
                return ComputeStringOrCollection(UnwrapNullable(named.TypeArguments[0]));
        }
        if (Enumerables.Contains(name)) return true;
        return type.AllInterfaces.Any(i => Enumerables.Contains(SymbolMatch.MetadataName(i)));
    }

    private readonly Dictionary<(ITypeSymbol, bool), bool> _injectionCache = new();

    /// JSON values, which hold text or a number (fix round 1 of Task 23, M1): JToken (JValue, JObject, ...), JsonNode,
    /// JsonElement.
    private static readonly HashSet<string> JsonValues = new(StringComparer.Ordinal)
    {
        "Newtonsoft.Json.Linq.JToken", "System.Text.Json.Nodes.JsonNode", "System.Text.Json.JsonElement",
    };

    /// Whether a value of this type can carry an injection by itself (ruling R-E18): a string-like type, a scalar of the
    /// model (a number, bool, char, ...), a JSON value, or an array or sequence of such values (StringValues,
    /// List<string>, string[]), also as a Task's or ValueTask's result; a type parameter (unless a constraint is a type
    /// that cannot: `where T : Entity`, M4) or `dynamic` counts too (it may be one). Any other type (an object such as a
    /// settings record, an entity, a content item; `object` itself) cannot.
    public bool CanCarryInjection(ITypeSymbol? type) => type == null || CanCarryInjection(type, 0, typeParameters: true);

    /// Whether a type can carry an injection only because a type parameter in it may be one (CanCarryInjection with
    /// type parameters taken as unable): a lookup into it is a Label.ViaKey flow (R-E23).
    public bool CarriesOnlyAsTypeParameter(ITypeSymbol? type) =>
        type != null && CanCarryInjection(type, 0, typeParameters: true) && !CanCarryInjection(type, 0, typeParameters: false);

    private bool CanCarryInjection(ITypeSymbol type, int depth, bool typeParameters)
    {
        if (_injectionCache.TryGetValue((type, typeParameters), out var cached)) return cached;
        var t = UnwrapNullable(type);
        bool result;
        if (t is ITypeParameterSymbol parameter)
            result = typeParameters && (depth >= 3 || !parameter.ConstraintTypes.Any(c => ExcludesCarriers(c, depth)));
        else if (t.TypeKind is TypeKind.Dynamic or TypeKind.Error) result = true;
        else if (StringLike.Contains(SymbolMatch.MetadataName(t)) || IsScalar(t) || t.TypeKind == TypeKind.Enum || IsJsonValue(t)) result = true;
        else if (depth >= 3) result = false;
        else if (t is IArrayTypeSymbol array) result = CanCarryInjection(array.ElementType, depth + 1, typeParameters);
        else if (t is INamedTypeSymbol { TypeArguments.Length: 1 } task
            && SymbolMatch.MetadataName(task.OriginalDefinition) is "System.Threading.Tasks.Task`1" or "System.Threading.Tasks.ValueTask`1")
            result = CanCarryInjection(task.TypeArguments[0], depth + 1, typeParameters);
        else
            result = Sequences(t).Any(e => CanCarryInjection(e, depth + 1, typeParameters));
        _injectionCache[(type, typeParameters)] = result;
        return result;
    }

    /// Whether a constraint type rules out every type that can carry an injection (fix round 2 of Task 23, R1-I1): a
    /// class other than string, object, ValueType and Enum (every carrier is sealed or a struct, so none derives from
    /// it), or an interface declared outside the System namespaces (string and the scalars implement only System ones:
    /// IComparable, IEquatable<T>, IConvertible, ...). A type parameter constraint is as that type parameter.
    private bool ExcludesCarriers(ITypeSymbol constraint, int depth) => constraint switch
    {
        ITypeParameterSymbol other => !CanCarryInjection(other, depth + 1, typeParameters: true),
        { TypeKind: TypeKind.Interface } => !InSystemNamespace(constraint),
        { TypeKind: TypeKind.Class } => constraint.SpecialType is not (SpecialType.System_String or SpecialType.System_Object
            or SpecialType.System_ValueType or SpecialType.System_Enum) && !CanCarryInjection(constraint, depth + 1, typeParameters: true),
        _ => false,
    };

    private static bool InSystemNamespace(ITypeSymbol type)
    {
        var ns = type.ContainingNamespace;
        while (ns is { IsGlobalNamespace: false, ContainingNamespace.IsGlobalNamespace: false }) ns = ns.ContainingNamespace;
        return ns is { IsGlobalNamespace: false, Name: "System" };
    }

    private static bool IsJsonValue(ITypeSymbol type)
    {
        for (var t = type as INamedTypeSymbol; t != null; t = t.BaseType)
            if (JsonValues.Contains(SymbolMatch.MetadataName(t))) return true;
        return false;
    }

    /// The element types of the IEnumerable<T> a type is or implements.
    private static IEnumerable<ITypeSymbol> Sequences(ITypeSymbol type)
    {
        if (type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Collections_Generic_IEnumerable_T } self)
            yield return self.TypeArguments[0];
        foreach (var i in type.AllInterfaces)
            if (i.OriginalDefinition.SpecialType == SpecialType.System_Collections_Generic_IEnumerable_T) yield return i.TypeArguments[0];
    }

    public static ITypeSymbol UnwrapNullable(ITypeSymbol type) =>
        type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } n ? n.TypeArguments[0] : type;

    // ---- Helpers ----

    private static IEnumerable<INamedTypeSymbol> BaseTypes(INamedTypeSymbol type)
    {
        for (var b = type.BaseType; b != null; b = b.BaseType) yield return b;
    }

    private static IEnumerable<INamedTypeSymbol> SelfAndBases(INamedTypeSymbol type)
    {
        for (INamedTypeSymbol? t = type; t != null; t = t.BaseType) yield return t;
    }

    /// An attribute of one of these classes, or of a class derived from one.
    private static bool HasAttribute(IEnumerable<AttributeData> attributes, HashSet<string> names)
    {
        if (names.Count == 0) return false;
        foreach (var a in attributes)
            for (var c = a.AttributeClass; c != null; c = c.BaseType)
                if (names.Contains(SymbolMatch.MetadataName(c))) return true;
        return false;
    }
}
