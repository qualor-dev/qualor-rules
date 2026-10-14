using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// What the solution creates (decision R-7), the facts Dispatch narrows a virtual call with. A concrete type is
/// - created: built with `new` (target-typed too) or `Activator.CreateInstance<T>()` and other external generic methods
///   given it as an explicit type argument; registered in the DI container (`Add{Scoped,Transient,Singleton}`, keyed and
///   `TryAdd*` forms, `AddHostedService`, `AddDbContext`, `AddHttpClient`, Scrutor's `Decorate`, Autofac's
///   `RegisterType`/`RegisterGeneric`: the implementation type argument, or the `implementationType` of a `typeof` pair,
///   open generics included; `ServiceDescriptor` constructors and factories; a factory lambda's `new`); a type parameter
///   a project's own registration helper passes on is followed to its callers' type arguments; built by the framework
///   (controllers, Razor views and pages, page models, view components, tag helpers, filters and every attribute,
///   middleware, hubs, hosted services, Blazor components, EF migrations and type configurations); the parameter type of
///   an entry point (model binding); any struct;
/// - open, with every subtype: named by `typeof` outside a registration, a service lookup or an assembly designator
///   (reflection filters such as `typeof(IPlugin).IsAssignableFrom(t)`, attribute arguments such as
///   `[ServiceFilter(typeof(F))]`, `Activator.CreateInstance(typeof(T))`), the target of a cast, `as` or `is` of an object
///   made by reflection (`(IPlugin)Activator.CreateInstance(t)`, `JsonSerializer.Deserialize(s, type) as Item`), a
///   `DbSet<T>`'s entity, a Scrutor filter `AssignableTo<T>()`; and the type argument of a generic method whose type
///   parameter reaches one of these (`GetExports<T>()` over `typeof(T)`, `new T()`);
/// - in an open project: every type of a project whose assembly a scan registers without a filter: Scrutor `Scan`,
///   Autofac `RegisterAssemblyTypes`, and the enumeration of `Assembly.GetTypes()`/`GetExportedTypes()` when a body
///   registers or builds types by a `Type` value with no filter (a `typeof` of a type that can bound a scan: an
///   interface, an abstract or overridable base, a library base, a type parameter, not an attribute; an assignability
///   test; the type the objects are cast to). The enumerating body and the registering one may differ (a type-finder
///   helper and its caller) when the enumerated assembly is named (`typeof(T).Assembly`, the executing assembly); a body
///   that enumerates unknown assemblies (`AppDomain.GetAssemblies()`, a variable) and registers by a run-time type itself
///   opens every project. A library's assembly scan (MediatR `RegisterServicesFromAssembly*`, FluentValidation
///   `AddValidatorsFromAssembly*`, AutoMapper `AddAutoMapper(assemblies or types)`, MassTransit `AddConsumers`,
///   FluentMigrator `ScanIn`) opens a project only when its assembly is named (ruling R-E27); an unknown assembly list
///   is ignored. Every project no project with a registration is or references is open too (its registration code is
///   not in source: a library whose host is elsewhere, a solution without DI).
/// The fallback scope is the implementation's project (scans enumerate assemblies; a missing registration is a property
/// of a project and the projects referencing it) or the open type (a reflection filter names it), never the whole
/// solution unless the scanned assemblies are unknown: every measured large project uses reflection somewhere, so a
/// solution-wide fallback would undo the narrowing everywhere.
internal sealed partial class Dispatch
{
    private enum Known { None, Open, Created }

    [Flags]
    private enum Role { None = 0, Reflecting = 1, Registering = 2 }

    private const string ServiceCollection = "Microsoft.Extensions.DependencyInjection.IServiceCollection";
    private const string ServiceDescriptor = "Microsoft.Extensions.DependencyInjection.ServiceDescriptor";

    private static readonly HashSet<string> RegistrationNames = new(StringComparer.Ordinal)
    {
        "AddScoped", "AddTransient", "AddSingleton", "AddKeyedScoped", "AddKeyedTransient", "AddKeyedSingleton",
        "TryAddScoped", "TryAddTransient", "TryAddSingleton", "TryAddKeyedScoped", "TryAddKeyedTransient", "TryAddKeyedSingleton",
        "AddHostedService", "Decorate", "TryDecorate", "AddDbContext", "AddDbContextPool", "AddDbContextFactory",
        "AddPooledDbContextFactory", "AddHttpClient", "RegisterType", "RegisterGeneric",
        "Scoped", "Transient", "Singleton", "Describe", "KeyedScoped", "KeyedTransient", "KeyedSingleton", "DescribeKeyed",
        "Add", "TryAdd", "TryAddEnumerable", "Replace",
    };

    /// Parameters that give the service another way than by its type (no implementation type follows from the type
    /// argument then).
    private static readonly HashSet<string> FactoryParameters = new(StringComparer.Ordinal)
    {
        "implementationFactory", "implementationInstance", "factory", "instance", "decorator", "instanceFactory",
    };

    private static readonly HashSet<string> ImplementationTypeParameters = new(StringComparer.Ordinal)
    {
        "implementationType", "decoratorType", "implementer",
    };

    /// Service lookups and logger categories: a `typeof` given to them names a service, not a type something builds.
    private static readonly HashSet<string> LookupNames = new(StringComparer.Ordinal)
    {
        "GetService", "GetRequiredService", "GetServices", "GetKeyedService", "GetRequiredKeyedService", "GetKeyedServices",
        "Resolve", "ResolveOptional", "ResolveNamed", "ResolveKeyed", "IsService", "IsRegistered", "CreateLogger",
    };

    /// Reflection and deserialization calls that build an object of a type given at run time.
    private static readonly HashSet<string> CreationNames = new(StringComparer.Ordinal)
    {
        "CreateInstance", "GetServiceOrCreateInstance", "CreateInstanceFrom", "Deserialize", "DeserializeObject",
        "DeserializeAsync", "GetUninitializedObject",
    };

    private static readonly HashSet<string> ScanNames = new(StringComparer.Ordinal)
    {
        "Scan", "RegisterAssemblyTypes", "RegisterAssemblyOpenGenericTypes",
    };

    private static readonly HashSet<string> OwnAssemblyNames = new(StringComparer.Ordinal)
    {
        "GetExecutingAssembly", "GetCallingAssembly", "GetEntryAssembly", "FromExecutingAssembly", "FromCallingAssembly",
        "FromEntryAssembly",
    };

    private static readonly HashSet<string> UnknownAssemblyNames = new(StringComparer.Ordinal)
    {
        "GetAssemblies", "FromApplicationDependencies", "FromDependencyContext", "FromAssemblies", "FromAssemblyDependencies",
        "LoadFrom", "LoadFile", "Load",
    };

    private static readonly HashSet<string> FrameworkBases = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Mvc.ControllerBase", "Microsoft.AspNetCore.Mvc.RazorPages.PageModel",
        "Microsoft.AspNetCore.Mvc.Razor.RazorPageBase", "Microsoft.AspNetCore.Mvc.ViewComponent",
        "Microsoft.AspNetCore.SignalR.Hub", "Microsoft.AspNetCore.SignalR.Hub`1", "System.Attribute",
        "Microsoft.EntityFrameworkCore.Migrations.Migration", "Microsoft.EntityFrameworkCore.Infrastructure.ModelSnapshot",
        "Microsoft.AspNetCore.Components.ComponentBase",
    };

    private static readonly HashSet<string> FrameworkInterfaces = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Razor.TagHelpers.ITagHelper", "Microsoft.AspNetCore.Razor.TagHelpers.ITagHelperComponent",
        "Microsoft.AspNetCore.Mvc.Filters.IFilterMetadata", "Microsoft.AspNetCore.Http.IMiddleware",
        "Microsoft.Extensions.Hosting.IHostedService", "Microsoft.AspNetCore.Components.IComponent",
        "Microsoft.EntityFrameworkCore.IEntityTypeConfiguration`1",
    };

    private static readonly HashSet<string> ControllerAttributes = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Mvc.ApiControllerAttribute", "Microsoft.AspNetCore.Mvc.ControllerAttribute",
        "Microsoft.AspNetCore.Mvc.ViewComponentAttribute",
    };

    private readonly List<Compilation> _compilations = new();
    private readonly HashSet<object> _created = new();
    private readonly HashSet<object> _registered = new();
    private readonly HashSet<object> _open = new();
    private readonly HashSet<string> _openProjects = new(StringComparer.Ordinal);
    private readonly HashSet<string> _hosting = new(StringComparer.Ordinal);
    private bool _everyProjectOpen;
    private readonly HashSet<string> _enumerated = new(StringComparer.Ordinal);
    private bool _reflectiveUnfiltered;
    private readonly Dictionary<(object Method, int Ordinal), Role> _roles = new();
    private readonly List<(IMethodSymbol Callee, ImmutableArray<ITypeSymbol> Arguments)> _genericCalls = new();
    private readonly Dictionary<object, Known> _known = new();
    private readonly Dictionary<object, bool> _live = new();
    private bool _sealed;

    /// Projects all of whose types count as created, and types all of whose subtypes do (stats).
    public int OpenProjects { get; private set; }

    public int OpenTypes => _open.Count;

    // ---- Types (the constructor, every source type once) ----

    private void ScanType(INamedTypeSymbol type)
    {
        var key = Key(type.OriginalDefinition);
        if (type.TypeKind == TypeKind.Struct) _created.Add(key);
        else if (type.TypeKind == TypeKind.Class && !type.IsAbstract && !type.IsStatic && FrameworkBuilt(type)) _created.Add(key);
        // An EF context's entity sets: EF builds their entities.
        for (var b = type.BaseType; b != null; b = b.BaseType)
        {
            if (SymbolMatch.MetadataName(b) != "Microsoft.EntityFrameworkCore.DbContext") continue;
            var visited = new HashSet<object>();
            foreach (var member in type.GetMembers())
                if (member is IPropertySymbol { Type: INamedTypeSymbol { TypeArguments.Length: 1 } set } && SymbolMatch.MetadataName(set) == "Microsoft.EntityFrameworkCore.DbSet`1")
                    OpenEntity(set.TypeArguments[0], visited, 0);
            break;
        }
    }

    /// An entity EF materialises, and the entities its navigation properties reach (references, and the elements of
    /// collections), transitively.
    private void OpenEntity(ITypeSymbol type, HashSet<object> visited, int depth)
    {
        if (depth > 8) return;
        if (type is IArrayTypeSymbol array)
        {
            OpenEntity(array.ElementType, visited, depth + 1);
            return;
        }
        if (type is not INamedTypeSymbol named) return;
        if (!SymbolKeys.InSource(named))
        {
            foreach (var argument in named.TypeArguments) OpenEntity(argument, visited, depth + 1);
            return;
        }
        if (named.TypeKind is not (TypeKind.Class or TypeKind.Interface) || !visited.Add(Key(named.OriginalDefinition))) return;
        Open(named);
        for (var t = named; t != null && SymbolKeys.InSource(t); t = t.BaseType)
            foreach (var member in t.GetMembers())
                if (member is IPropertySymbol { IsStatic: false } property) OpenEntity(property.Type, visited, depth + 1);
    }

    /// The types attribute arguments name by `typeof` (`[ServiceFilter(typeof(F))]`, `[JsonConverter(typeof(C))]`): the
    /// framework builds them. Found in the syntax first (declarations, not bodies), so only those attributes are bound.
    private void ScanAttributes(Compilation compilation, CancellationToken ct)
    {
        foreach (var tree in compilation.SyntaxTrees)
        {
            ct.ThrowIfCancellationRequested();
            SemanticModel? model = null;
            var root = tree.GetRoot(ct);
            foreach (var node in root.DescendantNodes(n => n is not (BlockSyntax or ArrowExpressionClauseSyntax or EqualsValueClauseSyntax)))
            {
                if (node is AttributeArgumentSyntax argument)
                {
                    foreach (var typeOf in argument.DescendantNodesAndSelf().OfType<TypeOfExpressionSyntax>())
                    {
                        model ??= compilation.GetSemanticModel(tree);
                        if (model.GetTypeInfo(typeOf.Type, ct).Type is { } named) Open(named);
                    }
                }
                else if (node is AttributeSyntax { Name: var name } && GenericName(name) is { } generic)
                {
                    // A generic attribute names the type by its type argument (`[ModelBinder<B>]`).
                    foreach (var typeArgument in generic.TypeArgumentList.Arguments)
                    {
                        model ??= compilation.GetSemanticModel(tree);
                        if (model.GetTypeInfo(typeArgument, ct).Type is { } named) Open(named);
                    }
                }
            }
        }
    }

    private static GenericNameSyntax? GenericName(NameSyntax name) => name switch
    {
        GenericNameSyntax g => g,
        QualifiedNameSyntax { Right: GenericNameSyntax g } => g,
        AliasQualifiedNameSyntax { Name: GenericNameSyntax g } => g,
        _ => null,
    };

    /// The types the attributes of a lambda's or local function's parameters (or of the function) name, inside a body
    /// (`MapPost("/x", ([ModelBinder(typeof(B))] string s) => …)`): `typeof` arguments and generic attribute type
    /// arguments.
    private void FunctionAttributes(IMethodSymbol function)
    {
        OpenAttributeTypes(function.GetAttributes());
        foreach (var p in function.Parameters) OpenAttributeTypes(p.GetAttributes());
    }

    private void OpenAttributeTypes(ImmutableArray<AttributeData> attributes)
    {
        foreach (var a in attributes)
        {
            if (a.AttributeClass is { IsGenericType: true } generic)
                foreach (var t in generic.TypeArguments) Open(t);
            foreach (var c in a.ConstructorArguments) OpenTypeConstant(c);
            foreach (var n in a.NamedArguments) OpenTypeConstant(n.Value);
        }
    }

    private void OpenTypeConstant(TypedConstant constant)
    {
        if (constant.Kind == TypedConstantKind.Type && constant.Value is ITypeSymbol t) Open(t);
        else if (constant.Kind == TypedConstantKind.Array && !constant.IsNull)
            foreach (var v in constant.Values) OpenTypeConstant(v);
    }

    /// Whether a lambda or local function declares attributes on itself or on a parameter.
    private static bool HasAttributes(SyntaxNode syntax) => syntax switch
    {
        ParenthesizedLambdaExpressionSyntax l => l.AttributeLists.Count > 0 || l.ParameterList.Parameters.Any(p => p.AttributeLists.Count > 0),
        SimpleLambdaExpressionSyntax l => l.AttributeLists.Count > 0 || l.Parameter.AttributeLists.Count > 0,
        LocalFunctionStatementSyntax f => f.AttributeLists.Count > 0 || f.ParameterList.Parameters.Any(p => p.AttributeLists.Count > 0),
        _ => false,
    };

    /// A type the framework builds itself: a controller (by base, attribute or name), a Razor view or page, a page model,
    /// a view component, a tag helper, a filter or attribute, middleware (IMiddleware or a conventional Invoke), a hub, a
    /// hosted service, a Blazor component, an EF migration or type configuration.
    private static bool FrameworkBuilt(INamedTypeSymbol type)
    {
        for (var b = type; b != null; b = b.BaseType)
        {
            if (FrameworkBases.Contains(SymbolMatch.MetadataName(b))) return true;
            foreach (var a in b.GetAttributes())
                if (a.AttributeClass is { } c && ControllerAttributes.Contains(SymbolMatch.MetadataName(c))) return true;
        }
        foreach (var i in type.AllInterfaces)
            if (FrameworkInterfaces.Contains(SymbolMatch.MetadataName(i))) return true;
        if (type.DeclaredAccessibility == Accessibility.Public
            && (type.Name.EndsWith("Controller", StringComparison.Ordinal) || type.Name.EndsWith("ViewComponent", StringComparison.Ordinal)))
            return true;
        foreach (var name in new[] { "Invoke", "InvokeAsync" })
            foreach (var m in type.GetMembers(name))
                if (m is IMethodSymbol { IsStatic: false, Parameters.Length: > 0 } invoke
                    && SymbolMatch.MetadataName(invoke.Parameters[0].Type) == "Microsoft.AspNetCore.Http.HttpContext")
                    return true;
        return false;
    }

    // ---- Bodies (CallGraph.Build, every body once) ----

    /// The facts one body tells: what it builds, registers, scans or names by `typeof`.
    public void Collect(IOperation root, Compilation compilation)
    {
        var own = compilation.AssemblyName ?? "";
        var unit = new UnitFacts(own);
        foreach (var op in root.DescendantsAndSelf())
        {
            switch (op)
            {
                case IObjectCreationOperation creation when creation.Type is INamedTypeSymbol created:
                    if (created.Name == "ServiceDescriptor" && SymbolMatch.MetadataName(created) == ServiceDescriptor)
                    {
                        _hosting.Add(own);
                        if (creation.Constructor != null) RegisteredByType(creation.Constructor, creation.Arguments, unit);
                    }
                    else
                    {
                        Create(created, false);
                    }
                    break;
                case ITypeParameterObjectCreationOperation { Type: ITypeParameterSymbol parameter }:
                    AddRole(parameter, Role.Reflecting);
                    break;
                case IAnonymousFunctionOperation { Symbol: var function } when HasAttributes(op.Syntax):
                    FunctionAttributes(function);
                    break;
                case ILocalFunctionOperation { Symbol: var local } when HasAttributes(op.Syntax):
                    FunctionAttributes(local);
                    break;
                case IInvocationOperation invocation:
                    Invocation(invocation, unit);
                    break;
                case IPropertyReferenceOperation { Property.Name: "DefinedTypes" or "ExportedTypes" } property
                    when property.Property.ContainingType is { } t && SymbolMatch.MetadataName(t) == "System.Reflection.Assembly":
                    unit.Enumerates = true;
                    Designate(property.Instance, unit);
                    break;
                case ITypeOfOperation typeOf:
                    TypeOf(typeOf, unit);
                    break;
                case IVariableDeclaratorOperation { Initializer.Value: { } value } declarator:
                    if (IsReflectedObject(value, null))
                        (unit.ReflectedLocals ??= new HashSet<ILocalSymbol>(SymbolEqualityComparer.Default)).Add(declarator.Symbol);
                    else if (SymbolMatch.MetadataName(declarator.Symbol.Type) == "System.Reflection.Assembly")
                        (unit.AssemblyLocals ??= new Dictionary<ILocalSymbol, string?>(SymbolEqualityComparer.Default))[declarator.Symbol] = AssemblyOf(value, unit);
                    break;
                case IConversionOperation { IsImplicit: false, Type: { } converted } conversion when IsReflectedObject(conversion.Operand, unit.ReflectedLocals):
                    Filter(converted, unit);
                    break;
                case IIsTypeOperation isType when IsReflectedObject(isType.ValueOperand, unit.ReflectedLocals):
                    Filter(isType.TypeOperand, unit);
                    break;
                case IIsPatternOperation pattern when IsReflectedObject(pattern.Value, unit.ReflectedLocals):
                    if (pattern.Pattern is IDeclarationPatternOperation { MatchedType: { } declared }) Filter(declared, unit);
                    else if (pattern.Pattern is ITypePatternOperation { MatchedType: { } matched }) Filter(matched, unit);
                    break;
            }
        }
        if (unit.Filtered) return;
        // A body that enumerates unknown assemblies and registers or builds by a run-time type registers them all.
        if (unit.Enumerates && unit.Reflective && (unit.UnknownAssembly || unit.Designated.Count == 0)) _everyProjectOpen = true;
        // Unfiltered enumerations of named assemblies and unfiltered registrations or creations by a run-time `Type` are
        // kept solution-wide: a scan split over a type-finder helper and its caller opens those assemblies at Seal.
        // (Unknown assemblies are not combined across bodies: Jellyfin's and OrchardCore's module loaders enumerate them,
        // and every project would open.)
        if (unit.Enumerates && !unit.UnknownAssembly) _enumerated.UnionWith(unit.Designated);
        if (unit.Reflective) _reflectiveUnfiltered = true;
    }

    /// The parameter types of an entry point: model binding builds them.
    public void CollectEntry(IMethodSymbol entry)
    {
        foreach (var p in entry.Parameters) CreateDeep(p.Type, 0);
    }

    private sealed class UnitFacts
    {
        public UnitFacts(string own) => Own = own;

        public string Own { get; }

        public bool Enumerates { get; set; }

        public bool Reflective { get; set; }

        /// A type named by `typeof` (a library's included) or the type an object built by reflection is cast to.
        public bool Filtered { get; set; }

        public bool UnknownAssembly { get; set; }

        public HashSet<string> Designated { get; } = new(StringComparer.Ordinal);

        public HashSet<ILocalSymbol>? ReflectedLocals { get; set; }

        /// Locals holding an assembly: its project's name, null when not known.
        public Dictionary<ILocalSymbol, string?>? AssemblyLocals { get; set; }
    }

    private void Invocation(IInvocationOperation invocation, UnitFacts unit)
    {
        var method = invocation.TargetMethod;
        var name = method.Name;
        if (RegistrationNames.Contains(name) && IsRegistration(method, invocation.Instance))
        {
            _hosting.Add(unit.Own);
            var hasFactory = method.Parameters.Any(p => FactoryParameters.Contains(p.Name));
            if (method.TypeArguments.Length > 0 && !(hasFactory && method.TypeArguments.Length == 1)) Register(method.TypeArguments[^1]);
            RegisteredByType(method, invocation.Arguments, unit);
            return;
        }
        if (ScanNames.Contains(name) && (IsRegistration(method, invocation.Instance) || IsAutofac(method, invocation.Instance)))
        {
            _hosting.Add(unit.Own);
            Scan(invocation, unit.Own);
            return;
        }
        if (name is "GetTypes" or "GetExportedTypes" && method.ContainingType is { } containing
            && SymbolMatch.MetadataName(containing) is "System.Reflection.Assembly" or "System.Reflection.Module")
        {
            unit.Enumerates = true;
            Designate(invocation.Instance, unit);
        }
        if (CreationNames.Contains(name) && invocation.Arguments.Any(a => a.Parameter?.Type is { } pt && SymbolMatch.MetadataName(pt) == "System.Type"
                && Unwrap(a.Value) is not ITypeOfOperation))
            unit.Reflective = true;
        // An assignability test bounds what the body enumerates by a type its caller names (that `typeof` opens it there).
        if (name is "IsAssignableFrom" or "IsAssignableTo" or "IsSubclassOf" or "IsInstanceOfType"
            && method.ContainingType is { Name: "Type" } typeType && SymbolMatch.MetadataName(typeType) == "System.Type")
            unit.Filtered = true;
        if (LibraryScan(invocation, unit.Own)) _hosting.Add(unit.Own);
        if (method.TypeArguments.Length == 0) return;
        if (SymbolKeys.InSource(method))
        {
            _genericCalls.Add((method, method.TypeArguments));
            return;
        }
        // A library builds what it is given as a type argument, and the element and argument types inside it
        // (`Deserialize<List<T>>`); a creation or deserialization call's inferred type argument counts too.
        var creation = CreationNames.Contains(name);
        if (!creation && !HasExplicitTypeArguments(invocation.Syntax)) return;
        foreach (var argument in method.TypeArguments)
        {
            if (argument is ITypeParameterSymbol parameter)
            {
                if (creation) AddRole(parameter, Role.Reflecting);
            }
            else
            {
                CreateDeep(argument, 0);
            }
        }
    }

    /// A concrete source type, an array's element type, and the type arguments of a library's generic type (a list, a
    /// dictionary), recursively.
    private void CreateDeep(ITypeSymbol type, int depth)
    {
        if (depth > 3) return;
        switch (type)
        {
            case IArrayTypeSymbol array:
                CreateDeep(array.ElementType, depth + 1);
                break;
            case INamedTypeSymbol named when SymbolKeys.InSource(named):
                Create(named, false);
                break;
            case INamedTypeSymbol { IsGenericType: true } library:
                foreach (var argument in library.TypeArguments) CreateDeep(argument, depth + 1);
                break;
        }
    }

    /// A library's assembly scan (ruling R-E27): a method of an `IServiceCollection` extension, or called inside a lambda
    /// given to one, that takes assemblies (MediatR `RegisterServicesFromAssembly`, MassTransit `AddConsumers`,
    /// FluentMigrator `ScanIn`), marker types by a parameter named for assemblies or markers (AutoMapper
    /// `AddAutoMapper(typeof(X))`), or a type argument with "Assembl" in its name (FluentValidation
    /// `AddValidatorsFromAssemblyContaining<T>()`). It opens the projects of the named assemblies only (`typeof(X).Assembly`,
    /// a `*Containing<T>` or marker type, the executing, calling or entry assembly, `Assembly.Load` of a literal name); an
    /// unknown assembly list is ignored, as split scans over unknown assemblies are.
    private bool LibraryScan(IInvocationOperation invocation, string own)
    {
        var method = invocation.TargetMethod;
        if (RegistrationNames.Contains(method.Name) || ScanNames.Contains(method.Name)) return false;
        var assemblyParameters = method.Parameters.Where(p => IsAssemblies(p.Type)).ToList();
        var markerParameters = method.Parameters.Where(p => IsTypes(p.Type)
            && (p.Name.Contains("Assembl", StringComparison.OrdinalIgnoreCase) || p.Name.Contains("Marker", StringComparison.OrdinalIgnoreCase))).ToList();
        var markerTypeArguments = method.Name.Contains("Assembl", StringComparison.Ordinal) && method.TypeArguments.Length > 0;
        if (assemblyParameters.Count == 0 && markerParameters.Count == 0 && !markerTypeArguments) return false;
        if (!IsServicesExtension(method) && !InsideServicesLambda(invocation)) return false;
        var designated = new HashSet<string>(StringComparer.Ordinal);
        var unit = new UnitFacts(own);
        if (markerTypeArguments)
            foreach (var t in method.TypeArguments) Assembly(t, designated);
        foreach (var argument in invocation.Arguments)
        {
            if (argument.Parameter is not { } parameter || argument.ArgumentKind == ArgumentKind.DefaultValue) continue;
            var ordinal = parameter.Ordinal;
            var isAssembly = assemblyParameters.Exists(p => p.Ordinal == ordinal);
            var isMarker = markerParameters.Exists(p => p.Ordinal == ordinal);
            if (!isAssembly && !isMarker) continue;
            var values = Unwrap(argument.Value) is IArrayCreationOperation { Initializer: { } init } ? init.ElementValues.ToList() : new List<IOperation> { argument.Value };
            foreach (var value in values)
            {
                if (isMarker)
                {
                    if (Unwrap(value) is ITypeOfOperation typeOf) Assembly(typeOf.TypeOperand, designated);
                }
                else if (AssemblyOf(value, unit) is { } name)
                {
                    designated.Add(name);
                }
            }
        }
        _openProjects.UnionWith(designated);
        return true;
    }

    private static bool IsAssemblies(ITypeSymbol type) => type switch
    {
        IArrayTypeSymbol array => IsAssembly(array.ElementType),
        INamedTypeSymbol { IsGenericType: true, TypeArguments: [var element] } named when named.Name == "IEnumerable" => IsAssembly(element),
        _ => IsAssembly(type),
    };

    private static bool IsAssembly(ITypeSymbol type) => type.Name == "Assembly" && SymbolMatch.MetadataName(type) == "System.Reflection.Assembly";

    private static bool IsTypes(ITypeSymbol type) => type switch
    {
        IArrayTypeSymbol array => IsType(array.ElementType),
        INamedTypeSymbol { IsGenericType: true, TypeArguments: [var element] } named when named.Name == "IEnumerable" => IsType(element),
        _ => IsType(type),
    };

    private static bool IsType(ITypeSymbol type) => type.Name == "Type" && SymbolMatch.MetadataName(type) == "System.Type";

    private static bool IsServicesExtension(IMethodSymbol method)
    {
        var m = method.ReducedFrom ?? method;
        return m.IsExtensionMethod && m.Parameters.Length > 0 && IsServices(m.Parameters[0].Type);
    }

    /// Whether a call sits in a lambda given to an `IServiceCollection` extension (`AddMediatR(c => c.Register…(asm))`).
    private static bool InsideServicesLambda(IOperation operation)
    {
        var depth = 0;
        for (var op = operation.Parent; op != null && depth < 40; op = op.Parent, depth++)
        {
            if (op is not IAnonymousFunctionOperation lambda) continue;
            var up = lambda.Parent;
            while (up is IDelegateCreationOperation or IConversionOperation) up = up.Parent;
            if (up is IArgumentOperation { Parent: IInvocationOperation call } && IsServicesExtension(call.TargetMethod)) return true;
        }
        return false;
    }

    private static bool HasExplicitTypeArguments(SyntaxNode syntax) => syntax is InvocationExpressionSyntax
    {
        Expression: GenericNameSyntax or MemberAccessExpressionSyntax { Name: GenericNameSyntax } or MemberBindingExpressionSyntax { Name: GenericNameSyntax },
    };

    /// A registration call: an IServiceCollection extension or member, a ServiceDescriptor factory, an Autofac
    /// ContainerBuilder registration.
    private static bool IsRegistration(IMethodSymbol method, IOperation? instance)
    {
        if (method.ContainingType is { } c && SymbolMatch.MetadataName(c) == ServiceDescriptor) return true;
        if (instance?.Type is { } receiver && IsServices(receiver)) return true;
        var m = method.ReducedFrom ?? method;
        return m.IsExtensionMethod && m.Parameters.Length > 0 && (IsServices(m.Parameters[0].Type) || IsAutofacBuilder(m.Parameters[0].Type));
    }

    private static bool IsAutofac(IMethodSymbol method, IOperation? instance) =>
        instance?.Type is { } receiver && IsAutofacBuilder(receiver);

    private static bool IsServices(ITypeSymbol type) =>
        type.Name == "IServiceCollection" && SymbolMatch.MetadataName(type) == ServiceCollection
        || type.AllInterfaces.Any(i => i.Name == "IServiceCollection" && SymbolMatch.MetadataName(i) == ServiceCollection);

    private static bool IsAutofacBuilder(ITypeSymbol type) => type.Name == "ContainerBuilder";

    /// The implementation a registration names by a `Type` argument (`implementationType`, or the only `serviceType` when
    /// no factory or instance is given); a value that is no `typeof` is a registration by reflection.
    private void RegisteredByType(IMethodSymbol method, ImmutableArray<IArgumentOperation> arguments, UnitFacts unit)
    {
        var typeParameters = method.Parameters.Where(p => SymbolMatch.MetadataName(p.Type) == "System.Type").ToList();
        if (typeParameters.Count == 0) return;
        var implementation = typeParameters.FirstOrDefault(p => ImplementationTypeParameters.Contains(p.Name));
        if (implementation == null && typeParameters.Count == 1 && !method.Parameters.Any(p => FactoryParameters.Contains(p.Name)))
            implementation = typeParameters[0];
        if (implementation == null) return;
        var argument = arguments.FirstOrDefault(a => a.Parameter?.Ordinal == implementation.Ordinal);
        if (argument == null || argument.ArgumentKind == ArgumentKind.DefaultValue) return;
        if (Unwrap(argument.Value) is ITypeOfOperation typeOf) Register(typeOf.TypeOperand);
        else unit.Reflective = true;
    }

    /// A scan (Scrutor `Scan`, Autofac `RegisterAssemblyTypes`): its filters (`AssignableTo<T>()`, `AssignableTo(typeof(T))`)
    /// open those types; without one, the scanned projects (`FromAssemblyOf<T>()`, `typeof(T).Assembly`, the calling
    /// assembly), or every project when they are not known.
    private void Scan(IInvocationOperation invocation, string own)
    {
        var designated = new HashSet<string>(StringComparer.Ordinal);
        var unknown = false;
        var filters = new List<ITypeSymbol>();
        foreach (var op in invocation.DescendantsAndSelf())
        {
            if (op is IInvocationOperation call)
            {
                var name = call.TargetMethod.Name;
                if (name is "FromAssemblyOf" or "FromAssembliesOf")
                    foreach (var t in call.TargetMethod.TypeArguments) Assembly(t, designated);
                else if (name is "AssignableTo" or "AssignableToAny")
                    filters.AddRange(call.TargetMethod.TypeArguments);
                else if (OwnAssemblyNames.Contains(name)) designated.Add(own);
                else if (UnknownAssemblyNames.Contains(name)) unknown = true;
            }
            else if (op is ITypeOfOperation typeOf)
            {
                var parent = Up(typeOf);
                if (parent is IArgumentOperation { Parent: IInvocationOperation { TargetMethod.Name: "AssignableTo" or "AssignableToAny" } })
                    filters.Add(typeOf.TypeOperand);
                else
                    Assembly(typeOf.TypeOperand, designated);
            }
        }
        if (filters.Count > 0)
            foreach (var f in filters) Open(f);
        else if (unknown || designated.Count == 0) _everyProjectOpen = true;
        else _openProjects.UnionWith(designated);
    }

    private static void Assembly(ITypeSymbol type, HashSet<string> designated)
    {
        if (type.ContainingAssembly?.Name is { } name) designated.Add(name);
    }

    /// The assembly whose types a body enumerates: `typeof(T).Assembly` (or `.GetTypeInfo().Assembly`), the executing
    /// assembly or `GetType().Assembly` (the body's own project), a local initialised with one of these; else unknown.
    private static void Designate(IOperation? receiver, UnitFacts unit)
    {
        if (AssemblyOf(receiver, unit) is { } name) unit.Designated.Add(name);
        else unit.UnknownAssembly = true;
    }

    private static string? AssemblyOf(IOperation? value, UnitFacts unit)
    {
        var r = Unwrap(value);
        if (r is ILocalReferenceOperation local)
            return unit.AssemblyLocals != null && unit.AssemblyLocals.TryGetValue(local.Local, out var held) ? held : null;
        if (r is IPropertyReferenceOperation { Property.Name: "Assembly" } assembly)
        {
            var inner = Unwrap(assembly.Instance);
            if (inner is IInvocationOperation { TargetMethod.Name: "GetTypeInfo" } info) inner = Unwrap(info.Arguments.Length > 0 ? info.Arguments[0].Value : info.Instance);
            if (inner is ITypeOfOperation typeOf) return typeOf.TypeOperand.ContainingAssembly?.Name;
            if (inner is IInvocationOperation { TargetMethod.Name: "GetType" } or IInstanceReferenceOperation) return unit.Own;
            return null;
        }
        if (r is IInvocationOperation { TargetMethod.Name: "Load", Arguments: [{ Value.ConstantValue: { HasValue: true, Value: string loaded } }] } load
            && load.TargetMethod.ContainingType is { Name: "Assembly" } assemblyType && SymbolMatch.MetadataName(assemblyType) == "System.Reflection.Assembly")
            return loaded.Split(',')[0].Trim();
        return r is IInvocationOperation { TargetMethod.Name: var name } && OwnAssemblyNames.Contains(name) ? unit.Own : null;
    }

    /// A `typeof` outside a registration, a service lookup or an assembly designator opens its type.
    private void TypeOf(ITypeOfOperation typeOf, UnitFacts unit)
    {
        var parent = Up(typeOf);
        if (parent is IPropertyReferenceOperation { Property.Name: "Assembly" or "Module" }) return;
        if (parent is IInvocationOperation { TargetMethod.Name: "GetTypeInfo" } info && Up(info) is IPropertyReferenceOperation { Property.Name: "Assembly" })
            return;
        if (parent is IArgumentOperation argument)
        {
            switch (argument.Parent)
            {
                case IInvocationOperation call:
                {
                    var name = call.TargetMethod.Name;
                    if (RegistrationNames.Contains(name) && IsRegistration(call.TargetMethod, call.Instance)) return;
                    if (LookupNames.Contains(name) || name is "FromAssemblyOf" or "FromAssembliesOf") return;
                    if (ScanNames.Contains(name)) return;
                    break;
                }
                case IObjectCreationOperation { Type: { Name: "ServiceDescriptor" } created } when SymbolMatch.MetadataName(created) == ServiceDescriptor:
                    return;
            }
        }
        // Only a type that can bound a scan filters it; a marker attribute, a namespace or name check, or a log line's
        // `typeof` only opens its type and leaves the scan unfiltered.
        if (CanBound(typeOf.TypeOperand)) Filter(typeOf.TypeOperand, unit);
        else Open(typeOf.TypeOperand);
    }

    /// A type a scan can be bounded by: a type parameter, an interface, an abstract class, a library class, or a source
    /// class with members to override; never an attribute.
    private static bool CanBound(ITypeSymbol type)
    {
        if (type is ITypeParameterSymbol) return true;
        if (type is not INamedTypeSymbol named) return false;
        for (var b = named; b != null; b = b.BaseType)
            if (b.Name == "Attribute" && SymbolMatch.MetadataName(b) == "System.Attribute") return false;
        if (named.TypeKind == TypeKind.Interface || named.IsAbstract) return true;
        if (named.TypeKind != TypeKind.Class || named.IsSealed || named.IsStatic || named.SpecialType != SpecialType.None) return false;
        return !SymbolKeys.InSource(named) || named.GetMembers().Any(m => m.IsVirtual || m.IsAbstract);
    }

    /// A type that filters what a body builds or registers by reflection: it and its subtypes are open.
    private void Filter(ITypeSymbol type, UnitFacts unit)
    {
        unit.Filtered = true;
        Open(type);
    }

    /// An object made by reflection or deserialization from a run-time type (`Activator.CreateInstance(t)`,
    /// `ActivatorUtilities.CreateInstance(sp, t)`, `JsonSerializer.Deserialize(s, t)`, `ConstructorInfo.Invoke`), or a local
    /// initialised with one.
    private static bool IsReflectedObject(IOperation? value, HashSet<ILocalSymbol>? locals)
    {
        value = Unwrap(value);
        if (value is ILocalReferenceOperation local) return locals != null && locals.Contains(local.Local);
        if (value is not IInvocationOperation { TargetMethod: { TypeArguments.Length: 0 } method }) return false;
        if (method.Name == "Invoke" && method.ContainingType is { } c && SymbolMatch.MetadataName(c) == "System.Reflection.ConstructorInfo") return true;
        return CreationNames.Contains(method.Name);
    }

    private static IOperation? Unwrap(IOperation? value)
    {
        while (value is IConversionOperation { IsImplicit: true } c) value = c.Operand;
        return value;
    }

    /// The operation that uses `op`'s value, above any implicit conversion.
    private static IOperation? Up(IOperation op)
    {
        var parent = op.Parent;
        while (parent is IConversionOperation { IsImplicit: true }) parent = parent.Parent;
        return parent;
    }

    private void Create(INamedTypeSymbol type, bool registered)
    {
        if (type.IsAbstract || type.TypeKind is not (TypeKind.Class or TypeKind.Struct) || !SymbolKeys.InSource(type)) return;
        var key = Key(type.OriginalDefinition);
        _created.Add(key);
        if (registered) _registered.Add(key);
    }

    private void Register(ITypeSymbol type)
    {
        if (type is ITypeParameterSymbol parameter) AddRole(parameter, Role.Registering);
        else if (type is INamedTypeSymbol named) Create(named, true);
    }

    private void Open(ITypeSymbol type)
    {
        if (type is ITypeParameterSymbol parameter) AddRole(parameter, Role.Reflecting);
        else if (type is INamedTypeSymbol named && SymbolKeys.InSource(named)) _open.Add(Key(named.OriginalDefinition));
    }

    /// A method type parameter's role (a class's type parameters are not followed).
    private bool AddRole(ITypeParameterSymbol parameter, Role role)
    {
        if (parameter.DeclaringMethod is not { } method) return false;
        var key = (Key(SymbolKeys.Definition(method)), parameter.Ordinal);
        _roles.TryGetValue(key, out var old);
        if ((old | role) == old) return false;
        _roles[key] = old | role;
        return true;
    }

    // ---- Seal (after every body is collected) ----

    /// Follows type parameter roles to the type arguments of the calls (a fixed point over the source generic calls,
    /// through the implementations of a virtual one), then opens the projects without a registration in source.
    public void Seal()
    {
        if (_sealed) return;
        var implementations = new Dictionary<object, IReadOnlyList<IMethodSymbol>>();
        IReadOnlyList<IMethodSymbol> Implementations(IMethodSymbol callee)
        {
            var def = (IMethodSymbol)SymbolKeys.Definition(callee);
            var key = Key(def);
            if (implementations.TryGetValue(key, out var list)) return list;
            var all = new List<IMethodSymbol> { def };
            if (Resolve(def, true, def.ContainingType) is { } resolution) all.AddRange(resolution.Targets);
            implementations[key] = all;
            return all;
        }
        var changed = true;
        for (var round = 0; changed && round < 50; round++)
        {
            changed = false;
            foreach (var (callee, arguments) in _genericCalls)
                foreach (var target in Implementations(callee))
                    for (var i = 0; i < arguments.Length; i++)
                    {
                        if (!_roles.TryGetValue((Key(target), i), out var role)) continue;
                        if (arguments[i] is ITypeParameterSymbol parameter)
                        {
                            changed |= AddRole(parameter, role);
                            continue;
                        }
                        if ((role & Role.Reflecting) != 0) Open(arguments[i]);
                        if ((role & Role.Registering) != 0) Register(arguments[i]);
                    }
        }
        // Some body registers or builds by an unfiltered run-time type, and some body enumerates assemblies unfiltered:
        // those assemblies are scanned (the two may be one body or a helper and its caller).
        if (_reflectiveUnfiltered) _openProjects.UnionWith(_enumerated);
        // A project is hosted when it or a project referencing it registers services; the others have their
        // registration code elsewhere.
        var names = _compilations.Select(c => c.AssemblyName ?? "").Distinct(StringComparer.Ordinal).ToList();
        var hosting = _compilations.Where(c => _hosting.Contains(c.AssemblyName ?? "")).ToList();
        foreach (var name in names)
            if (!hosting.Exists(h => h.AssemblyName == name || h.ReferencedAssemblyNames.Any(a => a.Name == name)))
                _openProjects.Add(name);
        OpenProjects = _everyProjectOpen ? names.Count : names.Count(_openProjects.Contains);
        _sealed = true;
    }

    /// Whether the solution creates instances of `type` itself (null for an abstract type or interface).
    private Known KnownOf(INamedTypeSymbol type)
    {
        var def = type.OriginalDefinition;
        var key = Key(def);
        if (_known.TryGetValue(key, out var known)) return known;
        known = Known.None;
        if (def.TypeKind == TypeKind.Struct || _created.Contains(key))
        {
            known = Known.Created;
        }
        else if (def.TypeKind == TypeKind.Class && !def.IsAbstract)
        {
            if (_everyProjectOpen || _openProjects.Contains(def.ContainingAssembly?.Name ?? "")) known = Known.Open;
            else
            {
                for (var b = def; b != null && known == Known.None; b = b.BaseType)
                    if (_open.Contains(Key(b.OriginalDefinition))) known = Known.Open;
                if (known == Known.None && def.AllInterfaces.Any(i => _open.Contains(Key(i.OriginalDefinition)))) known = Known.Open;
            }
        }
        _known[key] = known;
        return known;
    }

    /// Whether objects of `type` (or of a type derived from it) exist: the type or a subtype is created or open. True
    /// before Seal.
    public bool IsLive(INamedTypeSymbol type)
    {
        if (!_sealed || type.IsStatic) return true;
        var key = Key(type.OriginalDefinition);
        if (_live.TryGetValue(key, out var live)) return live;
        var seen = new HashSet<object> { key };
        var queue = new Queue<INamedTypeSymbol>();
        queue.Enqueue(type.OriginalDefinition);
        while (queue.Count > 0 && !live)
        {
            var t = queue.Dequeue();
            if (KnownOf(t) != Known.None) live = true;
            else if (_subtypes.TryGetValue(Key(t.OriginalDefinition), out var subtypes))
                foreach (var s in subtypes)
                    if (seen.Add(Key(s))) queue.Enqueue(s);
        }
        _live[key] = live;
        return live;
    }

    /// Whether a DI registration names `type` as an implementation.
    public bool IsRegistered(INamedTypeSymbol type) => _registered.Contains(Key(type.OriginalDefinition));
}
