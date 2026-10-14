using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// The request entry points and what each reaches (spec §5 "Heap" as amended, decision R-6), for the request-scoped heap.
///
/// - Entry points: the methods the sources model treats as receiving the request (SourceFinder.IsEntry: controller
///   actions, Razor Pages handlers, Minimal API handlers given as method groups, methods with a parameter bound by an
///   attribute), and each Minimal API handler given as a lambda or local function (its own entry, apart from the code
///   around it, with the top-level local functions it calls). Beyond the three kinds the spec names (rulings R-E15,
///   R-E16), request code the framework invokes, which no call edge reaches but which runs inside a request, when no
///   other entry point reaches it:
///   - each view and view component class (a layout, a view no action names), each tag helper and hub class: an entry
///     point of its own;
///   - code "around" every action (fix round 1, I1): filter, endpoint-filter and middleware classes (a controller's
///     filter overrides included), conventional middleware `Invoke(HttpContext, …)`, constructors DI builds (no `new`
///     reaches them, or their type, a base or an interface is a constructor parameter, or a DI registration names their
///     type) and units that read the request themselves: one shared entry point, Around. Instance code of a type the
///     solution never creates (Dispatch.IsLive, decision R-7) is neither around code nor an entry point. What around code writes
///     or reads from the request runs in every request, so its writes and its request data are widened to every entry
///     point (WriteReach, SourceScope); its reads keep its own bit (data an admin action saved stays out of it).
/// - Reach: from each entry point over the call graph (CallGraph: invocations, object creations, property accessors,
///   method groups, implicit ToString(), with Dispatch and its DI-aware targets), as one interned bit set per strongly
///   connected component,
///   propagated once from callers to callees in the components' top-down order.
/// - Edges added to the call graph before its components are computed:
///   - an action to the view it renders: `View()`/`PartialView()` of a controller resolve as MVC's default view locator
///     does for the conventional cases: the default name is the action's (`[ActionName]`, else the method name, also
///     without an `Async` suffix), looked up as Views/<Controller>/<name>.cshtml, Views/Shared/<name>.cshtml and
///     Pages/Shared/<name>.cshtml outside any area, or, for a controller with `[Area("X")]` (inherited),
///     Areas/X/Views/<Controller>/, Areas/X/Views/Shared/ and the root Views/Shared/; a path name (`~/…`, `/…`,
///     `….cshtml`) matches that path. `Page()` and every Razor Pages handler reach the page whose `Model` is the
///     handler's page model;
///   - a view to its partials (`Html.Partial*`, `Html.RenderPartial*`, `<partial name="…">`: the view's folder, then the
///     Shared folders of its area and of the root), its view components (`Component.InvokeAsync` by name, type or type
///     argument, `<vc:…>`), and the tag helpers it creates (`CreateTagHelper<T>()`: T's Init/Process/ProcessAsync);
///   - a view component's `View()` (also through an abstract base's wrapper: each concrete component derived from it) to
///     its Components/<name>/<view or Default>.cshtml (any view under Components/<name>/ for a name passed in);
///   - a constructor (or the `new` of a type with an implicit one) to its type's instance field and property
///     initializers.
///   A view is identified by the generator's RazorCompiledItem attributes, else by its `#line` file. A view name that
///   cannot be resolved reaches every view and view component of the caller's project and of the projects that
///   reference it, a view component name every view component of the solution (counted: UnresolvedViews); a path name
///   no compiled view has (a runtime-compiled view) reaches nothing (counted: UncompiledViews).
internal sealed class EntryPoints
{
    private const string RazorPageBase = "Microsoft.AspNetCore.Mvc.Razor.RazorPageBase";
    private const string RazorPagesPage = "Microsoft.AspNetCore.Mvc.RazorPages.Page";
    private const string ViewComponentBase = "Microsoft.AspNetCore.Mvc.ViewComponent";
    private const string ViewComponentAttribute = "Microsoft.AspNetCore.Mvc.ViewComponentAttribute";
    private const string PartialTagHelper = "Microsoft.AspNetCore.Mvc.TagHelpers.PartialTagHelper";
    private const string AreaAttribute = "Microsoft.AspNetCore.Mvc.AreaAttribute";

    private enum Kind { View, ComponentView, Page, Partial, Component }

    /// A view rendered by a unit: its kind, its name (null: the default; Unresolved: not a constant), a component's type.
    private sealed record Request(Unit Caller, Kind Kind, string? Name, INamedTypeSymbol? Component);

    private const string Unresolved = "\0";

    private enum Match { Suffix, Root, TwoWay, Folder }

    /// A candidate view path: Suffix (the view's path ends with it), Root (the same, outside any area), TwoWay (either
    /// ends with the other: an app-relative name against project-relative identifiers), Folder (the path contains it).
    private readonly record struct Candidate(string Text, Match Mode);

    private sealed class ViewClass
    {
        public required INamedTypeSymbol Type { get; init; }
        public required Compilation Compilation { get; init; }
        public string? Path { get; init; }
        public object? ModelKey { get; init; }
        public List<Unit> Units { get; } = new();
    }

    private sealed class ComponentClass
    {
        public required INamedTypeSymbol Type { get; init; }
        public required Compilation Compilation { get; init; }
        public required string Name { get; init; }
        public List<Unit> Units { get; } = new();
    }

    /// A Minimal API handler (lambda or local function) inside a unit: its spans (its own and those of the top-level
    /// local functions it calls) and its calls (resolved by Dispatch once it is sealed).
    private sealed record Handler(List<TextSpan> Spans, List<CallSite> Sites);

    private readonly SourceFinder _sources;
    private readonly ReachTable _table = new();
    private readonly List<Unit> _entryUnits = new();
    private readonly Dictionary<Unit, List<Handler>> _handlers = new();
    private readonly HashSet<Unit> _readsRequest = new();
    private readonly Dictionary<Unit, (object Key, bool Around)> _frameworkClass = new();
    private readonly HashSet<Unit> _constructors = new();
    private readonly HashSet<Unit> _staticInitializers = new();
    private readonly Dictionary<Unit, INamedTypeSymbol> _declaringTypes = new();
    private Dispatch? _dispatch;
    private readonly HashSet<object> _injected = new();
    private readonly Dictionary<object, List<Unit>> _constructorsOf = new();
    private readonly Dictionary<object, List<Unit>> _initializersOf = new();
    private readonly List<(Unit Caller, object Type)> _implicitNews = new();
    private readonly Dictionary<object, List<Unit>> _tagHelperUnits = new();
    private readonly List<(Unit View, INamedTypeSymbol Type)> _tagHelpers = new();
    private readonly List<Request> _requests = new();
    private readonly Dictionary<object, ViewClass?> _views = new();
    private readonly Dictionary<object, ComponentClass?> _components = new();
    private readonly Dictionary<Unit, ViewClass> _viewOfUnit = new();
    private readonly Dictionary<Compilation, Dictionary<object, string>> _compiledItems = new();
    private readonly Dictionary<object, bool> _derives = new();
    private readonly Dictionary<(Compilation, Compilation), bool> _references = new();

    private Reach[] _sccReach = Array.Empty<Reach>();
    private readonly Dictionary<Unit, List<(List<TextSpan> Spans, int Bit)>> _handlerBits = new();
    private readonly Dictionary<int, Reach> _bodyReach = new();
    private readonly Dictionary<int, Reach> _bodyWriteReach = new();
    private int _words;
    private int _aroundBit = -1;
    private Reach _all = Reach.None;

    public EntryPoints(SourceFinder sources) => _sources = sources;

    /// Entry points (explicit, handler bodies and implicit ones).
    public int Count { get; private set; }

    /// Views and view components rendered by name that were resolved, those that fell back to every view, and path
    /// names no compiled view has.
    public int ViewEdges { get; private set; }

    public int UnresolvedViews { get; private set; }

    public int UncompiledViews { get; private set; }

    // ---- Indexing (CallGraph.Build, once per unit) ----

    /// Records what a unit tells about entry points and views: whether it is an entry point, its Minimal API handler
    /// lambdas and local functions (with the callees of each), whether it reads the request itself, the view class, view
    /// component or framework class it belongs to, whether it is a constructor or an instance initializer, and the views
    /// and tag helpers it renders.
    public void Scan(Unit unit, IOperation operation, Dispatch dispatch)
    {
        _dispatch ??= dispatch;
        var type = unit.Symbol?.ContainingType ?? DeclaringType(unit);
        if (unit.Symbol == null && type != null) _declaringTypes[unit] = type;
        if (type != null)
        {
            var typeKey = SymbolKeys.Of(type.OriginalDefinition);
            if (ViewOf(type, unit.Compilation) is { } view)
            {
                view.Units.Add(unit);
                _viewOfUnit[unit] = view;
                _frameworkClass[unit] = (view, false);
            }
            else if (ComponentOf(type, unit.Compilation) is { } component)
            {
                component.Units.Add(unit);
                _frameworkClass[unit] = (component, false);
            }
            else if (FrameworkClass(type, unit.Symbol) is { } around)
            {
                _frameworkClass[unit] = (typeKey, around);
            }
            if (unit.Symbol is { MethodKind: MethodKind.Constructor, IsStatic: false } constructor)
            {
                _constructors.Add(unit);
                Add(_constructorsOf, typeKey, unit);
                foreach (var p in constructor.Parameters)
                    if (p.Type is INamedTypeSymbol injected) _injected.Add(SymbolKeys.Of(injected.OriginalDefinition));
            }
            if (operation is IFieldInitializerOperation { InitializedFields: [{ IsStatic: false }, ..] }
                or IPropertyInitializerOperation { InitializedProperties: [{ IsStatic: false }, ..] })
                Add(_initializersOf, typeKey, unit);
            else if (operation is IFieldInitializerOperation or IPropertyInitializerOperation)
                _staticInitializers.Add(unit);
            if (unit.Symbol is { Name: "Process" or "ProcessAsync" or "Init" }) Add(_tagHelperUnits, typeKey, unit);
        }
        if (unit.Symbol is { } symbol && _sources.IsEntry(symbol))
        {
            _entryUnits.Add(unit);
            dispatch.CollectEntry(symbol);
            // A Razor Pages handler renders its page (Page() or no result at all).
            if (type != null && _sources.IsPageHandler(symbol)) _requests.Add(new Request(unit, Kind.Page, null, type));
        }

        List<IOperation>? handlerOps = null;
        Dictionary<IMethodSymbol, ILocalFunctionOperation>? localFunctions = null;
        List<TextSpan>? requestReads = null;
        foreach (var op in operation.DescendantsAndSelf())
        {
            switch (op)
            {
                case IAnonymousFunctionOperation or ILocalFunctionOperation when _sources.IsHandlerSyntax(op.Syntax):
                    (handlerOps ??= new List<IOperation>()).Add(op);
                    if (op is ILocalFunctionOperation handlerFunction)
                        (localFunctions ??= new Dictionary<IMethodSymbol, ILocalFunctionOperation>(SymbolEqualityComparer.Default))[handlerFunction.Symbol] = handlerFunction;
                    break;
                case ILocalFunctionOperation local:
                    (localFunctions ??= new Dictionary<IMethodSymbol, ILocalFunctionOperation>(SymbolEqualityComparer.Default))[local.Symbol] = local;
                    break;
                case IInvocationOperation invocation:
                    if (_sources.SourceMember(invocation.TargetMethod, Access.Call) != null) (requestReads ??= new List<TextSpan>()).Add(op.Syntax.Span);
                    if (invocation.TargetMethod is { Name: "CreateTagHelper", TypeArguments: [INamedTypeSymbol tagHelper] }) _tagHelpers.Add((unit, tagHelper));
                    RendersView(unit, type, invocation);
                    break;
                case IPropertyReferenceOperation property:
                    if (_sources.SourceMember(property.Property, Access.Get) != null || _sources.IsBoundProperty(property.Property))
                        (requestReads ??= new List<TextSpan>()).Add(op.Syntax.Span);
                    break;
                case IObjectCreationOperation { Constructor: { IsImplicitlyDeclared: true } implicitConstructor }:
                    _implicitNews.Add((unit, SymbolKeys.Of(implicitConstructor.ContainingType.OriginalDefinition)));
                    break;
                case ISimpleAssignmentOperation { Target: IPropertyReferenceOperation { Property.Name: "Name" } target } assignment
                    when target.Property.ContainingType is { } t && SymbolMatch.MetadataName(t) == PartialTagHelper:
                    _requests.Add(new Request(unit, Kind.Partial, TagHelperValue(assignment.Value), null));
                    break;
            }
        }

        List<Handler>? handlers = null;
        if (handlerOps != null)
        {
            handlers = new List<Handler>();
            foreach (var op in handlerOps) handlers.Add(HandlerOf(op, localFunctions));
            _handlers[unit] = handlers;
        }
        // A read of the request outside the unit's Minimal API handlers (they are entry points of their own).
        if (requestReads != null && requestReads.Exists(r => handlers == null || !handlers.Exists(h => h.Spans.Exists(s => s.Contains(r)))))
            _readsRequest.Add(unit);
    }

    /// A handler's spans and calls: its own, and those of the top-level local functions it calls (transitively).
    private static Handler HandlerOf(IOperation op, Dictionary<IMethodSymbol, ILocalFunctionOperation>? localFunctions)
    {
        var spans = new List<TextSpan> { op.Syntax.Span };
        var sites = new List<CallSite>();
        var seen = new HashSet<IOperation> { op };
        var work = new Stack<IOperation>();
        work.Push(op);
        while (work.Count > 0)
        {
            var current = work.Pop();
            sites.AddRange(CallGraph.CallSites(current));
            if (localFunctions == null) continue;
            foreach (var d in current.Descendants())
            {
                var target = d switch
                {
                    IInvocationOperation { TargetMethod.MethodKind: MethodKind.LocalFunction } i => i.TargetMethod,
                    IMethodReferenceOperation { Method.MethodKind: MethodKind.LocalFunction } m => m.Method,
                    _ => null,
                };
                if (target == null || !localFunctions.TryGetValue(target.OriginalDefinition, out var local) || !seen.Add(local)) continue;
                if (spans.Exists(s => s.Contains(local.Syntax.Span))) continue;
                spans.Add(local.Syntax.Span);
                work.Push(local);
            }
        }
        return new Handler(spans, sites);
    }

    private static void Add(Dictionary<object, List<Unit>> map, object key, Unit unit)
    {
        if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Unit>();
        list.Add(unit);
    }

    private static INamedTypeSymbol? DeclaringType(Unit unit)
    {
        var declaration = unit.Root.AncestorsAndSelf().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        return declaration == null ? null : unit.Compilation.GetSemanticModel(unit.Root.SyntaxTree).GetDeclaredSymbol(declaration) as INamedTypeSymbol;
    }

    /// The view rendered by a call of MVC's view-result or partial or view-component methods, recorded with its name.
    private void RendersView(Unit unit, INamedTypeSymbol? callerType, IInvocationOperation invocation)
    {
        var method = invocation.TargetMethod;
        var declaring = method.ContainingType is { } c ? SymbolMatch.MetadataName(c) : null;
        Kind? kind = (declaring, method.Name) switch
        {
            ("Microsoft.AspNetCore.Mvc.Controller", "View" or "PartialView") => Kind.View,
            ("Microsoft.AspNetCore.Mvc.Controller", "ViewComponent") => Kind.Component,
            ("Microsoft.AspNetCore.Mvc.RazorPages.PageModel" or "Microsoft.AspNetCore.Mvc.RazorPages.PageBase", "Page") => Kind.Page,
            ("Microsoft.AspNetCore.Mvc.RazorPages.PageModel" or "Microsoft.AspNetCore.Mvc.RazorPages.PageBase", "Partial") => Kind.Partial,
            ("Microsoft.AspNetCore.Mvc.RazorPages.PageModel" or "Microsoft.AspNetCore.Mvc.RazorPages.PageBase", "ViewComponent") => Kind.Component,
            (ViewComponentBase, "View") => Kind.ComponentView,
            ("Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperPartialExtensions" or "Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper",
                "Partial" or "PartialAsync" or "RenderPartial" or "RenderPartialAsync") => Kind.Partial,
            // The helper's own InvokeAsync(name or type, arguments) and the extensions without arguments (Task 22: the
            // extensions are in the Rendering namespace).
            ("Microsoft.AspNetCore.Mvc.IViewComponentHelper" or "Microsoft.AspNetCore.Mvc.Rendering.ViewComponentHelperExtensions", "InvokeAsync") => Kind.Component,
            _ => null,
        };
        if (kind == null) return;
        if (kind == Kind.Page)
        {
            _requests.Add(new Request(unit, Kind.Page, null, callerType));
            return;
        }
        string? name = null;
        INamedTypeSymbol? component = null;
        if (kind == Kind.Component && method.TypeArguments.Length == 1) component = method.TypeArguments[0] as INamedTypeSymbol;
        foreach (var argument in invocation.Arguments)
        {
            var parameter = argument.Parameter;
            if (parameter == null) continue;
            if (parameter.Type.SpecialType == SpecialType.System_String)
            {
                name = argument.ArgumentKind == ArgumentKind.DefaultValue ? null
                    : argument.Value.ConstantValue is { HasValue: true, Value: var v } ? v as string : Unresolved;
                break;
            }
            if (kind == Kind.Component && SymbolMatch.MetadataName(parameter.Type) == "System.Type")
            {
                component = Unwrap(argument.Value) is ITypeOfOperation t ? t.TypeOperand as INamedTypeSymbol : null;
                if (component == null) name = Unresolved;
                break;
            }
        }
        if (kind == Kind.Component && name == null && component == null) name = Unresolved;
        _requests.Add(new Request(unit, kind.Value, name, component));
    }

    private static IOperation Unwrap(IOperation value)
    {
        while (value is IConversionOperation c) value = c.Operand;
        return value;
    }

    /// The constant a partial tag helper's `name` attribute gives (`Name = (string)__tagHelperAttribute_N.Value`, the
    /// field initialised with `new TagHelperAttribute("name", "<value>", …)`), else Unresolved.
    private static string TagHelperValue(IOperation value)
    {
        value = Unwrap(value);
        if (value.ConstantValue is { HasValue: true, Value: string s }) return s;
        if (value is IPropertyReferenceOperation { Property.Name: "Value", Instance: IFieldReferenceOperation field }
            && field.Field.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is VariableDeclaratorSyntax
            {
                Initializer.Value: BaseObjectCreationExpressionSyntax { ArgumentList.Arguments: { Count: >= 2 } args },
            }
            && args[1].Expression is LiteralExpressionSyntax literal && literal.Token.Value is string text)
            return text;
        return Unresolved;
    }

    /// Request code around every action (filters, endpoint filters, middleware; a controller is an action filter).
    private static readonly HashSet<string> AroundTypes = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Mvc.Filters.IActionFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncActionFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IResultFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncResultFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IAuthorizationFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IResourceFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncResourceFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IExceptionFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncExceptionFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IPageFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncPageFilter",
        "Microsoft.AspNetCore.Http.IMiddleware", "Microsoft.AspNetCore.Http.IEndpointFilter",
    };

    /// Request code with an entry point of its own: tag helpers, hubs.
    private static readonly HashSet<string> OwnEntryTypes = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Razor.TagHelpers.ITagHelperComponent", "Microsoft.AspNetCore.SignalR.Hub",
    };

    /// Whether a unit belongs to request code the framework invokes: true for code around every action (a filter,
    /// endpoint filter or middleware class; a conventional middleware's Invoke/InvokeAsync(HttpContext, …)), false for a
    /// tag helper or hub class, null otherwise.
    private bool? FrameworkClass(INamedTypeSymbol type, IMethodSymbol? method)
    {
        type = type.OriginalDefinition;
        var aroundKey = (SymbolKeys.Of(type), "around");
        var ownKey = (SymbolKeys.Of(type), "own");
        if (!_derives.TryGetValue(aroundKey, out var around))
        {
            bool Is(HashSet<string> names) => type.AllInterfaces.Any(i => names.Contains(SymbolMatch.MetadataName(i)))
                || SelfAndBases(type).Any(b => names.Contains(SymbolMatch.MetadataName(b)));
            around = Is(AroundTypes);
            _derives[aroundKey] = around;
            _derives[ownKey] = !around && Is(OwnEntryTypes);
        }
        if (around || (method is { Name: "Invoke" or "InvokeAsync", Parameters.Length: > 0 } m
                && SymbolMatch.MetadataName(m.Parameters[0].Type) == "Microsoft.AspNetCore.Http.HttpContext"))
            return true;
        return _derives[ownKey] ? false : null;
    }

    // ---- View and component classes ----

    private bool Derives(INamedTypeSymbol type, string baseName)
    {
        var key = (SymbolKeys.Of(type), baseName);
        if (_derives.TryGetValue(key, out var cached)) return cached;
        var result = false;
        for (var b = type.BaseType; b != null && !result; b = b.BaseType) result = SymbolMatch.MetadataName(b) == baseName;
        _derives[key] = result;
        return result;
    }

    /// The generated view class a type is (or is nested in), or null.
    private ViewClass? ViewOf(INamedTypeSymbol type, Compilation compilation)
    {
        for (INamedTypeSymbol? t = type; t != null; t = t.ContainingType)
        {
            t = t.OriginalDefinition;
            var key = SymbolKeys.Of(t);
            if (!_views.TryGetValue(key, out var view))
            {
                view = Derives(t, RazorPageBase) ? NewView(t, compilation) : null;
                _views[key] = view;
            }
            if (view != null) return view;
        }
        return null;
    }

    private ViewClass NewView(INamedTypeSymbol type, Compilation compilation)
    {
        var model = Derives(type, RazorPagesPage)
            ? type.GetMembers("Model").OfType<IPropertySymbol>().FirstOrDefault()?.Type as INamedTypeSymbol
            : null;
        return new ViewClass
        {
            Type = type,
            Compilation = compilation,
            Path = Normalize(ViewPath(type, compilation)),
            ModelKey = model == null ? null : SymbolKeys.Of(model),
        };
    }

    /// The .cshtml a generated class renders: the generator's RazorCompiledItemMetadata("Identifier", …) on the class, its
    /// assembly's RazorCompiledItem(typeof(class), kind, identifier), else the first `#line` file of its tree that is
    /// not an imports or view-start file.
    private string? ViewPath(INamedTypeSymbol type, Compilation compilation)
    {
        foreach (var a in type.GetAttributes())
            if (a.AttributeClass is { Name: "RazorCompiledItemMetadataAttribute" } && a.ConstructorArguments.Length == 2
                && a.ConstructorArguments[0].Value is "Identifier" && a.ConstructorArguments[1].Value is string id)
                return id;
        if (!_compiledItems.TryGetValue(compilation, out var items))
        {
            items = new Dictionary<object, string>();
            foreach (var a in compilation.Assembly.GetAttributes())
                if (a.AttributeClass is { Name: "RazorCompiledItemAttribute" } && a.ConstructorArguments.Length == 3
                    && a.ConstructorArguments[0].Value is INamedTypeSymbol t && a.ConstructorArguments[2].Value is string path)
                    items.TryAdd(SymbolKeys.Of(t), path);
            _compiledItems[compilation] = items;
        }
        if (items.TryGetValue(SymbolKeys.Of(type), out var item)) return item;
        foreach (var reference in type.DeclaringSyntaxReferences)
            foreach (var mapping in reference.SyntaxTree.GetLineMappings())
            {
                var path = mapping.MappedSpan.Path;
                if (!mapping.MappedSpan.HasMappedPath || !path.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase)) continue;
                var file = System.IO.Path.GetFileName(path.Replace('\\', '/'));
                if (file.StartsWith("_ViewImports", StringComparison.OrdinalIgnoreCase) || file.StartsWith("_ViewStart", StringComparison.OrdinalIgnoreCase)) continue;
                return path;
            }
        return null;
    }

    /// A view component class (concrete, derived from ViewComponent, with [ViewComponent], or named *ViewComponent), or
    /// null.
    private ComponentClass? ComponentOf(INamedTypeSymbol type, Compilation compilation)
    {
        type = type.OriginalDefinition;
        var key = SymbolKeys.Of(type);
        if (_components.TryGetValue(key, out var component)) return component;
        component = null;
        if (type.TypeKind == TypeKind.Class && !type.IsAbstract)
        {
            var attribute = SelfAndBases(type).SelectMany(t => t.GetAttributes())
                .FirstOrDefault(a => a.AttributeClass is { } c && SymbolMatch.MetadataName(c) == ViewComponentAttribute);
            if (attribute != null || Derives(type, ViewComponentBase) || type.Name.EndsWith("ViewComponent", StringComparison.Ordinal))
            {
                var name = attribute?.NamedArguments.FirstOrDefault(n => n.Key == "Name").Value.Value as string;
                if (string.IsNullOrEmpty(name))
                    name = type.Name.EndsWith("ViewComponent", StringComparison.Ordinal) ? type.Name[..^"ViewComponent".Length] : type.Name;
                component = new ComponentClass { Type = type, Compilation = compilation, Name = name };
            }
        }
        _components[key] = component;
        return component;
    }

    private static IEnumerable<INamedTypeSymbol> SelfAndBases(INamedTypeSymbol type)
    {
        for (INamedTypeSymbol? t = type; t != null; t = t.BaseType) yield return t;
    }

    // ---- Resolution (before the call graph's components are computed) ----

    /// Adds the edges to the call graph (Unit.Callees): each view request resolved to view or component units, views to
    /// the tag helpers they create, constructors and implicit `new`s to the type's instance initializers.
    public void Connect()
    {
        var views = _views.Values.OfType<ViewClass>().ToList();
        var components = _components.Values.OfType<ComponentClass>().ToList();
        var edges = new Dictionary<Unit, HashSet<Unit>>();
        void Edge(Unit from, IEnumerable<Unit> targets)
        {
            if (!edges.TryGetValue(from, out var seen)) edges[from] = seen = new HashSet<Unit>(from.Callees) { from };
            foreach (var target in targets)
                if (seen.Add(target)) from.Callees.Add(target);
        }

        foreach (var request in _requests)
        {
            var (targets, status) = Resolve(request, views, components);
            switch (status)
            {
                case Status.Resolved:
                    ViewEdges++;
                    Edge(request.Caller, targets!);
                    break;
                case Status.Uncompiled:
                    UncompiledViews++;
                    break;
                default:
                    UnresolvedViews++;
                    var caller = request.Caller.Compilation;
                    Edge(request.Caller, request.Kind == Kind.Component
                        ? components.SelectMany(c => c.Units)
                        : views.Where(v => References(v.Compilation, caller)).SelectMany(v => v.Units)
                            .Concat(components.Where(c => References(c.Compilation, caller)).SelectMany(c => c.Units)));
                    break;
            }
        }
        foreach (var (view, type) in _tagHelpers)
            foreach (var b in SelfAndBases(type))
                if (_tagHelperUnits.TryGetValue(SymbolKeys.Of(b.OriginalDefinition), out var units)) Edge(view, units);
        foreach (var (type, initializers) in _initializersOf)
            if (_constructorsOf.TryGetValue(type, out var constructors))
                foreach (var constructor in constructors) Edge(constructor, initializers);
        foreach (var (caller, type) in _implicitNews)
            if (_initializersOf.TryGetValue(type, out var initializers)) Edge(caller, initializers);
    }

    /// Whether project `project` is `caller` or references it.
    private bool References(Compilation project, Compilation caller)
    {
        if (project == caller) return true;
        if (_references.TryGetValue((project, caller), out var known)) return known;
        var name = caller.AssemblyName;
        known = project.ReferencedAssemblyNames.Any(a => a.Name == name);
        _references[(project, caller)] = known;
        return known;
    }

    private enum Status { Resolved, Unresolved, Uncompiled }

    /// The units a request reaches; Unresolved when its name cannot be resolved, Uncompiled when it names a path no
    /// compiled view has.
    private (IEnumerable<Unit>? Targets, Status Status) Resolve(Request request, List<ViewClass> views, List<ComponentClass> components)
    {
        var caller = request.Caller;
        var callerType = caller.Symbol?.ContainingType;
        switch (request.Kind)
        {
            case Kind.Page:
            {
                if (request.Component == null) return (null, Status.Unresolved);
                var key = SymbolKeys.Of(request.Component.OriginalDefinition);
                var pages = views.Where(v => Equals(v.ModelKey, key) || Equals(SymbolKeys.Of(v.Type), key)).ToList();
                return pages.Count == 0 ? (null, Status.Unresolved) : (pages.SelectMany(v => v.Units), Status.Resolved);
            }
            case Kind.Component:
            {
                if (request.Name == Unresolved) return (null, Status.Unresolved);
                var found = components.Where(c => request.Component != null
                    ? Equals(SymbolKeys.Of(c.Type), SymbolKeys.Of(request.Component.OriginalDefinition))
                    : string.Equals(c.Name, request.Name, StringComparison.OrdinalIgnoreCase)
                      || string.Equals(c.Type.ToDisplayString(), request.Name, StringComparison.Ordinal)).ToList();
                return found.Count == 0 ? (null, Status.Unresolved) : (found.SelectMany(c => c.Units), Status.Resolved);
            }
        }

        var candidates = new List<Candidate>();
        var name = request.Name;
        var pathsOnly = true;
        void Named(string n, string? folder, IEnumerable<Candidate> conventional)
        {
            if (IsPath(n))
            {
                candidates.Add(PathCandidate(n, folder));
                return;
            }
            pathsOnly = false;
            candidates.AddRange(conventional);
        }

        if (request.Kind == Kind.ComponentView)
        {
            // The caller's component, or each concrete component derived from the abstract base that calls View().
            var own = callerType == null ? null : ComponentOf(callerType, caller.Compilation);
            var owners = own != null ? new List<ComponentClass> { own }
                : callerType == null ? new List<ComponentClass>()
                : components.Where(c => SelfAndBases(c.Type).Any(b => Equals(SymbolKeys.Of(b.OriginalDefinition), SymbolKeys.Of(callerType.OriginalDefinition)))).ToList();
            if (owners.Count == 0) return (null, Status.Unresolved);
            foreach (var owner in owners)
            {
                if (name == Unresolved)
                {
                    pathsOnly = false;
                    candidates.Add(new Candidate($"/Components/{owner.Name}/", Match.Folder));
                }
                else
                {
                    Named(name ?? "Default", null, new[] { new Candidate($"/Components/{owner.Name}/{name ?? "Default"}.cshtml", Match.Suffix) });
                }
            }
        }
        else if (name == Unresolved)
        {
            return (null, Status.Unresolved);
        }
        else if (request.Kind == Kind.View)
        {
            var names = new List<string>();
            if (name != null) names.Add(name);
            else if (caller.Symbol is { } action && _sources.IsAction(action)) names.AddRange(ActionNames(action));
            else return (null, Status.Unresolved);
            var controller = callerType == null ? null
                : callerType.Name.EndsWith("Controller", StringComparison.Ordinal) ? callerType.Name[..^"Controller".Length] : callerType.Name;
            var area = callerType == null ? null : AreaOf(callerType);
            foreach (var n in names) Named(n, null, Conventional(n, controller, area));
        }
        else
        {
            if (name == null) return (null, Status.Unresolved);
            var callerPath = _viewOfUnit.TryGetValue(caller, out var callerView) ? callerView.Path : null;
            var folder = callerPath?[..(callerPath.LastIndexOf('/') + 1)];
            var area = callerPath == null ? null : AreaOfPath(callerPath);
            var controller = callerType != null && callerType.Name.EndsWith("Controller", StringComparison.Ordinal)
                ? callerType.Name[..^"Controller".Length] : null;
            var conventional = Conventional(name, controller, area ?? (callerType == null ? null : AreaOf(callerType))).ToList();
            if (folder != null) conventional.Insert(0, new Candidate(folder + name + ".cshtml", Match.TwoWay));
            Named(name, folder, conventional);
        }

        // The caller's project first, then the solution (a Razor class library's views).
        var matched = views.Where(v => v.Compilation == caller.Compilation && candidates.Exists(c => Matches(v.Path, c))).ToList();
        if (matched.Count == 0) matched = views.Where(v => candidates.Exists(c => Matches(v.Path, c))).ToList();
        if (matched.Count > 0) return (matched.SelectMany(v => v.Units), Status.Resolved);
        return (null, pathsOnly ? Status.Uncompiled : Status.Unresolved);
    }

    /// MVC's conventional locations of a view name: in an area its own folders then the root Shared, else the root
    /// folders outside any area.
    private static IEnumerable<Candidate> Conventional(string name, string? controller, string? area)
    {
        if (area != null)
        {
            if (controller != null) yield return new Candidate($"/Areas/{area}/Views/{controller}/{name}.cshtml", Match.Suffix);
            yield return new Candidate($"/Areas/{area}/Views/Shared/{name}.cshtml", Match.Suffix);
            yield return new Candidate($"/Views/Shared/{name}.cshtml", Match.Root);
            yield break;
        }
        if (controller != null) yield return new Candidate($"/Views/{controller}/{name}.cshtml", Match.Root);
        yield return new Candidate($"/Views/Shared/{name}.cshtml", Match.Root);
        yield return new Candidate($"/Pages/Shared/{name}.cshtml", Match.Root);
    }

    /// The area of a controller: `[Area("X")]` on it or a base class.
    private static string? AreaOf(INamedTypeSymbol type)
    {
        foreach (var t in SelfAndBases(type))
            foreach (var a in t.GetAttributes())
                for (var c = a.AttributeClass; c != null; c = c.BaseType)
                    if (SymbolMatch.MetadataName(c) == AreaAttribute)
                        return a.ConstructorArguments.Length == 1 && a.ConstructorArguments[0].Value is string area ? area : null;
        return null;
    }

    private static string? AreaOfPath(string path)
    {
        var i = path.IndexOf("/Areas/", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        var start = i + "/Areas/".Length;
        var end = path.IndexOf('/', start);
        return end < 0 ? null : path[start..end];
    }

    /// An action's view names: [ActionName], else its name, and that name without an `Async` suffix (MVC removes it by
    /// default).
    private static IEnumerable<string> ActionNames(IMethodSymbol action)
    {
        foreach (var a in action.GetAttributes())
            if (a.AttributeClass is { Name: "ActionNameAttribute" } && a.ConstructorArguments.Length == 1 && a.ConstructorArguments[0].Value is string named)
                return new[] { named };
        return action.Name.EndsWith("Async", StringComparison.Ordinal) && action.Name.Length > 5
            ? new[] { action.Name, action.Name[..^5] }
            : new[] { action.Name };
    }

    private static bool IsPath(string name) =>
        name.StartsWith('~') || name.StartsWith('/') || name.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase);

    /// A view name that is a path: app-relative (`~/`, `/`) matched either way against project-relative identifiers;
    /// relative (`x.cshtml`) under the caller view's folder when known, else as a suffix.
    private static Candidate PathCandidate(string name, string? folder)
    {
        name = name.Replace('\\', '/');
        var appRelative = name.StartsWith('~') || name.StartsWith('/');
        if (name.StartsWith('~')) name = name[1..];
        if (!name.StartsWith('/')) name = (folder ?? "/") + name;
        if (!name.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase)) name += ".cshtml";
        return new Candidate(name, appRelative || folder != null ? Match.TwoWay : Match.Suffix);
    }

    private static string? Normalize(string? path)
    {
        if (path == null) return null;
        path = path.Replace('\\', '/');
        return path.StartsWith('/') ? path : "/" + path;
    }

    private static bool Matches(string? path, Candidate candidate)
    {
        if (path == null) return false;
        var text = candidate.Text;
        return candidate.Mode switch
        {
            Match.Suffix => path.EndsWith(text, StringComparison.OrdinalIgnoreCase),
            Match.Root => path.EndsWith(text, StringComparison.OrdinalIgnoreCase) && !path.Contains("/Areas/", StringComparison.OrdinalIgnoreCase),
            Match.TwoWay => path.EndsWith(text, StringComparison.OrdinalIgnoreCase) || text.EndsWith(path, StringComparison.OrdinalIgnoreCase),
            _ => path.Contains(text, StringComparison.OrdinalIgnoreCase),
        };
    }

    // ---- Reach (after the call graph's components are computed) ----

    /// Computes each component's reach: explicit and handler entry points first; then, for the request code no entry
    /// point reaches, one entry point per view, view component, tag helper or hub class and one shared Around entry
    /// point for the code around every action, and the reach is computed again with those.
    public void ComputeReach(CallGraph graph)
    {
        var entries = new List<Entry>();
        foreach (var unit in _entryUnits) entries.Add(new Entry(new List<Unit> { unit }, null, null));
        foreach (var (unit, handlers) in _handlers)
            foreach (var handler in handlers)
                entries.Add(new Entry(null, handler.Sites.SelectMany(_dispatch!.Targets).Select(_dispatch.Key).ToList(), (unit, handler.Spans)));
        var explicitCount = entries.Count;
        var reach = Propagate(graph, entries);
        var groups = new Dictionary<object, List<Unit>>();
        var around = new List<Unit>();
        foreach (var unit in graph.Units)
        {
            // A constructor DI builds (its type, a base or an interface of it is a constructor parameter somewhere, or a
            // registration names its type) runs around the actions even when an action also builds the type with `new`
            // (fix round 2, RR3; R-7).
            if (reach[unit.Scc] != null)
            {
                if (_constructors.Contains(unit) && IsLive(unit) && (IsInjected(unit.Symbol!.ContainingType) || _dispatch!.IsRegistered(unit.Symbol.ContainingType)))
                    around.Add(unit);
                continue;
            }
            // Instance code of a type nobody creates never runs (R-7: the same facts as dispatch).
            if (!IsLive(unit)) continue;
            if (_frameworkClass.TryGetValue(unit, out var framework))
            {
                if (framework.Around) around.Add(unit);
                else Add(groups, framework.Key, unit);
            }
            else if (_readsRequest.Contains(unit) || _constructors.Contains(unit))
            {
                around.Add(unit);
            }
        }
        foreach (var units in groups.Values) entries.Add(new Entry(units, null, null));
        if (around.Count > 0)
        {
            _aroundBit = entries.Count;
            entries.Add(new Entry(around, null, null));
        }
        if (entries.Count > explicitCount) reach = Propagate(graph, entries);

        Count = entries.Count;
        _words = (entries.Count + 63) / 64;
        var all = new ulong[_words];
        for (var i = 0; i < entries.Count; i++) all[i >> 6] |= 1UL << (i & 63);
        _all = _table.Of(all);
        _sccReach = new Reach[graph.Sccs.Count];
        for (var s = 0; s < reach.Length; s++) _sccReach[s] = reach[s] == null ? Reach.None : _table.Of(reach[s]!);
        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].Handler is not { } handler) continue;
            if (!_handlerBits.TryGetValue(handler.Owner, out var list)) _handlerBits[handler.Owner] = list = new List<(List<TextSpan>, int)>();
            list.Add((handler.Spans, i));
        }
    }

    /// Whether a unit's code can run: static code, or instance code of a type the solution creates (or a subtype of it).
    private bool IsLive(Unit unit)
    {
        if (_dispatch == null || _staticInitializers.Contains(unit) || unit.Symbol is { IsStatic: true }) return true;
        var type = unit.Symbol?.ContainingType ?? _declaringTypes.GetValueOrDefault(unit);
        return type == null || _dispatch.IsLive(type);
    }

    private bool IsInjected(INamedTypeSymbol type) =>
        SelfAndBases(type).Any(t => _injected.Contains(SymbolKeys.Of(t.OriginalDefinition)))
        || type.AllInterfaces.Any(i => _injected.Contains(SymbolKeys.Of(i.OriginalDefinition)));

    /// An entry point: units it starts in, or a Minimal API handler (its unit and spans) with its callees' keys.
    private sealed record Entry(List<Unit>? Units, List<object>? Callees, (Unit Owner, List<TextSpan> Spans)? Handler);

    private static ulong[]?[] Propagate(CallGraph graph, List<Entry> entries)
    {
        var words = (entries.Count + 63) / 64;
        var reach = new ulong[]?[graph.Sccs.Count];
        void Set(int scc, int bit)
        {
            reach[scc] ??= new ulong[words];
            reach[scc]![bit >> 6] |= 1UL << (bit & 63);
        }
        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].Units is { } units)
                foreach (var unit in units) Set(unit.Scc, i);
            else
                foreach (var key in entries[i].Callees!)
                    if (graph.UnitOf(key) is { } callee) Set(callee.Scc, i);
        }
        // Components are in bottom-up order (callees first): callers are done before their callees.
        for (var s = graph.Sccs.Count - 1; s >= 0; s--)
        {
            var own = reach[s];
            if (own == null) continue;
            foreach (var unit in graph.Sccs[s])
                foreach (var callee in unit.Callees)
                {
                    if (callee.Scc == s) continue;
                    var target = reach[callee.Scc] ??= new ulong[words];
                    for (var w = 0; w < words; w++) target[w] |= own[w];
                }
        }
        return reach;
    }

    /// The entry points a body is reached from (what it reads the heap under): its unit's component's, or, for a body in
    /// a Minimal API handler lambda or in a top-level local function a handler calls, those handlers' own.
    public Reach Of(Body body)
    {
        if (_bodyReach.TryGetValue(body.Id, out var cached)) return cached;
        var reach = body.Unit.Scc < _sccReach.Length ? _sccReach[body.Unit.Scc] : Reach.None;
        if (body.Nested && _handlerBits.TryGetValue(body.Unit, out var handlers)
            && body.Symbol?.DeclaringSyntaxReferences.FirstOrDefault() is { } syntax && syntax.SyntaxTree == body.Unit.Root.SyntaxTree)
        {
            ulong[]? bits = null;
            foreach (var (spans, bit) in handlers)
            {
                if (!spans.Exists(s => s.Contains(syntax.Span))) continue;
                bits ??= new ulong[_words];
                bits[bit >> 6] |= 1UL << (bit & 63);
            }
            if (bits != null) reach = _table.Of(bits);
        }
        _bodyReach[body.Id] = reach;
        return reach;
    }

    /// The entry points a body writes the heap under and scopes the request data it reads under: its reach, widened to
    /// every entry point for code the Around entry point reaches (code around every action runs in every request).
    public Reach WriteReach(Body body)
    {
        if (_bodyWriteReach.TryGetValue(body.Id, out var cached)) return cached;
        var reach = Widen(Of(body));
        _bodyWriteReach[body.Id] = reach;
        return reach;
    }

    /// Every entry point when `reach` holds Around (ruling R-E17 as revised: code that runs around the actions, alone or
    /// shared with some actions, runs in every request), else `reach`. Heap.Write still narrows each write to the
    /// written data's scope, so what an admin action saves through a service a filter also calls keeps the admin's scope.
    public Reach Widen(Reach reach) => _aroundBit >= 0 && reach.Has(_aroundBit) ? _all : reach;

    /// The interned Reach sets of the run.
    public int ReachSets => _table.Count;
}
