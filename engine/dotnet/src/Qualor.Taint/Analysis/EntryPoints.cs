using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// A set of entry points (bit i: entry i): what reaches a strongly connected component of the call graph or a Minimal
/// API handler's body, and the entry points request data read from the heap is valid for (TaintValue.Scope). Compared
/// by value. Intersections and unions are remembered per pair (one engine run uses its sets from one thread), so the
/// heap's reads and the joins of scoped values do not allocate a new set each time.
internal sealed class Reach : IEquatable<Reach>
{
    public static readonly Reach None = new(Array.Empty<ulong>());

    private readonly int _hash;
    private Dictionary<Reach, Reach>? _intersections;
    private Dictionary<Reach, Reach>? _unions;

    public Reach(ulong[] bits)
    {
        Bits = bits;
        IsEmpty = Array.TrueForAll(bits, w => w == 0);
        var hash = new HashCode();
        var last = bits.Length - 1;
        while (last >= 0 && bits[last] == 0) last--;
        for (var i = 0; i <= last; i++) hash.Add(bits[i]);
        _hash = hash.ToHashCode();
    }

    public ulong[] Bits { get; }

    public bool IsEmpty { get; }

    public bool Intersects(Reach other)
    {
        var a = Bits;
        var b = other.Bits;
        var n = Math.Min(a.Length, b.Length);
        for (var i = 0; i < n; i++)
            if ((a[i] & b[i]) != 0) return true;
        return false;
    }

    /// The entry points in both (None when they share none; `this` when it is the smaller).
    public Reach Intersect(Reach other)
    {
        if (ReferenceEquals(this, other) || IsEmpty) return this;
        if (other.IsEmpty) return None;
        _intersections ??= new Dictionary<Reach, Reach>(ReferenceEqualityComparer.Instance);
        if (_intersections.TryGetValue(other, out var known)) return known;
        known = ComputeIntersect(other);
        if (_intersections.Count < MaxMemo) _intersections[other] = known;
        return known;
    }

    private const int MaxMemo = 4096;

    private Reach ComputeIntersect(Reach other)
    {
        var n = Math.Min(Bits.Length, other.Bits.Length);
        var bits = new ulong[n];
        var same = true;
        var any = false;
        for (var i = 0; i < n; i++)
        {
            bits[i] = Bits[i] & other.Bits[i];
            if (bits[i] != Bits[i]) same = false;
            if (bits[i] != 0) any = true;
        }
        for (var i = n; i < Bits.Length; i++) if (Bits[i] != 0) same = false;
        return !any ? None : same ? this : new Reach(bits);
    }

    /// The entry points in either (`this` when it holds the other).
    public Reach Union(Reach other)
    {
        if (ReferenceEquals(this, other) || other.IsEmpty) return this;
        if (IsEmpty) return other;
        _unions ??= new Dictionary<Reach, Reach>(ReferenceEqualityComparer.Instance);
        if (_unions.TryGetValue(other, out var known)) return known;
        known = ComputeUnion(other);
        if (_unions.Count < MaxMemo) _unions[other] = known;
        return known;
    }

    private Reach ComputeUnion(Reach other)
    {
        var n = Math.Max(Bits.Length, other.Bits.Length);
        var bits = new ulong[n];
        var same = true;
        for (var i = 0; i < n; i++)
        {
            var a = i < Bits.Length ? Bits[i] : 0;
            bits[i] = a | (i < other.Bits.Length ? other.Bits[i] : 0);
            if (bits[i] != a) same = false;
        }
        return same ? this : new Reach(bits);
    }

    public bool Equals(Reach? other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other is null || _hash != other._hash) return false;
        var n = Math.Max(Bits.Length, other.Bits.Length);
        for (var i = 0; i < n; i++)
            if ((i < Bits.Length ? Bits[i] : 0) != (i < other.Bits.Length ? other.Bits[i] : 0)) return false;
        return true;
    }

    public override bool Equals(object? obj) => Equals(obj as Reach);

    public override int GetHashCode() => _hash;
}

/// The request entry points and what each reaches (spec §5 "Heap" as amended, decision R-6), for the request-scoped heap.
///
/// - Entry points: the methods the sources model treats as receiving the request (SourceFinder.IsEntry: controller
///   actions, Razor Pages handlers, Minimal API handlers given as method groups, methods with a parameter bound by an
///   attribute), each Minimal API handler given as a lambda or local function (its own entry, apart from the code around
///   it), and — beyond the three kinds the spec names — request code the framework invokes, which no call edge reaches
///   but which runs inside a request: when no other entry point reaches it, each view and view component class (a
///   layout, a view no action names), each filter, middleware, tag helper or hub class, and each other unit that reads
///   the request itself (a source member or a bound property) is an entry point of its own.
/// - Reach: from each entry point over the call graph (CallGraph: invocations, object creations, property accessors,
///   method groups, with Dispatch), as one bit set per strongly connected component, propagated once from callers to
///   callees in the components' top-down order.
/// - Views: the call graph gets an edge from the unit that renders a view to every unit of the view's generated class
///   (and of the classes nested in it). `View()`/`PartialView()` of a controller resolve as MVC's default view locator
///   does for the conventional cases: the default name is the action's (`[ActionName]`, else the method name, also
///   without an `Async` suffix), looked up as Views/<Controller>/<name>.cshtml and Views/Shared/<name>.cshtml (any area
///   or theme folder above them); a name that is a path (`~/…`, `/…`, `….cshtml`) matches that path. `Page()` and
///   every Razor Pages handler reach the page whose `Model` is the handler's page model. In a view, partials
///   (`Html.Partial*`, `Html.RenderPartial*`, `<partial name="…">`) resolve in the view's folder, then Views/Shared and
///   Pages/Shared; view components (`Component.InvokeAsync` by name, type or type argument, `<vc:…>`) reach the
///   component class, whose `View()` resolves under Components/<name>/ (default view "Default"). A view is identified
///   by the generator's RazorCompiledItem attributes, else by its `#line` file. A name that cannot be resolved (not a
///   constant, or no view of that name) reaches every view and view component of the caller's project (counted).
internal sealed class EntryPoints
{
    private const string RazorPageBase = "Microsoft.AspNetCore.Mvc.Razor.RazorPageBase";
    private const string RazorPagesPage = "Microsoft.AspNetCore.Mvc.RazorPages.Page";
    private const string ViewComponentBase = "Microsoft.AspNetCore.Mvc.ViewComponent";
    private const string ViewComponentAttribute = "Microsoft.AspNetCore.Mvc.ViewComponentAttribute";
    private const string PartialTagHelper = "Microsoft.AspNetCore.Mvc.TagHelpers.PartialTagHelper";

    private enum Kind { View, ComponentView, Page, Partial, Component }

    /// A view rendered by a unit: its kind, its name (null: the default; Unresolved: not a constant), a component's type.
    private sealed record Request(Unit Caller, Kind Kind, string? Name, INamedTypeSymbol? Component);

    private const string Unresolved = "\0";

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

    private readonly SourceFinder _sources;
    private readonly List<Unit> _entryUnits = new();
    private readonly Dictionary<Unit, List<(TextSpan Span, List<object> Callees)>> _handlers = new();
    private readonly HashSet<Unit> _readsRequest = new();
    private readonly Dictionary<Unit, object> _frameworkClass = new();
    private readonly List<Request> _requests = new();
    private readonly Dictionary<object, ViewClass?> _views = new();
    private readonly Dictionary<object, ComponentClass?> _components = new();
    private readonly Dictionary<Unit, ViewClass> _viewOfUnit = new();
    private readonly Dictionary<Compilation, Dictionary<object, string>> _compiledItems = new();
    private readonly Dictionary<object, bool> _derives = new();

    private Reach[] _sccReach = Array.Empty<Reach>();
    private readonly Dictionary<Unit, List<(TextSpan Span, int Bit)>> _handlerBits = new();
    private readonly Dictionary<int, Reach> _bodyReach = new();
    private int _words;

    public EntryPoints(SourceFinder sources) => _sources = sources;

    /// Entry points (explicit, handler bodies and implicit ones).
    public int Count { get; private set; }

    /// Views and view components rendered by name that were resolved, and those that fell back to every view.
    public int ViewEdges { get; private set; }

    public int UnresolvedViews { get; private set; }

    // ---- Indexing (CallGraph.Build, once per unit) ----

    /// Records what a unit tells about entry points and views: whether it is an entry point, its Minimal API handler
    /// lambdas and local functions (with the callees of each), whether it reads the request itself, the view class or
    /// view component it belongs to, and the views it renders.
    public void Scan(Unit unit, IOperation operation, Dispatch dispatch)
    {
        var type = unit.Symbol?.ContainingType ?? DeclaringType(unit);
        if (type != null)
        {
            if (ViewOf(type, unit.Compilation) is { } view)
            {
                view.Units.Add(unit);
                _viewOfUnit[unit] = view;
                _frameworkClass[unit] = view;
            }
            else if (ComponentOf(type, unit.Compilation) is { } component)
            {
                component.Units.Add(unit);
                _frameworkClass[unit] = component;
            }
            else if (IsFrameworkInvoked(type, unit.Symbol))
            {
                _frameworkClass[unit] = SymbolKeys.Of(type.OriginalDefinition);
            }
        }
        if (unit.Symbol is { } symbol && _sources.IsEntry(symbol))
        {
            _entryUnits.Add(unit);
            // A Razor Pages handler renders its page (Page() or no result at all).
            if (type != null && _sources.IsPageHandler(symbol)) _requests.Add(new Request(unit, Kind.Page, null, type));
        }

        List<(TextSpan Span, List<object> Callees)>? handlers = null;
        foreach (var op in operation.DescendantsAndSelf())
        {
            switch (op)
            {
                case IAnonymousFunctionOperation or ILocalFunctionOperation when _sources.IsHandlerSyntax(op.Syntax):
                    handlers ??= new List<(TextSpan, List<object>)>();
                    var callees = new List<object>();
                    foreach (var callee in CallGraph.Callees(op, dispatch)) callees.Add(dispatch.Key(callee));
                    handlers.Add((op.Syntax.Span, callees));
                    break;
                case IInvocationOperation invocation:
                    if (_sources.SourceMember(invocation.TargetMethod, Access.Call) != null) ReadsRequest(unit, op, handlers);
                    RendersView(unit, type, invocation);
                    break;
                case IPropertyReferenceOperation property:
                    if (_sources.SourceMember(property.Property, Access.Get) != null || _sources.IsBoundProperty(property.Property))
                        ReadsRequest(unit, op, handlers);
                    break;
                case ISimpleAssignmentOperation { Target: IPropertyReferenceOperation { Property.Name: "Name" } target } assignment
                    when target.Property.ContainingType is { } t && SymbolMatch.MetadataName(t) == PartialTagHelper:
                    _requests.Add(new Request(unit, Kind.Partial, TagHelperValue(assignment.Value), null));
                    break;
            }
        }
        if (handlers != null) _handlers[unit] = handlers;
    }

    /// A read of the request outside the unit's Minimal API handlers (they are entry points of their own).
    private void ReadsRequest(Unit unit, IOperation op, List<(TextSpan Span, List<object> Callees)>? handlers)
    {
        if (handlers != null && handlers.Exists(h => h.Span.Contains(op.Syntax.Span))) return;
        _readsRequest.Add(unit);
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
            ("Microsoft.AspNetCore.Mvc.IViewComponentHelper" or "Microsoft.AspNetCore.Mvc.ViewComponentHelperExtensions", "InvokeAsync") => Kind.Component,
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

    /// Interfaces and base classes of request code the framework invokes: filters, middleware, tag helpers, hubs.
    private static readonly HashSet<string> FrameworkTypes = new(StringComparer.Ordinal)
    {
        "Microsoft.AspNetCore.Mvc.Filters.IActionFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncActionFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IResultFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncResultFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IAuthorizationFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IResourceFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncResourceFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IExceptionFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncExceptionFilter",
        "Microsoft.AspNetCore.Mvc.Filters.IPageFilter", "Microsoft.AspNetCore.Mvc.Filters.IAsyncPageFilter",
        "Microsoft.AspNetCore.Http.IMiddleware", "Microsoft.AspNetCore.Http.IEndpointFilter",
        "Microsoft.AspNetCore.Razor.TagHelpers.ITagHelperComponent", "Microsoft.AspNetCore.SignalR.Hub",
    };

    /// A unit of request code the framework invokes: a member of a filter, middleware, tag helper or hub class, or a
    /// conventional middleware's Invoke/InvokeAsync(HttpContext, …).
    private bool IsFrameworkInvoked(INamedTypeSymbol type, IMethodSymbol? method)
    {
        type = type.OriginalDefinition;
        var key = (SymbolKeys.Of(type), "framework");
        if (!_derives.TryGetValue(key, out var result))
        {
            result = type.AllInterfaces.Any(i => FrameworkTypes.Contains(SymbolMatch.MetadataName(i)))
                || SelfAndBases(type).Any(b => FrameworkTypes.Contains(SymbolMatch.MetadataName(b)));
            _derives[key] = result;
        }
        return result || (method is { Name: "Invoke" or "InvokeAsync", Parameters.Length: > 0 } m
            && SymbolMatch.MetadataName(m.Parameters[0].Type) == "Microsoft.AspNetCore.Http.HttpContext");
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

    /// A view component class (derived from ViewComponent, with [ViewComponent], or named *ViewComponent), or null.
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

    /// Adds the view edges to the call graph: each request resolved to view or component units (Unit.Callees).
    public void Connect()
    {
        var views = _views.Values.OfType<ViewClass>().ToList();
        var components = _components.Values.OfType<ComponentClass>().ToList();
        var edges = new Dictionary<Unit, HashSet<Unit>>();
        foreach (var request in _requests)
        {
            if (!edges.TryGetValue(request.Caller, out var seen)) edges[request.Caller] = seen = new HashSet<Unit>(request.Caller.Callees) { request.Caller };
            var targets = Resolve(request, views, components);
            if (targets == null)
            {
                UnresolvedViews++;
                targets = views.Where(v => v.Compilation == request.Caller.Compilation).SelectMany(v => v.Units)
                    .Concat(components.Where(c => c.Compilation == request.Caller.Compilation).SelectMany(c => c.Units));
            }
            else
            {
                ViewEdges++;
            }
            foreach (var target in targets)
                if (seen.Add(target)) request.Caller.Callees.Add(target);
        }
    }

    /// The units a request reaches, or null when its name cannot be resolved.
    private IEnumerable<Unit>? Resolve(Request request, List<ViewClass> views, List<ComponentClass> components)
    {
        if (request.Name == Unresolved) return null;
        var caller = request.Caller;
        var callerType = caller.Symbol?.ContainingType;
        switch (request.Kind)
        {
            case Kind.Page:
            {
                if (request.Component == null) return null;
                var key = SymbolKeys.Of(request.Component.OriginalDefinition);
                var pages = views.Where(v => Equals(v.ModelKey, key) || Equals(SymbolKeys.Of(v.Type), key)).ToList();
                return pages.Count == 0 ? null : pages.SelectMany(v => v.Units);
            }
            case Kind.Component:
            {
                var found = components.Where(c => request.Component != null
                    ? Equals(SymbolKeys.Of(c.Type), SymbolKeys.Of(request.Component.OriginalDefinition))
                    : string.Equals(c.Name, request.Name, StringComparison.OrdinalIgnoreCase)
                      || string.Equals(c.Type.ToDisplayString(), request.Name, StringComparison.Ordinal)).ToList();
                return found.Count == 0 ? null : found.SelectMany(c => c.Units);
            }
        }

        var candidates = new List<string>();
        var name = request.Name;
        if (request.Kind == Kind.ComponentView)
        {
            var component = callerType == null ? null : ComponentOf(callerType, caller.Compilation);
            if (component == null) return null;
            name ??= "Default";
            if (IsPath(name)) candidates.Add(PathName(name, null));
            else candidates.Add($"/Components/{component.Name}/{name}.cshtml");
        }
        else if (request.Kind == Kind.View)
        {
            var names = new List<string>();
            if (name != null) names.Add(name);
            else if (caller.Symbol is { } action && _sources.IsAction(action)) names.AddRange(ActionNames(action));
            else return null;
            var controller = callerType == null ? null
                : callerType.Name.EndsWith("Controller", StringComparison.Ordinal) ? callerType.Name[..^"Controller".Length] : callerType.Name;
            foreach (var n in names)
            {
                if (IsPath(n))
                {
                    candidates.Add(PathName(n, null));
                    continue;
                }
                if (controller != null) candidates.Add($"/Views/{controller}/{n}.cshtml");
                candidates.Add($"/Views/Shared/{n}.cshtml");
                candidates.Add($"/Pages/Shared/{n}.cshtml");
            }
        }
        else
        {
            if (name == null) return null;
            var folder = _viewOfUnit.TryGetValue(caller, out var callerView) && callerView.Path is { } p ? p[..(p.LastIndexOf('/') + 1)] : null;
            if (IsPath(name))
            {
                candidates.Add(PathName(name, folder));
            }
            else
            {
                if (folder != null) candidates.Add(folder + name + ".cshtml");
                candidates.Add($"/Views/Shared/{name}.cshtml");
                candidates.Add($"/Pages/Shared/{name}.cshtml");
                if (callerType != null && callerType.Name.EndsWith("Controller", StringComparison.Ordinal))
                    candidates.Add($"/Views/{callerType.Name[..^"Controller".Length]}/{name}.cshtml");
            }
        }

        // The caller's project first, then the solution (a Razor class library's views).
        var matched = views.Where(v => v.Compilation == caller.Compilation && candidates.Exists(c => Matches(v.Path, c))).ToList();
        if (matched.Count == 0) matched = views.Where(v => candidates.Exists(c => Matches(v.Path, c))).ToList();
        return matched.Count == 0 ? null : matched.SelectMany(v => v.Units);
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

    /// A view name that is a path: app-relative (`~/`, `/`) as it is; relative (`../x.cshtml`, `x.cshtml`) under the
    /// caller view's folder when known.
    private static string PathName(string name, string? folder)
    {
        name = name.Replace('\\', '/');
        if (name.StartsWith('~')) name = name[1..];
        if (!name.StartsWith('/')) name = (folder ?? "/") + name;
        if (!name.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase)) name += ".cshtml";
        return name;
    }

    private static string? Normalize(string? path)
    {
        if (path == null) return null;
        path = path.Replace('\\', '/');
        return path.StartsWith('/') ? path : "/" + path;
    }

    /// A view path and a candidate name the same file: one ends with the other (identifiers are project-relative,
    /// `#line` paths absolute, candidates relative to any area, theme or project folder).
    private static bool Matches(string? path, string candidate) =>
        path != null && (path.EndsWith(candidate, StringComparison.OrdinalIgnoreCase) || candidate.EndsWith(path, StringComparison.OrdinalIgnoreCase));

    // ---- Reach (after the call graph's components are computed) ----

    /// Computes each component's reach: explicit and handler entry points first; then every unit that reads the request
    /// but none of them reaches gets an entry point of its own, and the reach is computed again with those.
    public void ComputeReach(CallGraph graph)
    {
        var entries = new List<Entry>();
        foreach (var unit in _entryUnits) entries.Add(new Entry(new List<Unit> { unit }, null, default, null));
        foreach (var (unit, handlers) in _handlers)
            foreach (var (span, callees) in handlers) entries.Add(new Entry(null, callees, span, unit));
        var explicitCount = entries.Count;
        var reach = Propagate(graph, entries);
        // Request code the framework invokes (no call edge leads to it): one entry point per view, view component,
        // filter, middleware, tag helper or hub class, and one per other unit that reads the request itself.
        var groups = new Dictionary<object, List<Unit>>();
        foreach (var unit in graph.Units)
        {
            if (reach[unit.Scc] != null) continue;
            object? key = _frameworkClass.TryGetValue(unit, out var k) ? k : _readsRequest.Contains(unit) ? unit : null;
            if (key == null) continue;
            if (!groups.TryGetValue(key, out var list)) groups[key] = list = new List<Unit>();
            list.Add(unit);
        }
        foreach (var units in groups.Values) entries.Add(new Entry(units, null, default, null));
        if (entries.Count > explicitCount) reach = Propagate(graph, entries);

        Count = entries.Count;
        _words = (entries.Count + 63) / 64;
        _sccReach = new Reach[graph.Sccs.Count];
        for (var s = 0; s < reach.Length; s++) _sccReach[s] = reach[s] == null ? Reach.None : new Reach(reach[s]!);
        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i].Owner is not { } owner) continue;
            if (!_handlerBits.TryGetValue(owner, out var list)) _handlerBits[owner] = list = new List<(TextSpan, int)>();
            list.Add((entries[i].Span, i));
        }
    }

    /// An entry point: units it starts in, or a Minimal API handler inside unit Owner (its Span) with its callees' keys.
    private sealed record Entry(List<Unit>? Units, List<object>? Callees, TextSpan Span, Unit? Owner);

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

    /// The entry points a body is reached from: its unit's component's, or, for a Minimal API handler lambda or local
    /// function (and the bodies inside it), that handler's own.
    public Reach Of(Body body)
    {
        if (_bodyReach.TryGetValue(body.Id, out var cached)) return cached;
        var reach = body.Unit.Scc < _sccReach.Length ? _sccReach[body.Unit.Scc] : Reach.None;
        if (body.Nested && _handlerBits.TryGetValue(body.Unit, out var handlers)
            && body.Symbol?.DeclaringSyntaxReferences.FirstOrDefault() is { } syntax && syntax.SyntaxTree == body.Unit.Root.SyntaxTree)
        {
            ulong[]? bits = null;
            foreach (var (span, bit) in handlers)
            {
                if (!span.Contains(syntax.Span)) continue;
                bits ??= new ulong[_words];
                bits[bit >> 6] |= 1UL << (bit & 63);
            }
            if (bits != null) reach = new Reach(bits);
        }
        _bodyReach[body.Id] = reach;
        return reach;
    }
}
