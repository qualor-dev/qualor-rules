using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// The request-scoped stores the framework keeps per request outside the objects the heap tracks by field (Task 22):
/// - ViewData: a view data dictionary's entries (`ViewData["k"]`, `ViewData.Add("k", v)`, `TryGetValue`), shared by
///   the action, its view, the partials and view components the view renders (each gets a copy of the same entries) and
///   the filters around the action; `ViewBag.K` is the entry "K" (ViewBag reads and writes ViewData). Keys compare
///   without case, as the dictionary's do.
/// - Items: `HttpContext.Items`, the request's own dictionary (keys compared as given).
/// - ViewModel: the model a view renders: what an action gives `View(model)` / `PartialView(model)`, a view component
///   its `View(model)`, a view `Html.Partial*(name, model)` or `<partial model="…">`; read as the view's `Model` (and
///   `ViewData.Model`, and written by `ViewData.Model = m`). Its key is a type (with its generic arguments): a model is
///   written under its static type, that type's base classes (not object) and its interfaces, and under the exact entry
///   of its static type; a view reads the key of its own model type and the exact entries of its model type's base
///   classes declared in the project and of its generic collection interfaces (ruling R-E24). So a model reaches a view
///   of its static type or a supertype of it, and a view of a subtype only when the model is statically typed by a
///   project base class or a generic collection interface. A model whose static type is object or
///   dynamic is written to the "any key" entry, which every view reads, and a view whose model type is object or dynamic
///   reads only that entry. A model whose type holds a type parameter (`T`, `List<T>`, `T[]`: a generic helper's
///   `View(name, model)`) is written to the Generic entry, which no view reads: each call of the helper writes its
///   argument under the argument's own type (MethodAnalyzer.GenericModels; a change of a summary's Generic entry is a
///   change of its local effects, so the callers are analysed again).
/// Each entry is a heap location (Heap, KeyedLocation), so it is request data only where code reachable from the same
/// entry point reads it (R-6); an action reaches the views it renders through the view edges (EntryPoints). A key that
/// is not a constant writes the store's "any key" entry, which every read of the store joins; a read with a key that is
/// not a constant joins every entry of the store. TempData is not a store here: it is read in a later request (R-6).
internal enum KeyedStore { ViewData, Items, ViewModel }

/// One entry of a keyed store: Key the constant key (ViewData's in lower case), null for the "any key" entry.
internal sealed record KeyedLocation(KeyedStore Store, string? Key)
{
    /// The registration of the readers that read every entry of the store (a key that is not a constant).
    internal const string AllKeys = "\0*";

    public KeyedLocation Any => Key == null ? this : new KeyedLocation(Store, null);

    public KeyedLocation All => new(Store, AllKeys);

    /// The view model of a generic helper, written at its callers under their types.
    public static readonly KeyedLocation Generic = new(KeyedStore.ViewModel, "\0T");
}

internal static class KeyedStores
{
    private const string ViewDataDictionary = "Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary";
    private const string ViewDataDictionaryOfT = "Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary`1";
    private const string RazorPageOfT = "Microsoft.AspNetCore.Mvc.Razor.RazorPage`1";
    private const string HttpContext = "Microsoft.AspNetCore.Http.HttpContext";
    private const string PartialTagHelper = "Microsoft.AspNetCore.Mvc.TagHelpers.PartialTagHelper";

    /// Whether a type is a view data dictionary (ViewDataDictionary, ViewDataDictionary<T>, a class derived from them).
    public static bool IsViewData(ITypeSymbol? type)
    {
        for (var t = type as INamedTypeSymbol; t != null; t = t.BaseType)
            if (SymbolMatch.MetadataName(t.OriginalDefinition) is ViewDataDictionary or ViewDataDictionaryOfT) return true;
        return false;
    }

    /// Whether an operation is `<HttpContext>.Items` (through conversions), or a local initialised with it and never
    /// assigned again (`var items = HttpContext.Items;`), when `compilation` is given to bind the initializer.
    public static bool IsItems(IOperation? operation, Compilation? compilation = null)
    {
        while (operation is IConversionOperation c) operation = c.Operand;
        if (operation is ILocalReferenceOperation { Local: { IsRef: false } local } && compilation != null)
        {
            // Only a local of the Items type (IDictionary<object, object?>) can hold it; the answer is kept per local.
            if (local.Type is not INamedTypeSymbol { Arity: 2 } dictionary || SymbolMatch.MetadataName(dictionary) != "System.Collections.Generic.IDictionary`2"
                || dictionary.TypeArguments[0].SpecialType != SpecialType.System_Object || dictionary.TypeArguments[1].SpecialType != SpecialType.System_Object)
                return false;
            if (Aliases.TryGetValue(local, out var known)) return (bool)known;
            var alias = AliasOf(local, compilation) is { } initializer && IsItems(initializer);
            Aliases.AddOrUpdate(local, alias);
            return alias;
        }
        return operation is IPropertyReferenceOperation { Property: { Name: "Items" } p } && !SymbolKeys.InSource(p)
            && p.ContainingType is { } t && SymbolMatch.MetadataName(t) == HttpContext;
    }

    /// Locals already checked for holding HttpContext.Items (weakly keyed: a run's symbols go with its compilations).
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ILocalSymbol, object> Aliases = new();

    /// The initializer of a local that no other statement assigns (by name in its declaring member), bound; else null.
    private static IOperation? AliasOf(ILocalSymbol local, Compilation compilation)
    {
        if (local.DeclaringSyntaxReferences.Length != 1
            || local.DeclaringSyntaxReferences[0].GetSyntax() is not VariableDeclaratorSyntax { Initializer.Value: { } value } declarator)
            return null;
        var scope = declarator.Ancestors().FirstOrDefault(a => a is MemberDeclarationSyntax or LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax);
        if (scope == null) return null;
        foreach (var node in scope.DescendantNodes())
        {
            var written = node switch
            {
                AssignmentExpressionSyntax a => a.Left,
                ArgumentSyntax { RefKindKeyword.RawKind: not 0 } r => r.Expression,
                _ => null,
            };
            if (written is IdentifierNameSyntax id && id.Identifier.ValueText == local.Name) return null;
        }
        return compilation.GetSemanticModel(declarator.SyntaxTree).GetOperation(value);
    }

    /// Whether an operation is a framework `ViewBag` (the dynamic view of ViewData: a Controller's, a view's, a view
    /// component's), through conversions.
    public static bool IsViewBag(IOperation? operation)
    {
        while (operation is IConversionOperation c) operation = c.Operand;
        return operation is IPropertyReferenceOperation { Property: { Name: "ViewBag", Type.TypeKind: TypeKind.Dynamic } p } && !SymbolKeys.InSource(p);
    }

    /// The store an indexer access reads or writes: a view data dictionary's, or `HttpContext.Items`'s; else null.
    public static KeyedStore? IndexerStore(IPropertyReferenceOperation operation, Compilation? compilation = null)
    {
        var property = operation.Property;
        if (!property.IsIndexer || SymbolKeys.InSource(property) || property.Parameters.Length != 1) return null;
        if (IsViewData(property.ContainingType) || IsViewData(operation.Instance?.Type)) return KeyedStore.ViewData;
        if (IsItems(operation.Instance, compilation)) return KeyedStore.Items;
        return null;
    }

    /// The store a dictionary method of a call works on (`Add`, `TryAdd`, `TryGetValue` of a view data dictionary or of
    /// `HttpContext.Items`), else null.
    public static KeyedStore? MethodStore(IMethodSymbol method, IOperation? instance, Compilation? compilation = null)
    {
        if (method.Name is not ("Add" or "TryAdd" or "TryGetValue") || SymbolKeys.InSource(method) || method.Parameters.Length != 2) return null;
        if (IsViewData(method.ContainingType) || IsViewData(instance?.Type)) return KeyedStore.ViewData;
        if (IsItems(instance, compilation)) return KeyedStore.Items;
        return null;
    }

    /// The entry a key operation names: its constant (ViewData's in lower case), else the store's "any key" entry. A
    /// static member that is a constant in all but name counts as its constant: a property returning a string literal
    /// (`static string K => "k";`, `static string K { get; } = "k";`), a static readonly field initialised with one.
    public static KeyedLocation Location(KeyedStore store, IOperation? key)
    {
        while (key is IConversionOperation c) key = c.Operand;
        var text = key?.ConstantValue is { HasValue: true, Value: string s } ? s : NamedConstant(key);
        if (text != null && store == KeyedStore.ViewData) text = text.ToLowerInvariant();
        return new KeyedLocation(store, text);
    }

    internal static string? NamedConstant(IOperation? key)
    {
        var (symbol, isStatic) = key switch
        {
            IFieldReferenceOperation { Field: { IsReadOnly: true } f } => ((ISymbol)f, f.IsStatic),
            IPropertyReferenceOperation { Property: { IsIndexer: false, SetMethod: null } p } => (p, p.IsStatic),
            _ => (null, false),
        };
        if (symbol == null || !isStatic || symbol.DeclaringSyntaxReferences.Length != 1) return null;
        ExpressionSyntax? value = symbol.DeclaringSyntaxReferences[0].GetSyntax() switch
        {
            VariableDeclaratorSyntax v => v.Initializer?.Value,
            PropertyDeclarationSyntax { ExpressionBody: { } body } => body.Expression,
            PropertyDeclarationSyntax { Initializer: { } init, AccessorList: { } accessors }
                when accessors.Accessors.All(a => a.Body == null && a.ExpressionBody == null) => init.Value,
            _ => null,
        };
        return value is LiteralExpressionSyntax literal && literal.Token.Value is string text ? text : null;
    }

    /// ViewBag's member `K` is ViewData's entry "K".
    public static KeyedLocation ViewBagLocation(string member) => new(KeyedStore.ViewData, member.ToLowerInvariant());

    /// Whether a property is the model a view renders: a view's `Model` (RazorPage<T>), a view data dictionary's
    /// `Model`.
    public static bool IsViewModel(IPropertySymbol property)
    {
        if (property.Name != "Model" || property.IsIndexer || SymbolKeys.InSource(property)) return false;
        var type = property.ContainingType?.OriginalDefinition;
        return type != null && SymbolMatch.MetadataName(type) is RazorPageOfT or ViewDataDictionary or ViewDataDictionaryOfT;
    }

    /// The ordinal (in the method's definition, an extension's `this` counted) of the parameter that takes the model a
    /// view is rendered with: `model` of Controller.View/PartialView, ViewComponent.View, PageModel/PageBase.Partial, the
    /// HTML helper's Partial*/RenderPartial*; else -1.
    public static int ModelParameter(IMethodSymbol method)
    {
        if (SymbolKeys.InSource(method)) return -1;
        var definition = method.ReducedFrom ?? method.OriginalDefinition;
        var declaring = definition.ContainingType is { } c ? SymbolMatch.MetadataName(c.OriginalDefinition) : null;
        var renders = (declaring, definition.Name) switch
        {
            ("Microsoft.AspNetCore.Mvc.Controller", "View" or "PartialView") => true,
            ("Microsoft.AspNetCore.Mvc.ViewComponent", "View") => true,
            ("Microsoft.AspNetCore.Mvc.RazorPages.PageModel" or "Microsoft.AspNetCore.Mvc.RazorPages.PageBase", "Partial") => true,
            ("Microsoft.AspNetCore.Mvc.Rendering.HtmlHelperPartialExtensions" or "Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper",
                "Partial" or "PartialAsync" or "RenderPartial" or "RenderPartialAsync") => true,
            _ => false,
        };
        if (!renders) return -1;
        foreach (var p in definition.Parameters)
            if (p.Name == "model") return p.Ordinal;
        return -1;
    }

    /// Whether a type holds a type parameter (itself, a type argument, an array's element, a containing type).
    public static bool ContainsTypeParameter(ITypeSymbol type) => type switch
    {
        ITypeParameterSymbol => true,
        IArrayTypeSymbol a => ContainsTypeParameter(a.ElementType),
        INamedTypeSymbol n => n.TypeArguments.Any(ContainsTypeParameter) || (n.ContainingType != null && ContainsTypeParameter(n.ContainingType)),
        _ => false,
    };

    /// Whether a property set gives a partial tag helper its model (`<partial name="…" model="…">`; `for="…"` is a
    /// model expression, not followed).
    public static bool IsPartialModel(IPropertySymbol property) =>
        property.Name == "Model" && property.ContainingType is { } t && SymbolMatch.MetadataName(t) == PartialTagHelper;
}

/// The view-model entries of types, cached per type for one run (AnalysisContext.ModelKeys).
internal sealed class ModelKeys
{
    private readonly Dictionary<ITypeSymbol, string> _names = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ITypeSymbol, KeyedLocation[]> _writes = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ITypeSymbol, KeyedLocation[]> _reads = new(SymbolEqualityComparer.Default);

    private static readonly HashSet<string> CollectionInterfaces = new(StringComparer.Ordinal)
    {
        "System.Collections.Generic.IEnumerable`1", "System.Collections.Generic.ICollection`1", "System.Collections.Generic.IList`1",
        "System.Collections.Generic.IReadOnlyCollection`1", "System.Collections.Generic.IReadOnlyList`1",
    };

    private static readonly KeyedLocation[] AnyEntry = { new(KeyedStore.ViewModel, null) };
    private static readonly KeyedLocation[] GenericEntry = { KeyedLocation.Generic };
    private static readonly KeyedLocation[] ObjectView = { new(KeyedStore.ViewModel, "System.Object") };

    private string Name(ITypeSymbol type)
    {
        if (!_names.TryGetValue(type, out var name)) _names[type] = name = type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return name;
    }

    private KeyedLocation Key(ITypeSymbol type) => new(KeyedStore.ViewModel, Name(type));

    private KeyedLocation Exact(ITypeSymbol type) => new(KeyedStore.ViewModel, "=" + Name(type));

    /// The entries a model of static type `type` is written to: the type, its base classes but object and its interfaces
    /// (with their generic arguments), and the type's exact entry; the "any key" entry for object, dynamic or an unknown
    /// type; the Generic entry for a type holding a type parameter.
    public IReadOnlyList<KeyedLocation> Writes(ITypeSymbol? type)
    {
        if (type == null || type.SpecialType == SpecialType.System_Object || type.TypeKind is TypeKind.Dynamic or TypeKind.Error) return AnyEntry;
        if (KeyedStores.ContainsTypeParameter(type)) return GenericEntry;
        if (_writes.TryGetValue(type, out var cached)) return cached;
        var list = new List<KeyedLocation>();
        for (var t = type; t != null && t.SpecialType != SpecialType.System_Object; t = t.BaseType) list.Add(Key(t));
        foreach (var i in type.AllInterfaces) list.Add(Key(i));
        list.Add(Exact(type));
        return _writes[type] = list.ToArray();
    }

    /// The entries a view whose model has static type `type` reads (each joined with the "any key" entry, Heap.Read): its
    /// type's key, and the exact entries of its base classes declared in the project and of its generic collection
    /// interfaces (a model statically typed wider than the view's type). An object or dynamic view reads only the "any
    /// key" entry.
    public IReadOnlyList<KeyedLocation> Reads(ITypeSymbol? type)
    {
        if (type == null || type.SpecialType == SpecialType.System_Object || type.TypeKind is TypeKind.Dynamic or TypeKind.Error) return ObjectView;
        if (_reads.TryGetValue(type, out var cached)) return cached;
        var list = new List<KeyedLocation> { Key(type) };
        // Wider reads only through base classes declared in the project and the generic collection interfaces (ruling
        // R-E24): an interface or library base that many view models share would join them all.
        for (var t = type.BaseType; t != null && t.SpecialType != SpecialType.System_Object; t = t.BaseType)
            if (SymbolKeys.InSource(t)) list.Add(Exact(t));
        foreach (var i in type.AllInterfaces)
            if (CollectionInterfaces.Contains(SymbolMatch.MetadataName(i))) list.Add(Exact(i));
        return _reads[type] = list.ToArray();
    }
}
