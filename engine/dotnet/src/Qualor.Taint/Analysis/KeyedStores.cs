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
///   `ViewData.Model`). Its key is a type (with its generic arguments): a model is written under its static type, that
///   type's base classes (not object) and its interfaces, and a view reads the key of its own model type, so only a model
///   a view of that type can be given reaches it; a model whose static type is object or dynamic is written to the "any
///   key" entry, which every view reads, and a view whose model type is object or dynamic reads only that entry. A model
///   typed by a type parameter (a generic helper's `View(name, model)`) is written to the Generic entry, which no view
///   reads: each call of the helper writes its argument under the argument's own type (MethodAnalyzer.Apply).
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

    /// Whether an operation is `<HttpContext>.Items` (through conversions).
    public static bool IsItems(IOperation? operation)
    {
        while (operation is IConversionOperation c) operation = c.Operand;
        return operation is IPropertyReferenceOperation { Property: { Name: "Items" } p } && !SymbolKeys.InSource(p)
            && p.ContainingType is { } t && SymbolMatch.MetadataName(t) == HttpContext;
    }

    /// Whether an operation is a framework `ViewBag` (the dynamic view of ViewData: a Controller's, a view's, a view
    /// component's), through conversions.
    public static bool IsViewBag(IOperation? operation)
    {
        while (operation is IConversionOperation c) operation = c.Operand;
        return operation is IPropertyReferenceOperation { Property: { Name: "ViewBag", Type.TypeKind: TypeKind.Dynamic } p } && !SymbolKeys.InSource(p);
    }

    /// The store an indexer access reads or writes: a view data dictionary's, or `HttpContext.Items`'s; else null.
    public static KeyedStore? IndexerStore(IPropertyReferenceOperation operation)
    {
        var property = operation.Property;
        if (!property.IsIndexer || SymbolKeys.InSource(property) || property.Parameters.Length != 1) return null;
        if (IsViewData(property.ContainingType) || IsViewData(operation.Instance?.Type)) return KeyedStore.ViewData;
        if (IsItems(operation.Instance)) return KeyedStore.Items;
        return null;
    }

    /// The store a dictionary method of a call works on (`Add`, `TryAdd`, `TryGetValue` of a view data dictionary or of
    /// `HttpContext.Items`), else null.
    public static KeyedStore? MethodStore(IMethodSymbol method, IOperation? instance)
    {
        if (method.Name is not ("Add" or "TryAdd" or "TryGetValue") || SymbolKeys.InSource(method) || method.Parameters.Length != 2) return null;
        if (IsViewData(method.ContainingType) || IsViewData(instance?.Type)) return KeyedStore.ViewData;
        if (IsItems(instance)) return KeyedStore.Items;
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

    private static string? NamedConstant(IOperation? key)
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

    /// The view-model entries a model of static type `type` is written to: the type, its base classes but object, its
    /// interfaces (with their generic arguments); the "any key" entry for object, dynamic or an unknown type; the Generic
    /// entry for a type parameter.
    public static IEnumerable<KeyedLocation> ModelWrites(ITypeSymbol? type)
    {
        if (type == null || type.SpecialType == SpecialType.System_Object || type.TypeKind is TypeKind.Dynamic or TypeKind.Error)
        {
            yield return new KeyedLocation(KeyedStore.ViewModel, null);
            yield break;
        }
        if (type is ITypeParameterSymbol)
        {
            yield return KeyedLocation.Generic;
            yield break;
        }
        for (var t = type; t != null && t.SpecialType != SpecialType.System_Object; t = t.BaseType)
            yield return ModelRead(t);
        foreach (var i in type.AllInterfaces) yield return ModelRead(i);
    }

    /// The view-model entry a view whose model has static type `type` reads (with the "any key" entry, Heap.Read).
    public static KeyedLocation ModelRead(ITypeSymbol? type) => new(KeyedStore.ViewModel,
        type == null || type.TypeKind is TypeKind.Dynamic or TypeKind.Error ? "System.Object" : type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat));

    /// Whether a property set gives a partial tag helper its model (`<partial name="…" model="…">`; `for="…"` is a
    /// model expression, not followed).
    public static bool IsPartialModel(IPropertySymbol property) =>
        property.Name == "Model" && property.ContainingType is { } t && SymbolMatch.MetadataName(t) == PartialTagHelper;
}
