using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// A symbol's identity across the compilations of one solution. A project reference is a CompilationReference, so a
/// referencing project usually sees the referenced compilation's own symbols; when Roslyn retargets them (another
/// core library) they are other objects with the same declaring syntax. A symbol declared in source is therefore keyed
/// by its declaring syntax (tree and span; a partial method by its implementation part), an external one by its
/// documentation comment id and assembly name.
internal static class SymbolKeys
{
    private readonly record struct SourceKey(SyntaxTree Tree, TextSpan Span);

    private readonly record struct MetadataKey(string Id, string? Assembly);

    /// The symbol a key and a body are taken from: a reduced extension method's static form, a partial method's
    /// implementation part, the original definition of a constructed generic.
    public static ISymbol Definition(ISymbol symbol)
    {
        if (symbol is IMethodSymbol m)
        {
            m = (m.ReducedFrom ?? m).OriginalDefinition;
            return m.PartialImplementationPart ?? m;
        }
        return symbol.OriginalDefinition;
    }

    public static object Of(ISymbol symbol)
    {
        symbol = Definition(symbol);
        var references = symbol.DeclaringSyntaxReferences;
        if (references.Length > 0) return new SourceKey(references[0].SyntaxTree, references[0].Span);
        return new MetadataKey(symbol.GetDocumentationCommentId() ?? symbol.ToDisplayString(), symbol.ContainingAssembly?.Identity.Name);
    }

    /// The key of the body declared by this syntax (a lambda or local function, a member's declaration).
    public static object Of(SyntaxNode syntax) => new SourceKey(syntax.SyntaxTree, syntax.Span);

    public static bool InSource(ISymbol symbol) => Definition(symbol).DeclaringSyntaxReferences.Length > 0;
}

//// One call a body makes: the method named, whether it dispatches virtually, the receiver's static type.
internal readonly record struct CallSite(IMethodSymbol Method, bool IsVirtual, ITypeSymbol? Receiver);

/// How a virtual call was resolved (decision R-7): to implementations the solution creates or registers, to those of
/// projects or types opened by scanning, reflection or a missing registration only, or by the class hierarchy.
internal enum DispatchKind { None, Registrations, Scanning, Hierarchy }

/// Virtual and interface dispatch over every compilation of the solution (spec §5 "Dispatch", decision R-7): a virtual
/// call's candidates are the implementations of the method in its receiver's static type and in every source type
/// derived from it or implementing it, in any project (class hierarchy); of those, the call runs the ones whose type the
/// solution creates (Dispatch.Created.cs: `new`, DI registrations, framework-built types, scanned or reflected types),
/// and every candidate when none is known. A call of an external virtual method on an external receiver type
/// (`object.ToString()`, `IDisposable.Dispose()`) keeps its external target: its propagator model stands for every
/// implementation (known limit: a source implementation reached only through an external interface is not followed).
/// What the solution creates is collected while the call graph is built (Collect, every body once) and fixed by Seal;
/// a virtual call is resolved only after it (CallGraph keeps those calls pending until then).
internal sealed partial class Dispatch
{
    private readonly Dictionary<object, List<INamedTypeSymbol>> _subtypes = new();
    private readonly Dictionary<(object Method, object Root), Resolution> _cache = new();
    private readonly Dictionary<ISymbol, object> _keys = new(SymbolEqualityComparer.Default);

    /// The targets of one (method, receiver type) pair and how they were found.
    private sealed record Resolution(IReadOnlyList<IMethodSymbol> Targets, DispatchKind Kind, bool Narrowed);

    public Dispatch(IEnumerable<Compilation> compilations, CancellationToken ct)
    {
        foreach (var compilation in compilations)
        {
            ct.ThrowIfCancellationRequested();
            _compilations.Add(compilation);
            foreach (var type in Types(compilation.Assembly.GlobalNamespace))
            {
                if (type.BaseType is { } baseType) AddSubtype(baseType, type);
                foreach (var i in type.Interfaces) AddSubtype(i, type);
                ScanType(type);
            }
            ScanAttributes(compilation, ct);
        }
    }

    private void AddSubtype(INamedTypeSymbol super, INamedTypeSymbol type)
    {
        var key = Key(super.OriginalDefinition);
        if (!_subtypes.TryGetValue(key, out var list)) _subtypes[key] = list = new List<INamedTypeSymbol>();
        list.Add(type);
    }

    private static IEnumerable<INamedTypeSymbol> Types(INamespaceOrTypeSymbol container)
    {
        foreach (var member in container.GetMembers())
        {
            if (member is INamespaceSymbol ns)
            {
                foreach (var t in Types(ns)) yield return t;
            }
            else if (member is INamedTypeSymbol type)
            {
                yield return type;
                foreach (var t in Types(type)) yield return t;
            }
        }
    }

    public object Key(ISymbol symbol)
    {
        if (_keys.TryGetValue(symbol, out var key)) return key;
        key = SymbolKeys.Of(symbol);
        _keys[symbol] = key;
        return key;
    }

    /// The brief's form: every override or implementation of a virtual or interface method in the solution's source
    /// compilations (the receiver type taken as the method's containing type); the method itself when it is not virtual.
    public IReadOnlyList<IMethodSymbol> Targets(IMethodSymbol method) => Targets(method, true, method.ContainingType);

    public IReadOnlyList<IMethodSymbol> Targets(CallSite site) => Targets(site.Method, site.IsVirtual, site.Receiver);

    /// Whether a call needs the dispatch analysis (a virtual call with a source method or receiver type); the others run
    /// the method itself.
    public static bool IsDispatched(CallSite site) => Root(site.Method, site.IsVirtual, site.Receiver) != null;

    /// The receiver type a virtual call is resolved from, or null when the call runs the method itself.
    private static INamedTypeSymbol? Root(IMethodSymbol method, bool isVirtual, ITypeSymbol? receiverType)
    {
        var def = (IMethodSymbol)SymbolKeys.Definition(method);
        var containing = def.ContainingType;
        if (!isVirtual || def.IsStatic || containing == null
            || !(def.IsVirtual || def.IsAbstract || def.IsOverride || containing.TypeKind == TypeKind.Interface))
            return null;
        var root = receiverType is INamedTypeSymbol named && named.TypeKind != TypeKind.TypeParameter ? named.OriginalDefinition : containing.OriginalDefinition;
        if (!SymbolKeys.InSource(def) && !SymbolKeys.InSource(root)) return null;
        return root;
    }

    /// The methods a call may run: the method itself (its definition) for a non-virtual call (`base.M()`, a static or
    /// sealed member); for a virtual call, the implementation in the receiver's static type and in every source type
    /// derived from it (class hierarchy analysis), abstract ones left out, narrowed to the types the solution creates
    /// when it creates any of them (R-7).
    public IReadOnlyList<IMethodSymbol> Targets(IMethodSymbol method, bool isVirtual, ITypeSymbol? receiverType) =>
        Resolve(method, isVirtual, receiverType)?.Targets ?? new[] { (IMethodSymbol)SymbolKeys.Definition(method) };

    /// Counts one call site of the call graph in the stats (once per site, CallGraph.Build).
    public void Count(CallSite site)
    {
        if (Resolve(site.Method, site.IsVirtual, site.Receiver) is not { } resolution) return;
        switch (resolution.Kind)
        {
            case DispatchKind.Registrations: ByRegistrations++; break;
            case DispatchKind.Scanning: ByScanning++; break;
            case DispatchKind.Hierarchy: ByHierarchy++; break;
            default: return;
        }
        if (resolution.Narrowed) Narrowed++;
    }

    public int ByRegistrations { get; private set; }

    public int ByScanning { get; private set; }

    public int ByHierarchy { get; private set; }

    public int Narrowed { get; private set; }

    private Resolution? Resolve(IMethodSymbol method, bool isVirtual, ITypeSymbol? receiverType)
    {
        var root = Root(method, isVirtual, receiverType);
        if (root == null) return null;
        var def = (IMethodSymbol)SymbolKeys.Definition(method);
        var cacheKey = (Key(def), Key(root));
        if (_cache.TryGetValue(cacheKey, out var cached)) return cached;
        var hierarchy = new List<IMethodSymbol>();
        var known = new List<IMethodSymbol>();
        var seenTypes = new HashSet<object>();
        var seenTargets = new HashSet<object>();
        var seenKnown = new HashSet<object>();
        var anyCreated = false;
        var queue = new Queue<INamedTypeSymbol>();
        queue.Enqueue(root);
        seenTypes.Add(Key(root));
        while (queue.Count > 0)
        {
            var type = queue.Dequeue();
            if (type.TypeKind is TypeKind.Class or TypeKind.Struct && Implementation(type, def) is { } impl)
            {
                var target = (IMethodSymbol)SymbolKeys.Definition(impl);
                var implKey = Key(target);
                if (seenTargets.Add(implKey)) hierarchy.Add(target);
                // Narrowing needs the sealed facts; before Seal the class hierarchy stands (and is not cached).
                var created = _sealed ? KnownOf(type) : Known.None;
                if (created != Known.None)
                {
                    anyCreated |= created == Known.Created;
                    if (seenKnown.Add(implKey)) known.Add(target);
                }
            }
            if (_subtypes.TryGetValue(Key(type.OriginalDefinition), out var subtypes))
                foreach (var s in subtypes)
                    if (seenTypes.Add(Key(s))) queue.Enqueue(s);
        }
        Resolution result;
        if (known.Count > 0)
            result = new Resolution(known, anyCreated ? DispatchKind.Registrations : DispatchKind.Scanning, known.Count < hierarchy.Count);
        else if (hierarchy.Count > 0)
            result = new Resolution(hierarchy, DispatchKind.Hierarchy, false);
        else
            // An interface member with a default body, or a virtual method no source type was found for.
            result = new Resolution(def.IsAbstract ? Array.Empty<IMethodSymbol>() : new[] { def }, DispatchKind.None, false);
        if (_sealed) _cache[cacheKey] = result;
        return result;
    }

    /// The method that runs for `def` on an instance of `type`: the interface member's implementation, or the most
    /// derived override (or `def` itself) up the base chain; null when it is abstract there.
    private IMethodSymbol? Implementation(INamedTypeSymbol type, IMethodSymbol def)
    {
        var defKey = Key(def);
        if (def.ContainingType.TypeKind == TypeKind.Interface)
        {
            var interfaceKey = Key(def.ContainingType.OriginalDefinition);
            foreach (var i in type.AllInterfaces)
            {
                if (!Equals(Key(i.OriginalDefinition), interfaceKey)) continue;
                foreach (var member in i.GetMembers(def.Name))
                {
                    if (member is not IMethodSymbol m || !Equals(Key(m.OriginalDefinition), defKey)) continue;
                    var impl = type.FindImplementationForInterfaceMember(m) as IMethodSymbol ?? AccessorImplementation(type, m);
                    // The interface map names the method that implements the member, possibly a base class's virtual or
                    // abstract one; on this type its most derived override runs (Task 22).
                    if (impl is { IsVirtual: true } or { IsAbstract: true } or { IsOverride: true } && impl.ContainingType.TypeKind != TypeKind.Interface)
                        impl = Override(type, (IMethodSymbol)SymbolKeys.Definition(impl));
                    return impl is { IsAbstract: false } ? impl : null;
                }
            }
            return null;
        }
        return Override(type, def);
    }

    /// The most derived override of class method `def` (or `def` itself) up the base chain from `type`; null when it is
    /// abstract there.
    private IMethodSymbol? Override(INamedTypeSymbol type, IMethodSymbol def)
    {
        var defKey = Key(def);
        for (var t = type; t != null; t = t.BaseType)
        {
            foreach (var member in t.GetMembers(def.Name))
            {
                if (member is not IMethodSymbol m) continue;
                if (Equals(Key(m), defKey)) return m.IsAbstract ? null : m;
                for (var o = m.OverriddenMethod; o != null; o = o.OverriddenMethod)
                    if (Equals(Key(o), defKey)) return m.IsAbstract ? null : m;
            }
        }
        return null;
    }

    /// An interface property accessor's implementation through its property (when the accessor itself is not found).
    private static IMethodSymbol? AccessorImplementation(INamedTypeSymbol type, IMethodSymbol accessor)
    {
        if (accessor.AssociatedSymbol is not IPropertySymbol property) return null;
        if (type.FindImplementationForInterfaceMember(property) is not IPropertySymbol impl) return null;
        return accessor.MethodKind == MethodKind.PropertyGet ? impl.GetMethod : impl.SetMethod;
    }

    /// Whether an access of a member through `instance` dispatches virtually: a virtual, abstract, override or
    /// interface member not reached through `base`.
    public static bool IsVirtualAccess(ISymbol member, IOperation? instance)
    {
        if (member.IsStatic || instance == null) return false;
        if (instance.Syntax is BaseExpressionSyntax) return false;
        return member.IsVirtual || member.IsAbstract || member.IsOverride || member.ContainingType?.TypeKind == TypeKind.Interface;
    }
}
