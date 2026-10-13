using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// Whether a symbol is a member a model names (models/README.md, "Matching").
///
/// - A constructor pattern matches the constructors of exactly its type (constructors are not inherited).
/// - Another pattern `T.M` matches a member named M (or starting with M for `M*`) of the right kind declared on T or on
///   a class derived from T (an override, or a member hiding T's with `new`), and a member that implements a member
///   M of interface T (implicitly or explicitly, also through a base class's implementation it overrides).
/// - Generic members and types match by their definitions (`Query<User>` is `Query`, `List<int>` is `List`1`);
///   an extension method called as one (reduced) matches its static form.
/// - Property patterns take the property itself (the caller knows whether it reads or writes) or the accessor
///   of their kind (get for property-get; set or init for property-set).
public static class SymbolMatch
{
    public static bool Matches(MemberPattern p, ISymbol symbol)
    {
        switch (p.Kind)
        {
            case MemberKind.Constructor:
                return symbol is IMethodSymbol { MethodKind: MethodKind.Constructor } ctor
                    && MetadataName(ctor.ContainingType) == p.TypeName;
            case MemberKind.Method:
                if (symbol is not IMethodSymbol method || !IsOrdinaryMethod(method)) return false;
                method = method.ReducedFrom ?? method;
                return MatchesMember(p, method.OriginalDefinition);
            case MemberKind.PropertyGet:
            case MemberKind.PropertySet:
                var property = symbol switch
                {
                    IPropertySymbol prop => prop,
                    IMethodSymbol { MethodKind: MethodKind.PropertyGet, AssociatedSymbol: IPropertySymbol prop } when p.Kind == MemberKind.PropertyGet => prop,
                    IMethodSymbol { MethodKind: MethodKind.PropertySet, AssociatedSymbol: IPropertySymbol prop } when p.Kind == MemberKind.PropertySet => prop,
                    _ => null,
                };
                return property != null && MatchesMember(p, property.OriginalDefinition);
            default:
                return false;
        }
    }

    /// The metadata name of a type's definition: `System.Collections.Generic.IDictionary`2`, nested types joined by `+`,
    /// arrays as `<element>[]` (`[,]` for two dimensions).
    public static string MetadataName(ITypeSymbol type)
    {
        switch (type)
        {
            case IArrayTypeSymbol array:
                return MetadataName(array.ElementType) + "[" + new string(',', array.Rank - 1) + "]";
            case INamedTypeSymbol named:
                named = named.OriginalDefinition;
                if (named.ContainingType != null) return MetadataName(named.ContainingType) + "+" + named.MetadataName;
                var ns = named.ContainingNamespace;
                return ns == null || ns.IsGlobalNamespace ? named.MetadataName : ns.ToDisplayString() + "." + named.MetadataName;
            default:
                return type.MetadataName;
        }
    }

    private static bool IsOrdinaryMethod(IMethodSymbol m) => m.MethodKind is MethodKind.Ordinary or MethodKind.ReducedExtension
        or MethodKind.ExplicitInterfaceImplementation or MethodKind.UserDefinedOperator or MethodKind.Conversion or MethodKind.DelegateInvoke;

    private static bool NameMatches(MemberPattern p, string name) =>
        p.Prefix ? name.StartsWith(p.MemberName, StringComparison.Ordinal) : name == p.MemberName;

    private static bool KindMatches(MemberPattern p, ISymbol member) => p.Kind switch
    {
        MemberKind.Method => member is IMethodSymbol m && IsOrdinaryMethod(m),
        MemberKind.PropertyGet or MemberKind.PropertySet => member is IPropertySymbol,
        _ => false,
    };

    private static bool MatchesMember(MemberPattern p, ISymbol member)
    {
        var type = member.ContainingType;
        if (type == null) return false;

        // Declared on T or on a class derived from it (overrides and hiding members have the member's own name).
        if (NameMatches(p, member.Name))
        {
            if (type.TypeKind == TypeKind.Interface)
            {
                if (MetadataName(type) == p.TypeName || type.AllInterfaces.Any(i => MetadataName(i) == p.TypeName)) return true;
            }
            else
            {
                for (var t = type; t != null; t = t.BaseType)
                {
                    if (MetadataName(t) == p.TypeName) return true;
                }
            }
        }

        // Implements a member of interface T: the member, or a member it overrides, is T's member's implementation.
        if (type.TypeKind == TypeKind.Interface) return false;
        foreach (var iface in type.AllInterfaces)
        {
            if (MetadataName(iface) != p.TypeName) continue;
            foreach (var candidate in iface.GetMembers())
            {
                if (!KindMatches(p, candidate) || !NameMatches(p, candidate.Name)) continue;
                var impl = type.FindImplementationForInterfaceMember(candidate);
                if (impl == null) continue;
                for (var m = member; m != null; m = Overridden(m))
                {
                    if (SymbolEqualityComparer.Default.Equals(impl.OriginalDefinition, m.OriginalDefinition)) return true;
                }
            }
        }
        return false;
    }

    private static ISymbol? Overridden(ISymbol member) => member switch
    {
        IMethodSymbol m => m.OverriddenMethod,
        IPropertySymbol p => p.OverriddenProperty,
        _ => null,
    };
}
