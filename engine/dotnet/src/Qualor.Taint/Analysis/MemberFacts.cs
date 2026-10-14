using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// An access path `x.M` or `x.M.N` (Task 21, guards on members): a root (a local, a parameter, `this`, or none for a static
/// member) and one to MaxMembers fields or non-indexer properties, by their definitions. ObjectTypes are the types of the
/// objects along the path that a call could change (see MemberFacts.MayChange): the root's and each member's, where the
/// type is a reference type other than string and delegates, or a struct declared in source.
internal sealed class AccessPath : IEquatable<AccessPath>
{
    public const int MaxMembers = 4;

    /// The root of `this.M` (and of an own member read without `this`).
    public static readonly object This = new Marker("this");

    /// The root of a static member's path.
    public static readonly object Static = new Marker("static");

    private readonly int _hash;

    public AccessPath(object root, ImmutableArray<ISymbol> members, ImmutableArray<ITypeSymbol> objectTypes)
    {
        Root = root;
        Members = members;
        ObjectTypes = objectTypes;
        var hash = SymbolOrCapture.Comparer.GetHashCode(root);
        foreach (var m in members) hash = (hash * 31) + SymbolEqualityComparer.Default.GetHashCode(m);
        _hash = hash;
    }

    public object Root { get; }

    public ImmutableArray<ISymbol> Members { get; }

    public ImmutableArray<ITypeSymbol> ObjectTypes { get; }

    public bool Mentions(ISymbol member)
    {
        foreach (var m in Members) if (SymbolEqualityComparer.Default.Equals(m, member)) return true;
        return false;
    }

    public bool Equals(AccessPath? other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (other == null || other._hash != _hash || other.Members.Length != Members.Length || !SymbolOrCapture.Comparer.Equals(Root, other.Root)) return false;
        for (var i = 0; i < Members.Length; i++)
            if (!SymbolEqualityComparer.Default.Equals(Members[i], other.Members[i])) return false;
        return true;
    }

    public override bool Equals(object? obj) => obj is AccessPath p && Equals(p);

    public override int GetHashCode() => _hash;

    public override string ToString() => $"{(Root is ISymbol s ? s.Name : Root.ToString())}.{string.Join(".", Members.Select(m => m.Name))}";

    private sealed class Marker
    {
        private readonly string _name;

        public Marker(string name) => _name = name;

        public override string ToString() => _name;
    }
}

/// What a guard established for one access path on this branch (must-hold): the path's value is clean for every rule
/// (All: it equals a constant) or for Rules; Pending: the calls of `not-null` guards that were given the path's value, still
/// unchanged since (a null check of the call's held result turns one into Rules).
internal sealed record MemberFact(AccessPath Path, bool All, ImmutableHashSet<string> Rules, ImmutableHashSet<IOperation> Pending)
{
    public bool Cleans => All || Rules.Count > 0;

    public bool Empty => !All && Rules.Count == 0 && Pending.Count == 0;

    /// The fact on both sides of a join: what holds on each of them.
    public MemberFact Meet(MemberFact other)
    {
        var all = All && other.All;
        var rules = All ? other.Rules : other.All ? Rules : Rules.Intersect(other.Rules);
        var pending = Pending.Count == 0 || other.Pending.Count == 0 ? ImmutableHashSet<IOperation>.Empty : Pending.Intersect(other.Pending);
        if (all == All && rules.Count == Rules.Count && pending.Count == Pending.Count) return this;
        return new MemberFact(Path, all, rules, pending);
    }
}

/// The member facts of a state (Task 21): a must-hold set, so a join keeps a fact only where every predecessor has it
/// (intersection), and a missing fact means nothing is known. Immutable; at most MaxFacts facts (a guard beyond them is
/// not recorded).
internal static class MemberFacts
{
    public const int MaxFacts = 64;

    public static MemberFact? Find(ImmutableArray<MemberFact> facts, AccessPath path)
    {
        foreach (var f in facts) if (f.Path.Equals(path)) return f;
        return null;
    }

    /// The facts with `fact` added to (united with) the one already held for its path.
    public static ImmutableArray<MemberFact> Add(ImmutableArray<MemberFact> facts, MemberFact fact)
    {
        for (var i = 0; i < facts.Length; i++)
        {
            var f = facts[i];
            if (!f.Path.Equals(fact.Path)) continue;
            var all = f.All || fact.All;
            var rules = f.Rules.Union(fact.Rules);
            var pending = f.Pending.Union(fact.Pending);
            if (all == f.All && rules.Count == f.Rules.Count && pending.Count == f.Pending.Count) return facts;
            return facts.SetItem(i, new MemberFact(f.Path, all, rules, pending));
        }
        return facts.Length >= MaxFacts ? facts : facts.Add(fact);
    }

    /// The facts both sides hold (`a` itself when nothing is lost).
    public static ImmutableArray<MemberFact> Meet(ImmutableArray<MemberFact> a, ImmutableArray<MemberFact> b, out bool changed)
    {
        changed = false;
        if (a.IsEmpty) return a;
        ImmutableArray<MemberFact>.Builder? kept = null;
        for (var i = 0; i < a.Length; i++)
        {
            var other = Find(b, a[i].Path);
            var met = other == null ? null : a[i].Meet(other);
            if (met != null && met.Empty) met = null;
            if (kept == null && ReferenceEquals(met, a[i])) continue;
            if (kept == null)
            {
                kept = ImmutableArray.CreateBuilder<MemberFact>(a.Length);
                for (var j = 0; j < i; j++) kept.Add(a[j]);
            }
            if (met != null) kept.Add(met);
        }
        if (kept == null) return a;
        changed = true;
        return kept.ToImmutable();
    }

    public static ImmutableArray<MemberFact> RemoveWhere(ImmutableArray<MemberFact> facts, Func<AccessPath, bool> predicate)
    {
        if (facts.IsEmpty) return facts;
        var any = false;
        foreach (var f in facts) if (predicate(f.Path)) any = true;
        return any ? facts.RemoveAll(f => predicate(f.Path)) : facts;
    }

    /// Whether a call given an object of type `argument` (as its receiver or an argument) may change an object of type
    /// `held` (one along a path): the same type, one derived from the other, an interface the held type implements, or
    /// either typed object, dynamic or a type parameter. A subclass of the held type that would implement an interface
    /// only it names is not considered.
    public static bool MayChange(ITypeSymbol argument, ITypeSymbol held)
    {
        argument = argument.OriginalDefinition;
        held = held.OriginalDefinition;
        if (argument.SpecialType is SpecialType.System_Object or SpecialType.System_ValueType || argument.TypeKind is TypeKind.Dynamic or TypeKind.TypeParameter)
            return true;
        if (held.SpecialType == SpecialType.System_Object || held.TypeKind is TypeKind.Dynamic or TypeKind.TypeParameter) return true;
        if (argument is IArrayTypeSymbol array) return MayChange(array.ElementType, held);
        if (SymbolEqualityComparer.Default.Equals(argument, held)) return true;
        if (argument.TypeKind == TypeKind.Interface)
            return held.AllInterfaces.Any(i => SymbolEqualityComparer.Default.Equals(i.OriginalDefinition, argument))
                || (held.TypeKind == TypeKind.Interface && argument.AllInterfaces.Any(i => SymbolEqualityComparer.Default.Equals(i.OriginalDefinition, held)));
        if (held.TypeKind == TypeKind.Interface)
            return argument.AllInterfaces.Any(i => SymbolEqualityComparer.Default.Equals(i.OriginalDefinition, held));
        return Derives(argument, held) || Derives(held, argument);

        static bool Derives(ITypeSymbol type, ITypeSymbol from)
        {
            for (var t = type.BaseType; t != null; t = t.BaseType)
                if (SymbolEqualityComparer.Default.Equals(t.OriginalDefinition, from)) return true;
            return false;
        }
    }

    /// An object type a call could change: a reference type other than string and delegates (object included), or a
    /// struct declared in source (not an enum).
    public static bool IsChangeable(ITypeSymbol? type)
    {
        if (type == null) return false;
        if (type.SpecialType == SpecialType.System_Object) return true;
        if (type.SpecialType != SpecialType.None) return false;
        return type.TypeKind switch
        {
            TypeKind.Class or TypeKind.Interface or TypeKind.TypeParameter or TypeKind.Dynamic => true,
            TypeKind.Array => true,
            TypeKind.Struct => type.Locations.Any(l => l.IsInSource),
            _ => false,
        };
    }
}
