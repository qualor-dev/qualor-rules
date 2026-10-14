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
///
/// Holds (Task 27, strong updates): the path was last assigned this value on every path here, and nothing since may have
/// changed it (an assignment of its root, a write of a member on it through any object, a call that may write it: see
/// MethodAnalyzer.ForgetForCall), so a read of the path is exactly that value: not the object's whole taint, not the heap.
internal sealed record MemberFact(AccessPath Path, bool All, ImmutableHashSet<string> Rules, ImmutableHashSet<IOperation> Pending)
{
    public TaintValue? Holds { get; init; }

    public bool Cleans => All || Rules.Count > 0;

    /// A guard's part: All, Rules or Pending.
    public bool Guards => All || Rules.Count > 0 || Pending.Count > 0;

    public bool Empty => !Guards && Holds == null;

    /// The fact on both sides of a join: what holds on each of them.
    public MemberFact Meet(MemberFact other)
    {
        var all = All && other.All;
        var rules = All ? other.Rules : other.All ? Rules : Rules.Intersect(other.Rules);
        var pending = Pending.Count == 0 || other.Pending.Count == 0 ? ImmutableHashSet<IOperation>.Empty : Pending.Intersect(other.Pending);
        var holds = Holds == null || other.Holds == null ? null : Holds.Join(other.Holds);
        if (all == All && rules.Count == Rules.Count && pending.Count == Pending.Count && ReferenceEquals(holds, Holds)) return this;
        return new MemberFact(Path, all, rules, pending) { Holds = holds };
    }

    /// The fact without its guard part.
    public MemberFact? WithoutGuards() => Holds == null ? null : Guards ? new MemberFact(Path, false, ImmutableHashSet<string>.Empty, ImmutableHashSet<IOperation>.Empty) { Holds = Holds } : this;

    /// The fact without its strong update.
    public MemberFact? WithoutHolds() => !Guards ? null : Holds == null ? this : this with { Holds = null };
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
            var holds = fact.Holds ?? f.Holds;
            if (all == f.All && rules.Count == f.Rules.Count && pending.Count == f.Pending.Count && ReferenceEquals(holds, f.Holds)) return facts;
            return facts.SetItem(i, new MemberFact(f.Path, all, rules, pending) { Holds = holds });
        }
        return facts.Length >= MaxFacts ? facts : facts.Add(fact);
    }

    /// The facts with the strong update of `path` set to `value` (a fact for the path is kept for its guard part).
    public static ImmutableArray<MemberFact> SetHolds(ImmutableArray<MemberFact> facts, AccessPath path, TaintValue value)
    {
        // Exactness is one level deep (fix round 1 of Task 27, C1): a held value keeps its objects, not what it knows of
        // its own members, which a write through a longer path or an alias would leave stale.
        value = MemberMap.Flat(value);
        for (var i = 0; i < facts.Length; i++)
            if (facts[i].Path.Equals(path)) return facts.SetItem(i, facts[i] with { Holds = value });
        return facts.Length >= MaxFacts ? facts : facts.Add(new MemberFact(path, false, ImmutableHashSet<string>.Empty, ImmutableHashSet<IOperation>.Empty) { Holds = value });
    }

    /// The facts without the guard parts `guards` holds for and the strong updates `holds` holds for.
    public static ImmutableArray<MemberFact> RemoveParts(ImmutableArray<MemberFact> facts, Func<AccessPath, bool> guards, Func<AccessPath, bool> holds)
    {
        if (facts.IsEmpty) return facts;
        ImmutableArray<MemberFact>.Builder? kept = null;
        for (var i = 0; i < facts.Length; i++)
        {
            var f = facts[i];
            MemberFact? g = f;
            if (g.Guards && guards(f.Path)) g = g.WithoutGuards();
            if (g != null && g.Holds != null && holds(f.Path)) g = g.WithoutHolds();
            if (kept == null && ReferenceEquals(g, f)) continue;
            if (kept == null)
            {
                kept = ImmutableArray.CreateBuilder<MemberFact>(facts.Length);
                for (var j = 0; j < i; j++) kept.Add(facts[j]);
            }
            if (g != null) kept.Add(g);
        }
        return kept == null ? facts : kept.ToImmutable();
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

    /// Whether a call given a value of type `argument` (as its receiver or an argument) may change an object of type
    /// `held` (one along a path): some type the value may reach (`reach`: itself, an array's elements, a generic type's
    /// type arguments, the instance fields of a type declared in source; TypeReach) is the held type, one derived from it
    /// or one it derives from, an interface the held type implements, or object, dynamic or a type parameter (either
    /// side). A subclass of the held type that would implement an interface only it names is not considered.
    public static bool MayChange(TypeReach.Result reach, ITypeSymbol held)
    {
        // A reach cut off at its bounds may lead anywhere (fix round 2, RR1).
        if (reach.Open) return true;
        held = held.OriginalDefinition;
        if (held.SpecialType == SpecialType.System_Object || held.TypeKind is TypeKind.Dynamic or TypeKind.TypeParameter) return true;
        foreach (var t in reach.Types)
            if (Related(t.OriginalDefinition, held)) return true;
        return false;
    }

    private static bool Related(ITypeSymbol argument, ITypeSymbol held)
    {
        if (argument.SpecialType is SpecialType.System_Object or SpecialType.System_ValueType || argument.TypeKind is TypeKind.Dynamic or TypeKind.TypeParameter)
            return true;
        if (argument is IArrayTypeSymbol) return false;
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

    /// A value a call is given that may lead to an object: anything but string, scalars, enums, delegates and pointers
    /// (a struct too, passed by value: a tuple or a struct may hold a reference).
    public static bool MayHold(ITypeSymbol? type)
    {
        if (type == null) return false;
        if (type.SpecialType == SpecialType.System_Object) return true;
        if (type.TypeKind is TypeKind.Enum or TypeKind.Delegate or TypeKind.Pointer or TypeKind.FunctionPointer or TypeKind.Error) return false;
        return type.SpecialType == SpecialType.None;
    }
}

/// The types a value of a type may reach (Task 21 fix round 1, I3), cached per type for one run: the type itself, an
/// array's element type, a generic type's type arguments (List<Form>, Dictionary<_, Form>, a tuple), and the instance
/// fields of a type declared in source (its bases' too; an auto-property's hidden field included), recursively, at most
/// MaxDepth steps and MaxTypes types. A walk cut off at either bound with types left to expand is Open: it may reach
/// anything (fix round 2, RR1). A field typed object, dynamic or a type parameter is not followed, and an interface- or
/// base-typed field reaches only its declared type, not the implementations that may hold the object (a lock object or
/// a cache would otherwise reach every object; the heap gap of models/README.md "Guards on members").
internal sealed class TypeReach
{
    public const int MaxDepth = 3;
    public const int MaxTypes = 32;

    internal readonly record struct Result(ImmutableArray<ITypeSymbol> Types, bool Open);

    private readonly Dictionary<ITypeSymbol, Result> _cache = new(SymbolEqualityComparer.IncludeNullability);

    public Result Of(ITypeSymbol type)
    {
        if (_cache.TryGetValue(type, out var cached)) return cached;
        var seen = new HashSet<ITypeSymbol>(SymbolEqualityComparer.Default) { type };
        var result = ImmutableArray.CreateBuilder<ITypeSymbol>();
        result.Add(type);
        var queue = new Queue<(ITypeSymbol Type, int Depth)>();
        queue.Enqueue((type, 0));
        var open = false;
        while (queue.Count > 0 && !open)
        {
            var (t, depth) = queue.Dequeue();
            foreach (var child in Children(t))
            {
                if (seen.Contains(child)) continue;
                if (depth >= MaxDepth || result.Count >= MaxTypes)
                {
                    open = true;
                    break;
                }
                seen.Add(child);
                result.Add(child);
                queue.Enqueue((child, depth + 1));
            }
        }
        var built = new Result(result.ToImmutable(), open);
        _cache[type] = built;
        return built;
    }

    /// The types a value of type `t` holds directly: an array's elements, the type arguments, the instance fields of a
    /// type of the project (and of its bases in source).
    private static IEnumerable<ITypeSymbol> Children(ITypeSymbol t)
    {
        if (t is IArrayTypeSymbol array)
        {
            if (MemberFacts.MayHold(array.ElementType)) yield return array.ElementType;
            yield break;
        }
        if (t is not INamedTypeSymbol named) yield break;
        foreach (var a in named.TypeArguments)
            if (MemberFacts.MayHold(a)) yield return a;
        for (var b = named; b != null && b.Locations.Any(l => l.IsInSource); b = b.BaseType)
        {
            foreach (var f in b.GetMembers().OfType<IFieldSymbol>())
            {
                if (f.IsStatic || f.IsConst || !MemberFacts.MayHold(f.Type)) continue;
                if (f.Type.SpecialType == SpecialType.System_Object || f.Type.TypeKind is TypeKind.Dynamic or TypeKind.TypeParameter) continue;
                yield return f.Type;
            }
        }
    }
}
