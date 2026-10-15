using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// The allow-list tables of the shared allow-lists (models/README.md, "Allow-lists"). A table is a `static readonly` field
/// declared in source that no code outside its assembly can reach (it, or a type holding it, is private or internal),
/// - whose type and initializer type are .NET's own collections (an array, or a type of System.Collections.Generic,
///   System.Collections.Frozen or System.Collections.Immutable; not a project's subclass, whose Contains may mean
///   something else), initialized in place with constants (comparer arguments: .NET's own comparers), and
/// - every use of which in its class's files (a private field) or its compilation's files is a known read: the receiver
///   of a read-only member (Contains, ContainsKey, TryGetValue, an indexer or element read, Count, Keys, ...), argument 0
///   of a read-only static method (System.Linq.Enumerable, Array.IndexOf, string.Join, ...), a foreach collection,
///   `nameof`. Any other use (an alias, an argument of another method, a cast, a span, a write, `ref`) may change it: the
///   field is no table.
/// A field of another project is no table. The answer is cached per field.
internal sealed class AllowLists
{
    /// Members of .NET collections that only read them.
    private static readonly HashSet<string> ReadMembers = new(StringComparer.Ordinal)
    {
        "Contains", "ContainsKey", "ContainsValue", "TryGetValue", "GetValueOrDefault", "IndexOf", "LastIndexOf", "BinarySearch",
        "Exists", "Find", "FindIndex", "FindLast", "FindLastIndex", "FindAll", "TrueForAll", "GetEnumerator", "ToArray", "ToList",
        "IsSubsetOf", "IsSupersetOf", "IsProperSubsetOf", "IsProperSupersetOf", "Overlaps", "SetEquals", "Equals", "GetHashCode",
        "ToString", "GetType", "Count", "Length", "LongLength", "Keys", "Values", "Comparer", "IsReadOnly", "Rank", "Item",
    };

    /// Static types whose methods only read the collection given as their first argument (by name, ReadStatics).
    private static readonly HashSet<string> ReadStaticTypes = new(StringComparer.Ordinal)
    {
        "System.Linq.Enumerable", "System.String", "System.Array", "System.Collections.Generic.CollectionExtensions",
    };

    /// Methods of ReadStaticTypes that read (Enumerable's are all reads; Array's and CollectionExtensions' are not).
    private static readonly HashSet<string> ReadStatics = new(StringComparer.Ordinal)
    {
        "Join", "Concat", "IndexOf", "LastIndexOf", "BinarySearch", "Exists", "Find", "FindIndex", "FindAll", "TrueForAll",
        "GetValueOrDefault",
    };

    private static readonly string[] CollectionNamespaces =
    {
        "System.Collections.Generic.", "System.Collections.Frozen.", "System.Collections.Immutable.",
    };

    private readonly Dictionary<IFieldSymbol, bool> _tables = new(SymbolEqualityComparer.Default);

    /// Whether `op` reads an allow-list table (also its Keys or Values).
    public bool IsTable(IOperation? op, Compilation? compilation)
    {
        op = Unwrap(op);
        if (op is IPropertyReferenceOperation { Property.Name: "Keys" or "Values", Arguments.Length: 0, Instance: { } owner }) op = Unwrap(owner);
        if (op is not IFieldReferenceOperation { Field: { IsStatic: true, IsReadOnly: true } field }) return false;
        field = field.OriginalDefinition;
        if (_tables.TryGetValue(field, out var known)) return known;
        var result = compilation != null && Compute(field, compilation);
        _tables[field] = result;
        return result;
    }

    private static bool Compute(IFieldSymbol field, Compilation compilation)
    {
        if (field.DeclaringSyntaxReferences.Length != 1 || !IsNetCollection(field.Type) || VisibleOutside(field)) return false;
        var reference = field.DeclaringSyntaxReferences[0];
        if (!compilation.ContainsSyntaxTree(reference.SyntaxTree)) return false;
        if (reference.GetSyntax() is not VariableDeclaratorSyntax { Initializer.Value: { } value }) return false;
        var models = new Dictionary<SyntaxTree, SemanticModel>();
        SemanticModel Model(SyntaxTree tree)
        {
            if (!models.TryGetValue(tree, out var m)) models[tree] = m = compilation.GetSemanticModel(tree);
            return m;
        }
        if (!IsLiteralCollection(Model(reference.SyntaxTree).GetOperation(value))) return false;

        var trees = field.DeclaredAccessibility == Accessibility.Private
            ? field.ContainingType.DeclaringSyntaxReferences.Select(r => r.SyntaxTree).Where(compilation.ContainsSyntaxTree).Distinct()
            : compilation.SyntaxTrees;
        foreach (var tree in trees)
        {
            foreach (var name in tree.GetRoot().DescendantNodes().OfType<IdentifierNameSyntax>())
            {
                if (name.Identifier.ValueText != field.Name) continue;
                var model = Model(tree);
                if (!SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol?.OriginalDefinition, field)) continue;
                SyntaxNode node = name;
                if (name.Parent is MemberAccessExpressionSyntax access && access.Name == name) node = access;
                else if (name.Parent is MemberBindingExpressionSyntax binding && binding.Name == name) node = binding;
                if (model.GetOperation(node) is not { } operation || !IsRead(operation)) return false;
            }
        }
        return true;
    }

    private readonly Dictionary<IFieldSymbol, bool> _servers = new(SymbolEqualityComparer.Default);

    /// Whether a field holds a collection built by the server (Task 33, membership guards; models/README.md
    /// "Membership"): a field declared in source of .NET's own collection type that no other assembly can reach, every use
    /// of which (in its class's files, or its compilation's) is a known read (IsRead), a removal, an assignment of the
    /// whole collection from a known build (KnownBuild), or, in a constructor of its type, a write into it. Whether it
    /// holds request data is the caller's question (the heap: what its builds and writes put there, in any request; a
    /// dictionary's keys apart, KeysLocation). Cached per field.
    public bool IsServerCollection(IFieldSymbol field, Compilation? compilation)
    {
        field = field.OriginalDefinition;
        if (_servers.TryGetValue(field, out var known)) return known;
        var result = compilation != null && ComputeServer(field, compilation);
        _servers[field] = result;
        return result;
    }

    private static bool ComputeServer(IFieldSymbol field, Compilation compilation)
    {
        if (field.IsConst || field.DeclaringSyntaxReferences.Length != 1 || !IsNetCollection(field.Type) || VisibleOutside(field)) return false;
        var reference = field.DeclaringSyntaxReferences[0];
        if (!compilation.ContainsSyntaxTree(reference.SyntaxTree)) return false;
        var dictionary = IsDictionary(field.Type);
        var models = new Dictionary<SyntaxTree, SemanticModel>();
        SemanticModel Model(SyntaxTree tree)
        {
            if (!models.TryGetValue(tree, out var m)) models[tree] = m = compilation.GetSemanticModel(tree);
            return m;
        }
        if (reference.GetSyntax() is VariableDeclaratorSyntax { Initializer.Value: { } value } && !KnownBuild(Model(reference.SyntaxTree).GetOperation(value), dictionary))
            return false;
        var trees = field.DeclaredAccessibility == Accessibility.Private
            ? field.ContainingType.DeclaringSyntaxReferences.Select(r => r.SyntaxTree).Where(compilation.ContainsSyntaxTree).Distinct()
            : compilation.SyntaxTrees;
        foreach (var tree in trees)
        {
            foreach (var name in tree.GetRoot().DescendantNodes().OfType<IdentifierNameSyntax>())
            {
                if (name.Identifier.ValueText != field.Name) continue;
                var model = Model(tree);
                if (!SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol?.OriginalDefinition, field)) continue;
                SyntaxNode node = name;
                if (name.Parent is MemberAccessExpressionSyntax access && access.Name == name) node = access;
                else if (name.Parent is MemberBindingExpressionSyntax binding && binding.Name == name) node = binding;
                if (model.GetOperation(node) is not { } operation) return false;
                if (IsRead(operation) || IsRemoval(operation)) continue;
                if (operation.Parent is ISimpleAssignmentOperation assignment && ReferenceEquals(assignment.Target, operation))
                {
                    if (!KnownBuild(assignment.Value, dictionary)) return false;
                    continue;
                }
                if (IsWriteInto(operation) && InConstructorOf(model, name, field)) continue;
                return false;
            }
        }
        return true;
    }

    /// Whether a local holds a collection built here (Task 33): of .NET's own collection type, every use of which in
    /// `body` (the operation tree that declares it, its lambdas too) is a known read, a removal, an assignment from a known
    /// build, or, for a collection that is no dictionary, a write into it (what it adds is in the local's value; a
    /// dictionary's keys are not, ruling R-E21).
    public static bool IsBuiltHere(ILocalSymbol local, IOperation body)
    {
        if (!IsNetCollection(local.Type)) return false;
        var dictionary = IsDictionary(local.Type);
        foreach (var o in body.DescendantsAndSelf())
        {
            switch (o)
            {
                case IVariableDeclaratorOperation d when SymbolEqualityComparer.Default.Equals(d.Symbol, local):
                    if (d.Initializer != null && !KnownBuild(d.Initializer.Value, dictionary)) return false;
                    break;
                case ILocalReferenceOperation l when SymbolEqualityComparer.Default.Equals(l.Local, local):
                    if (l.IsDeclaration || IsRead(l) || IsRemoval(l)) break;
                    if (l.Parent is ISimpleAssignmentOperation assignment && ReferenceEquals(assignment.Target, l))
                    {
                        if (!KnownBuild(assignment.Value, dictionary)) return false;
                        break;
                    }
                    if (!dictionary && IsWriteInto(l)) break;
                    return false;
            }
        }
        return true;
    }

    private static readonly HashSet<string> RemovalNames = new(StringComparer.Ordinal)
    {
        "Remove", "RemoveAt", "RemoveAll", "RemoveWhere", "RemoveRange", "Clear", "TryRemove", "ExceptWith", "IntersectWith", "TrimExcess",
        "EnsureCapacity",
    };

    private static readonly HashSet<string> WriteNames = new(StringComparer.Ordinal)
    {
        "Add", "AddRange", "Insert", "InsertRange", "Push", "Enqueue", "TryAdd", "AddOrUpdate", "GetOrAdd", "UnionWith",
        "SymmetricExceptWith", "TryUpdate",
    };

    /// The receiver of a method of .NET's collections that only takes elements out.
    private static bool IsRemoval(IOperation use) =>
        use.Parent is IInvocationOperation call && ReferenceEquals(call.Instance, use) && !SymbolKeys.InSource(call.TargetMethod)
        && RemovalNames.Contains(call.TargetMethod.Name);

    /// The receiver of a write of .NET's collections (an Add, an indexer set), no element taken by `ref`.
    private static bool IsWriteInto(IOperation use)
    {
        switch (use.Parent)
        {
            case IInvocationOperation call when ReferenceEquals(call.Instance, use):
                return !SymbolKeys.InSource(call.TargetMethod) && WriteNames.Contains(call.TargetMethod.Name)
                    && call.Arguments.All(a => a.Parameter == null || a.Parameter.RefKind == RefKind.None);
            case IPropertyReferenceOperation { Property.IsIndexer: true } indexer when ReferenceEquals(indexer.Instance, use):
                return indexer.Parent is ISimpleAssignmentOperation set && ReferenceEquals(set.Target, indexer) && indexer.Syntax.Parent is not RefExpressionSyntax;
            default:
                return false;
        }
    }

    /// Whether a use is inside an instance constructor of the field's type (a static constructor for a static field).
    private static bool InConstructorOf(SemanticModel model, SyntaxNode use, IFieldSymbol field) =>
        model.GetEnclosingSymbol(use.SpanStart) is IMethodSymbol { MethodKind: MethodKind.Constructor or MethodKind.StaticConstructor } m
        && m.IsStatic == field.IsStatic && SymbolEqualityComparer.Default.Equals(m.ContainingType?.OriginalDefinition, field.ContainingType.OriginalDefinition);

    /// A known build of a whole collection (Task 33): a value whose request data the collection's value then carries,
    /// with .NET's own comparers only:
    /// - an array or a collection expression;
    /// - a `new` of .NET's own collection type whose comparer arguments are .NET's own; for a dictionary, given no other
    ///   collection (copying one copies keys its value does not carry) and an initializer whose keys are constants;
    /// - .NET's ToArray, ToList, ToHashSet, ToDictionary, ToFrozenSet, ToFrozenDictionary, the immutable ToImmutable* and
    ///   Create*, Array.Empty, an `Empty` member; a dictionary only from a key selector given there.
    internal static bool KnownBuild(IOperation? op, bool dictionary)
    {
        switch (Unwrap(op))
        {
            case IArrayCreationOperation or IArrayInitializerOperation or ICollectionExpressionOperation:
                return !dictionary;
            case IObjectCreationOperation creation:
            {
                if (creation.Type is not { } type || !IsNetCollection(type)) return false;
                foreach (var a in creation.Arguments)
                {
                    var p = a.Parameter?.Type;
                    if (p != null && IsComparerType(p))
                    {
                        if (!IsNetComparer(Unwrap(a.Value))) return false;
                    }
                    else if (dictionary && p != null && p.SpecialType != SpecialType.System_Int32)
                    {
                        return false;
                    }
                }
                if (creation.Initializer == null) return true;
                return creation.Initializer.Initializers.All(i => i switch
                {
                    IInvocationOperation add => !dictionary || (add.Arguments.Length > 0 && Constant(add.Arguments[0].Value)),
                    ISimpleAssignmentOperation { Target: IPropertyReferenceOperation { Property.IsIndexer: true } indexer } =>
                        !dictionary || indexer.Arguments.All(a => Constant(a.Value)),
                    _ => false,
                });
            }
            case IInvocationOperation call:
            {
                var method = call.TargetMethod;
                if (SymbolKeys.InSource(method)) return false;
                if (!BuildNames.Contains(method.Name) && !(method.Name == "Empty" && method.ContainingType?.SpecialType == SpecialType.System_Array)) return false;
                foreach (var a in call.Arguments)
                    if (a.Parameter?.Type is { } p && IsComparerType(p) && a.ArgumentKind != ArgumentKind.DefaultValue && !IsNetComparer(Unwrap(a.Value))) return false;
                // A dictionary's keys must come from a key selector given here (its value then carries them).
                return !dictionary || call.Arguments.Any(a => a.Parameter?.Name == "keySelector");
            }
            case IFieldReferenceOperation { Field: { IsStatic: true, Name: "Empty" } f }:
                return !SymbolKeys.InSource(f);
            case IPropertyReferenceOperation { Property: { IsStatic: true, Name: "Empty" } p }:
                return !SymbolKeys.InSource(p);
            default:
                return false;
        }
    }

    private static readonly HashSet<string> BuildNames = new(StringComparer.Ordinal)
    {
        "ToArray", "ToList", "ToHashSet", "ToDictionary", "ToFrozenSet", "ToFrozenDictionary", "ToImmutableArray", "ToImmutableList",
        "ToImmutableHashSet", "ToImmutableDictionary", "ToImmutableSortedSet", "ToImmutableSortedDictionary", "Create", "CreateRange",
    };

    private static bool IsComparerType(ITypeSymbol type)
    {
        static bool Named(ITypeSymbol t) => SymbolMatch.MetadataName(t.OriginalDefinition) is "System.Collections.Generic.IEqualityComparer`1"
            or "System.Collections.Generic.IComparer`1" or "System.Collections.IEqualityComparer" or "System.Collections.IComparer";
        return Named(type) || type.AllInterfaces.Any(Named);
    }

    /// A dictionary: a type that is or implements IDictionary<K, V> or IReadOnlyDictionary<K, V>.
    internal static bool IsDictionary(ITypeSymbol? type)
    {
        if (type == null) return false;
        static bool Named(ITypeSymbol t) => SymbolMatch.MetadataName(t.OriginalDefinition) is
            "System.Collections.Generic.IDictionary`2" or "System.Collections.Generic.IReadOnlyDictionary`2";
        return Named(type) || type.AllInterfaces.Any(Named);
    }

    /// A field no code of another assembly can reach: it or a type that holds it is private, internal or private
    /// protected.
    private static bool VisibleOutside(ISymbol field)
    {
        for (ISymbol? s = field; s is not null and not INamespaceSymbol; s = s.ContainingSymbol)
            if (s.DeclaredAccessibility is Accessibility.Private or Accessibility.Internal or Accessibility.ProtectedAndInternal) return false;
        return true;
    }

    /// Whether this use of the table only reads it.
    internal static bool IsRead(IOperation use)
    {
        var current = use;
        while (current.Parent is IConversionOperation { IsImplicit: true } conversion && conversion.Type is { } target
               && (IsNetCollection(target) || SymbolMatch.MetadataName(target) == "System.Collections.IEnumerable"))
            current = conversion;
        switch (current.Parent)
        {
            case IInvocationOperation call when ReferenceEquals(call.Instance, current):
                return ReadMembers.Contains(call.TargetMethod.Name) && !SymbolKeys.InSource(call.TargetMethod);
            case IArgumentOperation { Parameter.Ordinal: 0, Parameter.RefKind: RefKind.None, Parent: IInvocationOperation call }
                when call.TargetMethod is { IsStatic: true, ContainingType: { } holder } && ReadStaticTypes.Contains(SymbolMatch.MetadataName(holder)):
                return SymbolMatch.MetadataName(holder) == "System.Linq.Enumerable" || ReadStatics.Contains(call.TargetMethod.Name);
            case IArgumentOperation { Parameter.RefKind: RefKind.None, Parent: IInvocationOperation { TargetMethod: { IsStatic: true, Name: "Join" or "Concat", ContainingType.SpecialType: SpecialType.System_String } } }:
                return true;
            case IPropertyReferenceOperation property when ReferenceEquals(property.Instance, current):
                return ReadMembers.Contains(property.Property.MetadataName) && !SymbolKeys.InSource(property.Property) && !IsWritten(property);
            case IArrayElementReferenceOperation element when ReferenceEquals(element.ArrayReference, current):
                return !IsWritten(element);
            case IForEachLoopOperation loop when ReferenceEquals(loop.Collection, current):
                return true;
            case INameOfOperation:
                return true;
            default:
                return false;
        }
    }

    /// A write of an element (an assignment, an increment, a `ref` or `out` argument) or a `ref` taken to it.
    private static bool IsWritten(IOperation target)
    {
        if (target.Syntax.Parent is RefExpressionSyntax) return true;
        var parent = target.Parent;
        while (parent is ITupleOperation or IConversionOperation) parent = parent.Parent;
        return parent switch
        {
            IAssignmentOperation assignment => ReferenceEquals(assignment.Target, target) || assignment is IDeconstructionAssignmentOperation,
            IIncrementOrDecrementOperation => true,
            IArgumentOperation argument => argument.Parameter?.RefKind is not RefKind.None,
            _ => false,
        };
    }

    /// .NET's own collection: an array, or a type of System.Collections.Generic, Frozen or Immutable declared in metadata.
    internal static bool IsNetCollection(ITypeSymbol type)
    {
        if (type is IArrayTypeSymbol) return true;
        if (type is not INamedTypeSymbol named || SymbolKeys.InSource(named)) return false;
        var name = SymbolMatch.MetadataName(named);
        return CollectionNamespaces.Any(n => name.StartsWith(n, StringComparison.Ordinal));
    }

    /// A collection of constants written in place: an array (also an initializer alone), a collection expression, or a
    /// `new` of .NET's own collection whose arguments are constants or .NET's own comparers and whose initializer holds
    /// constant elements, Add calls of constants or indexer assignments of constants.
    internal static bool IsLiteralCollection(IOperation? op)
    {
        switch (Unwrap(op))
        {
            case IArrayCreationOperation { Initializer: { } init } array:
                return array.DimensionSizes.All(Constant) && init.ElementValues.All(Constant);
            case IArrayInitializerOperation init:
                return init.ElementValues.All(Constant);
            case ICollectionExpressionOperation collection:
                return collection.Elements.All(Constant);
            case IObjectCreationOperation creation:
                if (creation.Type is not { } type || !IsNetCollection(type)) return false;
                if (!creation.Arguments.All(a => Constant(a.Value) || IsNetComparer(Unwrap(a.Value)))) return false;
                return creation.Initializer == null || creation.Initializer.Initializers.All(i => i switch
                {
                    IInvocationOperation add => add.Arguments.All(a => Constant(a.Value)),
                    ISimpleAssignmentOperation { Target: IPropertyReferenceOperation { Property.IsIndexer: true } indexer } set =>
                        indexer.Arguments.All(a => Constant(a.Value)) && Constant(set.Value),
                    _ => false,
                });
            default:
                return false;
        }
    }

    private static bool Constant(IOperation? op) => op != null && (op.ConstantValue.HasValue || (Unwrap(op)?.ConstantValue.HasValue ?? false));

    /// One of .NET's own comparers that tells strings apart by every character they hold (review I4 of Task 33: a
    /// comparer that ignores symbols calls `../etc/passwd` equal to `etcpasswd`): StringComparer's Ordinal,
    /// OrdinalIgnoreCase, InvariantCulture(IgnoreCase) and CurrentCulture(IgnoreCase), StringComparer.FromComparison(...),
    /// StringComparer.Create(culture, ignoreCase), StringComparer.Create and the GetStringComparer extension of CompareInfo with constant
    /// options None or IgnoreCase, EqualityComparer<T>.Default and Comparer<T>.Default.
    internal static bool IsNetComparer(IOperation? op)
    {
        switch (op)
        {
            case IPropertyReferenceOperation { Property: { IsStatic: true } p }:
            {
                var type = SymbolMatch.MetadataName(p.ContainingType.OriginalDefinition);
                return (type == "System.StringComparer" && p.Name is "Ordinal" or "OrdinalIgnoreCase" or "InvariantCulture" or "InvariantCultureIgnoreCase"
                        or "CurrentCulture" or "CurrentCultureIgnoreCase")
                    || (type is "System.Collections.Generic.EqualityComparer`1" or "System.Collections.Generic.Comparer`1" && p.Name == "Default");
            }
            case IInvocationOperation { TargetMethod: { } m } call:
            {
                var type = m.ContainingType is { } t ? SymbolMatch.MetadataName(t.OriginalDefinition) : "";
                if (type == "System.StringComparer" && m.Name == "FromComparison") return true;
                if (!(type == "System.StringComparer" && m.Name == "Create") && !(type == "System.Globalization.GlobalizationExtensions" && m.Name == "GetStringComparer")) return false;
                foreach (var a in call.Arguments)
                {
                    if (a.Parameter?.Type is not { } pt) continue;
                    if (SymbolMatch.MetadataName(pt) == "System.Globalization.CompareOptions"
                        && Unwrap(a.Value)?.ConstantValue is not { HasValue: true, Value: 0 or 1 }) return false;
                }
                return true;
            }
            default:
                return false;
        }
    }

    private static IOperation? Unwrap(IOperation? op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }
}
