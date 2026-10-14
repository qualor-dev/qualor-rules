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

    /// A field no code of another assembly can reach: it or a type that holds it is private, internal or private
    /// protected.
    private static bool VisibleOutside(ISymbol field)
    {
        for (ISymbol? s = field; s is not null and not INamespaceSymbol; s = s.ContainingSymbol)
            if (s.DeclaredAccessibility is Accessibility.Private or Accessibility.Internal or Accessibility.ProtectedAndInternal) return false;
        return true;
    }

    /// Whether this use of the table only reads it.
    private static bool IsRead(IOperation use)
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
    private static bool IsNetCollection(ITypeSymbol type)
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

    /// One of .NET's own comparers (StringComparer.Ordinal, EqualityComparer<T>.Default, ...): a value of a type declared
    /// in metadata that is an equality comparer or a comparer.
    internal static bool IsNetComparer(IOperation? op)
    {
        if (op?.Type is not { } type || SymbolKeys.InSource(type)) return false;
        static bool Named(ITypeSymbol t) => SymbolMatch.MetadataName(t) is "System.Collections.Generic.IEqualityComparer`1" or "System.Collections.Generic.IComparer`1"
            or "System.Collections.IEqualityComparer" or "System.Collections.IComparer";
        if (!Named(type) && !type.AllInterfaces.Any(Named)) return false;
        // A value typed by the interface may be anything: only a member of .NET's own types gives one of its comparers.
        return op switch
        {
            IPropertyReferenceOperation p => !SymbolKeys.InSource(p.Property),
            IFieldReferenceOperation f => !SymbolKeys.InSource(f.Field),
            IInvocationOperation i => !SymbolKeys.InSource(i.TargetMethod),
            _ => false,
        };
    }

    private static IOperation? Unwrap(IOperation? op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }
}
