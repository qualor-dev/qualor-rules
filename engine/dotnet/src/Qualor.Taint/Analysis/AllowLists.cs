using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// The allow-list tables of the shared allow-lists (models/README.md, "Allow-lists"): a `static readonly` field declared
/// in source whose initializer is a collection of constants written in place (an array, a collection expression, a
/// collection or dictionary initializer of a `new` whose constructor takes at most a comparer or a constant capacity),
/// and that no code of its compilation changes: no Add, TryAdd, AddRange, Insert, InsertRange, UnionWith,
/// SymmetricExceptWith, Push, Enqueue, AddOrUpdate or GetOrAdd call on it, no write of an element or the field, no
/// `ref` or `out` passing, anywhere in its compilation; a field of another project (no tree of the analysed compilation)
/// is no table. The places that could change a collection (the receiver of a call so named, an argument of such a call,
/// an assignment or increment target, a `ref` or `out` argument) are indexed by name once per compilation; only those
/// that name the field are bound. The answer is cached per field.
internal sealed class AllowLists
{
    private static readonly HashSet<string> Mutators = new(StringComparer.Ordinal)
    {
        "Add", "TryAdd", "AddRange", "Insert", "InsertRange", "UnionWith", "SymmetricExceptWith", "Push", "Enqueue", "AddOrUpdate",
        "GetOrAdd",
    };

    private readonly Dictionary<IFieldSymbol, bool> _tables = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<Compilation, Dictionary<string, List<IdentifierNameSyntax>>> _sites = new();

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

    private bool Compute(IFieldSymbol field, Compilation compilation)
    {
        if (field.DeclaringSyntaxReferences.Length != 1) return false;
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

        if (!Sites(compilation).TryGetValue(field.Name, out var names)) return true;
        foreach (var name in names)
        {
            var model = Model(name.SyntaxTree);
            if (!SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name).Symbol?.OriginalDefinition, field)) continue;
            SyntaxNode node = name;
            if (name.Parent is MemberAccessExpressionSyntax access && access.Name == name) node = access;
            else if (name.Parent is MemberBindingExpressionSyntax binding && binding.Name == name) node = binding;
            if (model.GetOperation(node) is not { } operation || Mutates(operation)) return false;
        }
        return true;
    }

    /// The names (by their text) at the places of a compilation that could change a collection they name.
    private Dictionary<string, List<IdentifierNameSyntax>> Sites(Compilation compilation)
    {
        if (_sites.TryGetValue(compilation, out var known)) return known;
        var sites = new Dictionary<string, List<IdentifierNameSyntax>>(StringComparer.Ordinal);
        foreach (var tree in compilation.SyntaxTrees)
        {
            foreach (var node in tree.GetRoot().DescendantNodes())
            {
                switch (node)
                {
                    case InvocationExpressionSyntax call when Mutators.Contains(InvokedName(call.Expression)):
                        if (call.Expression is MemberAccessExpressionSyntax member) Record(member.Expression);
                        else if (call.Expression is MemberBindingExpressionSyntax && call.Parent is ConditionalAccessExpressionSyntax conditional) Record(conditional.Expression);
                        foreach (var a in call.ArgumentList.Arguments) Record(a.Expression);
                        break;
                    case AssignmentExpressionSyntax assignment:
                        Record(assignment.Left);
                        break;
                    case PrefixUnaryExpressionSyntax { RawKind: (int)Microsoft.CodeAnalysis.CSharp.SyntaxKind.PreIncrementExpression or (int)Microsoft.CodeAnalysis.CSharp.SyntaxKind.PreDecrementExpression } prefix:
                        Record(prefix.Operand);
                        break;
                    case PostfixUnaryExpressionSyntax postfix:
                        Record(postfix.Operand);
                        break;
                    case ArgumentSyntax { RefKindKeyword.RawKind: not 0 } byRef:
                        Record(byRef.Expression);
                        break;
                }
            }
        }
        _sites[compilation] = sites;
        return sites;

        void Record(ExpressionSyntax? expression)
        {
            for (var depth = 0; expression != null && depth < 16; depth++)
            {
                switch (expression)
                {
                    case ParenthesizedExpressionSyntax p:
                        expression = p.Expression;
                        continue;
                    case ElementAccessExpressionSyntax e:
                        expression = e.Expression;
                        continue;
                    case PostfixUnaryExpressionSyntax { RawKind: (int)Microsoft.CodeAnalysis.CSharp.SyntaxKind.SuppressNullableWarningExpression } bang:
                        expression = bang.Operand;
                        continue;
                    case TupleExpressionSyntax tuple:
                        foreach (var a in tuple.Arguments) Record(a.Expression);
                        return;
                    case MemberAccessExpressionSyntax { Name: IdentifierNameSyntax name }:
                        Add(name);
                        return;
                    case IdentifierNameSyntax name:
                        Add(name);
                        return;
                    default:
                        return;
                }
            }
        }

        void Add(IdentifierNameSyntax name)
        {
            if (!sites.TryGetValue(name.Identifier.ValueText, out var list)) sites[name.Identifier.ValueText] = list = new List<IdentifierNameSyntax>();
            list.Add(name);
        }
    }

    private static string InvokedName(ExpressionSyntax expression) => expression switch
    {
        MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
        MemberBindingExpressionSyntax b => b.Name.Identifier.ValueText,
        SimpleNameSyntax n => n.Identifier.ValueText,
        _ => "",
    };

    /// Whether this read of the table changes it: a mutating call on it, a write of one of its elements or of the field
    /// itself, a `ref` or `out` argument.
    private static bool Mutates(IOperation read)
    {
        var current = read;
        while (current.Parent is IConversionOperation conversion) current = conversion;
        switch (current.Parent)
        {
            case IInvocationOperation call when ReferenceEquals(call.Instance, current):
                return Mutators.Contains(call.TargetMethod.Name);
            case IArgumentOperation argument:
                if (argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out) return true;
                return argument.Parent is IInvocationOperation { TargetMethod.IsExtensionMethod: true } extension
                    && argument.Parameter?.Ordinal == 0 && Mutators.Contains(extension.TargetMethod.Name);
            case IPropertyReferenceOperation { Property.IsIndexer: true } element when ReferenceEquals(element.Instance, current):
                return IsWritten(element);
            case IArrayElementReferenceOperation element when ReferenceEquals(element.ArrayReference, current):
                return IsWritten(element);
            default:
                return IsWritten(current);
        }
    }

    private static bool IsWritten(IOperation target)
    {
        var parent = target.Parent;
        while (parent is ITupleOperation or IConversionOperation) parent = parent.Parent;
        return parent switch
        {
            IAssignmentOperation assignment => ReferenceEquals(assignment.Target, target) || assignment is IDeconstructionAssignmentOperation,
            IIncrementOrDecrementOperation => true,
            IArgumentOperation argument => argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out,
            _ => false,
        };
    }

    /// A collection of constants written in place: an array (also an initializer alone), a collection expression, or a
    /// `new` whose arguments are comparers or constants and whose initializer holds constant elements, Add calls of
    /// constants or indexer assignments of constants.
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
                if (creation.Type is not { } type || !IsCollection(type)) return false;
                if (!creation.Arguments.All(a => Constant(a.Value) || IsComparer(Unwrap(a.Value)?.Type))) return false;
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

    private static bool IsCollection(ITypeSymbol type) =>
        type.AllInterfaces.Any(i => i.SpecialType == SpecialType.System_Collections_IEnumerable);

    private static bool IsComparer(ITypeSymbol? type)
    {
        if (type == null) return false;
        static bool Named(ITypeSymbol t) => SymbolMatch.MetadataName(t) is "System.Collections.Generic.IEqualityComparer`1" or "System.Collections.Generic.IComparer`1"
            or "System.Collections.IEqualityComparer" or "System.Collections.IComparer";
        return Named(type) || type.AllInterfaces.Any(Named);
    }

    private static IOperation? Unwrap(IOperation? op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }
}
