using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// What a project body reads, for the provenance lever's callee walk (Task 35, review C1; MethodAnalyzer.CalleeClean),
/// from its operation tree as written. Built once per run (re-review M4); whether a heap member was written with request
/// data is asked at each use, since the heap grows during the run.
///
/// - HeapMembers: the fields and auto-properties of the project it reads (not through a virtual access), each of a type
///   the heap tracks (HeapTracked; any other type rejects the body);
/// - Callees: the project methods it calls and the getters of the project properties it reads that are not plain heap
///   members (a getter body, an interface's, an abstract or virtual one, an indexer), each with how it is dispatched;
/// - Rejected: it does what the walk cannot vouch for: a member of .NET (property, indexer or method) that is not static
///   and is read or called on anything but its own parameters, locals or a constant (a field, `this`, a static member
///   may hold an object a request filled: re-review I1), a property with no getter, a delegate invocation, a dynamic
///   operation, a constructor of the project, or a body whose tree cannot be bound.
internal sealed class BodyReads
{
    private BodyReads(bool rejected, List<ISymbol> heapMembers, List<(IMethodSymbol Method, bool IsVirtual, ITypeSymbol? ReceiverType)> callees)
    {
        Rejected = rejected;
        HeapMembers = heapMembers;
        Callees = callees;
    }

    public bool Rejected { get; }

    public IReadOnlyList<ISymbol> HeapMembers { get; }

    public IReadOnlyList<(IMethodSymbol Method, bool IsVirtual, ITypeSymbol? ReceiverType)> Callees { get; }

    private static readonly BodyReads None = new(true, new List<ISymbol>(), new List<(IMethodSymbol, bool, ITypeSymbol?)>());

    public static BodyReads Of(Body body, IMethodSymbol method, Func<ISymbol, bool> isHeapMember, Func<ITypeSymbol, bool> isScalar)
    {
        if (method.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not { } syntax) return None;
        IOperation? root;
        try
        {
            root = body.Unit.Compilation.GetSemanticModel(syntax.SyntaxTree).GetOperation(syntax);
        }
        catch (ArgumentException)
        {
            return None;
        }
        if (root == null) return None;
        var heap = new List<ISymbol>();
        var callees = new List<(IMethodSymbol, bool, ITypeSymbol?)>();
        foreach (var o in root.DescendantsAndSelf())
        {
            if (HandsToDotnet(o)) return None;
            switch (o)
            {
                case IFieldReferenceOperation f when SymbolKeys.InSource(f.Field):
                    if (!isHeapMember(f.Field)) break;
                    if (!HeapTracked(f.Field.Type, isScalar)) return None;
                    heap.Add(f.Field);
                    break;
                case IPropertyReferenceOperation p when SymbolKeys.InSource(p.Property):
                {
                    var isVirtual = Dispatch.IsVirtualAccess(p.Property, p.Instance);
                    if (isHeapMember(p.Property) && !isVirtual)
                    {
                        if (!HeapTracked(p.Property.Type, isScalar)) return None;
                        heap.Add(p.Property);
                    }
                    else if (p.Property.GetMethod is { } getter) callees.Add((getter, isVirtual, p.Instance?.Type));
                    else return None;
                    break;
                }
                case IPropertyReferenceOperation p:
                    if (!p.Property.IsStatic && !(p.Type != null && isScalar(p.Type)) && !OwnReceiver(p.Instance)) return None;
                    break;
                case IInvocationOperation { TargetMethod.MethodKind: MethodKind.DelegateInvoke }:
                    return None;
                case IInvocationOperation c when SymbolKeys.InSource(c.TargetMethod):
                    callees.Add((c.TargetMethod, c.IsVirtual, c.Instance?.Type));
                    break;
                case IInvocationOperation c:
                    if (c.Instance != null && !OwnReceiver(c.Instance)) return None;
                    break;
                case IObjectCreationOperation { Constructor: { } constructor } when SymbolKeys.InSource(constructor):
                    return None;
                case IDynamicInvocationOperation or IDynamicMemberReferenceOperation or IDynamicIndexerAccessOperation or IDynamicObjectCreationOperation:
                    return None;
            }
        }
        return new BodyReads(false, heap, callees);
    }

    /// Whether data in a field or auto-property of this type can change only by a write the heap sees (re-review 2, I1):
    /// a string, a scalar, an enum (or Nullable of one), or a type declared in the project, whose members the heap
    /// tracks. Any other type (a builder, an AsyncLocal, a collection, an array, a stream, a type parameter) holds an
    /// object a request can fill (Append, a Value set, an Add, an alias of a request store) with no write of the member,
    /// so a read of it, as a receiver or as a value given on, is no part of a derivation.
    public static bool HeapTracked(ITypeSymbol type, Func<ITypeSymbol, bool> isScalar)
    {
        type = SourceFinder.UnwrapNullable(type);
        if (type.SpecialType == SpecialType.System_String || type.TypeKind == TypeKind.Enum || isScalar(type)) return true;
        return type is INamedTypeSymbol named && SymbolKeys.InSource(named.OriginalDefinition);
    }

    /// Whether an operation hands a value of a project type to code of .NET that may call the project's own overrides
    /// (re-review 3, M1; ToString through Concat or Format, an interpolation hole, `+` with a string, Equals or
    /// GetHashCode in a collection): a conversion of a project-typed value to a type that is not the project's (`object`,
    /// IFormattable, IEnumerable), or a project-defined conversion; an interpolation hole of a project type (a handler
    /// takes it as a type parameter, with no conversion); an argument of a .NET method whose type mentions a project type
    /// (`string.Join<T>(..., IEnumerable<T>)`). The walk follows no override run by .NET, so such a derivation ends.
    public static bool HandsToDotnet(IOperation o)
    {
        switch (o)
        {
            case IConversionOperation { Operand.Type: { } from } conversion:
                if (conversion.OperatorMethod != null && SymbolKeys.InSource(conversion.OperatorMethod)) return true;
                return MentionsProject(from, 0) && !(conversion.Type is { } to && MentionsProject(to, 0));
            case IInterpolationOperation { Expression.Type: { } hole }:
                return MentionsProject(hole, 0);
            case IArgumentOperation { Value.Type: { } given, Parent: IInvocationOperation call } when !SymbolKeys.InSource(call.TargetMethod):
                return MentionsProject(given, 0);
            default:
                return false;
        }
    }

    /// A type declared in the project, or one built from it (an array of it, a generic type given it).
    private static bool MentionsProject(ITypeSymbol type, int depth)
    {
        if (depth > 6) return false;
        if (type is IArrayTypeSymbol array) return MentionsProject(array.ElementType, depth + 1);
        if (type is not INamedTypeSymbol named) return false;
        if (SymbolKeys.InSource(named.OriginalDefinition)) return true;
        foreach (var a in named.TypeArguments)
            if (MentionsProject(a, depth + 1)) return true;
        return false;
    }

    /// The body's own parameter or local, or a constant.
    private static bool OwnReceiver(IOperation? receiver)
    {
        while (receiver is IConversionOperation c) receiver = c.Operand;
        return receiver is ILocalReferenceOperation or IParameterReferenceOperation || receiver?.ConstantValue.HasValue == true;
    }
}
