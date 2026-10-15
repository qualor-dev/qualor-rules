using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// What each parameter of a lambda given to one of .NET's members receives (Task 35; models/README.md, "Interprocedural"):
/// the member's documented signature (learn.microsoft.com, the API reference of each type) says what the member passes to
/// its delegate, so the lambda's parameter gets that and nothing else, no longer the join of the call's receiver and every
/// argument. A member or a delegate parameter the table does not name, and a parameter it leaves open (an accumulator, a
/// group, a result paired with another selector's), keeps that join.
///
/// - ConcurrentDictionary<TKey,TValue>: GetOrAdd's `valueFactory` and AddOrUpdate's `addValueFactory` get the key (and
///   the `factoryArgument`); `updateValueFactory` the key, the value stored for it (the dictionary's) and the
///   `factoryArgument`.
/// - List<T> (ForEach, Find, FindAll, FindIndex, FindLast, FindLastIndex, Exists, TrueForAll, RemoveAll, ConvertAll, Sort)
///   and Array (the same as static methods given the array): an element (the list's or the array's taint).
/// - Enumerable: a `predicate`, `selector`, `keySelector`, `elementSelector` or `collectionSelector` of a method with a
///   `source`: an element of `source` (an index: nothing); Zip's `resultSelector` an element of `first` and of `second`;
///   Join's and GroupJoin's key selectors an element of `outer` or `inner`, their `resultSelector` one of each (GroupJoin:
///   the group of `inner`). Aggregate, GroupBy's and SelectMany's result selectors stay open.
/// - TaskFactory.StartNew's `action` or `function` given a `state`: the state; Task.ContinueWith's continuation: the task
///   (the receiver) and its `state`. (Task.Run's delegates take no parameter.)
internal sealed partial class MethodAnalyzer
{
    /// The receiver among a binding's sources.
    private const int BoundReceiver = -1;

    private static readonly HashSet<string> CallbackMethods = new(StringComparer.Ordinal)
    {
        "ForEach", "Find", "FindAll", "FindIndex", "FindLast", "FindLastIndex", "Exists", "TrueForAll", "RemoveAll", "ConvertAll", "Sort",
    };

    private static readonly HashSet<string> ElementSelectors = new(StringComparer.Ordinal)
    {
        "predicate", "selector", "keySelector", "elementSelector", "collectionSelector",
    };

    /// For a delegate given as `delegateParameter` of the external member `definition`: per parameter of the delegate, the
    /// definition ordinals of the inputs whose values it gets (BoundReceiver: the receiver; empty: nothing), or null where
    /// it is open; null when the member is not in the table.
    private static int[]?[]? DelegateBinding(IMethodSymbol definition, IParameterSymbol delegateParameter)
    {
        if (SymbolKeys.InSource(definition) || definition.ContainingType is not { } type) return null;
        if (delegateParameter.Type is not INamedTypeSymbol { DelegateInvokeMethod: { } invoke }) return null;
        var arity = invoke.Parameters.Length;
        int Of(string name) => definition.Parameters.FirstOrDefault(p => p.Name == name)?.Ordinal ?? -2;
        int[]?[]? Each(params int[]?[] sources) => sources.Length == arity && sources.All(s => s == null || s.All(o => o != -2)) ? sources : null;
        int[]?[] All(int source) => Enumerable.Range(0, arity).Select(_ => (int[]?)new[] { source }).ToArray();
        var name = delegateParameter.Name;
        switch (SymbolMatch.MetadataName(type.OriginalDefinition))
        {
            case "System.Collections.Concurrent.ConcurrentDictionary`2":
                if ((definition.Name == "GetOrAdd" && name == "valueFactory") || (definition.Name == "AddOrUpdate" && name == "addValueFactory"))
                    return arity == 1 ? Each(new[] { Of("key") }) : Each(new[] { Of("key") }, new[] { Of("factoryArgument") });
                if (definition.Name == "AddOrUpdate" && name == "updateValueFactory")
                    return arity == 2 ? Each(new[] { Of("key") }, new[] { BoundReceiver }) : Each(new[] { Of("key") }, new[] { BoundReceiver }, new[] { Of("factoryArgument") });
                return null;
            case "System.Collections.Generic.List`1" when !definition.IsStatic && CallbackMethods.Contains(definition.Name):
                return All(BoundReceiver);
            case "System.Array" when definition.IsStatic && CallbackMethods.Contains(definition.Name) && Of("array") >= 0:
                return All(Of("array"));
            case "System.Linq.Enumerable":
                switch (definition.Name, name)
                {
                    case ("Zip", "resultSelector"):
                        return Each(new[] { Of("first") }, new[] { Of("second") });
                    case ("Join" or "GroupJoin", "outerKeySelector"):
                        return Each(new[] { Of("outer") });
                    case ("Join" or "GroupJoin", "innerKeySelector"):
                        return Each(new[] { Of("inner") });
                    case ("Join" or "GroupJoin", "resultSelector"):
                        return Each(new[] { Of("outer") }, new[] { Of("inner") });
                    case ("Aggregate", _):
                        return null;
                }
                if (!ElementSelectors.Contains(name) || Of("source") < 0) return null;
                // An element of the source; an index (Select((x, i) => ...)) carries nothing.
                return invoke.Parameters.Select(p => p.Type.SpecialType == SpecialType.System_Int32 ? Array.Empty<int>() : (int[]?)new[] { Of("source") }).ToArray();
            case "System.Threading.Tasks.TaskFactory" or "System.Threading.Tasks.TaskFactory`1"
                when definition.Name == "StartNew" && name is "action" or "function" && Of("state") >= 0:
                return Each(new[] { Of("state") });
            case "System.Threading.Tasks.Task" or "System.Threading.Tasks.Task`1"
                when definition.Name == "ContinueWith" && name is "continuationAction" or "continuationFunction":
                return arity == 1 ? Each(new[] { BoundReceiver }) : Each(new[] { BoundReceiver }, new[] { Of("state") });
            default:
                return null;
        }
    }

    /// The value a bound lambda parameter gets: the join of its sources among the call's inputs (and receiver).
    private static TaintValue Bound(int[] sources, Input[] inputs, TaintValue receiver)
    {
        var value = TaintValue.Clean;
        foreach (var s in sources)
        {
            if (s == BoundReceiver)
            {
                value = value.Join(receiver);
                continue;
            }
            foreach (var i in inputs)
                if (i.Ordinal == s && i.RefKind != RefKind.Out) value = value.Join(i.Value);
        }
        return value;
    }
}
